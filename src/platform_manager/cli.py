"""pmgr: check platform access, pipelines and Argo CD; switch clusters safely."""

import argparse
import json
import os
import sys
import webbrowser
from importlib import resources
from pathlib import Path

from . import __version__, report
from .config import ConfigError, config_path, load
from .findings import Severity, worst
from .runner import Runner
from .senses import AREAS, auth, clusters, sweep


def _exit_code(findings):
    w = worst(findings)
    return 1 if w is not None and w >= Severity.ERROR else 0


def _emit(args, result):
    fmt = getattr(args, "format", "text")
    if fmt == "json":
        text = report.as_json(result.findings, result.statuses, result.unseen, result.usage, result.accounts)
    elif fmt == "md":
        text = report.as_markdown(result.findings, result.statuses, result.unseen, result.usage, result.accounts)
    else:
        floor = Severity.INFO if getattr(args, "all", False) else Severity.WARNING
        report.terminal(
            result.findings, result.statuses, result.unseen, result.usage, min_severity=floor, accounts=result.accounts
        )
        return
    if getattr(args, "out", None):
        Path(args.out).write_text(text)
        print(f"Wrote {args.out}", file=sys.stderr)
    else:
        print(text)


# --- commands ---------------------------------------------------------------


def cmd_status(args, cfg, runner):
    result = sweep(runner, cfg, areas=["access"], cluster_names=args.clusters or None)
    _emit(args, result)
    return _exit_code(result.findings)


def cmd_doctor(args, cfg, runner):
    areas = args.only or AREAS
    result = sweep(runner, cfg, areas=areas, repos=args.repo or None, cluster_names=args.cluster or None)
    _emit(args, result)
    return _exit_code(result.findings)


def cmd_pipelines(args, cfg, runner):
    result = sweep(runner, cfg, areas=["pipelines", "workflows"], repos=args.repo or None)
    _emit(args, result)
    return _exit_code(result.findings)


def cmd_argo(args, cfg, runner):
    result = sweep(runner, cfg, areas=["argo"], cluster_names=args.clusters or None)
    _emit(args, result)
    return _exit_code(result.findings)


def cmd_use(args, cfg, runner):
    target = cfg.cluster(args.cluster)
    status = clusters.check_all(runner, _only(cfg, target))[0]
    problems = [f for f in clusters.findings_for(status, cfg) if f.severity >= Severity.ERROR]
    if problems and not args.force:
        report.terminal(problems)
        print(f"\nNot switching to {target.name}. Fix the above, or use --force.", file=sys.stderr)
        return 1
    r = clusters.switch(runner, target)
    if not r.ok:
        print(r.output, file=sys.stderr)
        return 1
    print(f"Switched to {target.name} ({target.context}).", file=sys.stderr)
    print(f"For aws commands in this shell: export AWS_PROFILE={target.aws_profile}", file=sys.stderr)
    print(f'Or run: eval "$(pmgr env {target.name})"', file=sys.stderr)
    return 0


def cmd_env(args, cfg, runner):
    c = cfg.cluster(args.cluster)
    print(f"export AWS_PROFILE={c.aws_profile}")
    if c.region:
        print(f"export AWS_REGION={c.region}")
    return 0


def cmd_login(args, cfg, runner):
    target = cfg.target(args.cluster)
    cmd = cfg.refresh_args(target)
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    code = runner.interactive(cmd)
    if code != 0:
        print(f"Login command exited with {code}.", file=sys.stderr)
    if target not in cfg.clusters:  # an account profile with no cluster
        status = clusters.ClusterStatus(target, auth.check_profile(runner, target.aws_profile, target.expected_role))
        found = auth.findings_for(target, status.auth, cfg)
    else:
        status = clusters.check_all(runner, _only(cfg, target))[0]
        found = clusters.findings_for(status, cfg)
    if not found:
        print(f"{target.name}: AWS session and cluster access are OK.", file=sys.stderr)
        return 0
    report.terminal(found)
    if status.auth.state == auth.NO_ACCESS and cfg.pim_url:
        print(f"\nThe role isn't active yet. Activate it in PIM: {cfg.pim_url}", file=sys.stderr)
    return _exit_code(found)


def cmd_jit(args, cfg, runner):
    if not cfg.pim_url:
        print("No PIM activation URL is configured ([pim] activation_url is empty).", file=sys.stderr)
        return 2
    if args.cluster:
        c = cfg.target(args.cluster)
        if c.pim_group:
            print(f"Activate PIM group: {c.pim_group}")
    print(cfg.pim_url)
    if not args.no_open:
        webbrowser.open(cfg.pim_url)
    return 0


def _only(cfg, cluster):
    from dataclasses import replace

    return replace(cfg, clusters=[cluster])


# --- init -------------------------------------------------------------------


def discover_clusters(runner):
    """Read EKS contexts from kubeconfig and the AWS profile each one's exec plugin uses."""
    r = runner.run(["kubectl", "config", "view", "-o", "json"], timeout=10)
    if not r.ok:
        return []
    kc = json.loads(r.stdout)
    users = {u["name"]: (u.get("user") or {}) for u in kc.get("users") or []}
    found = []
    for ctx in kc.get("contexts") or []:
        name, spec = ctx.get("name", ""), ctx.get("context") or {}
        exec_ = (users.get(spec.get("user")) or {}).get("exec") or {}
        args_ = exec_.get("args") or []
        env = {e.get("name"): e.get("value") for e in exec_.get("env") or []}
        profile = env.get("AWS_PROFILE", "")
        if "--profile" in args_ and args_.index("--profile") + 1 < len(args_):
            profile = args_[args_.index("--profile") + 1]
        region = args_[args_.index("--region") + 1] if "--region" in args_[:-1] else ""
        if "eks" not in " ".join(args_) and ":eks:" not in name:
            continue
        short = name.rsplit("/", 1)[-1]
        eks = args_[args_.index("--cluster-name") + 1] if "--cluster-name" in args_[:-1] else ""
        entry = {"name": short, "context": name, "aws_profile": profile or "SET-ME", "region": region}
        if eks and not name.startswith("arn:aws:eks:"):
            entry["eks_cluster"] = eks  # an alias context doesn't name its cluster, so record it
        found.append(entry)
    return found


def _toml_clusters(found):
    blocks = []
    for c in found:
        lines = ["[[clusters]]"] + [f"{k} = {json.dumps(v)}" for k, v in c.items() if v]
        lines += ['expected_role = ""   # e.g. "PlatformAdmin"', 'pim_group = ""       # Entra group you activate']
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n\n"


def cmd_init(args, cfg_unused, runner):
    path = Path(args.path).expanduser() if args.path else config_path()
    if path.exists() and not args.force:
        print(f"{path} already exists. Use --force to overwrite.", file=sys.stderr)
        return 2
    text = resources.files("platform_manager").joinpath("config.example.toml").read_text()
    if args.from_kubeconfig:
        found = discover_clusters(runner)
        if found:
            start = text.index("# One block per cluster")
            end = text.index("[github]")
            text = (
                text[:start]
                + "# Discovered from kubeconfig. Check each aws_profile.\n"
                + _toml_clusters(found)
                + text[end:]
            )
            print(f"Found {len(found)} EKS context(s) in kubeconfig.", file=sys.stderr)
        else:
            print("No EKS contexts found in kubeconfig. Writing the example clusters.", file=sys.stderr)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    print(f"Wrote {path}. Edit it, then run `pmgr status`.", file=sys.stderr)
    return 0


# --- parser -----------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(prog="pmgr", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", help="Config file (default: $PMGR_CONFIG or ~/.config/platform-manager/config.toml)")
    sub = p.add_subparsers(dest="command", required=True)

    def outputs(sp):
        sp.add_argument("--format", choices=["text", "json", "md"], default="text")
        sp.add_argument("--out", help="Write json/md output to this file")
        sp.add_argument("--all", action="store_true", help="Include info-level findings in text output")

    sp = sub.add_parser("status", help="AWS session and cluster access for each cluster")
    sp.add_argument("clusters", nargs="*")
    outputs(sp)
    sp.set_defaults(fn=cmd_status)

    sp = sub.add_parser("use", help="Check a cluster, then switch kubectl to it")
    sp.add_argument("cluster")
    sp.add_argument("--force", action="store_true", help="Switch even if checks fail")
    sp.set_defaults(fn=cmd_use)

    sp = sub.add_parser("env", help="Print exports for a cluster, for eval")
    sp.add_argument("cluster")
    sp.set_defaults(fn=cmd_env)

    sp = sub.add_parser("login", help="Refresh a cluster's AWS session, then re-check it")
    sp.add_argument("cluster")
    sp.set_defaults(fn=cmd_login)

    sp = sub.add_parser("jit", help="Open the Azure PIM activation page")
    sp.add_argument("cluster", nargs="?")
    sp.add_argument("--no-open", action="store_true", help="Print the link without opening a browser")
    sp.set_defaults(fn=cmd_jit)

    sp = sub.add_parser("pipelines", help="Pipeline failures, flakiness, slowness, and workflow gaps")
    sp.add_argument("--repo", action="append", help="Limit to this repo (repeatable)")
    outputs(sp)
    sp.set_defaults(fn=cmd_pipelines)

    sp = sub.add_parser("argo", help="Argo CD Application health on each reachable cluster")
    sp.add_argument("clusters", nargs="*")
    outputs(sp)
    sp.set_defaults(fn=cmd_argo)

    sp = sub.add_parser("doctor", help="Everything: access, Argo CD, pipelines and workflow gaps")
    sp.add_argument("--only", action="append", choices=AREAS, help="Limit to an area (repeatable)")
    sp.add_argument("--repo", action="append")
    sp.add_argument("--cluster", action="append")
    outputs(sp)
    sp.set_defaults(fn=cmd_doctor)

    sp = sub.add_parser("init", help="Create a config file")
    sp.add_argument("--from-kubeconfig", action="store_true", help="Pre-fill clusters from kubeconfig")
    sp.add_argument("--path", help="Where to write it")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_init)
    return p


def main(argv=None, runner=None):
    args = build_parser().parse_args(argv)
    runner = runner or Runner()
    if args.config:
        os.environ["PMGR_CONFIG"] = args.config
    try:
        cfg = None if args.command == "init" else load()
        return args.fn(args, cfg, runner)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
