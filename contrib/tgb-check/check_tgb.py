#!/usr/bin/env python3
"""Validate TargetGroupBindings in platform-apps before Argo syncs them.

Renders each Kustomize overlay and checks that every TargetGroupBinding:
  - names a target group (targetGroupName or targetGroupARN)
  - points at a Service and port that exist in the same build
  - (with --aws) references a target group that exists, has a matching
    target type, and is attached to a load balancer
  - is the only binding for its target group, unless multiClusterTargetGroup is set

Needs no cluster access. The --aws checks need only
elasticloadbalancing:DescribeTargetGroups.
"""

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

TG_NAME_MAX = 32  # AWS limit on target group names


@dataclass
class Finding:
    level: str  # "error" or "warning"
    where: str
    message: str


@dataclass
class Report:
    findings: list = field(default_factory=list)

    def error(self, where, message):
        self.findings.append(Finding("error", where, message))

    def warn(self, where, message):
        self.findings.append(Finding("warning", where, message))

    @property
    def errors(self):
        return [f for f in self.findings if f.level == "error"]


def kustomize_cmd():
    if shutil.which("kustomize"):
        return ["kustomize", "build"]
    if shutil.which("kubectl"):
        return ["kubectl", "kustomize"]
    sys.exit("Neither kustomize nor kubectl is on PATH.")


def discover(root, match):
    """Find kustomization directories under root whose path contains `match`."""
    dirs = set()
    for name in ("kustomization.yaml", "kustomization.yml", "Kustomization"):
        for p in Path(root).rglob(name):
            if match in f"/{p.parent.as_posix()}/":
                dirs.add(p.parent)
    return sorted(dirs)


def build(path, cmd):
    result = subprocess.run(cmd + [str(path)], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "kustomize build failed")
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def service_ports(svc):
    ports = set()
    for p in svc.get("spec", {}).get("ports", []) or []:
        if "port" in p:
            ports.add(p["port"])
        if p.get("name"):
            ports.add(p["name"])
    return ports


def load_target_groups(region):
    import boto3

    client = boto3.client("elbv2", region_name=region)
    by_name, by_arn = {}, {}
    for page in client.get_paginator("describe_target_groups").paginate():
        for tg in page["TargetGroups"]:
            by_name[tg["TargetGroupName"]] = tg
            by_arn[tg["TargetGroupArn"]] = tg
    return by_name, by_arn


def check_build(where, docs, report, target_groups, seen):
    services = {
        (d["metadata"].get("namespace"), d["metadata"]["name"]): d
        for d in docs
        if d.get("kind") == "Service"
    }
    bindings = [
        d
        for d in docs
        if d.get("kind") == "TargetGroupBinding"
        and d.get("apiVersion", "").startswith("elbv2.k8s.aws/")
    ]

    for tgb in bindings:
        meta = tgb["metadata"]
        spec = tgb.get("spec", {})
        ns = meta.get("namespace")
        label = f"TargetGroupBinding {ns or '<no namespace>'}/{meta['name']}"

        tg_name = spec.get("targetGroupName")
        tg_arn = spec.get("targetGroupARN")
        if not tg_name and not tg_arn:
            report.error(where, f"{label}: sets neither targetGroupName nor targetGroupARN")
        if tg_name and tg_arn:
            report.warn(where, f"{label}: sets both targetGroupName and targetGroupARN; the ARN wins")
        if tg_name and len(tg_name) > TG_NAME_MAX:
            report.error(where, f"{label}: targetGroupName '{tg_name}' is over {TG_NAME_MAX} characters")

        ref = spec.get("serviceRef") or {}
        svc = services.get((ns, ref.get("name")))
        if not ref.get("name"):
            report.error(where, f"{label}: serviceRef.name is missing")
        elif svc is None:
            report.error(where, f"{label}: no Service '{ref['name']}' in this build (namespace {ns or '<none>'})")
        elif ref.get("port") not in service_ports(svc):
            ports = sorted(map(str, service_ports(svc)))
            report.error(
                where,
                f"{label}: Service '{ref['name']}' has no port '{ref.get('port')}' (has: {', '.join(ports) or 'none'})",
            )

        tg = None
        if target_groups is not None:
            by_name, by_arn = target_groups
            tg = by_arn.get(tg_arn) if tg_arn else by_name.get(tg_name)
            ident = tg_arn or tg_name
            if ident and tg is None:
                report.error(where, f"{label}: target group '{ident}' does not exist in AWS")
            elif tg is not None:
                want = spec.get("targetType")
                if want and want != tg["TargetType"]:
                    report.error(
                        where,
                        f"{label}: targetType '{want}' but target group "
                        f"'{tg['TargetGroupName']}' is '{tg['TargetType']}'",
                    )
                if not tg.get("LoadBalancerArns"):
                    report.warn(
                        where,
                        f"{label}: target group '{tg['TargetGroupName']}' is not attached to any load balancer "
                        "(missing listener rule?)",
                    )

        # Two bindings on one target group fight over registrations unless both opt in.
        key = tg["TargetGroupArn"] if tg is not None else (tg_arn or tg_name)
        if key:
            if key in seen and not (spec.get("multiClusterTargetGroup") and seen[key][1]):
                report.error(where, f"{label}: target group '{key}' is also bound in {seen[key][0]}")
            else:
                seen[key] = (f"{where} ({label})", bool(spec.get("multiClusterTargetGroup")))


def annotate(finding):
    msg = finding.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{finding.level} file={finding.where}::{msg}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", help="Kustomization directories to check")
    parser.add_argument("--discover", metavar="ROOT", help="Find kustomization directories under ROOT")
    parser.add_argument(
        "--match",
        default="/overlays/",
        help="With --discover, only check directories whose path contains this (default: /overlays/)",
    )
    parser.add_argument("--aws", action="store_true", help="Also check target groups against AWS")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION"), help="AWS region for --aws")
    args = parser.parse_args(argv)

    paths = [Path(p) for p in args.paths]
    if args.discover:
        paths += discover(args.discover, args.match)
    if not paths:
        parser.error("Give kustomization directories or --discover ROOT")

    target_groups = load_target_groups(args.region) if args.aws else None
    cmd = kustomize_cmd()
    report = Report()
    seen = {}
    checked = 0

    for path in paths:
        where = path.as_posix()
        try:
            docs = build(path, cmd)
        except RuntimeError as exc:
            report.error(where, f"kustomize build failed: {exc}")
            continue
        check_build(where, docs, report, target_groups, seen)
        checked += 1

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for f in report.findings:
        if in_actions:
            annotate(f)
        print(f"{f.level.upper():7} {f.where}: {f.message}")

    warnings = len(report.findings) - len(report.errors)
    print(f"\nChecked {checked} build(s): {len(report.errors)} error(s), {warnings} warning(s).")
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
