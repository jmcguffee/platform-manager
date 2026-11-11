"""The senses: read-only checks that each return findings.

Each sense module has `collect(...)`, which does I/O through the runner or gh, and
`assess(...)`, which is pure. `sweep()` runs them in order, because cluster access
decides which clusters the Argo check can read.

Nothing here writes anything. Fixes are a person's job, or later a "hand" that
opens a pull request for a person to merge.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

from ..findings import Finding, Severity
from ..github import GitHub, GitHubError
from . import argo, auth, clusters, pipelines, workflows

AREAS = ("access", "argo", "pipelines", "workflows")


@dataclass
class Sweep:
    findings: list = field(default_factory=list)
    statuses: list = field(default_factory=list)
    usage: dict = field(default_factory=dict)  # repo -> [(workflow, minutes)]
    unseen: list = field(default_factory=list)  # things we couldn't read, said out loud


def github_finding(org, err):
    base = {"area": "auth", "resource": f"github:{org}"}
    if err.kind == "saml":
        return Finding(
            "github.saml",
            Severity.ERROR,
            message=f"GitHub token isn't authorized for {org}'s SAML SSO",
            fix="Run `gh auth refresh -h github.com` and approve SSO for the org in the browser.",
            link=f"https://github.com/orgs/{org}/sso",
            **base,
        )
    if err.kind == "auth":
        return Finding(
            "github.auth",
            Severity.ERROR,
            message=f"GitHub access failed: {err}",
            fix="Run `gh auth login` (or `gh auth status` to see which account is active).",
            **base,
        )
    if err.kind == "rate_limit":
        return Finding(
            "github.rate_limit",
            Severity.WARNING,
            message="GitHub API rate limit hit",
            fix="Wait for the limit to reset, or lower lookback_days / max_runs_per_repo.",
            **base,
        )
    if err.kind == "missing_cli":
        return Finding("github.no_cli", Severity.CRITICAL, message=str(err), fix="Install the GitHub CLI.", **base)
    return Finding("github.error", Severity.ERROR, message=f"GitHub request failed: {err}", **base)


def _repo(gh, cfg, repo, want):
    """One repo's senses. Access-wide problems (auth, SAML, rate limit) propagate; anything else
    stays with this repo, so one bad repo doesn't hide the others."""
    try:
        return _repo_senses(gh, cfg, repo, want)
    except GitHubError as err:
        if err.kind != "error":
            raise
        return [], [], [f"{repo.name}: {err}"]


def _repo_senses(gh, cfg, repo, want):
    found, usage, unseen = [], [], []
    if "pipelines" in want:
        got = pipelines.collect(gh, repo.name, cfg.lookback_days, cfg.max_runs_per_repo)
        if got is None:
            unseen.append(f"{repo.name}: Actions runs")
        else:
            branch, runs, explained = got
            found += pipelines.assess(repo.name, branch, runs, explained, cfg.lookback_days)
            usage = pipelines.usage(runs)
    if "workflows" in want:
        files = gh.workflow_files(repo.name)
        if files is None:
            unseen.append(f"{repo.name}: workflow files")
        found += workflows.assess_repo(repo.name, repo.kind, files)
    return found, usage, unseen


def sweep(runner, cfg, areas=AREAS, repos=None, cluster_names=None):
    want = set(areas)
    result = Sweep()
    chosen = [c for c in cfg.clusters if not cluster_names or c.name in cluster_names]

    if want & {"access", "argo"} and chosen:
        result.statuses = clusters.check_all(runner, replace(cfg, clusters=chosen))
        if "access" in want:
            for s in result.statuses:
                result.findings += clusters.findings_for(s, cfg)
        if "argo" in want:
            for s in result.statuses:
                if s.k8s != clusters.K8S_OK:
                    result.unseen.append(f"{s.cluster.name}: Argo CD (no cluster access)")
                    continue
                apps = argo.collect(runner, s.cluster)
                if apps is None:
                    result.unseen.append(f"{s.cluster.name}: Argo CD Applications (not readable)")
                result.findings += argo.assess(s.cluster.name, apps)

    targets = [r for r in cfg.repos if not repos or r.name in repos]
    if want & {"pipelines", "workflows"} and targets:
        gh = GitHub(runner, cfg.github_org)
        try:
            gh.check_access()
            with ThreadPoolExecutor(max_workers=4) as pool:
                for repo, (found, usage, unseen) in zip(
                    targets, pool.map(lambda r: _repo(gh, cfg, r, want), targets), strict=True
                ):
                    result.findings += found
                    result.unseen += unseen
                    if usage:
                        result.usage[repo.name] = usage
        except GitHubError as err:
            result.findings.append(github_finding(cfg.github_org, err))

    result.findings.sort(key=lambda f: (-f.severity, f.area, f.resource))
    return result


__all__ = ["AREAS", "Sweep", "argo", "auth", "clusters", "pipelines", "sweep", "workflows"]
