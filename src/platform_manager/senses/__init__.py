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
    accounts: list = field(default_factory=list)  # [(Account, AuthStatus)] for profiles without a cluster
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

    if "access" in want and not cluster_names:
        covered = {c.aws_profile for c in cfg.clusters}
        extra = [a for a in cfg.accounts if a.aws_profile not in covered]
        with ThreadPoolExecutor(max_workers=8) as pool:
            checked = pool.map(
                lambda a: auth.check_profile(runner, a.aws_profile, a.expected_role, cfg.warn_minutes), extra
            )
            result.accounts = list(zip(extra, checked, strict=True))
        for account, status in result.accounts:
            result.findings += auth.findings_for(account, status, cfg)

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

    result.findings = auth.collapse_sessions(result.findings)

    targets = [r for r in cfg.repos if not repos or r.name in repos or r.name.rsplit("/", 1)[-1] in repos]
    if want & {"pipelines", "workflows"} and targets:
        gh = GitHub(runner, cfg.github_org)
        # Check each owner separately, so a SAML block on one org doesn't hide the others.
        readable = []
        for owner in dict.fromkeys(r.owner(cfg.github_org) for r in targets):
            try:
                gh.check_access(owner)
                readable += [r for r in targets if r.owner(cfg.github_org) == owner]
            except GitHubError as err:
                result.findings.append(github_finding(owner, err))
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                for repo, (found, usage, unseen) in zip(
                    readable, pool.map(lambda r: _repo(gh, cfg, r, want), readable), strict=True
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
