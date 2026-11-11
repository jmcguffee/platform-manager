"""Load ~/.config/platform-manager/config.toml.

The config holds everything org-specific (account IDs, cluster names, repo
names), so it lives outside the repo. See config.example.toml.
"""

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path.home() / ".config" / "platform-manager" / "config.toml"
DEFAULT_PIM_URL = "https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup"
REPO_KINDS = {"terraform", "gitops", "app", "other"}


class ConfigError(Exception):
    pass


@dataclass
class Cluster:
    name: str
    context: str
    aws_profile: str
    expected_role: str = ""  # substring of the assumed-role ARN, e.g. "PlatformAdmin"
    pim_group: str = ""  # Entra group to activate in PIM for this access
    region: str = ""
    argocd_namespace: str = "argocd"


@dataclass
class Repo:
    name: str
    kind: str = "other"


@dataclass
class Config:
    clusters: list[Cluster]
    pim_url: str = DEFAULT_PIM_URL
    session_hours: float = 8
    warn_minutes: int = 30
    refresh_command: list[str] = field(default_factory=lambda: ["aws", "sso", "login", "--profile", "{profile}"])
    github_org: str = ""
    repos: list[Repo] = field(default_factory=list)
    lookback_days: int = 14
    max_runs_per_repo: int = 300
    path: Path | None = None

    def cluster(self, name):
        for c in self.clusters:
            if c.name == name or c.context == name:
                return c
        known = ", ".join(c.name for c in self.clusters) or "none configured"
        raise ConfigError(f"Unknown cluster '{name}'. Known clusters: {known}")

    def refresh_args(self, cluster):
        return [part.replace("{profile}", cluster.aws_profile) for part in self.refresh_command]


def config_path():
    return Path(os.environ.get("PMGR_CONFIG", DEFAULT_PATH)).expanduser()


def _take(table, cls, where):
    allowed = set(cls.__dataclass_fields__)
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)} (allowed: {sorted(allowed)})")
    try:
        return cls(**table)
    except TypeError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


def parse(data, path=None):
    clusters = [_take(t, Cluster, f"clusters[{i}]") for i, t in enumerate(data.get("clusters", []))]
    names = [c.name for c in clusters]
    if len(names) != len(set(names)):
        raise ConfigError("Cluster names must be unique")

    pim = data.get("pim", {})
    aws = data.get("aws", {})
    gh = data.get("github", {})
    repos = [_take(t, Repo, f"github.repos[{i}]") for i, t in enumerate(gh.get("repos", []))]
    for r in repos:
        if r.kind not in REPO_KINDS:
            raise ConfigError(f"github.repos '{r.name}': kind must be one of {sorted(REPO_KINDS)}")

    refresh = aws.get("refresh_command", Config.__dataclass_fields__["refresh_command"].default_factory())
    if not isinstance(refresh, list) or not all(isinstance(p, str) for p in refresh) or not refresh:
        raise ConfigError("aws.refresh_command must be a list of strings, e.g. ['aws', 'sso', 'login']")

    return Config(
        clusters=clusters,
        pim_url=pim.get("activation_url", DEFAULT_PIM_URL),
        session_hours=pim.get("session_hours", 8),
        warn_minutes=pim.get("warn_minutes", 30),
        refresh_command=refresh,
        github_org=gh.get("org", ""),
        repos=repos,
        lookback_days=gh.get("lookback_days", 14),
        max_runs_per_repo=gh.get("max_runs_per_repo", 300),
        path=path,
    )


def load(path=None):
    path = Path(path) if path else config_path()
    if not path.exists():
        raise ConfigError(f"No config at {path}. Run 'pmgr init' to create one.")
    with path.open("rb") as fh:
        try:
            data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
    return parse(data, path)
