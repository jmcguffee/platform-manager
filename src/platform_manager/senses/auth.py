"""AWS session checks for SSO roles activated through Entra PIM.

`aws sts get-caller-identity` tells us whether a profile works. When it
doesn't, the error text tells us why: an expired session needs a refresh,
while a role that was never granted needs a PIM activation first.
"""

import configparser
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..findings import Finding, Severity

OK = "ok"
EXPIRING = "expiring"
EXPIRED = "expired"
NO_ACCESS = "no_access"
WRONG_ROLE = "wrong_role"
UNREACHABLE = "unreachable"
NO_PROFILE = "no_profile"
NO_CLI = "no_cli"
UNKNOWN = "unknown"

# Lowercase substrings from AWS CLI errors, checked in this order.
_PATTERNS = [
    (NO_PROFILE, ["config profile", "could not be found"]),
    (
        EXPIRED,
        [
            "token has expired",
            "expiredtoken",
            "sso session associated with this profile has expired",
            "error loading sso token",
            "unable to locate credentials",
            "security token included in the request is expired",
            "session token not found or invalid",
            "unauthorizedexception",
            "invalid_grant",
        ],
    ),
    (
        NO_ACCESS,
        [
            "forbiddenexception",
            "no access",
            "not authorized to perform: sts:assumerole",
            "accessdenied",
        ],
    ),
    (
        UNREACHABLE,
        [
            "could not connect to the endpoint url",
            "connect timeout",
            "read timeout",
            "name resolution",
            "network is unreachable",
            "connection refused",
        ],
    ),
]


@dataclass
class AuthStatus:
    profile: str
    state: str
    arn: str = ""
    account: str = ""
    expires_at: datetime | None = None
    detail: str = ""

    def minutes_left(self, now=None):
        if not self.expires_at:
            return None
        now = now or datetime.now(UTC)
        return int((self.expires_at - now).total_seconds() // 60)


def classify_error(text):
    low = text.lower()
    for state, needles in _PATTERNS:
        if state == NO_PROFILE:
            if all(n in low for n in needles):
                return state
        elif any(n in low for n in needles):
            return state
    return UNKNOWN


def _first_line(text):
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""


def profile_settings(profile, path=None):
    """The profile's block from ~/.aws/config (or AWS_CONFIG_FILE), or {} if there isn't one."""
    path = Path(path or os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")).expanduser()
    parser = configparser.RawConfigParser()
    try:
        parser.read(path)
    except configparser.Error:
        return {}
    section = "default" if profile == "default" else f"profile {profile}"
    return dict(parser[section]) if parser.has_section(section) else {}


def renews_itself(settings):
    """SSO and assume-role profiles get fresh role credentials from the CLI as they expire,
    so the role credentials' expiry says nothing about when you'll be locked out."""
    return any(k in settings for k in ("sso_session", "sso_start_url", "role_arn"))


def _expiry(runner, profile):
    """Read only the Expiration field. The credentials themselves are discarded right away."""
    r = runner.run(["aws", "configure", "export-credentials", "--profile", profile, "--format", "process"])
    if not r.ok:
        return None
    try:
        raw = json.loads(r.stdout).get("Expiration")
    except (ValueError, AttributeError):
        return None
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def check_profile(runner, profile, expected_role="", warn_minutes=30, now=None, settings=None):
    r = runner.run(["aws", "sts", "get-caller-identity", "--profile", profile, "--output", "json"])
    if r.code == 127:
        return AuthStatus(profile, NO_CLI, detail="The aws CLI is not on PATH")
    if r.timed_out:
        return AuthStatus(profile, UNREACHABLE, detail="Timed out calling STS (VPN or proxy?)")
    if not r.ok:
        return AuthStatus(profile, classify_error(r.output), detail=_first_line(r.stderr or r.stdout))

    ident = json.loads(r.stdout)
    status = AuthStatus(profile, OK, arn=ident.get("Arn", ""), account=ident.get("Account", ""))
    if expected_role and expected_role.lower() not in status.arn.lower():
        status.state = WRONG_ROLE
        status.detail = f"Signed in as {status.arn}, expected a role matching '{expected_role}'"
        return status

    settings = profile_settings(profile) if settings is None else settings
    if renews_itself(settings):
        return status  # the session's real end (SSO or PIM) isn't visible locally, so don't guess
    status.expires_at = _expiry(runner, profile)
    left = status.minutes_left(now)
    if left is not None and left <= warn_minutes:
        status.state = EXPIRING
        status.detail = f"Session ends in {max(left, 0)} min"
    return status


def findings_for(cluster, status, cfg):
    """Turn an AuthStatus into an actionable finding, or nothing when it's healthy.

    `cluster` is anything with .name and .pim_group: a cluster, or an account-only profile.
    With no PIM activation URL configured, hints point at SSO login and Identity Center instead.
    """
    login = f"pmgr login {cluster.name}"
    pim = bool(cfg.pim_url)
    group = f" (PIM group: {cluster.pim_group})" if cluster.pim_group else ""
    base = {"area": "auth", "resource": cluster.name, "evidence": {"profile": status.profile}, "link": cfg.pim_url}

    if status.state == OK:
        return []
    if status.state == EXPIRING:
        fix = f"Re-activate in PIM{group} before it lapses, then run `{login}`." if pim else f"Run `{login}`."
        return [
            Finding(
                "auth.expiring",
                Severity.WARNING,
                message=f"AWS session for {cluster.name} ends soon: {status.detail}",
                fix=fix,
                **base,
            )
        ]
    if status.state == EXPIRED:
        fix = f"Run `{login}`."
        if pim:
            fix += (
                f" If it still fails, your {cfg.session_hours:g}h PIM window has probably ended: "
                f"activate it again{group}."
            )
        return [
            Finding(
                "auth.expired",
                Severity.ERROR,
                message=f"AWS session for {cluster.name} has expired or is missing: {status.detail}",
                fix=fix,
                **base,
            )
        ]
    if status.state == NO_ACCESS:
        fix = (
            f"Activate the role in Azure PIM{group}. It can take a few minutes to reach AWS. Then run `{login}`."
            if pim
            else f"Your SSO user isn't assigned this role in this account. Check the permission set assignment "
            f"in IAM Identity Center, then run `{login}`."
        )
        return [
            Finding(
                "auth.no_access",
                Severity.ERROR,
                message=f"Signed in, but the role for {cluster.name} isn't granted: {status.detail}",
                fix=fix,
                **base,
            )
        ]
    if status.state == WRONG_ROLE:
        extra = f", or activate the right PIM group{group}" if pim else ""
        return [
            Finding(
                "auth.wrong_role",
                Severity.WARNING,
                message=status.detail,
                fix=f"Check aws_profile for {cluster.name} in your config{extra}.",
                **base,
            )
        ]
    base.pop("link")
    if status.state == UNREACHABLE:
        return [
            Finding(
                "auth.unreachable",
                Severity.ERROR,
                message=f"Can't reach AWS for {cluster.name}: {status.detail}",
                fix="Check VPN and proxy settings, then retry.",
                **base,
            )
        ]
    if status.state == NO_PROFILE:
        return [
            Finding(
                "auth.no_profile",
                Severity.ERROR,
                message=f"AWS profile '{status.profile}' isn't in ~/.aws/config",
                fix=f"Fix aws_profile for {cluster.name} in {cfg.path or 'your config'}.",
                **base,
            )
        ]
    if status.state == NO_CLI:
        return [Finding("auth.no_cli", Severity.CRITICAL, message=status.detail, fix="Install AWS CLI v2.", **base)]
    return [
        Finding(
            "auth.unknown",
            Severity.ERROR,
            message=f"AWS check for {cluster.name} failed: {status.detail}",
            fix=f"Run `aws sts get-caller-identity --profile {status.profile}` to see the full error.",
            **base,
        )
    ]


def collapse_sessions(findings, settings_for=profile_settings):
    """Profiles that share one SSO session expire together and one login fixes them all.
    Report that as one finding, not one per profile."""
    groups = {}
    for f in findings:
        if f.check == "auth.expired":
            session = settings_for(f.evidence.get("profile", "")).get("sso_session")
            if session:
                groups.setdefault(session, []).append(f)
    merged, dropped = [], set()
    for session, group in groups.items():
        if len(group) < 2:
            continue
        names = ", ".join(sorted(f.resource for f in group))
        merged.append(
            Finding(
                "auth.expired",
                Severity.ERROR,
                area="auth",
                resource=f"sso-session {session}",
                message=f"SSO session '{session}' has expired, so {len(group)} profiles can't sign in ({names})",
                fix=f"Run `pmgr login {group[0].resource}` (or `aws sso login --sso-session {session}`). "
                "One login covers all of them.",
                link=group[0].link,
                evidence={"profiles": sorted(f.evidence.get("profile", "") for f in group), "detail": group[0].message},
            )
        )
        dropped.update(id(f) for f in group)
    return [f for f in findings if id(f) not in dropped] + merged
