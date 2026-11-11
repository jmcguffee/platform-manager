"""AWS session checks for SSO roles activated through Entra PIM.

`aws sts get-caller-identity` tells us whether a profile works. When it
doesn't, the error text tells us why: an expired session needs a refresh,
while a role that was never granted needs a PIM activation first.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime

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


def check_profile(runner, profile, expected_role="", warn_minutes=30, now=None):
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

    status.expires_at = _expiry(runner, profile)
    left = status.minutes_left(now)
    if left is not None and left <= warn_minutes:
        status.state = EXPIRING
        status.detail = f"Session ends in {max(left, 0)} min"
    return status


def findings_for(cluster, status, cfg):
    """Turn an AuthStatus into an actionable finding, or nothing when it's healthy."""
    login = f"pmgr login {cluster.name}"
    pim_hint = f" (PIM group: {cluster.pim_group})" if cluster.pim_group else ""
    base = {"area": "auth", "resource": cluster.name, "evidence": {"profile": status.profile}}

    if status.state == OK:
        return []
    if status.state == EXPIRING:
        return [
            Finding(
                "auth.expiring",
                Severity.WARNING,
                message=f"AWS session for {cluster.name} ends soon: {status.detail}",
                fix=f"Re-activate in PIM{pim_hint} before it lapses, then run `{login}`.",
                link=cfg.pim_url,
                **base,
            )
        ]
    if status.state == EXPIRED:
        return [
            Finding(
                "auth.expired",
                Severity.ERROR,
                message=f"AWS session for {cluster.name} has expired or is missing",
                fix=f"Run `{login}`. If it still fails, your {cfg.session_hours:g}h PIM window has "
                f"probably ended: activate it again{pim_hint}.",
                link=cfg.pim_url,
                **base,
            )
        ]
    if status.state == NO_ACCESS:
        return [
            Finding(
                "auth.no_access",
                Severity.ERROR,
                message=f"Signed in, but the role for {cluster.name} isn't granted: {status.detail}",
                fix=f"Activate the role in Azure PIM{pim_hint}. It can take a few minutes to reach AWS. "
                f"Then run `{login}`.",
                link=cfg.pim_url,
                **base,
            )
        ]
    if status.state == WRONG_ROLE:
        return [
            Finding(
                "auth.wrong_role",
                Severity.WARNING,
                message=status.detail,
                fix=f"Check aws_profile for {cluster.name} in your config, or activate the right PIM group{pim_hint}.",
                link=cfg.pim_url,
                **base,
            )
        ]
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
