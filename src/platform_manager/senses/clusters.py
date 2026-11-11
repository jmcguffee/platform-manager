"""Check every configured cluster and switch kubectl contexts safely."""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..findings import Finding, Severity
from . import auth

K8S_OK = "ok"
K8S_LIMITED = "limited"  # authenticated, but RBAC says no to a basic read
K8S_FORBIDDEN = "forbidden"
K8S_UNAUTHORIZED = "unauthorized"
K8S_UNREACHABLE = "unreachable"
K8S_NO_CONTEXT = "no_context"
K8S_SKIPPED = "skipped"  # AWS session is broken, so the cluster check would only repeat that
K8S_UNKNOWN = "unknown"

_K8S_PATTERNS = [
    (K8S_NO_CONTEXT, ["context was not found", 'context "', "does not exist"]),
    (K8S_UNAUTHORIZED, ["unauthorized", "must be logged in", "getting credentials", "exec plugin"]),
    (K8S_FORBIDDEN, ["forbidden"]),
    (
        K8S_UNREACHABLE,
        ["unable to connect", "i/o timeout", "dial tcp", "no such host", "deadline exceeded", "connection refused"],
    ),
]


@dataclass
class ClusterStatus:
    cluster: object
    auth: auth.AuthStatus
    k8s: str = K8S_SKIPPED
    detail: str = ""
    current: bool = False


def _classify_k8s(text):
    low = text.lower()
    for state, needles in _K8S_PATTERNS:
        if state == K8S_NO_CONTEXT:
            if needles[0] in low or (needles[1] in low and needles[2] in low):
                return state
        elif any(n in low for n in needles):
            return state
    return K8S_UNKNOWN


def current_context(runner):
    r = runner.run(["kubectl", "config", "current-context"], timeout=5)
    return r.stdout.strip() if r.ok else ""


def contexts(runner):
    r = runner.run(["kubectl", "config", "get-contexts", "-o", "name"], timeout=5)
    return [c.strip() for c in r.stdout.splitlines() if c.strip()] if r.ok else []


def kube_env(cluster):
    """Point the kubeconfig's aws exec plugin at this cluster's profile."""
    return {**os.environ, "AWS_PROFILE": cluster.aws_profile}


def check_k8s(runner, cluster):
    r = runner.run(
        ["kubectl", "--context", cluster.context, "--request-timeout=8s", "auth", "can-i", "get", "namespaces"],
        timeout=15,
        env=kube_env(cluster),
    )
    if r.code == 127:
        return K8S_UNKNOWN, "kubectl is not on PATH"
    if r.timed_out:
        return K8S_UNREACHABLE, "Timed out reaching the API server"
    answer = r.stdout.strip().lower()
    if r.ok and answer.startswith("yes"):
        return K8S_OK, ""
    if answer.startswith("no") and not r.stderr.strip():
        return K8S_LIMITED, "Authenticated, but not allowed to list namespaces"
    text = r.output
    return _classify_k8s(text), auth._first_line(r.stderr or r.stdout)


def check_all(runner, cfg, now=None):
    # Several clusters can share one AWS profile. Check each profile once.
    profiles = {}
    for c in cfg.clusters:
        profiles.setdefault((c.aws_profile, c.expected_role), c)

    with ThreadPoolExecutor(max_workers=8) as pool:
        auth_results = dict(
            zip(
                profiles,
                pool.map(
                    lambda key: auth.check_profile(runner, key[0], key[1], cfg.warn_minutes, now),
                    profiles,
                ),
                strict=True,
            )
        )
        statuses = [ClusterStatus(c, auth_results[(c.aws_profile, c.expected_role)]) for c in cfg.clusters]

        usable = [s for s in statuses if s.auth.state in (auth.OK, auth.EXPIRING)]
        for s, (state, detail) in zip(usable, pool.map(lambda s: check_k8s(runner, s.cluster), usable), strict=True):
            s.k8s, s.detail = state, detail

    active = current_context(runner)
    for s in statuses:
        s.current = s.cluster.context == active
    return statuses


def findings_for(status, cfg):
    c = status.cluster
    found = auth.findings_for(c, status.auth, cfg)
    base = {"area": "cluster", "resource": c.name, "evidence": {"context": c.context}}

    if status.k8s == K8S_UNREACHABLE:
        found.append(
            Finding(
                "cluster.unreachable",
                Severity.ERROR,
                message=f"Can't reach the {c.name} API server: {status.detail}",
                fix="If the endpoint is private, connect to VPN. Otherwise check the cluster's public access CIDRs.",
                **base,
            )
        )
    elif status.k8s == K8S_UNAUTHORIZED:
        # The exec plugin often includes the AWS error, which says more than "Unauthorized".
        aws_state = auth.classify_error(status.detail)
        if aws_state in (auth.EXPIRED, auth.NO_ACCESS):
            found += auth.findings_for(c, auth.AuthStatus(c.aws_profile, aws_state, detail=status.detail), cfg)
        else:
            found.append(
                Finding(
                    "cluster.unauthorized",
                    Severity.ERROR,
                    message=f"{c.name} rejected your credentials: {status.detail}",
                    fix=f"Your role ({status.auth.arn or c.aws_profile}) may be missing an EKS access entry, "
                    "or the kubeconfig exec uses a different profile. Re-run "
                    f"`aws eks update-kubeconfig --name <cluster> --profile {c.aws_profile}`.",
                    **base,
                )
            )
    elif status.k8s == K8S_FORBIDDEN:
        found.append(
            Finding(
                "cluster.forbidden",
                Severity.ERROR,
                message=f"{c.name} authenticated you but denied access: {status.detail}",
                fix="Check the EKS access entry and access policy for your role.",
                **base,
            )
        )
    elif status.k8s == K8S_LIMITED:
        found.append(
            Finding(
                "cluster.limited",
                Severity.WARNING,
                message=f"{c.name}: {status.detail}",
                fix="Expected for read-only roles. For admin work, activate the admin PIM group.",
                link=cfg.pim_url,
                **base,
            )
        )
    elif status.k8s == K8S_NO_CONTEXT:
        found.append(
            Finding(
                "cluster.no_context",
                Severity.ERROR,
                message=f"kubeconfig has no context '{c.context}'",
                fix=f"Run `aws eks update-kubeconfig --name <cluster> --profile {c.aws_profile} --alias {c.context}`.",
                **base,
            )
        )
    elif status.k8s == K8S_UNKNOWN:
        found.append(
            Finding(
                "cluster.unknown",
                Severity.ERROR,
                message=f"Cluster check for {c.name} failed: {status.detail}",
                fix=f"Run `kubectl --context {c.context} auth can-i get namespaces` to see the full error.",
                **base,
            )
        )
    return found


def switch(runner, cluster):
    return runner.run(["kubectl", "config", "use-context", cluster.context], timeout=5)
