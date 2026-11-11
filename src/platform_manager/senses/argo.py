"""What Argo CD says about every Application on each cluster.

Read from the Application resources with kubectl, so it needs no Argo CD token,
only the same cluster access `pmgr status` checks. If listing Applications is
forbidden, it reports nothing rather than guessing.
"""

import json
from datetime import UTC, datetime

from ..findings import Finding, Severity
from .clusters import kube_env

PRODUCER = "argo"
STUCK_MINUTES = 15
_ERROR_CONDITIONS = {"ComparisonError", "InvalidSpecError", "SyncError", "UnknownError"}


def collect(runner, cluster):
    r = runner.run(
        [
            "kubectl",
            "--context",
            cluster.context,
            "--request-timeout=15s",
            "get",
            "applications.argoproj.io",
            "-A",
            "-o",
            "json",
        ],
        timeout=30,
        env=kube_env(cluster),
    )
    if not r.ok:
        return None
    try:
        return json.loads(r.stdout).get("items", [])
    except ValueError:
        return None


def _age_minutes(started, now):
    if not started:
        return None
    return (now - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds() / 60


def assess(cluster_name, apps, now=None):
    if apps is None:
        return []
    now = now or datetime.now(UTC)
    found = []
    for app in apps:
        meta, spec, status = app.get("metadata", {}), app.get("spec", {}), app.get("status", {})
        name = meta.get("name", "?")
        where = f"{cluster_name}/{meta.get('namespace', 'argocd')}/{name}"
        base = {"area": "argo", "resource": where}
        sync = (status.get("sync") or {}).get("status")
        health = (status.get("health") or {}).get("status")
        op = status.get("operationState") or {}
        # `automated: {}` means auto-sync with defaults, so presence counts, not truthiness.
        auto = (spec.get("syncPolicy") or {}).get("automated", None)
        automated = auto is not None and not (isinstance(auto, dict) and auto.get("enabled") is False)
        revision = ((status.get("sync") or {}).get("revision") or "")[:8]

        for cond in status.get("conditions") or []:
            if cond.get("type") in _ERROR_CONDITIONS:
                found.append(
                    Finding(
                        f"{PRODUCER}.condition",
                        Severity.ERROR,
                        message=f"{name}: {cond['type']}: {cond.get('message', '')[:400]}",
                        fix="A ComparisonError usually means the manifests don't render. Run "
                        "`kustomize build` on this app's overlay at the target revision.",
                        evidence={"condition": cond},
                        **base,
                    )
                )

        if op.get("phase") in ("Failed", "Error"):
            found.append(
                Finding(
                    f"{PRODUCER}.sync_failed",
                    Severity.ERROR,
                    message=f"{name}: last sync {op['phase'].lower()}: {op.get('message', '')[:400]}",
                    fix="The failing resource is named in the message. Check it with `kubectl describe`.",
                    evidence={"revision": (op.get("syncResult") or {}).get("revision", "")},
                    **base,
                )
            )
        elif op.get("phase") == "Running":
            age = _age_minutes(op.get("startedAt"), now)
            if age and age >= STUCK_MINUTES:
                found.append(
                    Finding(
                        f"{PRODUCER}.stuck",
                        Severity.WARNING,
                        message=f"{name}: sync has been running for {age:.0f} min",
                        fix="Usually a hook Job that never finishes, or a resource waiting on a finalizer. "
                        "Look at the app's resource tree for what is still Progressing.",
                        **base,
                    )
                )

        if health in ("Degraded", "Missing"):
            bad = [
                f"{r.get('kind')}/{r.get('name')}"
                + (f" ({r['health'].get('message', '')[:120]})" if (r.get("health") or {}).get("message") else "")
                for r in status.get("resources") or []
                if (r.get("health") or {}).get("status") in ("Degraded", "Missing")
            ]
            found.append(
                Finding(
                    f"{PRODUCER}.{health.lower()}",
                    Severity.ERROR,
                    message=f"{name} is {health}" + (f": {'; '.join(bad[:5])}" if bad else ""),
                    fix="Check pod events and logs for the resources listed.",
                    evidence={"resources": bad},
                    **base,
                )
            )

        if sync == "OutOfSync" and op.get("phase") not in ("Failed", "Error", "Running"):
            found.append(
                Finding(
                    f"{PRODUCER}.out_of_sync",
                    Severity.WARNING if automated else Severity.INFO,
                    message=f"{name} is OutOfSync"
                    + (f" at {revision}" if revision else "")
                    + (" even though auto-sync is on" if automated else " (manual sync)"),
                    fix="With auto-sync on, something keeps it from converging: an ignored diff, a "
                    "mutating webhook, or a field another controller owns. Compare in the Argo diff view."
                    if automated
                    else "Changes are waiting for a manual sync.",
                    **base,
                )
            )
    return found
