"""Render findings for a terminal, as Markdown to share, or as JSON for scripts."""

import json
import os
import sys
from datetime import UTC, datetime

from .findings import Severity
from .senses import auth, clusters

_COLORS = {Severity.CRITICAL: "35", Severity.ERROR: "31", Severity.WARNING: "33", Severity.INFO: "36"}
_LABEL = {Severity.CRITICAL: "CRIT", Severity.ERROR: "ERR ", Severity.WARNING: "WARN", Severity.INFO: "INFO"}
_AREA_TITLE = {
    "auth": "Access",
    "cluster": "Clusters",
    "argo": "Argo CD",
    "pipeline": "Pipelines",
    "workflow": "Workflow gaps",
}


def _color_on(stream):
    return stream.isatty() and "NO_COLOR" not in os.environ


def _c(code, text, on):
    return f"\033[{code}m{text}\033[0m" if on else text


def status_rows(statuses, now=None):
    rows = []
    for s in statuses:
        a = s.auth
        left = a.minutes_left(now)
        session = {
            auth.OK: f"ok, {left // 60}h{left % 60:02d}m left" if left is not None else "ok",
            auth.EXPIRING: f"expiring, {max(left or 0, 0)}m left",
        }.get(a.state, a.state.replace("_", " "))
        k8s = s.k8s.replace("_", " ") if s.k8s != clusters.K8S_SKIPPED else "-"
        rows.append(("*" if s.current else "", s.cluster.name, session, k8s, s.cluster.context))
    return rows


def table(rows, headers, stream=None):
    stream = stream or sys.stdout
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows, strict=True)]
    for row in [headers, *rows]:
        print("  ".join(str(v).ljust(w) for v, w in zip(row, widths, strict=True)).rstrip(), file=stream)


def terminal(findings, statuses=None, unseen=None, usage=None, stream=None, min_severity=Severity.INFO):
    stream = stream or sys.stdout
    hidden = sum(f.severity < min_severity for f in findings)
    findings = [f for f in findings if f.severity >= min_severity]
    on = _color_on(stream)
    if statuses:
        table(status_rows(statuses), ("", "CLUSTER", "AWS SESSION", "KUBERNETES", "CONTEXT"), stream)
        print(file=stream)
    if not findings:
        print(_c("32", "No warnings or errors." if hidden else "No problems found.", on), file=stream)
    area = None
    for f in findings:
        if f.area != area:
            area = f.area
            print(_c("1", _AREA_TITLE.get(area, area), on), file=stream)
        print(f"  {_c(_COLORS[f.severity], _LABEL[f.severity], on)} {f.resource}: {f.message}", file=stream)
        if f.fix:
            print(f"       fix: {f.fix}", file=stream)
        if f.link:
            print(f"       {_c('4', f.link, on)}", file=stream)
    if usage:
        print(_c("1", "\nWhere CI time goes (approximate minutes)", on), file=stream)
        for repo, rows in usage.items():
            top = ", ".join(f"{name} {mins:,.0f}" for name, mins in rows[:3])
            print(f"  {repo}: {top}", file=stream)
    if hidden:
        print(_c("2", f"\n{hidden} info-level finding(s) hidden. Use --all to show them.", on), file=stream)
    if unseen:
        print(_c("2", "\nCouldn't read (no findings reported for these): " + "; ".join(unseen), on), file=stream)


def as_json(findings, statuses=None, unseen=None, usage=None):
    return json.dumps(
        {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "clusters": [
                {
                    "name": s.cluster.name,
                    "context": s.cluster.context,
                    "current": s.current,
                    "aws": s.auth.state,
                    "arn": s.auth.arn,
                    "kubernetes": s.k8s,
                    "expires_at": s.auth.expires_at.isoformat() if s.auth.expires_at else None,
                }
                for s in statuses or []
            ],
            "findings": [f.to_dict() for f in findings],
            "usage_minutes": {repo: dict(rows) for repo, rows in (usage or {}).items()},
            "unseen": unseen or [],
        },
        indent=2,
    )


def as_markdown(findings, statuses=None, unseen=None, usage=None):
    out = [f"# Platform report, {datetime.now(UTC):%B %-d, %Y %H:%M} UTC", ""]
    counts = {s: sum(f.severity == s for f in findings) for s in Severity}
    out.append(" · ".join(f"**{counts[s]}** {s}" for s in reversed(Severity)))
    if statuses:
        out += ["", "## Clusters", "", "| | Cluster | AWS session | Kubernetes |", "|---|---|---|---|"]
        out += [f"| {cur} | {name} | {sess} | {k8s} |" for cur, name, sess, k8s, _ in status_rows(statuses)]
    area = None
    for f in findings:
        if f.area != area:
            area = f.area
            out += ["", f"## {_AREA_TITLE.get(area, area)}", ""]
        line = f"- **{f.severity}** `{f.resource}`: {f.message}"
        if f.fix:
            line += f"  \n  Fix: {f.fix}"
        if f.link:
            line += f"  \n  {f.link}"
        out.append(line)
    if usage:
        out += ["", "## Where CI time goes", "", "| Repo | Workflow | Minutes |", "|---|---|---|"]
        out += [f"| {repo} | {name} | {mins:,.0f} |" for repo, rows in usage.items() for name, mins in rows[:5]]
    if unseen:
        out += ["", "## Not checked", "", *[f"- {u}" for u in unseen]]
    return "\n".join(out) + "\n"
