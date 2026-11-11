"""Whether pipelines work, read from what they actually did.

Two different facts, reported separately:

  Broken now   The newest default-branch run failed and nothing has passed since.
               That's a state, not a rate: nothing merged is shipping.
  Unreliable   A workflow that fails one run in three on the default branch.
               Each failure got fixed, so nobody escalates it, and the team
               learns to expect red.

Plus the optimization signals: reruns that pass (flakiness), time spent queued
(runner capacity), and where CI minutes go.

Rates need enough history. Under MIN_RUNS runs, no rate is reported, because
0% failures over three runs isn't a score.
"""

from collections import defaultdict
from datetime import datetime

from ..findings import Finding, Severity
from . import runfailure

PRODUCER = "pipeline"
MIN_RUNS = 6
UNRELIABLE = 0.30
SHAKY = 0.15
FLAKY_SHARE = 0.10
FLAKY_MIN = 3
QUEUE_WARN_S = 5 * 60
SLOW_P50_S = 20 * 60
FAILED = {"failure", "timed_out", "startup_failure"}
IGNORED = {"cancelled", "skipped", "neutral", "action_required", "stale", None}


def _ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def _seconds(run, start_key, end_key):
    a, b = _ts(run.get(start_key)), _ts(run.get(end_key))
    return (b - a).total_seconds() if a and b and b >= a else None


def _pct(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))]


def _mins(seconds):
    return f"{seconds / 60:.0f} min" if seconds is not None else "n/a"


def by_workflow(runs):
    groups = defaultdict(list)
    for r in runs:
        groups[r.get("path") or r.get("name") or str(r.get("workflow_id"))].append(r)
    for rows in groups.values():
        rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)  # newest first
    return groups


def completed(rows, branch=None):
    return [
        r
        for r in rows
        if r.get("status") == "completed"
        and r.get("conclusion") not in IGNORED
        and (branch is None or r.get("head_branch") == branch)
    ]


def broken_now(rows, branch):
    """The failing streak at the head of the default branch, or None."""
    done = completed(rows, branch)
    if not done or done[0].get("conclusion") not in FAILED:
        return None
    streak = 0
    for r in done:
        if r.get("conclusion") not in FAILED:
            break
        streak += 1
    last_ok = next((r for r in done if r.get("conclusion") == "success"), None)
    return {"latest": done[0], "streak": streak, "last_success": last_ok}


def assess(repo, branch, runs, explanations=None, days=14):
    """Pure: runs in, findings out. `explanations` maps run ID -> runfailure.explain() results."""
    explanations = explanations or {}
    found = []
    for workflow, rows in by_workflow(runs).items():
        name = label(rows[0])
        where = f"{repo}:{workflow}"
        base = {"area": "pipeline", "resource": where}

        broken = broken_now(rows, branch)
        if broken:
            latest = broken["latest"]
            why = explanations.get(latest["id"], [])
            first = why[0] if why else {}
            diag = first.get("diagnosis") or {}
            since = broken["last_success"]["created_at"][:10] if broken["last_success"] else f"over {days} days"
            msg = f"'{name}' is failing on {branch}: {broken['streak']} failed run(s) in a row (last pass: {since})"
            if first.get("step"):
                msg += f". Fails at '{first['job']} › {first['step']}'"
            if first.get("error"):
                msg += f": {first['error']}"
            found.append(
                Finding(
                    f"{PRODUCER}.broken",
                    Severity.ERROR,
                    message=msg,
                    fix=" ".join(x for x in (diag.get("cause", ""), diag.get("fix", "")) if x),
                    link=latest.get("html_url", ""),
                    evidence={"streak": broken["streak"], "failures": why},
                    **base,
                )
            )

        main = completed(rows, branch)
        if len(main) >= MIN_RUNS and not broken:
            failed = sum(r.get("conclusion") in FAILED for r in main)
            rate = failed / len(main)
            if rate >= SHAKY:
                found.append(
                    Finding(
                        f"{PRODUCER}.unreliable",
                        Severity.WARNING if rate >= UNRELIABLE else Severity.INFO,
                        message=f"'{name}' failed {failed} of {len(main)} runs on {branch} "
                        f"in the last {days} days ({rate:.0%})",
                        fix="Group the failures by step with `pmgr pipelines --repo "
                        f"{repo} --explain` to see whether one cause dominates.",
                        evidence={"failed": failed, "runs": len(main), "rate": round(rate, 3)},
                        **base,
                    )
                )

        attempts = [r for r in rows if r.get("status") == "completed"]
        reruns = [r for r in attempts if (r.get("run_attempt") or 1) > 1 and r.get("conclusion") == "success"]
        if len(reruns) >= FLAKY_MIN and len(reruns) / max(len(attempts), 1) >= FLAKY_SHARE:
            found.append(
                Finding(
                    f"{PRODUCER}.flaky",
                    Severity.WARNING,
                    message=f"'{name}' passed only after a rerun {len(reruns)} times in {len(attempts)} runs",
                    fix="Reruns that pass point to flaky tests or a dependency that times out. "
                    "Find the job that fails on attempt 1.",
                    evidence={"reruns": len(reruns), "runs": len(attempts)},
                    **base,
                )
            )

        queued = [s for r in attempts if (s := _seconds(r, "created_at", "run_started_at")) is not None]
        q95 = _pct(queued, 0.95)
        if len(queued) >= MIN_RUNS and q95 and q95 >= QUEUE_WARN_S:
            found.append(
                Finding(
                    f"{PRODUCER}.queued",
                    Severity.WARNING,
                    message=f"'{name}' waits up to {_mins(q95)} for a runner (p95 queue time)",
                    fix="Runners are short. Check self-hosted runner scaling, or the org's concurrency limit.",
                    evidence={"queue_p95_s": q95},
                    **base,
                )
            )

        durations = [
            s
            for r in attempts
            if r.get("conclusion") == "success" and (s := _seconds(r, "run_started_at", "updated_at")) is not None
        ]
        p50 = _pct(durations, 0.5)
        if len(durations) >= MIN_RUNS and p50 and p50 >= SLOW_P50_S:
            found.append(
                Finding(
                    f"{PRODUCER}.slow",
                    Severity.INFO,
                    message=f"'{name}' typically takes {_mins(p50)} (p95 {_mins(_pct(durations, 0.95))})",
                    fix="Look for missing dependency caching, work that could run in parallel jobs, "
                    "or steps that could be skipped with `paths:` filters.",
                    evidence={"p50_s": p50, "p95_s": _pct(durations, 0.95)},
                    **base,
                )
            )
    return found


def label(run):
    """A stable name for a run's workflow. GitHub-managed workflows (Dependabot, dependency graph)
    get a new name every run, so they're labeled by their dynamic path instead."""
    path = run.get("path") or ""
    if path.startswith("dynamic/"):
        return path.split("/")[1].replace("-", " ").capitalize()
    return run.get("name") or path


def usage(runs):
    """Approximate CI minutes per workflow, largest first, for the optimization summary."""
    totals = defaultdict(float)
    for r in runs:
        s = _seconds(r, "run_started_at", "updated_at")
        if s:
            totals[label(r)] += s / 60
    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)


def collect(gh, repo, days, limit, explain_jobs=2):
    """Fetch runs, then pull logs only for workflows that are broken now. Returns (branch, runs, explanations)."""
    info = gh.repo(repo)
    if info is None:
        return None
    branch = info.get("default_branch", "main")
    runs = gh.runs(repo, days, limit)
    if runs is None:
        return None
    explanations = {}
    for rows in by_workflow(runs).values():
        broken = broken_now(rows, branch)
        if not broken:
            continue
        run_id = broken["latest"]["id"]
        jobs = gh.jobs(repo, run_id) or []
        failed_jobs = [j for j in jobs if j.get("conclusion") in FAILED][:explain_jobs]
        explanations[run_id] = [runfailure.explain(j, gh.job_log(repo, j["id"]) or "") for j in failed_jobs]
    return branch, runs, explanations
