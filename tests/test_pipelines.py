from datetime import UTC, datetime, timedelta

from platform_manager.senses import pipelines, runfailure

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def run(i, conclusion, branch="main", attempt=1, queue_s=10, dur_s=300, path=".github/workflows/deploy.yml"):
    created = T0 + timedelta(hours=i)
    started = created + timedelta(seconds=queue_s)
    return {
        "id": 1000 + i,
        "name": "Deploy",
        "path": path,
        "head_branch": branch,
        "status": "completed",
        "conclusion": conclusion,
        "run_attempt": attempt,
        "created_at": created.isoformat(),
        "run_started_at": started.isoformat(),
        "updated_at": (started + timedelta(seconds=dur_s)).isoformat(),
        "html_url": f"https://github.com/acme/infra/actions/runs/{1000 + i}",
    }


def checks(findings):
    return {f.check for f in findings}


def test_broken_now_counts_streak_and_attaches_explanation():
    runs = [run(0, "success"), run(1, "failure"), run(2, "cancelled"), run(3, "failure")]
    explained = {
        1003: [
            {
                "job": "apply",
                "step": "Terraform apply",
                "error": "Error acquiring the state lock",
                "diagnosis": runfailure.diagnose("Error acquiring the state lock"),
            }
        ]
    }
    [f] = pipelines.assess("infra", "main", runs, explained)
    assert f.check == "pipeline.broken" and f.evidence["streak"] == 2
    assert "apply › Terraform apply" in f.message and "force-unlock" in f.fix


def test_failures_on_feature_branches_dont_break_main():
    runs = [run(0, "success"), run(1, "failure", branch="feature/x")]
    assert pipelines.assess("infra", "main", runs) == []


def test_failure_rate_needs_enough_runs():
    few = [run(0, "failure"), run(1, "success"), run(2, "success")]
    assert "pipeline.unreliable" not in checks(pipelines.assess("infra", "main", few))
    # Newest run passes, so this is "unreliable", not "broken now".
    many = [run(i, "failure" if i % 3 == 0 else "success") for i in range(0, 9)]
    [f] = [f for f in pipelines.assess("infra", "main", many) if f.check == "pipeline.unreliable"]
    assert f.evidence["failed"] == 3 and f.evidence["runs"] == 9


def test_flaky_queued_and_slow():
    runs = [run(i, "success", attempt=2 if i < 4 else 1, queue_s=900, dur_s=40 * 60) for i in range(10)]
    assert {"pipeline.flaky", "pipeline.queued", "pipeline.slow"} <= checks(pipelines.assess("infra", "main", runs))


def test_usage_ranks_workflows():
    runs = [run(0, "success", dur_s=600), run(1, "success", dur_s=60, path="lint.yml")]
    runs[1]["name"] = "Lint"
    assert pipelines.usage(runs)[0][0] == "Deploy"


LOG = """2026-11-11T10:00:00.0000000Z Initializing...
2026-11-11T10:00:01.0000000Z \x1b[31m│\x1b[0m Error: Error acquiring the state lock
2026-11-11T10:00:01.0000000Z ##[error]Terraform exited with code 1.
2026-11-11T10:00:02.0000000Z ##[error]Process completed with exit code 1.
"""


def test_error_line_prefers_specific_runner_error():
    assert runfailure.error_line(LOG) == "Terraform exited with code 1."


def test_error_line_falls_back_to_tool_error():
    log = "2026-11-11T10:00:00Z Error: Invalid reference\n##[error]Process completed with exit code 1."
    assert runfailure.error_line(log) == "Invalid reference"


def test_diagnose_known_and_unknown():
    assert runfailure.diagnose(LOG)["id"] == "tf_state_lock"
    oidc = "Error: Not authorized to perform sts:AssumeRoleWithWebIdentity"
    assert runfailure.diagnose(oidc)["id"] == "oidc_trust"
    assert runfailure.diagnose("##[error]Tests failed: 3 of 200") is None
    assert runfailure.diagnose("##[error]The operation was canceled.")["id"] == "canceled"


def test_explain_names_failed_step():
    job = {
        "name": "plan",
        "html_url": "u",
        "steps": [{"name": "Init", "conclusion": "success"}, {"name": "Plan", "conclusion": "failure"}],
    }
    got = runfailure.explain(job, LOG)
    assert got["step"] == "Plan" and got["diagnosis"]["id"] == "tf_state_lock"


def test_dynamic_workflows_get_stable_labels():
    a, b = (
        run(0, "success", path="dynamic/dependabot/dependabot-updates"),
        run(1, "success", path="dynamic/dependabot/dependabot-updates"),
    )
    a["name"], b["name"] = "pip in /. - Update #1", "pip in /. - Update #2"
    assert [name for name, _ in pipelines.usage([a, b])] == ["Dependabot"]
