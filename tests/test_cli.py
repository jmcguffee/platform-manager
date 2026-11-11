import json
import tomllib

from platform_manager import cli

from .conftest import FakeRunner, identity
from .test_pipelines import run as gh_run

CONFIG = """
[pim]
activation_url = "https://pim.example/activate"

[[clusters]]
name = "staging"
context = "ctx-staging"
aws_profile = "stg"

[[clusters]]
name = "prod"
context = "ctx-prod"
aws_profile = "prd"
pim_group = "AWS-Prod"

[github]
org = "acme"

[[github.repos]]
name = "platform-infra"
kind = "terraform"
"""

PUSH_ONLY = (
    "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: x\n    timeout-minutes: 5\n"
    "    steps:\n      - run: terraform apply\n"
)


def platform(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(CONFIG)
    monkeypatch.setenv("PMGR_CONFIG", str(path))
    gh = "acme/platform-infra"
    return (
        FakeRunner()
        .add(["aws", "sts", "get-caller-identity", "--profile", "stg"], stdout=identity())
        .add(
            ["aws", "sts", "get-caller-identity", "--profile", "prd"],
            code=255,
            stderr="An error occurred (ForbiddenException) when calling the GetRoleCredentials operation: No access",
        )
        .add(["aws", "configure"], code=1)
        .add(["kubectl", "--context", "ctx-staging", "--request-timeout=8s", "auth"], stdout="yes\n")
        .add(
            ["kubectl", "--context", "ctx-staging", "--request-timeout=15s", "get"],
            stdout=json.dumps(
                {"items": [{"metadata": {"name": "api"}, "spec": {}, "status": {"health": {"status": "Degraded"}}}]}
            ),
        )
        .add(["kubectl", "config", "current-context"], stdout="ctx-prod\n")
        .add(["kubectl", "config", "use-context"], stdout="switched\n")
        .add(["gh", "api", "--method", "GET", "orgs/acme"], stdout="{}")
        .add(["gh", "api", "--method", "GET", f"repos/{gh}"], stdout=json.dumps({"default_branch": "main"}))
        .add(
            ["gh", "api", "--method", "GET", f"repos/{gh}/actions/runs?"],
            stdout=json.dumps({"workflow_runs": [gh_run(0, "success"), gh_run(1, "failure")]}),
        )
        .add(
            ["gh", "api", "--method", "GET", f"repos/{gh}/actions/runs/1001/jobs?per_page=100"],
            stdout=json.dumps(
                {
                    "jobs": [
                        {
                            "id": 7,
                            "name": "apply",
                            "conclusion": "failure",
                            "steps": [{"name": "Apply", "conclusion": "failure"}],
                        }
                    ]
                }
            ),
        )
        .add(
            [
                "gh",
                "api",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github.raw",
                f"repos/{gh}/actions/jobs/7/logs",
            ],
            stdout="Error: Error acquiring the state lock\n##[error]Process completed with exit code 1.",
        )
        .add(
            ["gh", "api", "--method", "GET", f"repos/{gh}/contents/.github/workflows"],
            stdout=json.dumps([{"type": "file", "name": "apply.yml", "path": ".github/workflows/apply.yml"}]),
        )
        .add(
            [
                "gh",
                "api",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github.raw",
                f"repos/{gh}/contents/.github/workflows/apply.yml",
            ],
            stdout=PUSH_ONLY,
        )
    )


def test_doctor_sees_the_whole_platform(tmp_path, monkeypatch, capsys):
    runner = platform(tmp_path, monkeypatch)
    out = tmp_path / "report.json"
    assert cli.main(["doctor", "--format", "json", "--out", str(out)], runner=runner) == 1
    report = json.loads(out.read_text())
    got = {f["check"] for f in report["findings"]}
    assert {
        "auth.no_access",
        "argo.degraded",
        "pipeline.broken",
        "workflow.no_plan_on_pr",
        "workflow.no_concurrency",
    } <= got
    prod = next(f for f in report["findings"] if f["check"] == "auth.no_access")
    assert prod["link"] == "https://pim.example/activate" and "AWS-Prod" in prod["fix"]
    broken = next(f for f in report["findings"] if f["check"] == "pipeline.broken")
    assert "force-unlock" in broken["fix"]
    assert "prod: Argo CD (no cluster access)" in report["unseen"]


def test_markdown_report(tmp_path, monkeypatch, capsys):
    runner = platform(tmp_path, monkeypatch)
    cli.main(["doctor", "--format", "md"], runner=runner)
    md = capsys.readouterr().out
    assert md.startswith("# Platform report") and "## Pipelines" in md and "| * | prod |" in md


def test_use_refuses_a_cluster_without_access(tmp_path, monkeypatch, capsys):
    runner = platform(tmp_path, monkeypatch)
    assert cli.main(["use", "prod"], runner=runner) == 1
    assert not any(args[:3] == ["kubectl", "config", "use-context"] for args, _ in runner.calls)
    assert "pim.example" in capsys.readouterr().out


def test_use_switches_a_healthy_cluster(tmp_path, monkeypatch):
    runner = platform(tmp_path, monkeypatch)
    assert cli.main(["use", "staging"], runner=runner) == 0
    assert ["kubectl", "config", "use-context", "ctx-staging"] in [args for args, _ in runner.calls]


def test_github_saml_is_explained(tmp_path, monkeypatch, capsys):
    runner = platform(tmp_path, monkeypatch).add(
        ["gh", "api", "--method", "GET", "orgs/acme"],
        code=1,
        stderr="Resource protected by organization SAML enforcement. You must grant your OAuth token access.",
    )
    cli.main(["pipelines", "--format", "json"], runner=runner)
    [f] = json.loads(capsys.readouterr().out)["findings"]
    assert f["check"] == "github.saml" and f["link"] == "https://github.com/orgs/acme/sso"


def test_init_from_kubeconfig(tmp_path):
    kubeconfig = {
        "contexts": [
            {"name": "arn:aws:eks:us-east-1:111:cluster/prod", "context": {"user": "u1"}},
            {"name": "kind-local", "context": {"user": "u2"}},
        ],
        "users": [
            {
                "name": "u1",
                "user": {
                    "exec": {
                        "command": "aws",
                        "args": [
                            "--region",
                            "us-east-1",
                            "eks",
                            "get-token",
                            "--cluster-name",
                            "prod",
                            "--profile",
                            "prd",
                        ],
                    }
                },
            },
            {"name": "u2", "user": {}},
        ],
    }
    runner = FakeRunner().add(["kubectl", "config", "view"], stdout=json.dumps(kubeconfig))
    path = tmp_path / "cfg.toml"
    assert cli.main(["init", "--from-kubeconfig", "--path", str(path)], runner=runner) == 0
    data = tomllib.loads(path.read_text())
    assert data["clusters"] == [
        {
            "name": "prod",
            "context": "arn:aws:eks:us-east-1:111:cluster/prod",
            "aws_profile": "prd",
            "region": "us-east-1",
            "expected_role": "",
            "pim_group": "",
        }
    ]
    assert oct(path.stat().st_mode & 0o777) == "0o600"
