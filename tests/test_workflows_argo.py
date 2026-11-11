from datetime import UTC, datetime

from platform_manager.senses import argo, workflows

RISKY = """
name: Deploy
on:
  pull_request:
jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: actions/setup-node@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
      - run: echo "${{ github.event.pull_request.title }}"
      - run: terraform apply -auto-approve
        continue-on-error: true
"""

CAREFUL = """
name: Plan
on: [pull_request]
permissions:
  contents: read
  id-token: write
concurrency: plan-${{ github.ref }}
jobs:
  plan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd # v3
      - run: terraform fmt -check && terraform validate
      - run: terraform plan
"""


def checks(found):
    return {f.check for f in found}


def test_risky_workflow_trips_every_rule():
    got = checks(workflows.assess_file("infra", "deploy.yml", RISKY))
    assert got == {
        "workflow.unpinned",
        "workflow.permissions",
        "workflow.static_aws_keys",
        "workflow.script_injection",
        "workflow.apply_on_pr",
        "workflow.no_concurrency",
        "workflow.no_timeout",
        "workflow.continue_on_error",
        "workflow.no_cache",
    }


def test_careful_workflow_is_clean():
    assert workflows.assess_file("infra", "plan.yml", CAREFUL) == []


def test_bare_on_key_is_read():
    # PyYAML turns `on:` into the boolean True. Triggers must still be found.
    assert workflows.triggers(workflows.parse(CAREFUL)) == {"pull_request"}


def test_terraform_repo_without_plan_on_pr():
    push_only = CAREFUL.replace("on: [pull_request]", "on: [push]")
    got = checks(workflows.assess_repo("infra", "terraform", {"p.yml": push_only}))
    assert {"workflow.no_pr_checks", "workflow.no_plan_on_pr", "workflow.no_tf_validate"} <= got


def test_terraform_repo_with_plan_on_pr_has_no_repo_gaps():
    got = checks(workflows.assess_repo("infra", "terraform", {"p.yml": CAREFUL}))
    assert not got & {"workflow.no_pr_checks", "workflow.no_plan_on_pr", "workflow.no_tf_validate"}


def test_reusable_workflow_suppresses_repo_gap():
    caller = "on: pull_request\npermissions: {}\njobs:\n  ci:\n    uses: acme/ci/.github/workflows/tf.yml@main\n"
    assert "workflow.no_plan_on_pr" not in checks(workflows.assess_repo("infra", "terraform", {"c.yml": caller}))


def test_gitops_repo_without_manifest_check():
    got = checks(workflows.assess_repo("apps", "gitops", {"p.yml": CAREFUL}))
    assert "workflow.no_manifest_check" in got


def test_unreadable_files_produce_nothing():
    assert workflows.assess_repo("infra", "terraform", None) == []


def app(name, sync="Synced", health="Healthy", op=None, automated=True, conditions=None, resources=None):
    return {
        "metadata": {"name": name, "namespace": "argocd"},
        "spec": {"syncPolicy": {"automated": {}} if automated else {}},
        "status": {
            "sync": {"status": sync, "revision": "abcdef123456"},
            "health": {"status": health},
            "operationState": op or {},
            "conditions": conditions or [],
            "resources": resources or [],
        },
    }


def test_argo_findings():
    now = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
    apps = [
        app("ok"),
        app("broken", op={"phase": "Failed", "message": "one or more objects failed to apply"}),
        app(
            "sick",
            health="Degraded",
            resources=[
                {
                    "kind": "Deployment",
                    "name": "api",
                    "health": {"status": "Degraded", "message": "progress deadline exceeded"},
                }
            ],
        ),
        app("drifting", sync="OutOfSync"),
        app("waiting", sync="OutOfSync", automated=False),
        app("stuck", op={"phase": "Running", "startedAt": "2026-11-11T11:00:00Z"}),
        app("norender", conditions=[{"type": "ComparisonError", "message": "kustomize build failed"}]),
    ]
    by_app = {f.resource.rsplit("/", 1)[-1]: f for f in argo.assess("prod", apps, now)}
    assert "ok" not in by_app
    assert by_app["broken"].check == "argo.sync_failed"
    assert "Deployment/api (progress deadline exceeded)" in by_app["sick"].message
    assert by_app["drifting"].severity > by_app["waiting"].severity
    assert by_app["stuck"].check == "argo.stuck"
    assert by_app["norender"].check == "argo.condition"


def test_argo_unreadable_reports_nothing():
    assert argo.assess("prod", None) == []
