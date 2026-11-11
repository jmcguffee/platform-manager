import json

from platform_manager.config import parse
from platform_manager.github import GitHub
from platform_manager.senses import auth, clusters, sweep

from .conftest import FakeRunner, identity
from .test_access import NOW, creds


def test_sso_profile_ignores_role_credential_expiry():
    # SSO role credentials last about an hour and the CLI renews them, so "12 minutes left" is noise.
    r = FakeRunner().add(["aws", "sts"], stdout=identity()).add(["aws", "configure"], stdout=creds(12))
    s = auth.check_profile(r, "stg", now=NOW, settings={"sso_session": "corp", "sso_role_name": "Admin"})
    assert s.state == auth.OK and s.expires_at is None
    assert not any(args[:2] == ["aws", "configure"] for args, _ in r.calls)


def test_profile_settings_reads_aws_config(tmp_path, monkeypatch):
    path = tmp_path / "config"
    path.write_text("[default]\nregion = us-east-1\n\n[profile dev]\nsso_session = corp\nsso_account_id = 1\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(path))
    assert auth.renews_itself(auth.profile_settings("dev"))
    assert not auth.renews_itself(auth.profile_settings("default"))
    assert auth.profile_settings("missing") == {}


def test_without_pim_hints_point_at_identity_center():
    cfg = parse({"pim": {"activation_url": ""}, "clusters": [{"name": "a", "context": "c", "aws_profile": "p"}]})
    [f] = auth.findings_for(cfg.clusters[0], auth.AuthStatus("p", auth.NO_ACCESS, detail="No access"), cfg)
    assert "IAM Identity Center" in f.fix and "PIM" not in f.fix and f.link == ""
    [f] = auth.findings_for(cfg.clusters[0], auth.AuthStatus("p", auth.EXPIRED, detail="x"), cfg)
    assert f.fix == "Run `pmgr login a`." and f.link == ""


GONE_CFG = {
    "pim": {"activation_url": ""},
    "clusters": [
        {"name": "old", "context": "arn:aws:eks:us-east-1:111:cluster/old", "aws_profile": "p"},
        {"name": "demo", "context": "demo", "aws_profile": "p", "eks_cluster": "demo-eks", "region": "us-east-2"},
    ],
}


def gone_runner(demo_status):
    return (
        FakeRunner()
        .add(["aws", "sts"], stdout=identity())
        .add(
            ["kubectl", "--context"], code=1, stderr="Unable to connect to the server: dial tcp: lookup x: no such host"
        )
        .add(
            ["aws", "eks", "describe-cluster", "--name", "old"],
            code=254,
            stderr="An error occurred (ResourceNotFoundException) when calling the DescribeCluster operation",
        )
        .add(
            ["aws", "eks", "describe-cluster", "--name", "demo-eks", "--region", "us-east-2"], stdout=f"{demo_status}\n"
        )
        .add(["kubectl", "config", "current-context"], stdout="old\n")
    )


def test_deleted_cluster_is_not_reported_as_a_vpn_problem():
    cfg = parse(GONE_CFG)
    old, demo = clusters.check_all(gone_runner("ACTIVE"), cfg)
    assert old.k8s == clusters.K8S_GONE
    [f] = clusters.findings_for(old, cfg)
    assert f.check == "cluster.gone" and "kubectl config delete-context arn:aws:eks:us-east-1:111:cluster/old" in f.fix
    # ACTIVE but unreachable really is a network problem.
    assert demo.k8s == clusters.K8S_UNREACHABLE


def test_cluster_mid_operation():
    _, demo = clusters.check_all(gone_runner("DELETING"), parse(GONE_CFG))
    assert demo.k8s == clusters.K8S_NOT_ACTIVE and "DELETING" in demo.detail


def test_account_profiles_are_checked_without_a_cluster():
    cfg = parse({"pim": {"activation_url": ""}, "aws": {"profiles": ["shared", "corp"]}, "clusters": []})
    r = (
        FakeRunner()
        .add(["aws", "sts", "get-caller-identity", "--profile", "shared"], stdout=identity(account="333333333333"))
        .add(
            ["aws", "sts", "get-caller-identity", "--profile", "corp"],
            code=255,
            stderr="Error when retrieving token from sso: Token has expired and refresh failed",
        )
    )
    result = sweep(r, cfg, areas=["access"])
    assert [(a.name, s.state) for a, s in result.accounts] == [("shared", auth.OK), ("corp", auth.EXPIRED)]
    [f] = result.findings
    assert f.resource == "corp" and f.fix == "Run `pmgr login corp`."


def test_repos_can_name_their_owner():
    r = FakeRunner().add(["gh", "api", "--method", "GET", "repos/Other-Org/tool"], stdout=json.dumps({"x": 1}))
    gh = GitHub(r, "default-org")
    assert gh.repo("Other-Org/tool") == {"x": 1}
    assert gh._slug("plain") == "default-org/plain"


def test_one_expired_sso_session_is_one_finding():
    cfg = parse({"pim": {"activation_url": ""}, "aws": {"profiles": ["a", "b", "solo"]}, "clusters": []})
    expired = [
        auth.findings_for(acct, auth.AuthStatus(acct.aws_profile, auth.EXPIRED, detail="x"), cfg)[0]
        for acct in cfg.accounts
    ]
    sessions = {"a": {"sso_session": "corp"}, "b": {"sso_session": "corp"}, "solo": {"sso_session": "other"}}
    got = auth.collapse_sessions(expired, settings_for=lambda p: sessions[p])
    assert sorted(f.resource for f in got) == ["solo", "sso-session corp"]
    corp = next(f for f in got if f.resource == "sso-session corp")
    assert corp.evidence["profiles"] == ["a", "b"] and "--sso-session corp" in corp.fix


def test_readable_repo_without_workflows_dir_is_none_not_unseen():
    r = (
        FakeRunner()
        .add(["gh", "api", "--method", "GET", "repos/acme/bare/contents/.github/workflows"], code=1, stderr="HTTP 404")
        .add(["gh", "api", "--method", "GET", "repos/acme/bare"], stdout=json.dumps({"default_branch": "main"}))
        .add(["gh", "api", "--method", "GET", "repos/acme/hidden"], code=1, stderr="HTTP 404")
    )
    gh = GitHub(r, "acme")
    assert gh.workflow_files("bare") == {}
    assert gh.workflow_files("hidden") is None
