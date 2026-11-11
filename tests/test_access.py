import json
from datetime import UTC, datetime, timedelta

import pytest

from platform_manager.config import ConfigError, parse
from platform_manager.senses import auth, clusters

from .conftest import FakeRunner, identity

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


def creds(minutes):
    return json.dumps({"Version": 1, "Expiration": (NOW + timedelta(minutes=minutes)).isoformat()})


@pytest.mark.parametrize(
    "text,state",
    [
        ("Error when retrieving token from sso: Token has expired and refresh failed", auth.EXPIRED),
        ("The SSO session associated with this profile has expired or is otherwise invalid.", auth.EXPIRED),
        ("Unable to locate credentials. You can configure credentials by running aws configure.", auth.EXPIRED),
        (
            "Error when retrieving credentials from sso: An error occurred (ForbiddenException) "
            "when calling the GetRoleCredentials operation: No access",
            auth.NO_ACCESS,
        ),
        ("The config profile (nope) could not be found", auth.NO_PROFILE),
        ('Could not connect to the endpoint URL: "https://sts.amazonaws.com/"', auth.UNREACHABLE),
        ("something new and strange", auth.UNKNOWN),
    ],
)
def test_classify_error(text, state):
    assert auth.classify_error(text) == state


def test_ok_with_time_left():
    r = FakeRunner().add(["aws", "sts"], stdout=identity()).add(["aws", "configure"], stdout=creds(300))
    s = auth.check_profile(r, "stg", "PlatformAdmin", now=NOW)
    assert s.state == auth.OK and s.account == "111111111111" and s.minutes_left(NOW) == 300


def test_expiring_soon():
    r = FakeRunner().add(["aws", "sts"], stdout=identity()).add(["aws", "configure"], stdout=creds(12))
    assert auth.check_profile(r, "stg", "PlatformAdmin", warn_minutes=30, now=NOW).state == auth.EXPIRING


def test_wrong_role():
    r = FakeRunner().add(["aws", "sts"], stdout=identity(role="AWSReservedSSO_ReadOnly_x"))
    s = auth.check_profile(r, "stg", "PlatformAdmin", now=NOW)
    assert s.state == auth.WRONG_ROLE and "ReadOnly" in s.detail


def test_timeout_is_unreachable():
    r = FakeRunner().add(["aws", "sts"], code=124, timed_out=True)
    assert auth.check_profile(r, "stg").state == auth.UNREACHABLE


def test_expired_and_no_access_link_to_pim(cfg):
    c = cfg.clusters[0]
    for state in (auth.EXPIRED, auth.NO_ACCESS):
        [f] = auth.findings_for(c, auth.AuthStatus("stg", state, detail="x"), cfg)
        assert f.link == "https://pim.example/activate"
        assert "AWS-Staging" in f.fix and "pmgr login staging" in f.fix


def test_check_all_skips_k8s_when_aws_broken(cfg):
    r = (
        FakeRunner()
        .add(["aws", "sts", "get-caller-identity", "--profile", "stg"], stdout=identity())
        .add(["aws", "configure"], stdout=creds(200))
        .add(["aws", "sts", "get-caller-identity", "--profile", "prd"], code=255, stderr="Token has expired")
        .add(["kubectl", "--context", "ctx-staging"], stdout="yes\n")
        .add(["kubectl", "config", "current-context"], stdout="ctx-staging\n")
    )
    staging, prod = clusters.check_all(r, cfg, now=NOW)
    assert staging.k8s == clusters.K8S_OK and staging.current
    assert prod.auth.state == auth.EXPIRED and prod.k8s == clusters.K8S_SKIPPED
    assert not any("ctx-prod" in call[0] for call in r.calls)
    # kubectl gets the cluster's profile, so the exec plugin uses the right role
    [env] = [env for args, env in r.calls if "ctx-staging" in args]
    assert env["AWS_PROFILE"] == "stg"


@pytest.mark.parametrize(
    "stderr,state",
    [
        ("Unable to connect to the server: dial tcp 10.0.0.1:443: i/o timeout", clusters.K8S_UNREACHABLE),
        ("error: You must be logged in to the server (Unauthorized)", clusters.K8S_UNAUTHORIZED),
        ('error: context "ctx-staging" does not exist', clusters.K8S_NO_CONTEXT),
        ("Error from server (Forbidden): namespaces is forbidden", clusters.K8S_FORBIDDEN),
    ],
)
def test_k8s_classification(cfg, stderr, state):
    r = FakeRunner().add(["kubectl"], code=1, stderr=stderr)
    assert clusters.check_k8s(r, cfg.clusters[0])[0] == state


def test_unauthorized_with_aws_error_becomes_auth_finding(cfg):
    s = clusters.ClusterStatus(
        cfg.clusters[0],
        auth.AuthStatus("stg", auth.OK),
        k8s=clusters.K8S_UNAUTHORIZED,
        detail="getting credentials: exec: ForbiddenException: No access",
    )
    [f] = clusters.findings_for(s, cfg)
    assert f.check == "auth.no_access" and f.link


def test_config_rejects_unknown_keys():
    with pytest.raises(ConfigError, match="unknown keys"):
        parse({"clusters": [{"name": "a", "context": "c", "aws_profile": "p", "typo": 1}]})


def test_refresh_command_substitutes_profile(cfg):
    assert cfg.refresh_args(cfg.clusters[1]) == ["aws", "sso", "login", "--profile", "prd"]
