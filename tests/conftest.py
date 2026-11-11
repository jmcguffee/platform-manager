import json

import pytest

from platform_manager.config import parse
from platform_manager.runner import Result


class FakeRunner:
    """Answers commands by longest matching argument prefix. Unknown commands fail loudly."""

    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.calls = []

    def add(self, prefix, code=0, stdout="", stderr="", timed_out=False):
        self.responses[tuple(prefix)] = Result(code, stdout, stderr, timed_out)
        return self

    def run(self, args, timeout=20, env=None):
        self.calls.append((list(args), env))
        # All but the last element must match exactly; the last may be a string prefix
        # (API paths carry query strings). The longest match wins.
        best, best_score = None, None
        for prefix, result in self.responses.items():
            n = len(prefix)
            if len(args) < n or tuple(args[: n - 1]) != prefix[:-1] or not str(args[n - 1]).startswith(prefix[-1]):
                continue
            score = (n, len(prefix[-1]))
            if best_score is None or score > best_score:
                best, best_score = result, score
        if best is None:
            return Result(1, "", f"FakeRunner: no response for {args}")
        return best

    def interactive(self, args, env=None):
        self.calls.append((list(args), env))
        return 0


def identity(role="AWSReservedSSO_PlatformAdmin_abc123", account="111111111111"):
    return json.dumps(
        {"UserId": "X", "Account": account, "Arn": f"arn:aws:sts::{account}:assumed-role/{role}/me@example.com"}
    )


@pytest.fixture
def cfg():
    return parse(
        {
            "pim": {"activation_url": "https://pim.example/activate"},
            "clusters": [
                {
                    "name": "staging",
                    "context": "ctx-staging",
                    "aws_profile": "stg",
                    "expected_role": "PlatformAdmin",
                    "pim_group": "AWS-Staging",
                },
                {"name": "prod", "context": "ctx-prod", "aws_profile": "prd", "expected_role": "PlatformAdmin"},
            ],
            "github": {"org": "acme", "repos": [{"name": "platform-infra", "kind": "terraform"}]},
        }
    )
