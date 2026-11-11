"""Why a GitHub Actions run failed: the step, the error line, and a fix only when it's certain.

The error line is nearly always enough to turn "the pipeline is red" into a task.
A suggested fix is a claim, so it's only made for the handful of failures whose
cause isn't ambiguous. Everything else gets the step and the error, no advice.
"""

import re

_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s?")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|[│╷╵]")
_GH_ERROR = re.compile(r"##\[error\](.*)")
_TOOL_ERROR = re.compile(r"^(?:Error|ERROR|FAILED|fatal|FATAL)[:\s]\s*(.+)")
_GENERIC = re.compile(r"process completed with exit code \d+", re.I)

# (id, lowercase needles (any match), cause, fix). Keep this list to certain cases.
DIAGNOSES = [
    (
        "tf_state_lock",
        ["error acquiring the state lock"],
        "Terraform state is locked by another run.",
        "Check for a concurrent run of this workflow. If none is running, confirm the lock ID in the log "
        "and run `terraform force-unlock <ID>`. Add a `concurrency:` group so runs can't overlap.",
    ),
    (
        "tf_lock_file",
        ["inconsistent dependency lock file"],
        "The Terraform lock file doesn't match the configured providers.",
        "Run `terraform init -upgrade` (or `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64`) "
        "locally and commit `.terraform.lock.hcl`.",
    ),
    (
        "oidc_trust",
        ["not authorized to perform sts:assumerolewithwebidentity"],
        "AWS rejected the GitHub OIDC token: the role's trust policy doesn't match this repo, branch or event.",
        "Compare the role's `token.actions.githubusercontent.com:sub` condition with this run's repo and ref "
        "(pull requests use `repo:ORG/REPO:pull_request`).",
    ),
    (
        "oidc_permission",
        ["could not load credentials from any providers", "unable to get actions_id_token_request_url"],
        "The job couldn't request an OIDC token.",
        "Add `permissions: id-token: write` to the workflow or job.",
    ),
    (
        "aws_expired_mid_run",
        ["expiredtoken", "security token included in the request is expired"],
        "AWS credentials expired during the run.",
        "The job ran longer than the role's session duration. Raise the role's max session duration and "
        "`role-duration-seconds`, or split the job.",
    ),
    (
        "token_permission",
        ["resource not accessible by integration"],
        "GITHUB_TOKEN lacks a permission this step needs.",
        "Grant the specific scope in the workflow's `permissions:` block (for example `pull-requests: write`).",
    ),
    (
        "docker_rate_limit",
        ["toomanyrequests", "pull rate limit"],
        "Docker Hub rate-limited the image pull.",
        "Log in to Docker Hub in the job, or pull through an ECR pull-through cache.",
    ),
    (
        "out_of_memory",
        ["exit code 137", "killed signal", "javascript heap out of memory"],
        "The job ran out of memory.",
        "Use a larger runner, or lower the build's parallelism.",
    ),
    (
        "disk_full",
        ["no space left on device"],
        "The runner ran out of disk.",
        "Prune images and caches in the job, or use a runner with more disk.",
    ),
    (
        "job_timeout",
        ["has exceeded the maximum execution time"],
        "The job hit its timeout.",
        "Find the slow step in the log. Raise `timeout-minutes` only if the work genuinely takes longer.",
    ),
]

CANCELED = "the operation was canceled"


def _clean(line):
    return _ANSI.sub("", _TIMESTAMP.sub("", line)).strip()


def error_line(log):
    """The most specific error in the log. The runner's last specific ##[error] usually names the cause."""
    if not log:
        return ""
    lines = [_clean(raw) for raw in log.splitlines()]
    gh = [m.group(1).strip() for line in lines if (m := _GH_ERROR.search(line)) and m.group(1).strip()]
    specific = [e for e in gh if not _GENERIC.search(e)]
    if specific:
        return specific[-1][:400]
    tool = [m.group(1).strip() for line in lines if (m := _TOOL_ERROR.match(line))]
    if tool:
        return tool[-1][:400]
    return (gh[-1] if gh else "")[:400]


def failed_step(job):
    for step in job.get("steps") or []:
        if step.get("conclusion") == "failure":
            return step.get("name", "")
    return ""


def diagnose(log, step=""):
    """Return {"id", "cause", "fix"} for a certain cause, or None."""
    low = (log or "").lower()
    if CANCELED in low and "##[error]" not in low.replace("##[error]the operation was canceled", ""):
        return {"id": "canceled", "cause": "The run was canceled, usually by a newer run.", "fix": ""}
    for diag_id, needles, cause, fix in DIAGNOSES:
        if any(n in low for n in needles):
            return {"id": diag_id, "cause": cause, "fix": fix}
    return None


def explain(job, log):
    """Everything known about one failed job, ready to attach to a finding."""
    return {
        "job": job.get("name", ""),
        "step": failed_step(job),
        "error": error_line(log),
        "diagnosis": diagnose(log, failed_step(job)),
        "url": job.get("html_url", ""),
    }
