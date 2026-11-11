"""Gaps in what pipelines are configured to do, read from .github/workflows.

Narrow on purpose. Each rule is something whose absence lets a bad change ship,
a secret leak, or minutes burn, not a style preference. Rules that depend on a
repo's job (Terraform, GitOps) only fire for repos configured with that kind.
"""

import re

import yaml

from ..findings import Finding, Severity

PRODUCER = "workflow"
_SHA = re.compile(r"@[0-9a-f]{40}$")
_FIRST_PARTY = ("actions/", "github/")
_INJECTABLE = re.compile(
    r"\$\{\{\s*github\.(head_ref|event\.(pull_request|issue|comment|review|review_comment|head_commit|discussion)"
    r"\.[\w.]*(title|body|message|name|label|ref|email))\s*\}\}"
)
_TF_APPLY = re.compile(r"\bterraform\s+apply\b|\bterragrunt\s+(run-all\s+)?apply\b")
_TF_PLAN = re.compile(r"\bterraform\s+plan\b|\bterragrunt\s+(run-all\s+)?plan\b")
_TF_FMT = re.compile(r"\bterraform\s+(fmt\s+-check|validate)\b")
_DEPLOY = re.compile(
    r"\bterraform\s+apply\b|\bkubectl\s+apply\b|\bhelm\s+(upgrade|install)\b|\bargocd\s+app\s+sync\b"
    r"|\bdocker\s+push\b|\baws\s+(s3\s+sync|ecs\s+update-service|cloudfront\s+create-invalidation)\b"
)
_K8S_VALIDATE = re.compile(r"\bkustomize\s+build\b|\bkubectl\s+kustomize\b|\bkubeconform\b|\bkubeval\b|check_tgb")
_CACHE_NEEDED = {"actions/setup-node": "cache", "actions/setup-python": "cache", "actions/setup-java": "cache"}


def parse(text):
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def triggers(wf):
    on = wf.get("on", wf.get(True))  # YAML 1.1 reads a bare `on:` key as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def jobs(wf):
    j = wf.get("jobs")
    return j if isinstance(j, dict) else {}


def steps(job):
    s = job.get("steps") if isinstance(job, dict) else None
    return [x for x in s if isinstance(x, dict)] if isinstance(s, list) else []


def run_text(wf):
    return "\n".join(str(st.get("run", "")) for job in jobs(wf).values() for st in steps(job))


def uses(wf):
    out = []
    for job in jobs(wf).values():
        if isinstance(job, dict) and isinstance(job.get("uses"), str):
            out.append((job["uses"], {}))  # reusable workflow
        for st in steps(job):
            if isinstance(st.get("uses"), str):
                out.append((st["uses"], st.get("with") or {}))
    return out


def assess_file(repo, path, text):
    where = f"{repo}:{path}"
    base = {"area": "workflow", "resource": where}
    wf = parse(text)
    if wf is None:
        return [
            Finding(
                f"{PRODUCER}.unparseable",
                Severity.ERROR,
                message="Workflow file isn't valid YAML",
                fix="GitHub won't run it. Fix the syntax.",
                **base,
            )
        ]
    found = []
    on = triggers(wf)
    all_jobs = jobs(wf)
    body = run_text(wf)

    unpinned = sorted(
        {
            u
            for u, _ in uses(wf)
            if "@" in u
            and not u.startswith(("./", "docker://"))
            and not u.startswith(_FIRST_PARTY)
            and not _SHA.search(u)
        }
    )
    if unpinned:
        found.append(
            Finding(
                f"{PRODUCER}.unpinned",
                Severity.WARNING,
                message=f"Third-party actions pinned to a movable tag: {', '.join(unpinned)}",
                fix="Pin each to a full commit SHA (keep the tag in a comment) and let Dependabot or Renovate "
                "bump them. "
                "A retagged action runs with this workflow's secrets.",
                evidence={"actions": unpinned},
                **base,
            )
        )

    if "permissions" not in wf and not all(isinstance(j, dict) and "permissions" in j for j in all_jobs.values()):
        found.append(
            Finding(
                f"{PRODUCER}.permissions",
                Severity.WARNING,
                message="No `permissions:` block, so GITHUB_TOKEN gets the repository default (possibly write-all)",
                fix="Add `permissions: contents: read` at the top and grant more per job only where needed.",
                **base,
            )
        )

    if "aws-access-key-id" in text or re.search(r"secrets\.AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)", text):
        found.append(
            Finding(
                f"{PRODUCER}.static_aws_keys",
                Severity.WARNING,
                message="Uses long-lived AWS access keys from secrets",
                fix="Switch to GitHub OIDC with `aws-actions/configure-aws-credentials` and `role-to-assume`, "
                "then delete the keys.",
                **base,
            )
        )

    if "pull_request_target" in on and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
        found.append(
            Finding(
                f"{PRODUCER}.prt_checkout",
                Severity.CRITICAL,
                message="`pull_request_target` checks out the pull request's code, "
                "which runs untrusted code with secrets",
                fix="Use `pull_request` instead, or never execute the checked-out head in this workflow.",
                **base,
            )
        )

    injected = sorted(
        {
            m.group(0)
            for job in all_jobs.values()
            for st in steps(job)
            for m in _INJECTABLE.finditer(str(st.get("run", "")))
        }
    )
    if injected:
        found.append(
            Finding(
                f"{PRODUCER}.script_injection",
                Severity.ERROR,
                message=f"User-controlled values are expanded straight into shell: {', '.join(injected)}",
                fix='Pass them through `env:` and reference the variable ("$TITLE") instead.',
                evidence={"expressions": injected},
                **base,
            )
        )

    if _TF_APPLY.search(body) and on & {"pull_request", "pull_request_target"} and "push" not in on:
        found.append(
            Finding(
                f"{PRODUCER}.apply_on_pr",
                Severity.ERROR,
                message="Runs `terraform apply` on pull requests, before review and merge",
                fix="Plan on pull requests, apply on push to the default branch (or with an environment approval).",
                **base,
            )
        )

    if (
        _DEPLOY.search(body)
        and "concurrency" not in wf
        and not any(isinstance(j, dict) and "concurrency" in j for j in all_jobs.values())
    ):
        found.append(
            Finding(
                f"{PRODUCER}.no_concurrency",
                Severity.WARNING,
                message="Deploys or applies with no `concurrency:` group, so two runs can overlap",
                fix="Add `concurrency: {group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: false}`.",
                **base,
            )
        )

    no_timeout = sorted(
        n for n, j in all_jobs.items() if isinstance(j, dict) and "uses" not in j and "timeout-minutes" not in j
    )
    if no_timeout:
        found.append(
            Finding(
                f"{PRODUCER}.no_timeout",
                Severity.INFO,
                message=f"Jobs without `timeout-minutes` (a hung job runs for 6 hours): {', '.join(no_timeout)}",
                fix="Set `timeout-minutes` a little above each job's normal duration.",
                evidence={"jobs": no_timeout},
                **base,
            )
        )

    swallowed = sorted(
        {
            n
            for n, j in all_jobs.items()
            if isinstance(j, dict)
            and (j.get("continue-on-error") is True or any(st.get("continue-on-error") is True for st in steps(j)))
        }
    )
    if swallowed:
        found.append(
            Finding(
                f"{PRODUCER}.continue_on_error",
                Severity.INFO,
                message=f"`continue-on-error: true` hides failures in: {', '.join(swallowed)}",
                fix="Remove it, or make sure something reports the failure.",
                **base,
            )
        )

    uncached = sorted(
        {
            u.split("@")[0]
            for u, w in uses(wf)
            if u.split("@")[0] in _CACHE_NEEDED and _CACHE_NEEDED[u.split("@")[0]] not in w
        }
    )
    if uncached:
        found.append(
            Finding(
                f"{PRODUCER}.no_cache",
                Severity.INFO,
                message=f"Dependency caching is off for: {', '.join(uncached)}",
                fix="Set `cache:` on the setup action (for example `cache: pip` or `cache: npm`).",
                **base,
            )
        )
    return found


def assess_repo(repo, kind, files):
    """Rules about the repo as a whole. `files` is {path: text}, or None if we couldn't read them."""
    if files is None:
        return []  # not seeing isn't the same as not there
    base = {"area": "workflow", "resource": repo}
    found = []
    parsed = {p: wf for p, t in files.items() if (wf := parse(t))}
    for path, text in files.items():
        found += assess_file(repo, path, text)

    pr = [wf for wf in parsed.values() if triggers(wf) & {"pull_request", "merge_group"}]
    pr_text = "\n".join(run_text(wf) + "\n" + "\n".join(u for u, _ in uses(wf)) for wf in pr)

    if not files:
        found.append(
            Finding(
                f"{PRODUCER}.none",
                Severity.WARNING,
                message="No GitHub Actions workflows",
                fix="Add at least a pull request check.",
                **base,
            )
        )
    elif not pr:
        found.append(
            Finding(
                f"{PRODUCER}.no_pr_checks",
                Severity.WARNING,
                message="No workflow runs on pull requests, so nothing checks a change before merge",
                fix="Add a `pull_request` workflow for the checks below.",
                **base,
            )
        )

    # A reusable workflow's steps aren't visible from here, so they could hold the check.
    delegates = any("/.github/workflows/" in u for wf in pr for u, _ in uses(wf))

    if kind == "terraform" and files and not delegates:
        plans = _TF_PLAN.search(pr_text) or re.search(r"terraform-plan|tfc-workflows|atlantis", pr_text, re.I)
        if not plans:
            found.append(
                Finding(
                    f"{PRODUCER}.no_plan_on_pr",
                    Severity.WARNING,
                    message="No `terraform plan` on pull requests, "
                    "so reviewers approve changes without seeing the plan",
                    fix="Run `terraform plan` on `pull_request` and post it as a comment or job summary.",
                    **base,
                )
            )
        if not _TF_FMT.search(pr_text):
            found.append(
                Finding(
                    f"{PRODUCER}.no_tf_validate",
                    Severity.INFO,
                    message="No `terraform fmt -check` or `terraform validate` on pull requests",
                    fix="Both are fast and catch errors before plan.",
                    **base,
                )
            )

    if kind == "gitops" and files and not delegates and not _K8S_VALIDATE.search(pr_text):
        found.append(
            Finding(
                f"{PRODUCER}.no_manifest_check",
                Severity.WARNING,
                message="Pull requests don't render or validate manifests, so a broken overlay is found by Argo",
                fix="Run `kustomize build` on every overlay in CI. contrib/tgb-check also checks "
                "TargetGroupBindings against their Services and target groups.",
                **base,
            )
        )
    return found
