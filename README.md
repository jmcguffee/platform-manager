# platform-manager

`pmgr` checks an AWS + EKS + Argo CD + GitHub Actions platform from your laptop
and tells you what's wrong in plain English. When it's certain of the cause, it
tells you the fix.

- **Access:** Is each AWS session alive, and can you reach each cluster? When you
  can't, it says why: expired SSO session (one finding per session, not per
  profile), role not activated in Azure PIM or not assigned in IAM Identity
  Center, VPN, missing EKS access entry, or a cluster that no longer exists.
  With PIM configured, it links you to the activation page.
- **Clusters:** Switch kubectl contexts only after the target passes its checks.
- **Argo CD:** Failed syncs, degraded or missing apps, syncs stuck mid-operation,
  render errors, and apps with auto-sync on that still won't converge.
- **Pipelines:** Workflows broken on the default branch right now (with the
  failing step, the error line and, for known causes, the fix), workflows that
  fail too often, flaky reruns, runner queue time, slow workflows, and where CI
  minutes go.
- **Workflow gaps:** Unpinned third-party actions, missing `permissions:`,
  long-lived AWS keys, script injection, `terraform apply` on pull requests,
  deploys without `concurrency:`, no timeouts, no caching. Repo-level checks
  depend on the repo's role: Terraform repos without `plan` on PRs, GitOps repos
  that never render their manifests.

It's read-only. It never changes your clusters, AWS accounts or repositories.

## Install

Needs Python 3.11+, plus the `aws` (v2), `kubectl` and `gh` CLIs you already use.

```bash
pipx install git+https://github.com/jmcguffee/platform-manager
```

Or with uv: `uv tool install git+https://github.com/jmcguffee/platform-manager`.

## Set up

```bash
pmgr init --from-kubeconfig   # writes ~/.config/platform-manager/config.toml (mode 600)
```

That pre-fills a block for each EKS context in your kubeconfig. Open the file and,
for each cluster, check `aws_profile`, then set `expected_role` (part of the
role name, such as `PlatformAdmin`) and `pim_group` (the Entra group you activate).
Then list your repos under `[github]` with a `kind` of `terraform`, `gitops`,
`app` or `other`. Use `owner/repo` for a repo outside `github.org`. SSO accounts
that have no cluster go in `[aws] profiles`. If you don't use PIM, set
`activation_url = ""`. [`config.example.toml`](src/platform_manager/config.example.toml)
documents every setting.

The config holds account IDs and names, so it stays out of this repo. `.gitignore`
blocks `config.toml` in case you copy it here.

## Use

```bash
pmgr status                 # AWS session + cluster access for every cluster
pmgr use prod               # check prod, then switch kubectl to it
eval "$(pmgr env prod)"     # set AWS_PROFILE for this shell
pmgr login prod             # refresh the session, then re-check
pmgr jit prod               # open the Azure PIM activation page

pmgr argo                   # Argo CD health on every reachable cluster
pmgr pipelines              # pipeline failures and workflow gaps
pmgr doctor                 # everything

pmgr doctor --format md --out report.md     # a report to share
pmgr doctor --format json                   # for scripts
pmgr pipelines --all                        # include info-level findings
```

Commands exit with 1 when there's an error-level finding, so they work in scripts
and cron.

### What `status` looks like

```
     CLUSTER  AWS SESSION      KUBERNETES  CONTEXT
  *  staging  ok, 6h12m left   ok          arn:aws:eks:us-east-1:111111111111:cluster/staging
     prod     no access        -           arn:aws:eks:us-east-1:222222222222:cluster/prod

Access
  ERR  prod: Signed in, but the role for prod isn't granted: ... ForbiddenException ... No access
       fix: Activate the role in Azure PIM (PIM group: AWS-Prod-PlatformAdmin). It can take a few
            minutes to reach AWS. Then run `pmgr login prod`.
       https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup
```

## How it decides

- **Not seeing isn't the same as not there.** If a token can't read something
  (a 403, a cluster you can't reach), `pmgr` reports nothing about it and lists
  it under "Couldn't read". A narrowly scoped token produces fewer findings, not
  false ones.
- **A fix is a claim.** Failure diagnosis always shows the failing step and error
  line, but only suggests a fix for causes that aren't ambiguous: state locks,
  OIDC trust mismatches, missing `id-token: write`, expired credentials, Docker
  Hub rate limits, out of memory, full disks, timeouts.
- **Broken now vs. unreliable.** A workflow failing on `main` right now is an
  error. One that fails 30% of the time is a warning. Rates need at least six
  runs, because a 0% failure rate over two runs isn't a score.
- **One cause, one finding.** If your AWS session is dead, `pmgr` doesn't also
  report every cluster and Argo app behind it.

## Design

```
src/platform_manager/
  senses/          read-only checks; each has collect() (I/O) and assess() (pure)
    auth.py        AWS session state per profile
    clusters.py    API server reachability and RBAC, context switching
    argo.py        Argo CD Application status
    pipelines.py   run history: broken, unreliable, flaky, queued, slow
    runfailure.py  the error line and certain fixes from a failed job's log
    workflows.py   gaps in .github/workflows
  findings.py      the one data model every sense returns
  runner.py        the only place that starts processes (argument lists, never a shell)
  github.py        read-only GitHub API through gh
contrib/tgb-check/ CI check for TargetGroupBindings in a GitOps repo
```

Every sense returns `Finding` objects, and `--format json` serializes them. That's
the seam for what comes next:

1. **Hands:** proposed fixes as pull requests (pin this action, add `timeout-minutes`,
   add `concurrency:`), opened only after you say yes and never merged by the tool.
2. **AI:** an agent that calls the same senses as tools and explains or correlates
   findings. The checks stay deterministic, and the AI layer reads their output.

## Security

- One runtime dependency (PyYAML, read with `safe_load` only). CI runs
  `pip-audit` and CodeQL, and Dependabot proposes updates after a 14-day cooldown.
- Every workflow action is pinned to a commit SHA.
- External commands run as argument lists with no shell, through `runner.py`.
- Credentials never leave the AWS CLI. For profiles with static or process
  credentials, `pmgr` shows time left by reading only the `Expiration` field from
  `aws configure export-credentials`. SSO and assume-role profiles renew their
  role credentials, so their true end (the SSO session or PIM window) isn't
  visible locally, and `pmgr` doesn't guess.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Develop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q && .venv/bin/ruff check src tests contrib
```

Tests use a fake runner, so they never call AWS, Kubernetes or GitHub.
