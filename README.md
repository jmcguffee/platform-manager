# platform-manager

`pmgr` checks an AWS + EKS + Argo CD + GitHub Actions platform from your laptop
and tells you what's wrong in plain English. When it's certain of the cause, it
tells you the fix. `pmgr ui` shows everything as a dashboard in your browser.

- **Access:** Is each AWS session alive, and can you reach each cluster? When you
  can't, it says why: an expired SSO session (one finding per session, not per
  profile), a role not activated in Azure PIM or not assigned in IAM Identity
  Center, VPN, a missing EKS access entry, or a cluster that no longer exists.
- **Clusters:** `pmgr use` switches kubectl contexts only after the target passes
  its checks.
- **Workloads:** Crash-looping or OOM-killed pods, image pull and missing-config errors, pods stuck
  Pending (with the scheduler's reason), Deployments and StatefulSets missing replicas, stalled
  rollouts, NotReady or pressured nodes, Pending PVCs, failed Jobs, and recent Warning events that
  status doesn't explain (volume mounts, CNI out of IPs, webhooks rejecting pods, failing probes, HPA
  metrics, TargetGroupBinding errors). Grouped by workload, so one broken Deployment is one finding.
- **Utilization:** Over- and under-used RDS, Redshift, ElastiCache and MSK, from 14 days of
  CloudWatch metrics: oversized (with the size to move to), idle, running hot, low on storage
  or memory, out of CPU credits, evicting keys. For EKS: nodes mostly empty or nearly full by
  requests, workloads requesting far more than they use, containers near their memory limit,
  idle nodes, and pods with no requests.
- **On-call (Datadog):** Who's on call now and for the next 7 days on your schedules,
  filterable to the people you care about (for example your DevOps team on a company-wide
  schedule), and any gap with nobody on call. Also unacknowledged and open pages, active and stable incidents by
  severity, and monitors alerting, warning or missing data, read through Datadog's CLI, Pup,
  with every call read-only. It also says when Pup isn't logged in and how to fix it.
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
The only thing it changes is your kubectl context, when you run `pmgr use`.

## Install

It's a bash tool: clone the repo and put `bin/` on your PATH. Nothing is
downloaded or installed besides the repo itself.

```bash
git clone https://github.com/jmcguffee/platform-manager.git ~/platform-manager
echo 'export PATH="$HOME/platform-manager/bin:$PATH"' >> ~/.zshrc
```

It needs the `aws` (v2), `kubectl` and `gh` CLIs you already use, plus `jq` and
`yq`:

```bash
brew install jq yq
```

It runs on the bash that ships with macOS (3.2), so you don't need a newer bash.
To update, run `git pull` in the clone.

### Datadog on-call

Install Pup, Datadog's CLI, and log in with your browser (SSO works):

```bash
brew install datadog-labs/pack/pup
pup auth login --site yourorg.datadoghq.com
```

Then add a `datadog` section to your config with the same site. To see who's on call, name the
schedules (wildcards work) and, optionally, the people to show:

```yaml
datadog:
  site: yourorg.datadoghq.com
  schedules: ["OnePass*"]            # or schedule IDs; empty = every schedule
  people: [maya@yourorg.com, priya@yourorg.com]   # e.g. your DevOps team; empty = everyone
```

See [`config.example.yaml`](config.example.yaml) for the rest. `pmgr` calls Pup with
`--read-only` every time.

## Set up

```bash
pmgr init --from-kubeconfig
```

That writes `~/.config/platform-manager/config.yaml` (mode 600) with an entry for
each EKS context in your kubeconfig. Then edit it:

- For each cluster, check `aws_profile`, and optionally set `expected_role` (part
  of the role name, such as `PlatformAdmin`) and `pim_group` (the Entra group you
  activate).
- List your repos under `github.repos`, each with a `kind` of `terraform`,
  `gitops`, `app` or `other`. Use `owner/repo` for a repo outside `github.org`.
- List SSO accounts that have no cluster under `aws.profiles`.
- If you don't use PIM, set `pim.activation_url: ""`.

[`config.example.yaml`](config.example.yaml) documents every setting. The config
holds account IDs and names, so it lives outside this repo.

## Use

```bash
pmgr ui                     # run everything and open the dashboard
pmgr status                 # AWS sessions and cluster access
pmgr use prod               # check prod, then switch kubectl to it
eval "$(pmgr env prod)"     # set AWS_PROFILE for this shell
pmgr login prod             # refresh the session, then re-check
pmgr jit prod               # open the Azure PIM activation page

pmgr workloads              # pods, nodes, controllers and Warning events
pmgr utilization            # over- and under-used databases, caches, Kafka and EKS capacity
pmgr oncall                 # Datadog pages, incidents and alerting monitors
pmgr argo                   # Argo CD health on every reachable cluster
pmgr pipelines              # pipeline failures and workflow gaps
pmgr doctor                 # everything, in the terminal

pmgr doctor --format md --out report.md     # a report to share
pmgr doctor --format json                   # for scripts
pmgr pipelines --all                        # include info-level findings
```

Commands exit with 1 when there's an error-level finding, so they work in scripts
and cron.

### The dashboard

`pmgr ui` runs every check (about 30 seconds) and opens the dashboard in your browser.
Click **Sync now** to run the checks again; the page redraws in place and keeps your view.
Press Ctrl+C in the terminal to stop it. The views:

- **Action items:** every finding as a to-do: fix now, save money (by $/month), this week, and
  hygiene, with Copy as Markdown for tickets.
- **On-call:** Datadog pages, incidents and alerting monitors.
- **Overview:** one sentence about what needs you, then an access chain for each cluster
  (AWS session, Kubernetes, workloads, Argo CD), what to fix first, and where CI time goes.
- **Access:** the chains and every access finding.
- **Workloads:** problems by cluster and namespace, filterable.
- **Utilization:** over- and under-used resources by account and service.
- **Pipelines:** each repo's CI minutes and pipeline findings.
- **Workflow gaps:** findings by repo, filterable by severity and text.
- **Argo CD:** Application problems by cluster.
- **Sources:** everything pmgr tried to read, and why anything couldn't be read.

Commands in a fix have a copy button.

The page is served from your machine only: `pmgr ui` listens on 127.0.0.1, every request needs
the random token in the link it prints, requests with any other Host header are refused (which
blocks DNS rebinding), and syncing needs a POST with the token header, which other websites can't
send. The socket is held by a few lines of the perl that ships with macOS (falling back to `nc`);
nothing extra is installed. The page's Content-Security-Policy allows requests to that server and
nowhere else, and report values are inserted as text, never as HTML.

`pmgr ui --file` writes a static copy to `~/.cache/platform-manager/dashboard.html` instead,
with no network access at all.

## How it decides

- **Not seeing isn't the same as not there.** If a token can't read something (a
  403, a cluster you can't reach), `pmgr` reports nothing about it and lists it
  under "Couldn't read". A narrowly scoped token produces fewer findings, not
  false ones.
- **A fix is a claim.** Failure diagnosis always shows the failing step and error
  line, but only suggests a fix for causes that aren't ambiguous: state locks,
  OIDC trust mismatches, missing `id-token: write`, expired credentials, Docker
  Hub rate limits, out of memory, full disks, timeouts.
- **Broken now vs. unreliable.** A workflow failing on `main` right now is an
  error. One that fails 30% of the time is a warning. Rates need at least six
  runs.
- **One cause, one finding.** If an SSO session is dead, that's one finding,
  and `pmgr` doesn't also report every cluster and Argo app behind it.
- **SSO sessions don't show a fake countdown.** SSO and assume-role profiles
  renew their role credentials, so their real end (the SSO session or PIM window)
  isn't visible locally. `pmgr` shows time left only for credentials that expire
  for real.

## Layout

```
bin/pmgr              entry point
lib/pmgr/
  core.sh             config, findings, running commands (argument lists, never a shell)
  auth.sh             AWS session state per profile
  clusters.sh         API reachability, RBAC, deleted clusters, context switching
  argo.sh             Argo CD Application status
  utilization.sh      CloudWatch and EKS capacity: over- and under-utilization
  workloads.sh        pods, controllers, nodes, volumes, jobs, Warning events
  github.sh           read-only GitHub API through gh
  pipelines.sh        run history: broken, unreliable, flaky, queued, slow
  runfailure.sh       the error line and certain fixes from a failed job's log
  workflows.sh        gaps in .github/workflows
  report.sh           terminal, Markdown, JSON and HTML output
  serve.sh            the local dashboard server behind `pmgr ui`
  commands.sh         commands and options
  jq/                 the analysis itself, as jq programs
share/pmgr/ui/        the dashboard page
contrib/tgb-check/    CI check for TargetGroupBindings in a GitOps repo
```

Every check returns findings in one JSON shape, which `--format json` prints. That
is the seam for what comes next:

1. **Hands:** proposed fixes as pull requests (pin this action, add
   `timeout-minutes`, add `concurrency:`), opened only after you say yes and never
   merged by the tool.
2. **AI:** an agent that reads the same JSON and explains or correlates findings.
   The checks stay deterministic.

## Security

- No package manager, no downloads: `git clone`, plus `jq` and `yq` from Homebrew.
- Commands run as argument lists, never through `eval` or `sh -c`, so values from
  config or API responses can't inject shell.
- Read-only GitHub access (GET requests only) through your existing `gh` login.
- Credentials never leave the AWS CLI. For credentials with a real expiry, `pmgr`
  reads only the `Expiration` field and discards the rest.
- Temp files go in a private directory that's removed on exit.
- CI runs ShellCheck and the test suite on macOS, with every action pinned to a
  commit SHA.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Develop

```bash
brew install bats-core shellcheck
bats tests/
shellcheck bin/pmgr lib/pmgr/*.sh
```

Tests put fake `aws`, `kubectl` and `gh` commands on PATH, so they never call AWS,
Kubernetes or GitHub.
