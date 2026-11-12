# platform-manager

`pmgr` checks an AWS + EKS + Argo CD + GitHub Actions platform from your laptop
and tells you what's wrong in plain English. When it's certain of the cause, it
tells you the fix. `pmgr ui` shows everything as a dashboard in your browser.

- **Access:** Is each AWS session alive, and can you reach each cluster? When you
  can't, it says why: an expired SSO session (one finding per session, not per
  profile), a role not activated in Azure PIM or not assigned in IAM Identity
  Center, VPN, a missing EKS access entry, or a cluster that no longer exists.
- **Security:** Internet exposure judged by environment, for private-VPC estates where
  `0.0.0.0/0` belongs only on the production internet-facing load balancer: security groups open
  to `0.0.0.0/0` or `::/0` (an error outside prd, and in prd unless the group is on the public
  load balancer and only on web ports), internet-facing load balancers outside prd, publicly
  accessible RDS and Redshift, MSK with public access, EKS API endpoints open to `0.0.0.0/0`,
  instances with public IPs outside prd, and S3 Block Public Access not fully on. The
  environment comes from a tag you choose (falling back to the VPC's tag, then a per-account
  setting), and deliberate exceptions go in `security.allowed_public`.
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
The only things it changes are your kubectl context, when you run `pmgr use`, and local
port-forwards you start with **Create tunnel** or `pmgr pf`.

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

It needs jq 1.8 or later (what Homebrew installs; `brew upgrade jq` if yours is older) and says
so if it finds an older one. It runs on the bash that ships with macOS (3.2), so you don't need a
newer bash. To update, run `git pull` in the clone.

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
  people_teams: [devops]             # everyone on these Datadog teams (handle or name)
  people: [contractor@yourorg.com]   # plus anyone else, by login email
```

Leave both `people_teams` and `people` empty to see everyone. Team members are looked up on each
sync, so the view follows the team as people join or leave.

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
pmgr security               # internet exposure by environment
pmgr diagnose checkout      # logs, events and describe output for a matching finding

pmgr pf argo prod           # port-forward to Argo CD on prod (stable local port) and open it
pmgr pf argo --all          # every environment
pmgr pf                     # list them (running or stopped)
pmgr pf stop all            # stop them
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
- **Security:** everything reachable from the internet, allowed or flagged, by environment.
- **Workloads:** problems by cluster and namespace, filterable.
- **Utilization:** over- and under-used resources by account and service.
- **Pipelines:** each repo's CI minutes and pipeline findings.
- **Workflow gaps:** findings by repo, filterable by severity and text.
- **Argo CD:** Application problems by cluster.
- **Sources:** everything pmgr tried to read, and why anything couldn't be read.

Commands in a fix have a copy button. Findings about something you can inspect have a
**Diagnose** button: it runs the read-only commands you'd run by hand and shows their output under
the finding, each with the exact command:

- a crashing or failing pod: `describe pod`, its events, the previous (crashed) and current
  container logs, and a `describe` of its Deployment or StatefulSet
- nodes, PVCs and other objects: `describe` and their events
- Argo CD apps: the resources that didn't sync and why, error conditions, unhealthy resources
- failing pipelines: the run's jobs and steps, and each failed job's log
- security groups: the rules and what's attached; load balancers: listeners and groups
- AWS sessions: the full error and how the profile is set up; Datadog monitors: their state

- workflow gaps: the workflow file itself; flaky, queued or slow workflows: their last 15 runs
- RDS, Redshift, ElastiCache, MSK, EC2 and EKS findings (utilization and security): the describe
  call for that resource and its last day of events; EKS capacity: `kubectl top nodes` and the nodes
- a cluster pmgr can't reach: what EKS says about it, its node groups, your kubeconfig entry, and
  whether its endpoint resolves (a private endpoint only resolves on VPN)
- Datadog pages and incidents: the page or incident itself

### Argo CD tunnels

The Argo CD view has an **Environments** table: one row per cluster with its tunnel status, the local
port, and **Create tunnel**, **Open Argo CD**, **Copy password** and **Stop** buttons. A tunnel is
`kubectl port-forward svc/argocd-server` on this machine's loopback only, run with the cluster's
AWS profile; it keeps running after you close the dashboard, until you stop it (or your SSO session
expires).

Each environment opens on its own name, like `https://dev.localhost:8080` and
`https://uat.localhost:8081`. Browsers keep cookies per host, not per port, so on plain `localhost`
every Argo CD would share one login cookie and signing in to one environment would sign you out of
the others. `*.localhost` always means this machine; nothing to add to `/etc/hosts`.

A tunnel only counts as up once Argo CD answers a request through it, so the scheme is whatever
Argo CD actually speaks (http when it runs with `server.insecure`, even behind a port named
https). If it doesn't answer, you get the reason: your role can't port-forward, no pod behind the
service, or the wrong port. **Check** (or `pmgr pf check dev`) shows each step: the process and its
log, a request over https and http, `auth can-i create pods/portforward`, the service, endpoints and
pods, what `dev.localhost` resolves to, and your proxy settings. If the request through the tunnel
works but the browser still can't connect, a proxy is taking `dev.localhost`: use the
`127.0.0.1` link under the button, or add `*.localhost` to the proxy's bypass list.

Ports: `argocd_port` fixes one. Otherwise pmgr reuses the port it used last time, else 8080, 8081, …
in config order, and if that one is taken, a free port the OS picks.

Login: set `argocd_secret` on the cluster to the Secrets Manager secret (its name, or its full ARN,
whose region is then used) holding the admin password
(plain text, or JSON with `argocd_secret_key`, default `password`). **Copy password** reads it with
your SSO session and puts it on your clipboard, cleared after 60 seconds. It never goes to the
browser, the report, a log or the terminal.

```bash
pmgr pf status            # every environment, its port, and whether a login is configured
pmgr pf argo dev          # create (or reuse) the tunnel, copy the password, open Argo CD
pmgr pf login dev         # just copy the password
pmgr pf stop all
```

The browser sends only a finding's id; what to inspect comes from pmgr's own report. From the
terminal, `pmgr diagnose checkout` does the same for the finding that matches.

The page is served from your machine only: `pmgr ui` listens on 127.0.0.1, every request needs
the random token in the link it prints, requests with any other Host header are refused (which
blocks DNS rebinding), and syncing needs a POST with the token header, which other websites can't
send. The socket is held by a few lines of the perl that ships with macOS (falling back to `nc`);
nothing extra is installed. The page's Content-Security-Policy allows requests to that server and
nowhere else, and report values are inserted as text, never as HTML.

`pmgr ui --file` writes a static copy to `~/.cache/platform-manager/dashboard.html` instead,
with no network access at all.

## Watch in the background

`pmgr watch on` installs a LaunchAgent (in `~/Library/LaunchAgents`, nothing system-wide) that runs
every check on a schedule, keeps each run in history (so the weekly report fills itself in), and sends
a macOS notification only when something new breaks at error level or worse, or your AWS sessions
run out; each problem is announced once. `pmgr watch status` shows the last runs, `pmgr watch off`
removes it. Configure it under `watch`:

```yaml
watch:
  every_minutes: 60   # at least 15
  hours: 8-18         # local time, 24-hour clock
  weekends: false
```

## Workspaces (one per contract)

Each workspace has its own config, history, last report, tunnels and watch, so one client's
findings never mix into another's weekly report:

```bash
pmgr workspace new acme --from-kubeconfig   # ~/.config/platform-manager/workspaces/acme.yaml
pmgr -w acme doctor                         # one command in that workspace
pmgr workspace use acme                     # or make it the default
pmgr workspace                              # list; * marks the one in use
```

Without a workspace, pmgr uses `config.yaml` and the cache exactly as before.

## Where to fix it

Findings link to the line that defines the resource in your own repos: "Defined in
platform-infra/modules/db/main.tf:2" in the dashboard (a GitHub link) and a `code:` line in the
terminal. pmgr searches local clones of the repos in `github.repos`: Terraform repos for the
resource's quoted name (`identifier = "orders-prd"`), GitOps repos for `name: api` in YAML. A
missing target group links to both the binding and the target group Terraform made. Set `path` on a
repo, or keep clones in `~/src`, `~/code`, `~/git`, `~/repos` or `~/Projects` and pmgr finds them.
It's a text search, so a name built by interpolation (`"${var.env}-orders"`) won't match; no link
means it wasn't found, not that it isn't in code.

## What changed

Every run is kept (the last 90, readable only by you, in `~/.cache/platform-manager/history`) and
compared with the last run that covered the same areas. The terminal report starts with a line like
"Since the last run: 2 new, 3 fixed", new findings are marked NEW, and `pmgr changes` lists them.
The dashboard's Overview has a "Since the last run" panel and tags new findings. A finding that
disappeared because its account or cluster couldn't be read this time is listed as "not checked",
never as fixed; a narrower run (say `pmgr lb`) is only compared on what it covered.

`pmgr weekly` (or the dashboard's Weekly report page, with a Copy button) turns that history into a
Markdown status update for the client: what got fixed (by area, leaving out anything that came
back), what's new and still open, what still needs attention, savings identified and already made,
EKS versions and CI success. `pmgr weekly --days 14 --out update.md` writes it to a file. It's only
as complete as your history, so run `pmgr doctor` (or leave `pmgr ui` syncing) during the week.

## App configuration

`pmgr apps` (and the App config view) reads each Deployment, StatefulSet and DaemonSet outside system
namespaces and flags privileged containers, hostPath mounts, containers that run (or may run) as
root, `:latest` or untagged images, missing memory limits and readiness probes, and in prd: single
replicas, no PodDisruptionBudget, and replicas that aren't asked to spread across nodes and zones.
It also flags PDBs that allow no evictions even when every pod is healthy, since those make node
drains, and so node group and Karpenter upgrades, hang. Environment comes from the namespace name,
then the cluster name. `apps.system_namespaces` lists the namespaces to skip (node agents like the
Datadog agent need privileges).

## Load balancing

`pmgr lb` (and the Load balancing view) checks every TargetGroupBinding on each reachable
cluster against the target groups in that cluster's account and region:

- the target group it names exists, and if not, the closest name that does ("did you mean
  prd-api-tg?"), since the binding and Terraform have to agree exactly
- a load balancer forwards to it (a listener or rule in Terraform)
- its Service and port exist, and the Service has ready pods
- the binding's `targetType` matches the target group's
- AWS says the targets are healthy, and when they aren't, AWS's reason (`Target.Timeout`,
  `Target.ResponseCodeMismatch`, …) with what usually fixes it
- the controller has applied the latest change, and no target group is bound twice (across
  clusters too) without `multiClusterTargetGroup`

Diagnose on a binding shows its description and events, each target's health, the target group's
health check settings, the Service and its endpoints, and the controller's recent logs. It needs
`get`/`list` on `targetgroupbindings.elbv2.k8s.aws`, services and endpointslices, and
`elasticloadbalancing:DescribeTargetGroups` and `DescribeTargetHealth`.

## Lifecycle

`pmgr lifecycle` (and the Lifecycle view) reads what ages out, using AWS's own calendar
(`eks describe-cluster-versions`) rather than dates baked into pmgr:

- clusters in extended support, with what it costs (`$0.60` instead of `$0.10` per cluster-hour,
  about $365 a month each; set `cost.eks_extended_usd_hour` if your price differs), counted as savings
- clusters past extended support, and standard support ending within 180 days, saying whether AWS
  will upgrade the cluster itself (upgrade policy STANDARD) or start charging for extended support
- add-ons reporting health issues, and add-ons behind the newest version for that Kubernetes version
- node groups reporting health issues (with the usual cause), lagging the control plane, behind
  AWS's recommended AMI release (from the public SSM parameters), or on an AMI type AWS no longer
  publishes for their version

It needs only the AWS session (no cluster access). Diagnose on an add-on or node group shows its
full status, versions, and recent Auto Scaling activity.

## AWS posture

`pmgr posture` (and the four AWS posture views) reads how each account is set up, in every region
it runs in, and judges it by environment:

- **Edge & WAF**: internet-facing ALBs without a web ACL; ALBs behind CloudFront that are still open
  to the world (so CloudFront's WAF can be skipped); WAF rules left in count mode, unattached ACLs,
  no logging, no AWS managed rules; HTTP listeners that don't redirect, TLS 1.0/1.1 policies,
  production load balancers without deletion protection or access logs; CloudFront without WAF,
  serving plain HTTP, accepting old TLS, reading S3 without origin access control, or talking to
  its ALB over HTTP; ACM certificates expired while in use, not renewing (with the exact DNS
  validation records to add to the dns repo), or unused.
- **Data stores**: public S3 buckets (AWS's own evaluation, plus ACLs), buckets that accept plain
  HTTP, unversioned production buckets, buckets with no lifecycle rules; RDS and Aurora without
  encryption, IAM auth, enough backups, Multi-AZ or deletion protection (in prd), on an expired CA,
  or with an unmanaged master password; Redshift without encryption, `require_ssl`, audit logs,
  enhanced VPC routing or snapshots; ElastiCache without TLS, encryption, AUTH, failover or backups;
  secrets whose rotation is failing, and secrets nobody has read in 90 days.
- **Identity & IAM**: GitHub Actions OIDC trust not pinned to a repository (any repo on GitHub could
  assume it), pinned only to the org, or open to any branch; IRSA roles any service account can
  assume; roles trusting anyone, or an account that isn't yours without an ExternalId; admin roles
  and `iam:PassRole` on `*`; roles unused for 90 days; IAM users without MFA or with old keys; root
  access keys or no root MFA; no logging CloudTrail; GuardDuty off; EBS not encrypted by default.
- **Compute & EBS**: IMDSv1 (reported once per node group or ASG); unencrypted volumes; unattached
  volumes, gp2 volumes and idle Elastic IPs with what they cost; old snapshots; previous-generation
  instance types; instances stopped for over 30 days.

Everything is a describe, list or get call; `ReadOnlyAccess` or `SecurityAudit` covers it. A call
your role can't make is listed under "not checked", never treated as clean. Savings feed the
Overview's total. Diagnose shows the resource as AWS sees it (for a secret, its metadata, never the
value). Set `posture.ignore` for things that are deliberate, and `posture.trusted_accounts` for
accounts outside your profiles that roles may trust.

## Regions

Utilization and security check every region you run in, account by account. Unless you say
otherwise, that's the profile's own region (from `~/.aws/config`) plus every region a configured
cluster in that account lives in, so a cluster in `us-west-2` brings `us-west-2` along. To list
them yourself, set `aws.regions: [us-east-1, us-west-2]` for every account, or
`utilization.regions` per profile. Findings and Diagnose name the region they came from. Prices
come from the AWS Pricing API, which only answers in `us-east-1`; each resource is still priced
for its own region.

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
- The only secret it reads is the `argocd_secret` you configure, and only when you ask for
  it. The value goes through pipes to the clipboard (cleared after 60 seconds); it never
  appears in a command line, file, log, report, terminal output or the browser.
- Tunnels listen on 127.0.0.1 only.
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
