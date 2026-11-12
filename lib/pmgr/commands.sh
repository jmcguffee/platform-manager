# shellcheck shell=bash
# Commands and argument parsing.

usage() {
  cat <<'EOF'
pmgr: read-only checks for AWS sessions, EKS clusters, Argo CD and GitHub Actions.

Usage: pmgr <command> [options]

Access
  status [CLUSTER...]     AWS session and cluster access for each cluster and account
  use CLUSTER [--force]   Check a cluster, then switch kubectl to it
  env CLUSTER             Print exports for a cluster: eval "$(pmgr env prod)"
  login NAME              Refresh a cluster's or account's AWS session, then re-check it
  jit [NAME]              Open the Azure PIM activation page

Health
  workloads [CLUSTER...]  Pods, controllers, nodes, volumes, jobs and Warning events
  apps [CLUSTER...]       App configuration: privileged, hostPath, root, :latest, limits, probes, replicas, PDBs
  lb [CLUSTER...]         TargetGroupBindings vs. their target groups: exists, attached, healthy, matching
  lifecycle [CLUSTER...]  EKS versions and support cost, add-ons, node group AMIs, skew and health
  posture                 AWS setup: WAF, CloudFront, ALB, ACM; S3, RDS, Redshift, ElastiCache,
                          Secrets Manager; IAM trust and users; EC2, EBS, Elastic IPs (with costs)
  argo [CLUSTER...]       Argo CD Application health on each reachable cluster
  utilization             Over- and under-used RDS, Redshift, ElastiCache, MSK and EKS capacity
  oncall                  Datadog: open pages, active incidents, alerting monitors (needs Pup)
  security                Internet exposure by environment: security groups, load balancers, public services
  diagnose NAME           Logs, events and describe output for a finding (matches its resource or message)
  changes                 What's new, fixed, or not checked since the run before the last one
  weekly [--days N]       A Markdown status update: fixed, new, still open, savings (from run history)
  watch on|off|status     Check in the background (macOS) and notify when something new breaks

Workspaces (one per contract: its own config, history, tunnels and watch)
  workspace [list]        List them; * marks the one in use
  workspace new NAME      Create one (asks nothing; add --from-kubeconfig to fill in clusters)
  workspace use NAME      Make it the default (use "default" for config.yaml)
  -w NAME <command>       Use a workspace for one command: pmgr -w acme doctor

Argo CD
  pf argo CLUSTER|--all   Port-forward to Argo CD on a stable local port and open it
  pf                      List port-forwards (running or stopped)
  pf stop [CLUSTER|all]   Stop port-forwards
  pipelines [--repo R]    Pipeline failures, flakiness, slowness, and workflow gaps
  doctor                  Everything above
  ui [--file]             Open the dashboard, with a Sync now button (--file: a static page)

Setup
  init [--from-kubeconfig] [--force]   Create ~/.config/platform-manager/config.yaml
  version

Output options for status, workloads, utilization, argo, pipelines and doctor:
  --format text|json|md|html   (default: text)
  --out FILE                   Write to a file instead of the terminal
  --all                        Include info-level findings in text output

Commands exit with 1 when there's an error-level finding.
EOF
}

# sweep AREA... : run the senses for these areas, leaving results in $PMGR_TMP.
# Filters come from SWEEP_CLUSTERS and SWEEP_REPOS (newline-separated names).
sweep() {
  # Which areas this run covers, so history compares it only with runs that covered the same.
  local w
  PMGR_AREAS=""
  for w in "$@"; do jq -e --arg w "$w" 'has($w)' <<<"$HISTORY_AREAS" >/dev/null && PMGR_AREAS="$PMGR_AREAS $w"; done
  export PMGR_AREAS
  : >"$PMGR_TMP/findings.jsonl"
  : >"$PMGR_TMP/usage.jsonl"
  : >"$PMGR_TMP/unseen.txt"
  : >"$PMGR_TMP/sources.jsonl"
  : >"$PMGR_TMP/metrics.jsonl"
  printf '[]' >"$PMGR_TMP/clusters.json"
  printf '[]' >"$PMGR_TMP/accounts.json"
  local areas=" $* " clusters_filter=()
  if [ -n "${SWEEP_CLUSTERS:-}" ]; then
    while IFS= read -r c; do [ -n "$c" ] && clusters_filter+=("$c"); done <<<"$SWEEP_CLUSTERS"
  fi

  case $areas in *" access "* | *" argo "* | *" workloads "* | *" apps "* | *" traffic "* | *" lifecycle "* | *" utilization "* | *" security "* | *" posture "*)
    access_sweep ${clusters_filter[@]+"${clusters_filter[@]}"} >"$PMGR_TMP/access.jsonl"
    case $areas in *" access "*) cat "$PMGR_TMP/access.jsonl" >>"$PMGR_TMP/findings.jsonl" ;; esac
    ;;
  esac
  case $areas in *" workloads "*) workloads_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" apps "*) apps_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" traffic "*) traffic_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" lifecycle "*) lifecycle_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" argo "*) argo_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" utilization "*) utilization_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" oncall "*) oncall_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" security "*) security_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" posture "*) posture_sweep >>"$PMGR_TMP/findings.jsonl" ;; esac
  case $areas in *" pipelines "* | *" workflows "*) github_sweep "$@" >>"$PMGR_TMP/findings.jsonl" ;; esac
  # Keep access findings but drop the cluster rows when access wasn't asked for.
  case $areas in *" access "*) ;; *)
    case $areas in *" argo "* | *" workloads "* | *" apps "* | *" traffic "* | *" lifecycle "* | *" utilization "* | *" security "* | *" posture "*) ;; *) printf '[]' >"$PMGR_TMP/clusters.json" ;; esac
    case $areas in *" utilization "* | *" security "* | *" posture "*) ;; *) printf '[]' >"$PMGR_TMP/accounts.json" ;; esac
    ;;
  esac
}

# emit FORMAT OUT ALL : render the report and return the exit code.
emit() {
  local format=$1 outfile=$2 all=$3 report text
  report=$(report_finalize "$(code_locate "$(report_build)")")
  case $format in
    text) report_text "$report" "$all" ;;
    json | md | html)
      case $format in
        json) text=$(jq . <<<"$report") ;;
        md) text=$(report_md "$report") ;;
        html) text=$(report_html "$report") ;;
      esac
      if [ -n "$outfile" ]; then
        printf '%s\n' "$text" >"$outfile"
        printf 'Wrote %s\n' "$outfile" >&2
      else
        printf '%s\n' "$text"
      fi
      ;;
    *) die "Unknown format '$format'. Use text, json, md or html." ;;
  esac
  report_exit "$report"
}

# Keep the latest report so `pmgr diagnose` can find its findings.
save_last_report() {
  local dir
  dir=$(pmgr_cache)
  mkdir -p "$dir" && chmod 700 "$dir"
  (umask 077 && printf '%s\n' "$1" >"$dir/last-report.json.tmp" && mv "$dir/last-report.json.tmp" "$dir/last-report.json")
}

# Shared option parsing for report commands. Sets FORMAT, OUTFILE, ALL, POSITIONAL, SWEEP_REPOS.
parse_report_args() {
  FORMAT=text OUTFILE="" ALL=0 POSITIONAL="" SWEEP_REPOS=""
  while [ $# -gt 0 ]; do
    case $1 in
      --format) FORMAT=${2:?--format needs a value}; shift ;;
      --format=*) FORMAT=${1#*=} ;;
      --out) OUTFILE=${2:?--out needs a file}; shift ;;
      --out=*) OUTFILE=${1#*=} ;;
      --all) ALL=1 ;;
      --repo) SWEEP_REPOS="$SWEEP_REPOS${2:?--repo needs a name}"$'\n'; shift ;;
      --repo=*) SWEEP_REPOS="$SWEEP_REPOS${1#*=}"$'\n' ;;
      -h | --help) usage; exit 0 ;;
      -*) die "Unknown option $1" ;;
      *) POSITIONAL="$POSITIONAL$1"$'\n' ;;
    esac
    shift
  done
  export SWEEP_REPOS
}

# target_json NAME : the cluster or account with this name.
target_json() {
  local t
  t=$(jq -c --arg n "$1" '
    ([.clusters // [] | .[] | select(.name == $n or .context == $n)] | first)
    // ([.aws.profiles // [] | .[] | select(. == $n)] | first | if . then {name: ., aws_profile: ., account: true} else null end)
    // empty' <<<"$PMGR_CONFIG_JSON")
  [ -n "$t" ] || die "Unknown cluster or account '$1'. Known: $(cfg '[(.clusters // [] | .[].name), (.aws.profiles // [] | .[])] | join(", ")')"
  printf '%s' "$t"
}

cmd_report() {
  local areas=$1
  shift
  parse_report_args "$@"
  SWEEP_CLUSTERS=$POSITIONAL
  # shellcheck disable=SC2086  # areas is a space-separated list on purpose
  sweep $areas
  emit "$FORMAT" "$OUTFILE" "$ALL"
}

cmd_use() {
  local name="" force=0
  while [ $# -gt 0 ]; do
    case $1 in --force) force=1 ;; -*) die "Unknown option $1" ;; *) name=$1 ;; esac
    shift
  done
  [ -n "$name" ] || die "Usage: pmgr use CLUSTER [--force]"
  local t ctx profile
  t=$(target_json "$name")
  jq -e 'has("context")' <<<"$t" >/dev/null || die "'$name' is an account, not a cluster"
  name=$(jq -r .name <<<"$t") ctx=$(jq -r .context <<<"$t") profile=$(jq -r .aws_profile <<<"$t")
  SWEEP_CLUSTERS=$name sweep access
  local problems
  problems=$(jq -s '[.[] | select(.severity == "error" or .severity == "critical")]' "$PMGR_TMP/findings.jsonl")
  if [ "$(jq length <<<"$problems")" -gt 0 ] && [ "$force" -eq 0 ]; then
    printf '[]' >"$PMGR_TMP/clusters.json"
    jq -c '.[]' <<<"$problems" >"$PMGR_TMP/findings.jsonl"
    report_text "$(report_build)" 1
    printf '\nNot switching to %s. Fix the above, or use --force.\n' "$name" >&2
    return 1
  fi
  capture use-context kubectl config use-context "$ctx" || { err use-context >&2; return 1; }
  printf 'Switched to %s (%s).\n' "$name" "$ctx" >&2
  printf 'For aws commands in this shell: export AWS_PROFILE=%s\n' "$profile" >&2
  printf 'Or run: eval "$(pmgr env %s)"\n' "$name" >&2
}

cmd_env() {
  [ $# -eq 1 ] || die "Usage: pmgr env NAME"
  local t region
  t=$(target_json "$1")
  printf 'export AWS_PROFILE=%q\n' "$(jq -r .aws_profile <<<"$t")"
  region=$(jq -r '.region // ""' <<<"$t")
  [ -z "$region" ] || printf 'export AWS_REGION=%q\n' "$region"
}

cmd_login() {
  [ $# -eq 1 ] || die "Usage: pmgr login NAME"
  local t name profile login_cmd=()
  t=$(target_json "$1")
  name=$(jq -r .name <<<"$t") profile=$(jq -r .aws_profile <<<"$t")
  while IFS= read -r part; do login_cmd+=("$part"); done < <(jq -r --arg p "$profile" \
    '(.aws.refresh_command // ["aws","sso","login","--profile","{profile}"])[] | gsub("\\{profile\\}"; $p)' \
    <<<"$PMGR_CONFIG_JSON")
  printf 'Running: %s\n' "${login_cmd[*]}" >&2
  "${login_cmd[@]}" || printf 'Login command exited with %s.\n' "$?" >&2

  if jq -e 'has("context")' <<<"$t" >/dev/null; then
    SWEEP_CLUSTERS=$name sweep access
  else
    sweep_reset_account "$profile"
  fi
  if [ ! -s "$PMGR_TMP/findings.jsonl" ]; then
    printf '%s: AWS session and cluster access are OK.\n' "$name" >&2
    return 0
  fi
  printf '[]' >"$PMGR_TMP/clusters.json"
  printf '[]' >"$PMGR_TMP/accounts.json"
  report_text "$(report_build)" 1
  [ -n "$(pim_url)" ] && grep -q '"auth.no_access"' "$PMGR_TMP/findings.jsonl" &&
    printf '\nThe role isn'"'"'t active yet. Activate it in PIM: %s\n' "$(pim_url)" >&2
  return 1
}

# Check one account profile, leaving its findings in findings.jsonl.
sweep_reset_account() {
  : >"$PMGR_TMP/findings.jsonl"
  : >"$PMGR_TMP/usage.jsonl"
  : >"$PMGR_TMP/unseen.txt"
  auth_findings "$1" "" "$(auth_check "$1")" >"$PMGR_TMP/findings.jsonl"
}

cmd_jit() {
  local url group=""
  url=$(pim_url)
  [ -n "$url" ] || die "No PIM activation URL is configured (pim.activation_url is empty)."
  if [ $# -gt 0 ] && [ "$1" != "--no-open" ]; then
    group=$(jq -r '.pim_group // ""' <<<"$(target_json "$1")")
    [ -z "$group" ] || printf 'Activate PIM group: %s\n' "$group"
  fi
  printf '%s\n' "$url"
  case " $* " in *" --no-open "*) ;; *) open_url "$url" ;; esac
}

open_url() {
  if command -v open >/dev/null 2>&1; then open "$1"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" >/dev/null 2>&1
  else printf 'Open this in your browser: %s\n' "$1" >&2
  fi
}

cmd_ui() {
  # With nc available, serve the dashboard so it can sync on demand. --file writes a static file.
  case " $* " in *" --file "*) ;; *)
    if command -v perl >/dev/null 2>&1 || command -v nc >/dev/null 2>&1; then
      serve_ui "$@"
      return $?
    fi
    printf 'Neither perl nor nc is available, so the dashboard is a static file. Run pmgr ui again to refresh.\n' >&2
    ;;
  esac
  local no_open=0
  case " $* " in *" --no-open "*) no_open=1 ;; esac
  local dir file
  dir=$(pmgr_cache)
  mkdir -p "$dir" && chmod 700 "$dir"
  file="$dir/dashboard.html"
  printf 'Checking your platform...\n' >&2
  sweep access security posture workloads apps traffic lifecycle utilization oncall argo pipelines workflows
  local code=0
  emit html "$file" 0 2>/dev/null || code=$?
  chmod 600 "$file"
  printf 'Dashboard: %s\n' "$file" >&2
  [ "$no_open" -eq 1 ] || open_url "$file"
  return "$code"
}

cmd_init() {
  local from_kube=0 force=0 path
  while [ $# -gt 0 ]; do
    case $1 in
      --from-kubeconfig) from_kube=1 ;;
      --force) force=1 ;;
      --path) export PMGR_CONFIG=${2:?}; shift ;;
      *) die "Unknown option $1" ;;
    esac
    shift
  done
  path=$(config_path)
  if [ -e "$path" ] && [ "$force" -eq 0 ]; then
    printf '%s already exists. Use --force to overwrite.\n' "$path" >&2
    return 2
  fi
  mkdir -p "$(dirname "$path")"
  local text
  text=$(cat "$PMGR_ROOT/config.example.yaml")
  if [ "$from_kube" -eq 1 ]; then
    local found
    found=$(discover_clusters)
    if [ "$(jq length <<<"$found")" -gt 0 ]; then
      text=$(PMGR_FOUND=$found yq '.clusters = env(PMGR_FOUND) | .clusters style=""' <<<"$text")
      printf 'Found %s EKS context(s) in kubeconfig. Check each aws_profile.\n' "$(jq length <<<"$found")" >&2
    else
      printf 'No EKS contexts found in kubeconfig. Writing the example clusters.\n' >&2
    fi
  fi
  (umask 077 && printf '%s\n' "$text" >"$path")
  printf 'Wrote %s. Edit it, then run `pmgr status`.\n' "$path" >&2
}

# EKS contexts from kubeconfig, with the AWS profile each one's exec plugin uses.
discover_clusters() {
  capture kubeconfig kubectl config view -o json || { printf '[]'; return 0; }
  out kubeconfig | jq -c '
    (.users // [] | map({key: .name, value: (.user.exec // {})}) | from_entries) as $users
    | [.contexts // [] | .[] | .name as $ctx | ($users[.context.user] // {}) as $e
       | ($e.args // []) as $a
       | def arg($flag): ($a | index($flag)) as $i | if $i != null and $i + 1 < ($a | length) then $a[$i + 1] else "" end;
       select(($a | join(" ") | contains("eks")) or ($ctx | contains(":eks:")))
       | {name: ($ctx | split("/") | last), context: $ctx,
          aws_profile: (arg("--profile") | if . == "" then ([$e.env // [] | .[] | select(.name == "AWS_PROFILE") | .value] | first // "SET-ME") else . end),
          region: arg("--region")}
       + (if ($ctx | startswith("arn:aws:eks:")) | not and arg("--cluster-name") != "" then {eks_cluster: arg("--cluster-name")} else {} end)
       | with_entries(select(.value != ""))]'
}

main() {
  # -w NAME / --workspace NAME picks the contract's workspace for this run.
  case ${1:-} in
    -w | --workspace) PMGR_WORKSPACE=${2:?-w needs a workspace name}; export PMGR_WORKSPACE; shift 2 ;;
    --workspace=*) PMGR_WORKSPACE=${1#*=}; export PMGR_WORKSPACE; shift ;;
  esac
  [ $# -gt 0 ] || { usage; exit 0; }
  local cmd=$1
  shift
  case $cmd in
    help | -h | --help) usage; return 0 ;;
    version | --version) printf 'pmgr %s\n' "$PMGR_VERSION"; return 0 ;;
  esac
  need_jq
  need yq yq
  pmgr_tmp_init
  [ "$cmd" = init ] && { cmd_init "$@"; exit $?; }
  [ "$cmd" = workspace ] && { cmd_workspace "$@"; exit $?; }
  # internal: answer one HTTP request for the ui server (stdin: request, stdout: response)
  [ "$cmd" = __handle ] && { serve_handle; exit 0; }
  config_load
  case $cmd in
    status) cmd_report "access" "$@" ;;
    argo) cmd_report "argo" "$@" ;;
    workloads) cmd_report "workloads" "$@" ;;
    lb | traffic) cmd_report "traffic" "$@" ;;
    apps) cmd_report "apps" --all "$@" ;;
    lifecycle) cmd_report "lifecycle" --all "$@" ;;
    posture) cmd_report "posture" --all "$@" ;;
    utilization) cmd_report "utilization" --all "$@" ;;
    oncall) cmd_report "oncall" --all "$@" ;;
    security) cmd_report "security" --all "$@" ;;
    diagnose) cmd_diagnose "$@" ;;
    weekly)
      local wdays=7 wout=""
      while [ $# -gt 0 ]; do
        case $1 in --days) wdays=${2:?--days needs a number}; shift ;; --out) wout=${2:?--out needs a file}; shift ;; *) die "Usage: pmgr weekly [--days N] [--out FILE]" ;; esac
        shift
      done
      case $wdays in '' | *[!0-9]*) die "--days needs a whole number" ;; esac
      if [ -n "$wout" ]; then weekly_report "$wdays" >"$wout" && printf 'Wrote %s\n' "$wout" >&2; else weekly_report "$wdays"; fi
      ;;
    __weekly) weekly_report "${1:-7}" ;;
    watch) cmd_watch "$@" ;;
    __scheduled) cmd_scheduled ;;
    changes)
      f="$(pmgr_cache)/last-report.json"
      [ -f "$f" ] || die "No report yet. Run pmgr doctor or pmgr ui first."
      changes_text "$(cat "$f")"
      ;;
    pf | port-forward) cmd_pf "$@" ;;
    __pf) # internal, for the ui server: start | stop | login one cluster's Argo CD tunnel, or status; prints JSON
      case ${1:?} in
        start) pf_start "${2:?}" || true ;;
        stop) pf_stop "${2:?}"; pf_status ;;
        login) pf_login "${2:?}" || true ;;
        check) pf_check "${2:?}" | jq -cs . ;;
        status) pf_status ;;
      esac
      ;;
    __diagnose) # internal: diagnose one finding of the ui server's report by id; prints a JSON array
      jq -c --arg id "${1:?}" '[.findings[] | select(.id == $id)] | first | .diag // empty' "$SERVE_DIR/report.json" >"$PMGR_TMP/diag.json"
      if [ -s "$PMGR_TMP/diag.json" ]; then diagnose_finding "$(cat "$PMGR_TMP/diag.json")" | jq -cs .; else printf '[]\n'; fi
      ;;
    pipelines) cmd_report "pipelines workflows" "$@" ;;
    doctor) cmd_report "access security posture workloads apps traffic lifecycle utilization oncall argo pipelines workflows" "$@" ;;
    use) cmd_use "$@" ;;
    env) cmd_env "$@" ;;
    login) cmd_login "$@" ;;
    jit) cmd_jit "$@" ;;
    ui) cmd_ui "$@" ;;
    __render) # internal: one full sweep rendered as the live dashboard (used by the ui server)
      sweep access security posture workloads apps traffic lifecycle utilization oncall argo pipelines workflows
      report=$(report_finalize "$(code_locate "$(report_build)")")
      report_html "$report" live >"${1:?}"
      [ -z "${2:-}" ] || printf '%s\n' "$report" >"$2"
      ;;
    *) printf 'pmgr: unknown command %s\n\n' "$cmd" >&2; usage >&2; exit 2 ;;
  esac
}

cmd_workspace() {
  local sub=${1:-list} name cur f
  [ $# -gt 0 ] && shift
  case $sub in
    list)
      cur=$(pmgr_workspace)
      printf '%s default  %s\n' "$([ -z "$cur" ] && echo '*' || echo ' ')" "$PMGR_CONFIG_DIR/config.yaml"
      for f in "$PMGR_CONFIG_DIR"/workspaces/*.yaml; do
        [ -f "$f" ] || continue
        name=$(basename "$f" .yaml)
        printf '%s %s  %s\n' "$([ "$name" = "$cur" ] && echo '*' || echo ' ')" "$name" "$f"
      done
      ;;
    new)
      name=${1:?Usage: pmgr workspace new NAME [--from-kubeconfig]}
      shift
      case $name in default | *[!a-z0-9_-]*) die "Use lowercase letters, digits, - and _ for a workspace name (not 'default')" ;; esac
      mkdir -p "$PMGR_CONFIG_DIR/workspaces" && chmod 700 "$PMGR_CONFIG_DIR/workspaces"
      PMGR_WORKSPACE=$name cmd_init "$@" || return $?
      printf 'Workspace %s is ready. Use it with: pmgr -w %s doctor   (or make it the default: pmgr workspace use %s)\n' "$name" "$name" "$name"
      ;;
    use)
      name=${1:?Usage: pmgr workspace use NAME}
      if [ "$name" != default ] && [ ! -f "$PMGR_CONFIG_DIR/workspaces/$name.yaml" ]; then die "No workspace $name. Create it with: pmgr workspace new $name"; fi
      mkdir -p "$PMGR_CONFIG_DIR"
      printf '%s\n' "$name" >"$PMGR_CONFIG_DIR/current-workspace"
      printf 'Using workspace %s.\n' "$name"
      ;;
    *) die "Usage: pmgr workspace [list | new NAME | use NAME]" ;;
  esac
}
