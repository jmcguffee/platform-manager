# shellcheck shell=bash
# Diagnose: for one finding, run the read-only commands you'd run by hand (describe, events,
# logs, the failing job's log) and return their output as sections.
#
# The finding's `diag` spec says what to look at. It comes from pmgr's own report, never from the
# browser, so the dashboard can only ask to diagnose findings pmgr produced.
#
# Output: JSON lines {title, command, output, ok}.

DIAG_MAX_LINES=150

# shell_words ARGS... : the args as you'd type them: single-quoted only when they need it.
shell_words() {
  local a out=""
  for a in "$@"; do
    case $a in
      *[[:space:]\'\"\`\$\|\&\;\(\)\<\>\*\?\[\]\{\}]* | "") out="$out'$(printf '%s' "$a" | sed "s/'/'\\\\''/g")' " ;;
      *) out="$out$a " ;;
    esac
  done
  printf '%s' "${out% }"
}

# diag_section TITLE CMD... : run a read-only command and print one section.
diag_section() {
  local title=$1 key code=0 text show
  shift
  key="diag-$(printf '%s' "$title" | tr -c 'A-Za-z0-9' '_' | cut -c1-40)-$RANDOM"
  capture "$key" "$@" || code=$?
  text=$( { out "$key"; err "$key"; } | tail -n "$DIAG_MAX_LINES")
  # Show the command as you'd type it, not pmgr's internal helper.
  case $1 in
    diag_k8s) show="kubectl --context $(jq -r .context <<<"$2") $(shell_words "${@:3}")" ;;
    diag_argo_status) show="kubectl --context $(jq -r .context <<<"$2") get applications.argoproj.io $4 -n $3 -o json  (summarized)" ;;
    diag_lb_listeners) show="aws elbv2 describe-listeners --load-balancer-arn <arn of $(jq -r .id <<<"$2")>" ;;
    *) show=$(shell_words "$@") ;;
  esac
  # A container that never restarted has no previous logs: say that plainly.
  if [ "$code" -ne 0 ] && printf '%s' "$text" | grep -q 'previous terminated container .* not found'; then
    text="No previous run to show: this container hasn't restarted." code=0
  fi
  jq -cn --arg title "$title" --arg command "${show% }" \
    --arg output "${text:-"(no output)"}" --argjson ok "$([ "$code" -eq 0 ] && echo true || echo false)" \
    '{title: $title, command: $command, output: $output, ok: $ok}'
}

# A cluster's context and profile from the config, by name.
diag_cluster() {
  jq -c --arg n "$1" '[.clusters // [] | .[] | select(.name == $n)] | first // empty' <<<"$PMGR_CONFIG_JSON"
}

diag_k8s() { # CLUSTER_JSON ARGS... : kubectl against that cluster with its AWS profile
  local c=$1
  shift
  env AWS_PROFILE="$(jq -r .aws_profile <<<"$c")" kubectl --context "$(jq -r .context <<<"$c")" --request-timeout=20s "$@"
}

diag_events() { # CLUSTER_JSON NS KIND NAME
  local c=$1 ns=$2 kind=$3 name=$4
  local args=(get events --sort-by=.lastTimestamp --field-selector "involvedObject.name=$name${kind:+,involvedObject.kind=$kind}")
  if [ -n "$ns" ]; then args+=(-n "$ns"); else args+=(-A); fi
  diag_section "Events for $name" diag_k8s "$c" "${args[@]}"
}

diagnose_finding() { # DIAG_JSON
  local d=$1 type c
  type=$(jq -r '.type // ""' <<<"$d")
  case $type in
    pod | workload | node | object | argo)
      c=$(diag_cluster "$(jq -r .cluster <<<"$d")")
      [ -n "$c" ] || { jq -cn '{title: "Cluster", command: "", output: "This cluster is no longer in your config.", ok: false}'; return 0; }
      ;;
  esac
  local ns kind name pod container
  ns=$(jq -r '.ns // ""' <<<"$d") kind=$(jq -r '.kind // ""' <<<"$d") name=$(jq -r '.name // ""' <<<"$d")
  pod=$(jq -r '.pod // ""' <<<"$d") container=$(jq -r '.container // ""' <<<"$d")
  case $type in
    pod)
      diag_section "Pod $pod" diag_k8s "$c" describe pod "$pod" -n "$ns"
      diag_events "$c" "$ns" Pod "$pod"
      if [ -n "$container" ]; then
        diag_section "Previous logs of $container (the run that crashed)" diag_k8s "$c" logs "$pod" -n "$ns" -c "$container" --previous --tail=80
        diag_section "Current logs of $container" diag_k8s "$c" logs "$pod" -n "$ns" -c "$container" --tail=40
      fi
      if [ -n "$kind" ] && [ "$kind" != Pod ]; then
        diag_section "$kind $name" diag_k8s "$c" describe "$(lower "$kind")" "$name" -n "$ns"
      fi
      ;;
    workload)
      diag_section "$kind $name" diag_k8s "$c" describe "$(lower "$kind")" "$name" -n "$ns"
      diag_events "$c" "$ns" "$kind" "$name"
      diag_section "Pods in $ns" diag_k8s "$c" get pods -n "$ns" -o wide
      ;;
    node)
      diag_section "Node $name" diag_k8s "$c" describe node "$name"
      diag_events "$c" "" Node "$name"
      diag_section "Pods on $name" diag_k8s "$c" get pods -A -o wide --field-selector "spec.nodeName=$name"
      ;;
    object)
      diag_section "$kind $name" diag_k8s "$c" describe "$(lower "$kind")" "$name" ${ns:+-n "$ns"}
      diag_events "$c" "$ns" "$kind" "$name"
      ;;
    argo)
      diag_section "Argo CD status for $name" diag_argo_status "$c" "$ns" "$name"
      diag_events "$c" "$ns" Application "$name"
      ;;
    run) diag_run "$d" ;;
    sg)
      diag_section "Security group $(jq -r .id <<<"$d")" aws ec2 describe-security-groups --group-ids "$(jq -r .id <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" --output table
      diag_section "What uses it" aws ec2 describe-network-interfaces --filters "Name=group-id,Values=$(jq -r .id <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" \
        --query 'NetworkInterfaces[].{Type:InterfaceType,Description:Description,PrivateIp:PrivateIpAddress,PublicIp:Association.PublicIp}' --output table
      ;;
    lb)
      diag_section "Load balancer $(jq -r .id <<<"$d")" aws elbv2 describe-load-balancers --names "$(jq -r .id <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" \
        --query 'LoadBalancers[].{Scheme:Scheme,Type:Type,DNS:DNSName,VPC:VpcId,SecurityGroups:join(`, `,SecurityGroups || `[]`)}' --output table
      diag_section "Listeners" diag_lb_listeners "$d"
      ;;
    auth)
      diag_section "AWS error for profile $(jq -r .profile <<<"$d")" aws sts get-caller-identity --profile "$(jq -r .profile <<<"$d")"
      diag_section "How the profile is set up" aws configure list --profile "$(jq -r .profile <<<"$d")"
      ;;
    monitor)
      diag_section "Monitor $(jq -r .id <<<"$d")" "$(cfg '.datadog.pup // "pup"')" monitors get "$(jq -r .id <<<"$d")" --read-only -o yaml
      ;;
    *) jq -cn '{title: "Diagnose", command: "", output: "There is nothing more to look up for this finding.", ok: false}' ;;
  esac
}

# The parts of an Argo CD Application's status that explain a failure, readable.
diag_argo_status() {
  local c=$1 ns=$2 name=$3
  diag_k8s "$c" get applications.argoproj.io "$name" -n "$ns" -o json | jq -r '
    .status as $s
    | "Sync: \($s.sync.status // "?") at \(($s.sync.revision // "")[0:12])    Health: \($s.health.status // "?")",
      (if $s.operationState then "Last operation: \($s.operationState.phase) – \($s.operationState.message // "")" else empty end),
      "",
      (($s.conditions // [])[] | "Condition \(.type): \(.message)"),
      (($s.operationState.syncResult.resources // [])[] | select(.status != "Synced")
        | "Sync \(.status): \(.kind)/\(.name) in \(.namespace // "-"): \(.message // "")"),
      (($s.resources // [])[] | select((.health.status // "Healthy") | IN("Healthy", "Suspended") | not)
        | "Health \(.health.status): \(.kind)/\(.name): \(.health.message // "")")'
}

diag_lb_listeners() {
  local d=$1 arn
  arn=$(aws elbv2 describe-load-balancers --names "$(jq -r .id <<<"$d")" --profile "$(jq -r .profile <<<"$d")" \
    --region "$(jq -r .region <<<"$d")" --query 'LoadBalancers[0].LoadBalancerArn' --output text) || return 1
  aws elbv2 describe-listeners --load-balancer-arn "$arn" --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" \
    --query 'Listeners[].{Port:Port,Protocol:Protocol,Certificate:Certificates[0].CertificateArn}' --output table
}

# A failed GitHub Actions run: its failing jobs and steps, then each failed job's log tail.
diag_run() {
  local d=$1 repo run slug job id
  repo=$(jq -r .repo <<<"$d") run=$(jq -r .run_id <<<"$d")
  slug=$(gh_slug "$repo")
  diag_section "Jobs in run $run" gh run view "$run" -R "$slug"
  while IFS=$'\t' read -r id job; do
    [ -n "$id" ] || continue
    diag_section "Log of failed job: $job (last $DIAG_MAX_LINES lines)" gh api --method GET -H "Accept: application/vnd.github.raw" "repos/$slug/actions/jobs/$id/logs"
  done < <(gh api --method GET "repos/$slug/actions/runs/$run/jobs?per_page=100" 2>/dev/null |
    jq -r '[.jobs[] | select(.conclusion | IN("failure", "timed_out", "startup_failure"))][:3][] | [.id, .name] | @tsv')
}

# cmd_diagnose TERM : find findings in the last report whose resource or message matches, and
# diagnose one. With several matches, list them so you can be more specific.
cmd_diagnose() {
  local term=${1:-} report matches n
  report="${XDG_CACHE_HOME:-$HOME/.cache}/platform-manager/last-report.json"
  [ -n "$term" ] || die "Usage: pmgr diagnose NAME   (part of a finding's resource, e.g. checkout or sg-0abc)"
  [ -f "$report" ] || die "No report yet. Run pmgr doctor or pmgr ui first."
  matches=$(jq -c --arg t "$(lower "$term")" '[.findings[] | select(.diag != null)
    | select((.id == $t) or ((.resource + " " + .message) | ascii_downcase | contains($t)))]' "$report")
  n=$(jq length <<<"$matches")
  if [ "$n" -eq 0 ]; then die "No finding with something to diagnose matches '$term'."; fi
  if [ "$n" -gt 1 ]; then
    printf 'Several findings match. Be more specific, or use an id:\n' >&2
    jq -r '.[] | "  \(.id)  \(.resource): \(.message[0:90])"' <<<"$matches" >&2
    return 2
  fi
  printf '%s\n\n' "$(jq -r '.[0] | "\(.resource): \(.message)"' <<<"$matches")"
  diagnose_finding "$(jq -c '.[0].diag' <<<"$matches")" | jq -r '"── \(.title) " + ("─" * ([60 - (.title | length), 3] | max)), "$ \(.command)", .output, ""'
}
