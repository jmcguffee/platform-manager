# shellcheck shell=bash
# Workload health on each reachable cluster: pods, controllers, nodes, volumes, jobs, and recent
# Warning events. Read with `kubectl get` only. A resource that can't be read is reported as
# unseen, not as healthy.

WORKLOAD_RESOURCES="pods nodes deployments statefulsets daemonsets pvcs jobs events"

# workloads_collect CLUSTER_JSON DIR : save each resource list as DIR/NAME.json ("null" if unreadable).
workloads_collect() {
  local c=$1 dir=$2 ctx profile name kind scope key
  ctx=$(jq -r .context <<<"$c") profile=$(jq -r .aws_profile <<<"$c") name=$(jq -r .name <<<"$c")
  mkdir -p "$dir"
  for kind in $WORKLOAD_RESOURCES; do
    (
      scope="-A"
      [ "$kind" = nodes ] && scope=""
      key="wl-$(safe_key "$name")-$kind"
      local args=(get "$kind")
      [ "$kind" = pvcs ] && args=(get persistentvolumeclaims)
      [ "$kind" = events ] && args+=(--field-selector type=Warning)
      [ -n "$scope" ] && args+=("$scope")
      if capture "$key" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=20s "${args[@]}" -o json &&
        jq -e 'has("items")' "$PMGR_TMP/$key.out" >/dev/null 2>&1; then
        cp "$PMGR_TMP/$key.out" "$dir/$kind.json"
      else
        printf 'null' >"$dir/$kind.json"
      fi
    ) &
  done
  wait
}

# workloads_assess CLUSTER_NAME DIR : findings from the collected lists.
workloads_assess() {
  local name=$1 dir=$2 kind args=()
  for kind in $WORKLOAD_RESOURCES; do args+=(--slurpfile "$kind" "$dir/$kind.json"); done
  jq -cn "${args[@]}" \
    '{pods: $pods[0], nodes: $nodes[0], deployments: $deployments[0], statefulsets: $statefulsets[0],
      daemonsets: $daemonsets[0], pvcs: $pvcs[0], jobs: $jobs[0], events: $events[0]}' |
    jq -c --arg cluster "$name" --arg now "${PMGR_NOW:-}" \
      --arg window "$(cfg '.workloads.event_window_minutes // 60')" \
      --argjson ignore "$(cfg '.workloads.ignore_namespaces // [] | tojson')" \
      -f "$PMGR_JQ/workloads.jq"
}

# workloads_sweep : workload findings for every cluster access_sweep found reachable.
workloads_sweep() {
  local c name dir kind unread
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    name=$(jq -r .name <<<"$c")
    if [ "$(jq -r .kubernetes <<<"$c")" != ok ]; then
      printf '%s: workloads and events (no cluster access)\n' "$name" >>"$PMGR_TMP/unseen.txt"
      continue
    fi
    dir="$PMGR_TMP/workloads/$(safe_key "$name")"
    workloads_collect "$c" "$dir"
    unread=""
    for kind in $WORKLOAD_RESOURCES; do
      [ "$(cat "$dir/$kind.json")" = null ] && unread="$unread $kind"
    done
    [ -z "$unread" ] || printf '%s: couldn'"'"'t read%s\n' "$name" "$(printf '%s' "$unread" | sed 's/ /, /g; s/^,//')" \
      >>"$PMGR_TMP/unseen.txt"
    workloads_assess "$name" "$dir"
  done < <(jq -c '.[]' "$PMGR_TMP/clusters.json")
}
