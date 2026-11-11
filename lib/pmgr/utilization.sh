# shellcheck shell=bash
# Over- and under-utilization: RDS, Redshift, ElastiCache and MSK from CloudWatch, and EKS from
# requests, capacity and metrics-server. Read-only: describe/list calls and GetMetricData.

# The accounts to check: every profile with a working session, once per AWS account.
util_accounts() {
  jq -sc '[.[0][] | {label: .name, profile: .aws_profile, account: .auth.account, state: .auth.state}]
          + [.[1][] | {label: .name, profile: .aws_profile, account: .auth.account, state: .auth.state}]
          | map(select(.state == "ok" or .state == "expiring"))
          | unique_by(.account) | map({label: .profile, profile, account})' \
    "$PMGR_TMP/clusters.json" "$PMGR_TMP/accounts.json"
}

util_region() {
  local r
  r=$(jq -r --arg p "$1" '.utilization.regions[$p] // ""' <<<"$PMGR_CONFIG_JSON")
  [ -n "$r" ] || r=$(aws_setting "$1" region)
  printf '%s' "${r:-us-east-1}"
}

# util_describe KEY PROFILE REGION ARGS... : one describe call into $dir/KEY.json, "null" if unreadable.
util_describe() {
  local key=$1 profile=$2 region=$3
  shift 3
  if capture "util-$key-$profile" aws "$@" --profile "$profile" --region "$region" --output json \
    --cli-connect-timeout 5 --cli-read-timeout 30; then
    cp "$PMGR_TMP/util-$key-$profile.out" "$UTIL_DIR/$key.json"
  else
    printf 'null' >"$UTIL_DIR/$key.json"
  fi
}

# util_account_sweep LABEL PROFILE : findings for one account's managed data services.
util_account_sweep() {
  local label=$1 profile=$2 region days
  region=$(util_region "$profile")
  days=$(cfg '.utilization.lookback_days // 14')
  UTIL_DIR="$PMGR_TMP/util/$(safe_key "$profile")"
  mkdir -p "$UTIL_DIR"

  util_describe rds "$profile" "$region" rds describe-db-instances &
  util_describe redshift "$profile" "$region" redshift describe-clusters &
  util_describe cache "$profile" "$region" elasticache describe-cache-clusters &
  util_describe kafka "$profile" "$region" kafka list-clusters-v2 &
  wait

  # MSK needs broker IDs for its per-broker metrics.
  local msk="[]" arn name
  if [ "$(cat "$UTIL_DIR/kafka.json")" != null ]; then
    while IFS=$'\t' read -r arn name; do
      [ -n "$arn" ] || continue
      if capture "util-msk-nodes" aws kafka list-nodes --cluster-arn "$arn" --profile "$profile" --region "$region" --output json; then
        msk=$(jq -c --arg n "$name" --argjson have "$msk" \
          '$have + [{ClusterName: $n, brokers: [.NodeInfoList[]? | .BrokerNodeInfo.BrokerId | select(. != null) | floor]}]' \
          "$PMGR_TMP/util-msk-nodes.out")
      fi
    done < <(jq -r '.ClusterInfoList[]? | select(.ClusterType == "PROVISIONED") | [.ClusterArn, .ClusterName] | @tsv' "$UTIL_DIR/kafka.json")
  fi

  local missing="" svc
  for svc in rds redshift cache kafka; do [ "$(cat "$UTIL_DIR/$svc.json")" = null ] && missing="$missing $svc"; done
  [ -z "$missing" ] || printf "%s: couldn't list%s\n" "$label" "$(printf '%s' "$missing" |
    sed 's/ rds/ RDS,/; s/ redshift/ Redshift,/; s/ cache/ ElastiCache,/; s/ kafka/ MSK,/; s/,$//')" >>"$PMGR_TMP/unseen.txt"

  local resources queries
  resources=$(jq -n --slurpfile rds "$UTIL_DIR/rds.json" --slurpfile redshift "$UTIL_DIR/redshift.json" \
    --slurpfile cache "$UTIL_DIR/cache.json" --argjson msk "$msk" \
    '{rds: $rds[0], redshift: $redshift[0], cache: $cache[0], msk: $msk}')
  queries=$(jq -c -f "$PMGR_JQ/utilization_queries.jq" <<<"$resources")
  [ "$(jq length <<<"$queries")" -gt 0 ] || return 0

  # GetMetricData returns at most 100,800 points per call, so size the batches to the window.
  local per_call start end total i=0 results="[]" token
  per_call=$((100800 / (days * 24)))
  [ "$per_call" -gt 500 ] && per_call=500
  total=$(jq length <<<"$queries")
  end=$(jq -rn --arg now "${PMGR_NOW:-}" '(if $now == "" then now else ($now | tonumber) end) | floor | todateiso8601')
  start=$(jq -rn --arg e "$end" --argjson d "$days" '$e | fromdateiso8601 - ($d * 86400) | todateiso8601')
  while [ "$i" -lt "$total" ]; do
    jq -c --argjson i "$i" --argjson n "$per_call" '.[$i:$i + $n] | map(.query)' <<<"$queries" >"$UTIL_DIR/q-$i.json"
    token=""
    while :; do
      local args=(cloudwatch get-metric-data --metric-data-queries "file://$UTIL_DIR/q-$i.json"
        --start-time "$start" --end-time "$end" --profile "$profile" --region "$region" --output json)
      [ -n "$token" ] && args+=(--next-token "$token")
      if ! capture "util-cw-$i" aws "${args[@]}"; then
        printf "%s: couldn't read CloudWatch metrics\n" "$label" >>"$PMGR_TMP/unseen.txt"
        return 0
      fi
      results=$(jq -c --argjson have "$results" '$have + (.MetricDataResults // [])' "$PMGR_TMP/util-cw-$i.out")
      token=$(jq -r '.NextToken // ""' "$PMGR_TMP/util-cw-$i.out")
      [ -n "$token" ] || break
    done
    i=$((i + per_call))
  done
  # Pages of one query come back as separate results with the same Id: join them.
  results=$(jq -c 'group_by(.Id) | map({Id: .[0].Id, Timestamps: (map(.Timestamps // []) | add),
                                         Values: (map(.Values // []) | add)})' <<<"$results")

  jq -cn --argjson resources "$resources" --argjson queries "$queries" --argjson results "$results" \
    --argjson days "$days" --arg label "$label" --argjson t "$(util_thresholds)" \
    '{resources: $resources, queries: $queries, results: $results, days: $days, t: $t, label: $label}' |
    jq -c -f "$PMGR_JQ/utilization.jq"
}

util_thresholds() {
  cfg '{cpu_low: (.utilization.cpu_low // 10), cpu_low_peak: (.utilization.cpu_low_peak // 30),
        cpu_high: (.utilization.cpu_high // 80), msk_cpu_high: (.utilization.msk_cpu_high // 60),
        storage_low: (.utilization.storage_free_low // 15), disk_high: (.utilization.disk_high // 80),
        memory_high: (.utilization.memory_high // 80)} | tojson'
}

# util_eks CLUSTER_JSON : EKS capacity findings, reusing the workload sense's collected lists.
util_eks() {
  local c=$1 name ctx profile dir
  name=$(jq -r .name <<<"$c") ctx=$(jq -r .context <<<"$c") profile=$(jq -r .aws_profile <<<"$c")
  dir="$PMGR_TMP/workloads/$(safe_key "$name")"
  [ -f "$dir/pods.json" ] || workloads_collect "$c" "$dir"
  local m kind
  for m in pods nodes; do
    kind="${m%s}metrics"
    if capture "eksm-$(safe_key "$name")-$m" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=20s \
      get --raw "/apis/metrics.k8s.io/v1beta1/$m" && jq -e 'has("items")' "$PMGR_TMP/eksm-$(safe_key "$name")-$m.out" >/dev/null 2>&1; then
      cp "$PMGR_TMP/eksm-$(safe_key "$name")-$m.out" "$dir/$kind.json"
    else
      printf 'null' >"$dir/$kind.json"
    fi
  done
  [ "$(cat "$dir/podmetrics.json")" != null ] ||
    printf "%s: usage (metrics-server isn't installed or readable), so only requests were checked\n" "$name" >>"$PMGR_TMP/unseen.txt"
  jq -cn --slurpfile pods "$dir/pods.json" --slurpfile nodes "$dir/nodes.json" \
    --slurpfile pm "$dir/podmetrics.json" --slurpfile nm "$dir/nodemetrics.json" \
    '{pods: $pods[0], nodes: $nodes[0], podmetrics: $pm[0], nodemetrics: $nm[0]}' |
    jq -c --arg cluster "$name" --argjson ignore "$(cfg '.workloads.ignore_namespaces // [] | tojson')" \
      -f "$PMGR_JQ/eks_utilization.jq"
}

# utilization_sweep : every account and every reachable cluster.
utilization_sweep() {
  local a c
  while IFS= read -r a; do
    [ -n "$a" ] || continue
    util_account_sweep "$(jq -r .label <<<"$a")" "$(jq -r .profile <<<"$a")"
  done < <(util_accounts | jq -c '.[]')
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    [ "$(jq -r .kubernetes <<<"$c")" = ok ] && util_eks "$c"
  done < <(jq -c '.[]' "$PMGR_TMP/clusters.json")
  return 0
}
