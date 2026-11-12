# shellcheck shell=bash
# Load balancing: every TargetGroupBinding on each reachable cluster, checked against the target
# groups Terraform made. Does the target group exist (and if not, which name is close), is a load
# balancer attached, does the Service and port exist with ready pods, do the target types match,
# and are the targets healthy, with AWS's reason when they aren't. Read with kubectl get and
# elbv2 describe calls only.

TGB_RESOURCE=targetgroupbindings.elbv2.k8s.aws

# traffic_region CLUSTER_JSON : the cluster's AWS region (from its EKS ARN or config, else its profile's).
traffic_region() {
  local t
  t=$(eks_target "$1")
  if [ -n "$t" ]; then printf '%s' "${t#*$'\t'}"; else util_region "$(jq -r .aws_profile <<<"$1")"; fi
}

# traffic_cluster CLUSTER_JSON : findings for one cluster; metric rows go to the metrics file.
traffic_cluster() {
  local c=$1 name ctx profile region dir key arn i=0
  name=$(jq -r .name <<<"$c") ctx=$(jq -r .context <<<"$c") profile=$(jq -r .aws_profile <<<"$c")
  region=$(traffic_region "$c")
  dir="$PMGR_TMP/traffic/$(safe_key "$name")"
  mkdir -p "$dir/health"
  key="tgb-$(safe_key "$name")"

  if ! capture "$key" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=20s get "$TGB_RESOURCE" -A -o json; then
    if err "$key" | grep -qiE "doesn't have a resource type|could not find the requested resource|no matches for kind"; then
      source_row tgb "$name" true "No TargetGroupBindings: the AWS Load Balancer Controller's CRD isn't installed"
    else
      printf '%s: TargetGroupBindings (%s)\n' "$name" "$(first_line "$(err "$key")")" >>"$PMGR_TMP/unseen.txt"
      source_row tgb "$name" false "Couldn't list TargetGroupBindings: $(first_line "$(err "$key")")" \
        "Your role needs get and list on targetgroupbindings.elbv2.k8s.aws."
    fi
    return 0
  fi
  cp "$PMGR_TMP/$key.out" "$dir/tgbs.json"
  if [ "$(jq '.items | length' "$dir/tgbs.json")" -eq 0 ]; then
    source_row tgb "$name" true "No TargetGroupBindings on this cluster"
    return 0
  fi

  # The Services they point at, their endpoints, and every target group in the region (one call, so
  # a missing name can be matched to the closest one that exists).
  (capture "$key-svc" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=20s get services -A -o json &&
    cp "$PMGR_TMP/$key-svc.out" "$dir/svcs.json" || printf 'null' >"$dir/svcs.json") &
  (capture "$key-eps" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=20s get endpointslices.discovery.k8s.io -A -o json &&
    cp "$PMGR_TMP/$key-eps.out" "$dir/slices.json" || printf 'null' >"$dir/slices.json") &
  (capture "$key-tgs" aws elbv2 describe-target-groups --profile "$profile" --region "$region" --output json \
      --cli-connect-timeout 5 --cli-read-timeout 20 &&
    cp "$PMGR_TMP/$key-tgs.out" "$dir/tgs.json" || printf 'null' >"$dir/tgs.json") &
  wait
  if [ "$(cat "$dir/tgs.json")" = null ]; then
    printf '%s: target groups in %s (%s)\n' "$name" "$region" "$(first_line "$(err "$key-tgs")")" >>"$PMGR_TMP/unseen.txt"
    source_row tgb "$name" false "Couldn't list target groups in $region: $(first_line "$(err "$key-tgs")")" \
      "Your role needs elasticloadbalancing:DescribeTargetGroups and DescribeTargetHealth."
    return 0
  fi

  # Health of each target group a binding uses, in parallel.
  while IFS= read -r arn; do
    [ -n "$arn" ] || continue
    (capture "$key-h$i" aws elbv2 describe-target-health --target-group-arn "$arn" --profile "$profile" --region "$region" \
        --output json --cli-connect-timeout 5 --cli-read-timeout 20 &&
      jq -c --arg a "$arn" '{($a): .TargetHealthDescriptions}' "$PMGR_TMP/$key-h$i.out" >"$dir/health/$i.json") &
    i=$((i + 1))
  done < <(jq -r --slurpfile tgs "$dir/tgs.json" '
      ($tgs[0].TargetGroups // []) as $all
      | [.items[] | .spec as $s | $all[] | select(.TargetGroupArn == $s.targetGroupARN or .TargetGroupName == $s.targetGroupName)
         | .TargetGroupArn] | unique[]' "$dir/tgbs.json")
  wait

  jq -cn --arg cluster "$name" --arg region "$region" --arg profile "$profile" \
    --slurpfile tgbs "$dir/tgbs.json" --slurpfile svcs "$dir/svcs.json" --slurpfile slices "$dir/slices.json" \
    --slurpfile tgs "$dir/tgs.json" \
    --argjson health "$(cat "$dir"/health/*.json 2>/dev/null | jq -cs 'add // {}')" \
    '{cluster: $cluster, region: $region, profile: $profile, tgbs: $tgbs[0], svcs: $svcs[0], slices: $slices[0],
      tgs: ($tgs[0].TargetGroups // []), health: $health}' |
    jq -c -f "$PMGR_JQ/traffic.jq" >"$dir/rows.jsonl"
  jq -c 'select(.kind == "tgb")' "$dir/rows.jsonl" | metric_rows
  jq -c 'select(has("check"))' "$dir/rows.jsonl"
  source_row tgb "$name" true "$(jq -rs 'map(select(.kind == "tgb")) | "\(length) TargetGroupBindings in \(.[0].region // "?"), \(map(select(.state == "ok")) | length) healthy"' "$dir/rows.jsonl")"
}

# traffic_shared : a target group bound from two places without multiClusterTargetGroup has two
# controllers each deregistering the other's targets.
traffic_shared() {
  [ -s "$PMGR_TMP/metrics.jsonl" ] || return 0
  jq -cs '[.[] | select(.kind == "tgb" and .tg_arn != null)] | group_by(.tg_arn)[] | select(length > 1 and (all(.multi) | not))
    | {area: "traffic", resource: "\(.[0].region)/tg/\(.[0].target_group)", link: "", evidence: {bindings: map("\(.cluster)/\(.ns)/\(.name)")},
       check: "tgb.shared_target_group", severity: "error",
       message: "Target group \(.[0].target_group) is bound \(length) times (\(map("\(.cluster)/\(.ns)/\(.name)") | join(", "))), so each load balancer controller deregisters the targets the other registered",
       fix: "Keep one binding per target group, or set multiClusterTargetGroup: true on every binding that shares it (controller v2.10 or later)."}' \
    "$PMGR_TMP/metrics.jsonl" 2>/dev/null
}

# traffic_sweep : every reachable cluster, then bindings that share a target group.
traffic_sweep() {
  local c
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    if [ "$(jq -r .kubernetes <<<"$c")" != ok ]; then
      printf '%s: TargetGroupBindings (no cluster access)\n' "$(jq -r .name <<<"$c")" >>"$PMGR_TMP/unseen.txt"
      continue
    fi
    traffic_cluster "$c"
  done < <(jq -c '.[]' "$PMGR_TMP/clusters.json")
  traffic_shared
  return 0
}
