# shellcheck shell=bash
# Apps: how workloads on each reachable cluster are configured (security context, images, limits,
# probes, replicas, PDBs, spreading). Read with kubectl get only. System namespaces are skipped;
# set apps.system_namespaces to change which.

APPS_RESOURCES="deployments statefulsets daemonsets pdbs"

apps_cluster() {
  local c=$1 name ctx profile dir kind key
  name=$(jq -r .name <<<"$c") ctx=$(jq -r .context <<<"$c") profile=$(jq -r .aws_profile <<<"$c")
  dir="$PMGR_TMP/apps/$(safe_key "$name")"
  mkdir -p "$dir"
  for kind in $APPS_RESOURCES; do
    (
      key="apps-$(safe_key "$name")-$kind"
      res=$kind
      [ "$kind" = pdbs ] && res=poddisruptionbudgets.policy
      if capture "$key" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=20s get "$res" -A -o json; then
        cp "$PMGR_TMP/$key.out" "$dir/$kind.json"
      else
        printf 'null' >"$dir/$kind.json"
        printf '%s: %s for app checks (%s)\n' "$name" "$kind" "$(first_line "$(err "$key")")" >>"$PMGR_TMP/unseen.txt"
      fi
    ) &
  done
  wait
  jq -cn --slurpfile d "$dir/deployments.json" --slurpfile s "$dir/statefulsets.json" --slurpfile ds "$dir/daemonsets.json" \
    --slurpfile p "$dir/pdbs.json" '{deployments: $d[0], statefulsets: $s[0], daemonsets: $ds[0], pdbs: $p[0]}' |
    jq -c --arg cluster "$name" \
      --arg env "$(jq -r '.name | ascii_downcase | (capture("(^|[-_])(?<e>prd|prod|production|uat|rc|stg|staging|dev|qa)([-_]|$)") // {}).e // ""' <<<"$c")" \
      --argjson system "$(cfg '(.apps.system_namespaces // ["kube-system", "kube-public", "kube-node-lease", "amazon-cloudwatch", "amazon-guardduty", "aws-observability", "datadog"]) + (.workloads.ignore_namespaces // []) | tojson')" \
      --argjson prd "$(cfg '.security.public_environments // ["prd", "prod", "production"] | tojson')" \
      -f "$PMGR_JQ/apps.jq"
}

apps_sweep() {
  local c
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    if [ "$(jq -r .kubernetes <<<"$c")" != ok ]; then
      printf '%s: app configuration (no cluster access)\n' "$(jq -r .name <<<"$c")" >>"$PMGR_TMP/unseen.txt"
      continue
    fi
    apps_cluster "$c"
  done < <(jq -c '.[]' "$PMGR_TMP/clusters.json")
  return 0
}
