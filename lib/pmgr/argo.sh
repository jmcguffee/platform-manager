# shellcheck shell=bash
# What Argo CD says about every Application on each reachable cluster.
#
# Read from the Application resources with kubectl, so it needs no Argo CD token. If listing
# Applications is forbidden or the cluster is unreachable, it reports nothing and says so.

# argo_assess CLUSTER APPS_FILE : findings for one cluster's Applications. PMGR_NOW overrides "now".
argo_assess() {
  jq -c --arg cluster "$1" --arg now "${PMGR_NOW:-}"  -f "$PMGR_JQ/argo.jq" "$2"
}

# argo_sweep : Argo CD findings for every cluster access_sweep found reachable.
argo_sweep() {
  local c name ctx profile key
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    name=$(jq -r .name <<<"$c")
    if [ "$(jq -r .kubernetes <<<"$c")" != ok ]; then
      printf '%s: Argo CD (no cluster access)\n' "$name" >>"$PMGR_TMP/unseen.txt"
      continue
    fi
    ctx=$(jq -r .context <<<"$c") profile=$(jq -r .aws_profile <<<"$c")
    key="argo-$(safe_key "$name")"
    if capture "$key" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=15s \
      get applications.argoproj.io -A -o json && jq -e . "$PMGR_TMP/$key.out" >/dev/null 2>&1; then
      argo_assess "$name" "$PMGR_TMP/$key.out"
    else
      printf '%s: Argo CD Applications (not readable)\n' "$name" >>"$PMGR_TMP/unseen.txt"
    fi
  done < <(jq -c '.[]' "$PMGR_TMP/clusters.json")
}
