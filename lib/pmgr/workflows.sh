# shellcheck shell=bash
# Gaps in what pipelines are configured to do, read from .github/workflows.
#
# Narrow on purpose: each rule is something whose absence lets a bad change ship, a secret
# leak, or minutes burn. Repo-level rules depend on the repo's kind (terraform, gitops).


# workflows_assess_file REPO PATH FILE : findings for one workflow file.
workflows_assess_file() {
  local repo=$1 path=$2 file=$3 json
  if ! json=$(yq -o=json '.' "$file" 2>/dev/null) || ! jq -e 'type == "object"' <<<"$json" >/dev/null 2>&1; then
    finding workflow.unparseable error workflow "$repo:$path" "Workflow file isn't valid YAML" \
      "GitHub won't run it. Fix the syntax."
    return 0
  fi
  jq -c --arg where "$repo:$path" --rawfile text "$file" -L "$PMGR_JQ" -f "$PMGR_JQ/workflow_file.jq" <<<"$json"
}

# workflows_assess_repo REPO KIND DIR : per-file findings plus repo-level gaps.
workflows_assess_repo() {
  local repo=$1 kind=$2 dir=$3 f parsed="[]" json
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    workflows_assess_file "$repo" ".github/workflows/$(basename "$f")" "$f"
    if json=$(yq -o=json '.' "$f" 2>/dev/null) && jq -e 'type == "object"' <<<"$json" >/dev/null 2>&1; then
      parsed=$(jq -c --argjson wf "$json" '. + [$wf]' <<<"$parsed")
    fi
  done
  local count
  count=$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
  jq -c --arg repo "$repo" --arg kind "$kind" --argjson count "$count" -L "$PMGR_JQ" -f "$PMGR_JQ/workflow_repo.jq" <<<"$parsed"
}
