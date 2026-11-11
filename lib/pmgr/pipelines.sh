# shellcheck shell=bash
# Whether pipelines work, read from what they actually did.
#
#   Broken now   The newest default-branch run failed and nothing has passed since.
#   Unreliable   Fails often on the default branch, though each failure got fixed.
# Plus reruns that pass (flaky), queue time (runner capacity), slow runs, and CI minutes.
# Rates need MIN_RUNS runs: 0% failures over three runs isn't a score.


# The latest failing run for each workflow that's broken now: one run ID per line.
pipelines_broken_runs() {
  jq -r --arg branch "$1" -L "$PMGR_JQ" 'include "pipelines"; by_workflow[] | broken($branch) | select(. != null) | .latest.id' "$2"
}

# pipelines_assess REPO BRANCH RUNS_FILE EXPLANATIONS_JSON DAYS : findings as JSON lines.
pipelines_assess() {
  jq -c --arg repo "$1" --arg branch "$2" --argjson why "$4" --argjson days "$5" -L "$PMGR_JQ" -f "$PMGR_JQ/pipeline_assess.jq" "$3"
}

# pipelines_usage RUNS_FILE : {workflow label: approximate minutes}.
pipelines_usage() {
  jq -c -L "$PMGR_JQ" -f "$PMGR_JQ/pipeline_usage.jq" "$1"
}

# pipelines_sweep REPO : fetch runs, explain workflows broken now, print findings.
# Returns 3 when the repo's runs can't be read.
pipelines_sweep() {
  local repo=$1 slug key days limit since branch page=1 count=0
  slug=$(gh_slug "$repo")
  key="pl-$(safe_key "$repo")"
  days=$(cfg '.github.lookback_days // 14')
  limit=$(cfg '.github.max_runs_per_repo // 300')
  local code=0
  gh_get "$key-repo" "repos/$slug" || code=$?
  if [ "$code" -ne 0 ]; then
    gh_source_failure "$repo" "$slug" "$code" "$key-repo"
    return 3
  fi
  branch=$(out "$key-repo" | jq -r '.default_branch // "main"')
  since=$(jq -rn --argjson d "$days" 'now - ($d * 86400) | strftime("%Y-%m-%d")')

  local runs="$PMGR_TMP/$key-runs.json"
  printf '[]' >"$runs"
  while [ "$count" -lt "$limit" ]; do
    if ! gh_get "$key-p$page" "repos/$slug/actions/runs?per_page=100&page=$page&created=%3E%3D$since&exclude_pull_requests=true"; then
      [ "$page" -gt 1 ] && break
      source_row repo "$repo" false "The repo is readable, but its Actions runs aren't: $(first_line "$(err "$key-p$page")")"         "Check that Actions is enabled for $slug and that your gh token has the repo scope (gh auth status)."
      return 3
    fi
    jq -s '.[0] + (.[1].workflow_runs // [])' "$runs" "$PMGR_TMP/$key-p$page.out" >"$runs.tmp" && mv "$runs.tmp" "$runs"
    count=$(jq length "$runs")
    [ "$(out "$key-p$page" | jq '.workflow_runs | length')" -lt 100 ] && break
    page=$((page + 1))
  done
  jq --argjson n "$limit" '.[:$n]' "$runs" >"$runs.tmp" && mv "$runs.tmp" "$runs"

  # Pull logs only for workflows that are broken now, two failed jobs each.
  local why="{}" run_id jobs job ex
  for run_id in $(pipelines_broken_runs "$branch" "$runs"); do
    ex="[]"
    if gh_get "$key-jobs-$run_id" "repos/$slug/actions/runs/$run_id/jobs?per_page=100"; then
      jobs=$(out "$key-jobs-$run_id" | jq -c '[.jobs // [] | .[] | select(.conclusion | IN("failure","timed_out","startup_failure"))][:2]')
      while IFS= read -r job; do
        [ -n "$job" ] || continue
        local job_id log="$PMGR_TMP/$key-log"
        job_id=$(jq -r .id <<<"$job")
        # Logs expire and can be large. A failed fetch means no log, not a failed sweep.
        if gh_get "$key-log-$job_id" "repos/$slug/actions/jobs/$job_id/logs" raw; then
          cp "$PMGR_TMP/$key-log-$job_id.out" "$log"
        else
          : >"$log"
        fi
        ex=$(jq -c --argjson e "$(explain "$job" "$log")" '. + [$e]' <<<"$ex")
      done < <(jq -c '.[]' <<<"$jobs")
    fi
    why=$(jq -c --arg id "$run_id" --argjson ex "$ex" '. + {($id): $ex}' <<<"$why")
  done

  pipelines_assess "$repo" "$branch" "$runs" "$why" "$days"
  jq -c --arg repo "$repo" --arg branch "$branch" -L "$PMGR_JQ" -f "$PMGR_JQ/pipeline_metrics.jq" "$runs" | metric_rows
  local n last
  n=$(jq length "$runs")
  last=$(jq -r 'map(.created_at) | max // ""' "$runs")
  if [ "$n" -eq 0 ]; then
    source_row repo "$repo" true "No workflow runs in the last $days days" \
      "Raise github.lookback_days in your config to look further back." \
      "$(jq -cn --argjson d "$days" --arg b "$branch" --argjson p "$(out "$key-repo" | jq '.private // false')" '{runs: 0, window_days: $d, branch: $b, private: $p}')"
  else
    source_row repo "$repo" true "$n runs in the last $days days$([ "$n" -ge "$limit" ] && printf ' (capped at max_runs_per_repo)')" "" \
      "$(jq -cn --argjson n "$n" --argjson d "$days" --arg b "$branch" --arg last "$last" --argjson p "$(out "$key-repo" | jq '.private // false')" \
        '{runs: $n, window_days: $d, branch: $b, last_run: $last, private: $p}')"
  fi
  jq -cn --arg repo "$repo" --argjson usage "$(pipelines_usage "$runs")" '{repo: $repo, usage: $usage}' \
    >>"$PMGR_TMP/usage.jsonl"
  return 0
}
