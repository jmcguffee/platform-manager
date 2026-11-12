#!/usr/bin/env bats
# Pipeline reliability and failure diagnosis.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []'
}

# runs SPEC... : write a runs file. Each SPEC is "hour:conclusion[:branch[:attempt[:queue_s[:dur_s[:path]]]]]".
runs() {
  local spec out="$BATS_TEST_TMPDIR/runs.json"
  for spec in "$@"; do printf '%s\n' "$spec"; done | jq -R 'split(":")' | jq -s '
    map(. as $s | ("2026-11-01T12:00:00Z" | fromdateiso8601) + (($s[0] | tonumber) * 3600) as $created
      | ($created + (($s[4] // "10") | tonumber)) as $started
      | {id: (1000 + ($s[0] | tonumber)), name: "Deploy", path: ($s[6] // ".github/workflows/deploy.yml"),
         head_branch: ($s[2] // "main"), status: "completed", conclusion: $s[1],
         run_attempt: (($s[3] // "1") | tonumber),
         created_at: ($created | todateiso8601), run_started_at: ($started | todateiso8601),
         updated_at: ($started + (($s[5] // "300") | tonumber) | todateiso8601),
         html_url: "https://github.com/acme/infra/actions/runs/\(1000 + ($s[0] | tonumber))"})' >"$out"
  printf '%s' "$out"
}

assess() { pipelines_assess infra main "$1" "${2:-"{}"}" 14; }

@test "broken now: counts the streak and attaches the failing step and fix" {
  f=$(runs 0:success 1:failure 2:cancelled 3:failure)
  [ "$(pipelines_broken_runs main "$f")" = 1003 ]
  why='{"1003":[{"job":"apply","step":"Terraform apply","error":"Error acquiring the state lock","diagnosis":{"id":"tf_state_lock","cause":"Terraform state is locked by another run.","fix":"run `terraform force-unlock <ID>`"}}]}'
  got=$(assess "$f" "$why")
  [ "$(jq -r .check <<<"$got")" = pipeline.broken ]
  [ "$(jq -r .evidence.streak <<<"$got")" = 2 ]
  [[ "$(jq -r .message <<<"$got")" == *"apply › Terraform apply"* ]]
  [[ "$(jq -r .fix <<<"$got")" == *force-unlock* ]]
}

@test "failures on feature branches don't break main" {
  got=$(assess "$(runs 0:success 1:failure:feature/x)")
  [ -z "$got" ]
}

@test "a failure rate needs enough runs, and only counts when main isn't broken now" {
  [[ "$(assess "$(runs 0:failure 1:success 2:success)")" != *unreliable* ]]
  got=$(assess "$(runs 0:failure 1:success 2:success 3:failure 4:success 5:success 6:failure 7:success 8:success)")
  [ "$(jq -r 'select(.check == "pipeline.unreliable") | "\(.evidence.failed)/\(.evidence.runs)"' <<<"$got")" = 3/9 ]
}

@test "reruns, queue time and slow runs are reported" {
  specs=()
  for i in 0 1 2 3 4 5 6 7 8 9; do
    attempt=1
    [ "$i" -lt 4 ] && attempt=2
    specs+=("$i:success:main:$attempt:900:2400")
  done
  got=$(assess "$(runs "${specs[@]}")" | checks)
  [ "$got" = "pipeline.flaky pipeline.queued pipeline.slow " ]
  # Diagnose lists the workflow's recent runs.
  [ "$(assess "$(runs "${specs[@]}")" | jq -r 'select(has("check")) | .diag.type' | sort -u)" = runs ]
}

@test "Dependabot runs get one stable label in CI usage" {
  f=$(runs 0:success:main:1:10:600:dynamic/dependabot/dependabot-updates 1:success:main:1:10:60)
  [ "$(pipelines_usage "$f" | jq -r 'keys | join(",")')" = "Dependabot,Deploy" ]
}

LOG=$'2026-11-11T10:00:00.0000000Z Initializing...\n2026-11-11T10:00:01.0000000Z \033[31m│\033[0m Error: Error acquiring the state lock\n2026-11-11T10:00:01.0000000Z ##[error]Terraform exited with code 1.\n2026-11-11T10:00:02.0000000Z ##[error]Process completed with exit code 1.\n'

@test "the error line prefers the runner's specific error over the generic exit code" {
  printf '%s' "$LOG" >"$BATS_TEST_TMPDIR/log"
  [ "$(error_line "$BATS_TEST_TMPDIR/log")" = "Terraform exited with code 1." ]
}

@test "the error line falls back to the tool's own error" {
  printf '2026-11-11T10:00:00Z Error: Invalid reference\n##[error]Process completed with exit code 1.\n' >"$BATS_TEST_TMPDIR/log"
  [ "$(error_line "$BATS_TEST_TMPDIR/log")" = "Invalid reference" ]
}

@test "known causes get a fix; unknown ones don't" {
  printf '%s' "$LOG" >"$BATS_TEST_TMPDIR/a"
  [ "$(diagnose "$BATS_TEST_TMPDIR/a" | jq -r .id)" = tf_state_lock ]
  printf 'Error: Not authorized to perform sts:AssumeRoleWithWebIdentity\n' >"$BATS_TEST_TMPDIR/b"
  [ "$(diagnose "$BATS_TEST_TMPDIR/b" | jq -r .id)" = oidc_trust ]
  printf '##[error]Tests failed: 3 of 200\n' >"$BATS_TEST_TMPDIR/c"
  [ -z "$(diagnose "$BATS_TEST_TMPDIR/c")" ]
  printf '##[error]The operation was canceled.\n' >"$BATS_TEST_TMPDIR/d"
  [ "$(diagnose "$BATS_TEST_TMPDIR/d" | jq -r .id)" = canceled ]
}

@test "explain names the failed step" {
  printf '%s' "$LOG" >"$BATS_TEST_TMPDIR/log"
  job='{"name":"plan","html_url":"u","steps":[{"name":"Init","conclusion":"success"},{"name":"Plan","conclusion":"failure"}]}'
  got=$(explain "$job" "$BATS_TEST_TMPDIR/log")
  [ "$(jq -r .step <<<"$got")" = Plan ]
  [ "$(jq -r .diagnosis.id <<<"$got")" = tf_state_lock ]
}

@test "workflow metrics: success on all branches and the default branch, durations, minutes, last run" {
  f=$(runs 0:success 1:failure:feature/x 2:success:main:2 3:success 4:failure)
  got=$(jq -c --arg repo infra --arg branch main -L "$PMGR_JQ" -f "$PMGR_JQ/pipeline_metrics.jq" "$f")
  [ "$(jq -r '"\(.runs) \(.failures) \(.reruns) \(.broken)"' <<<"$got")" = "5 2 1 true" ]
  [ "$(jq -r '.success_rate' <<<"$got")" = 0.6 ]
  [ "$(jq -r '.main_success_rate' <<<"$got")" = 0.75 ]
  [ "$(jq -r '.minutes' <<<"$got")" = 25 ]
  [ "$(jq -r '.last.conclusion' <<<"$got")" = failure ]
}

@test "a repo the token can't see says why, in the Sources list" {
  : >"$PMGR_TMP/sources.jsonl"
  config 'clusters: []
github: {org: acme, repos: [{name: infra}]}'
  fake 1 "" "Resource protected by organization SAML enforcement." gh api --method GET orgs/acme
  github_sweep pipelines >/dev/null
  got=$(cat "$PMGR_TMP/sources.jsonl")
  [ "$(jq -r '"\(.type) \(.name) \(.ok)"' <<<"$got")" = "repo infra false" ]
  [[ "$(jq -r .fix <<<"$got")" == *"gh auth refresh -h github.com"* ]]
}

@test "a run that never started says why that usually happens" {
  got=$(assess "$(runs 0:success 1:startup_failure)")
  [[ "$(jq -r .fix <<<"$got")" == *githubstatus.com* ]]
}
