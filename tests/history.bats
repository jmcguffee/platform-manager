#!/usr/bin/env bats
# History: what changed since the last comparable run.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []'
}

# rep AREAS FINDINGS [UNSEEN] : a minimal report.
rep() {
  jq -cn --arg areas "$1" --argjson f "$2" --argjson u "${3:-[]}" \
    '{generated_at: "2026-11-12T08:00:00Z", areas: ($areas | split(" ")), findings: $f, unseen: $u}'
}
F() { jq -cn --arg id "$1" --arg area "$2" --arg r "$3" '{id: $id, severity: "error", area: $area, resource: $r, message: "m \($id)"}'; }

@test "new and fixed are worked out by finding id" {
  printf '%s' "$(rep "posture" "[$(F a identity acct/role/x), $(F b data acct/us-east-2/rds/db)]")" >"$BATS_TEST_TMPDIR/prev.json"
  got=$(history_changes "$(rep "posture" "[$(F b data acct/us-east-2/rds/db), $(F c compute acct/us-east-2/ebs/v)]")" "$BATS_TEST_TMPDIR/prev.json")
  [ "$(jq -c '[.new[].id, "|", .fixed[].id, "|", .unchecked[].id]' <<<"$got")" = '["c","|","a","|"]' ]
}

@test "something that wasn't readable this time is 'not checked', never 'fixed'" {
  printf '%s' "$(rep "posture" "[$(F a identity acct/role/x), $(F b identity other/role/y)]")" >"$BATS_TEST_TMPDIR/prev.json"
  got=$(history_changes "$(rep "posture" "[]" '["acct (us-east-2): IAM roles and policies (AccessDenied)", "acct: AWS session expired, so its accounts weren'"'"'t checked"]')" "$BATS_TEST_TMPDIR/prev.json")
  [ "$(jq -c '[.fixed[].id, "|", .unchecked[].id]' <<<"$got")" = '["b","|","a"]' ]
}

@test "only areas both runs covered are compared" {
  # The last run was everything; this one is only load balancing, so IAM findings aren't "fixed".
  printf '%s' "$(rep "posture traffic" "[$(F a identity acct/role/x), $(F t traffic prd/shop/tgb/api)]")" >"$BATS_TEST_TMPDIR/prev.json"
  got=$(history_changes "$(rep "traffic" "[]")" "$BATS_TEST_TMPDIR/prev.json")
  [ "$(jq -c '[.fixed[].id]' <<<"$got")" = '["t"]' ]
}

@test "each run is saved privately, compared with the last run covering the same areas, and history is capped" {
  HISTORY_KEEP=3
  r1=$(report_finalize "$(rep "posture traffic" "[$(F a identity acct/role/x)]")")
  [ "$(jq -r 'has("changes")' <<<"$r1")" = false ]   # nothing to compare with yet
  sleep 1
  r2=$(report_finalize "$(rep "traffic" "[$(F t traffic prd/shop/tgb/api)]")")
  [ "$(jq -c '[.changes.new[].id]' <<<"$r2")" = '["t"]' ]
  sleep 1
  # A full run compares with r1 (r2 didn't cover posture).
  r3=$(report_finalize "$(rep "posture traffic" "[]")")
  [ "$(jq -c '[.changes.fixed[].id]' <<<"$r3")" = '["a"]' ]
  [ "$(jq -r .changes.since <<<"$r3")" = "2026-11-12T08:00:00Z" ]
  sleep 1
  report_finalize "$(rep "traffic" "[]")" >/dev/null
  [ "$(ls "$(history_dir)" | wc -l | tr -d ' ')" = 3 ]
  [ "$(stat -c %a "$(history_dir)" 2>/dev/null || stat -f %Lp "$(history_dir)")" = 700 ]
  [ "$(jq -c '[.changes.fixed[].id]' "${XDG_CACHE_HOME}/platform-manager/last-report.json")" = '[]' ]
}

@test "pmgr changes lists them; the text report sums them up and marks new findings" {
  r=$(jq -c '. + {changes: {since: "2026-11-12T08:00:00Z", new: [{id: "c", severity: "error", area: "compute", resource: "acct/us-east-2/ebs/v", message: "Volume v is unattached"}],
    fixed: [{id: "a", severity: "warning", area: "identity", resource: "acct/role/x", message: "Role x is unused"}], unchecked: []}}' <<<"$(rep "posture" "[$(F c compute acct/us-east-2/ebs/v)]")")
  out=$(changes_text "$r")
  [[ "$out" == *"1 new, 1 fixed."* ]] && [[ "$out" == *"New"*"ERRO  acct/us-east-2/ebs/v: Volume v is unattached"* ]] && [[ "$out" == *"Fixed"*"acct/role/x"* ]]
  text=$(report_text "$(jq -c '. + {clusters: [], accounts: [], usage_minutes: {}}' <<<"$r")")
  [[ "$text" == *"Since the last run: 1 new, 1 fixed"* ]]
  [[ "$text" == *"NEW acct/us-east-2/ebs/v"* ]]
}
