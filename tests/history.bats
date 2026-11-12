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

@test "the weekly report: fixed (not reopened), new and still open, what needs attention, savings, status" {
  export PMGR_NOW=$(jq -n '"2026-11-12T12:00:00Z" | fromdateiso8601')
  S() { jq -cn --arg id "$1" --arg sev "$2" --arg area "$3" --arg r "$4" --argjson save "${5:-0}" \
    '{id: $id, severity: $sev, area: $area, resource: $r, message: "m \($id)"} + (if $save > 0 then {savings_usd_month: $save} else {} end)'; }
  report_finalize "$(rep "posture" "[$(S a error identity acct/role/ci), $(S v warning compute acct/us-east-2/ebs/vol-1 10), $(S z error data acct/s3/b)]")" >/dev/null
  sleep 1
  report_finalize "$(rep "posture" "[$(S z error data acct/s3/b), $(S n error edge acct/us-east-2/lb/x), $(S g info compute acct/us-east-2/ebs/gp2 6.5)]" |
    jq -c '. + {metrics: [{kind: "eks_version", cluster: "prd", version: "1.32", status: "EXTENDED_SUPPORT", standard_end: "2026-03-23"},
                          {kind: "workflow", runs: 40, success_rate: 0.95}]}')" >/dev/null
  out=$(weekly_report 7)
  [[ "$out" == "# Platform update: November 5 to November 12, 2026"* ]]
  [[ "$out" == *"**2 fixed**, 2 new (2 still open), 2 errors open, 0 warnings. \$6.50/month in savings identified, \$10.00/month already saved."* ]]
  [[ "$out" == *"## Fixed"*"**Identity**"*"- **acct/role/ci**: m a"*"**Compute**"*"acct/us-east-2/ebs/vol-1"* ]]
  [[ "$out" == *"## Needs attention"*"acct/s3/b"*"acct/us-east-2/lb/x"* ]]
  [[ "$out" == *"| prd | 1.32 | extended support, standard support ends March 23, 2026 |"* ]]
  [[ "$out" == *"CI: 95% of 40 workflow runs succeeded."* ]]
  run "$PMGR_ROOT/bin/pmgr" weekly --days x
  [[ "$output" == *"--days needs a whole number"* ]]
}

@test "the dashboard's weekly route needs the token header and returns Markdown" {
  report_finalize "$(rep "posture" "[]")" >/dev/null
  SERVE_DIR="$BATS_TEST_TMPDIR/live"; mkdir -p "$SERVE_DIR"
  SERVE_HOST="127.0.0.1:8765"; SERVE_TOKEN="t0ken"
  export SERVE_DIR SERVE_HOST SERVE_TOKEN
  post() { printf 'POST /api/weekly HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n%sContent-Length: 11\r\n\r\n{"days":14}' "$1" | serve_handle; }
  [[ "$(post "" | head -1)" == *403* ]]
  got=$(post $'X-Pmgr-Token: t0ken\r\n')
  [[ "$got" == *"Content-Type: text/markdown"* ]]
  [[ "$got" == *"# Platform update: "* ]]
}
