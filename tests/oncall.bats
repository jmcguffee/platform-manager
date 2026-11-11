#!/usr/bin/env bats
# Datadog on-call through Pup: login state, pages, incidents and monitors.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []
datadog: {site: acme.datadoghq.com}'
  PMGR_NOW=$(jq -n '"2026-11-11T12:00:00Z" | fromdateiso8601')
  export PMGR_NOW
  : >"$PMGR_TMP/sources.jsonl"
  : >"$PMGR_TMP/metrics.jsonl"
}

ok() { jq -cn --argjson d "$1" '{status: "success", data: $d, metadata: {count: 1}}'; }

PAGES='[{"id": "p1", "type": "pages", "attributes": {"title": "checkout 5xx above 2%", "status": "triggered", "urgency": "high", "created_at": "2026-11-11T11:40:00Z"}},
        {"id": "p2", "type": "pages", "attributes": {"title": "disk 85% on db-1", "status": "acknowledged", "urgency": "low", "created_at": "2026-11-11T09:00:00Z"}},
        {"id": "p3", "type": "pages", "attributes": {"title": "old", "status": "resolved", "created_at": "2026-11-10T09:00:00Z"}}]'
INCIDENTS='{"type": "incidents_search_results", "attributes": {"incidents": [
        {"data": {"id": "i1", "type": "incidents", "attributes": {"public_id": 412, "title": "Checkout errors", "severity": "SEV-2", "state": "active", "customer_impacted": true, "created": "2026-11-11T11:30:00Z"}}},
        {"data": {"id": "i2", "type": "incidents", "attributes": {"public_id": 409, "title": "Slow search", "fields": {"severity": {"value": "SEV-4"}, "state": {"value": "stable"}}, "created": "2026-11-10T12:00:00Z"}}}]}}'
MONITORS='{"monitors": [{"id": 101, "name": "checkout p99 latency", "status": "Alert", "priority": 1, "last_triggered_ts": 1794398400},
                         {"id": 102, "name": "queue depth", "status": "Warn"}, {"id": 103, "name": "legacy cron heartbeat", "status": "No Data"},
                         {"id": 104, "name": "fine", "status": "OK"}]}'

all_fakes() {
  fake 0 "$(ok "$PAGES")" "" pup on-call pages list
  fake 0 "$(ok "$INCIDENTS")" "" pup incidents list
  fake 0 "$(ok "$MONITORS")" "" pup monitors search
}

@test "pages, incidents and monitors become findings with the right urgency" {
  all_fakes
  got=$(oncall_sweep)
  [ "$(jq -r 'select(.check == "oncall.page_open") | "\(.severity) \(.message)"' <<<"$got")" = \
    "error Unacknowledged high-urgency page: checkout 5xx above 2% (open 20 min)" ]
  [ "$(jq -r 'select(.check == "oncall.page_acknowledged") | .severity' <<<"$got")" = warning ]
  [ "$(jq -r 'select(.check == "oncall.incident_active") | "\(.severity) \(.link)"' <<<"$got")" = \
    "error https://acme.datadoghq.com/incidents/412" ]
  [[ "$(jq -r 'select(.check == "oncall.incident_active") | .message' <<<"$got")" == *"customers affected"* ]]
  [ "$(jq -r 'select(.check == "oncall.incident_stable") | .severity' <<<"$got")" = info ]   # severity read from fields.*
  [ "$(checks <<<"$got")" = "oncall.incident_active oncall.incident_stable oncall.monitor_alert oncall.monitor_no_data oncall.monitor_warn oncall.page_acknowledged oncall.page_open " ]
  [ -z "$(jq -r 'select(.message | test("old|fine"))' <<<"$got")" ]   # resolved pages and OK monitors are quiet
}

@test "every Pup call is read-only and goes to the configured site" {
  all_fakes
  oncall_sweep >/dev/null
  [ "$(grep -c '^pup' "$FAKE_DIR/calls")" = 3 ]
  [ "$(grep '^pup' "$FAKE_DIR/calls" | grep -vc -- '--read-only')" = 0 ]
  [ "$(jq -r 'select(.kind == "page") | .id' "$PMGR_TMP/metrics.jsonl" | wc -l | tr -d ' ')" = 3 ]
  [ "$(jq -r '"\(.type) \(.ok) \(.detail)"' "$PMGR_TMP/sources.jsonl")" = "datadog true 3 incidents, 3 monitors, 3 pages" ] ||
    [ "$(jq -r '.ok' "$PMGR_TMP/sources.jsonl")" = true ]
}

@test "pages can be limited to the configured teams" {
  config 'clusters: []
datadog: {site: acme.datadoghq.com, teams: [platform, sre]}'
  all_fakes
  oncall_sweep >/dev/null
  grep -q 'on-call pages list --team platform' "$FAKE_DIR/calls"
  grep -q 'on-call pages list --team sre' "$FAKE_DIR/calls"
}

@test "not logged in is one clear finding with the login command" {
  fake 1 "" "Error: authentication required: set DD_ACCESS_TOKEN for bearer auth, run 'pup auth login' for OAuth2" pup on-call pages list
  got=$(oncall_sweep)
  [ "$(jq -sr 'length' <<<"$got")" = 1 ]
  [ "$(jq -r .check <<<"$got")" = datadog.auth ]
  [[ "$(jq -r .fix <<<"$got")" == *"pup auth login --site acme.datadoghq.com"* ]]
  [ "$(jq -r .ok "$PMGR_TMP/sources.jsonl")" = false ]
  ! grep -q "incidents list" "$FAKE_DIR/calls"   # no point calling the rest
}

@test "a product the role can't read is named, the rest still works" {
  fake 0 "$(ok "$PAGES")" "" pup on-call pages list
  fake 0 "$(ok "$MONITORS")" "" pup monitors search
  fake 1 "" "Error: 404 Not Found: incident management isn't enabled" pup incidents list
  got=$(oncall_sweep)
  [[ "$(checks <<<"$got")" == *oncall.page_open* ]]
  [[ "$(jq -r .detail "$PMGR_TMP/sources.jsonl")" == *"couldn't read: incidents"* ]]
}

@test "no datadog section means no Pup calls at all" {
  config 'clusters: []'
  [ -z "$(oncall_sweep)" ]
  ! grep -q '^pup' "$FAKE_DIR/calls"
}

@test "Pup missing says how to install it" {
  config 'clusters: []
datadog: {site: datadoghq.com, pup: /nonexistent/pup}'
  got=$(oncall_sweep)
  [ "$(jq -r .check <<<"$got")" = datadog.no_cli ]
  [[ "$(jq -r .fix <<<"$got")" == *"brew install datadog-labs/pack/pup"* ]]
}
