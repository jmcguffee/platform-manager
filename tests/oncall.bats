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
  [ "$(grep -c '^pup' "$FAKE_DIR/calls")" -ge 3 ]
  [ "$(grep '^pup' "$FAKE_DIR/calls" | grep -vc -- '--read-only')" = 0 ]
  ! grep '^pup' "$FAKE_DIR/calls" | grep -qE -- '-X (POST|PUT|PATCH|DELETE)'   # only ever GETs
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

# responders AT CURRENT_START CURRENT_END CURRENT_EMAIL [NEXT_START NEXT_END NEXT_EMAIL] : a Pup envelope for
# GET .../responders, in Datadog's documented shape (shifts and users in `included`).
responders() {
  jq -cn --arg cs "$2" --arg ce "$3" --arg cu "$4" --arg ns "${5:-}" --arg ne "${6:-}" --arg nu "${7:-}" '
    def user($e): {id: "u-\($e)", type: "users", attributes: {email: $e, name: ($e | split("@")[0] | ascii_upcase), status: "active"}};
    def shift($id; $s; $e; $u): {id: $id, type: "shifts", attributes: {start: $s, end: $e}, relationships: {user: {data: {id: "u-\($u)", type: "users"}}}};
    {status: "success", data: {id: "r", type: "schedule_oncall_responders", attributes: {}},
     included: ([{id: "rc", type: "schedule_oncall_responder", attributes: {position: "current"}, relationships: {shifts: {data: [{id: "s-\($cs)", type: "shifts"}]}}},
                 shift("s-\($cs)"; $cs; $ce; $cu), user($cu)]
               + (if $ns == "" then [] else [{id: "rn", type: "schedule_oncall_responder", attributes: {position: "next"}, relationships: {shifts: {data: [{id: "s-\($ns)", type: "shifts"}]}}},
                 shift("s-\($ns)"; $ns; $ne; $nu), user($nu)] end))}'
}

day() { jq -rn --argjson d "$1" '"2026-11-11T12:00:00Z" | fromdateiso8601 + ($d * 86400) | todateiso8601'; }

@test "who's on call: walks the schedule shift by shift for the whole week" {
  config 'clusters: []
datadog: {site: acme.datadoghq.com, schedules: ["OnePass*"], people: [Alice@onepass.example]}'
  fake 0 '{"status":"success","data":[]}' "" pup on-call pages list
  fake 0 '{"status":"success","data":[]}' "" pup incidents list
  fake 0 '{"status":"success","data":{"monitors":[]}}' "" pup monitors search
  fake 0 '{"status":"success","data":[{"id":"sch-1","type":"schedules","attributes":{"name":"OnePass Primary","time_zone":"America/New_York"}}]}' "" \
    pup api v2/on-call/schedules -F "filter[query]=OnePass*"
  people=(alice@onepass.example bob@onepass.example cara@onepass.example dev@onepass.example)
  for d in 0 1 2 3 4 5 6 7; do
    fake 0 "$(responders x "$(day "$d")" "$(day $((d + 1)))" "${people[$((d % 4))]}" "$(day $((d + 1)))" "$(day $((d + 2)))" "${people[$(((d + 1) % 4))]}")" "" \
      pup api v2/on-call/schedules/sch-1/responders -F "filter[at_ts]=$(day "$d")"
  done
  oncall_sweep >/dev/null
  shifts=$(jq -c 'select(.kind == "shift")' "$PMGR_TMP/metrics.jsonl")
  [ "$(jq -s length <<<"$shifts")" -ge 7 ]
  [ "$(jq -rs '.[0] | "\(.schedule) \(.email) \(.name)"' <<<"$shifts")" = "OnePass Primary alice@onepass.example ALICE" ]
  [ "$(jq -rs 'map(.email) | .[1:4] | join(",")' <<<"$shifts")" = "bob@onepass.example,cara@onepass.example,dev@onepass.example" ]
  [ "$(grep -c 'responders' "$FAKE_DIR/calls")" -le 8 ]   # one call per shift, not one per hour
  grep -q -- '-F include=responders.shifts.user' "$FAKE_DIR/calls"
}

@test "a gap with nobody on call is a warning" {
  config 'clusters: []
datadog: {site: acme.datadoghq.com, schedules: ["0000000a-0000-0000-0000-000000000001"], oncall_days: 1}'
  fake 0 '{"status":"success","data":[]}' "" pup on-call pages list
  fake 0 '{"status":"success","data":[]}' "" pup incidents list
  fake 0 '{"status":"success","data":{"monitors":[]}}' "" pup monitors search
  fake 0 '{"status":"success","data":{"id":"0000000a-0000-0000-0000-000000000001","type":"schedules","attributes":{"name":"Weekend"}}}' "" \
    pup api v2/on-call/schedules/0000000a-0000-0000-0000-000000000001 --read-only
  fake 0 "$(responders x 2026-11-11T10:00:00Z 2026-11-11T18:00:00Z alice@x.example 2026-11-11T20:00:00Z 2026-11-12T20:00:00Z bob@x.example)" "" \
    pup api v2/on-call/schedules/0000000a-0000-0000-0000-000000000001/responders -F "filter[at_ts]=2026-11-11T12:00:00Z"
  fake 0 "$(responders x 2026-11-11T20:00:00Z 2026-11-12T20:00:00Z bob@x.example)" "" \
    pup api v2/on-call/schedules/0000000a-0000-0000-0000-000000000001/responders -F "filter[at_ts]=2026-11-11T18:00:00Z"
  got=$(oncall_sweep)
  [ "$(jq -r 'select(.check == "oncall.schedule_gap") | .message' <<<"$got")" = "Nobody is on call for Weekend from 2026-11-11 18:00 to 2026-11-11 20:00 UTC" ]
}
