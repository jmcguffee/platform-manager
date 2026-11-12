#!/usr/bin/env bats
# Diagnose: the read-only commands you'd run by hand, run for you, for one finding.

load helpers

setup() {
  setup_pmgr
  config 'clusters: [{name: prod, context: ctx-prod, aws_profile: prd}]'
  POD='{"type":"pod","cluster":"prod","ns":"shop","pod":"api-7d4b9c8f6-aaaaa","container":"app","kind":"Deployment","name":"api"}'
}

@test "a crashing pod gets describe, events, previous and current logs, and its Deployment" {
  fake 0 "Name: api-7d4b9c8f6-aaaaa" "" kubectl --context ctx-prod --request-timeout=20s describe pod
  fake 0 "LAST SEEN  TYPE     REASON   MESSAGE" "" kubectl --context ctx-prod --request-timeout=20s get events
  fake 0 "panic: nil map" "" kubectl --context ctx-prod --request-timeout=20s logs api-7d4b9c8f6-aaaaa -n shop -c app --previous
  fake 0 "starting" "" kubectl --context ctx-prod --request-timeout=20s logs api-7d4b9c8f6-aaaaa -n shop -c app --tail=40
  fake 0 "Name: api" "" kubectl --context ctx-prod --request-timeout=20s describe deployment
  got=$(diagnose_finding "$POD")
  [ "$(jq -r .title <<<"$got" | tr '\n' '|')" = "Pod api-7d4b9c8f6-aaaaa|Events for api-7d4b9c8f6-aaaaa|Previous logs of app (the run that crashed)|Current logs of app|Deployment api|" ]
  [ "$(jq -r 'select(.title | startswith("Previous")) | .output' <<<"$got")" = "panic: nil map" ]
  # The command is shown as you'd type it, with the right context.
  [ "$(jq -r 'select(.title | startswith("Pod")) | .command' <<<"$got")" = \
    "kubectl --context ctx-prod describe pod api-7d4b9c8f6-aaaaa -n shop" ]
  grep -q $'^kubectl\tprd\t' "$FAKE_DIR/calls"   # with the cluster's AWS profile
  ! grep -qE 'kubectl.*(delete|apply|patch|edit|scale|rollout restart|exec)' "$FAKE_DIR/calls"
}

@test "a container that never restarted says so instead of showing an error" {
  fake 0 "x" "" kubectl --context ctx-prod --request-timeout=20s describe
  fake 0 "x" "" kubectl --context ctx-prod --request-timeout=20s get events
  fake 1 "" 'Error from server (BadRequest): previous terminated container "app" in pod "api-7d4b9c8f6-aaaaa" not found' \
    kubectl --context ctx-prod --request-timeout=20s logs api-7d4b9c8f6-aaaaa -n shop -c app --previous
  fake 0 "ok" "" kubectl --context ctx-prod --request-timeout=20s logs api-7d4b9c8f6-aaaaa -n shop -c app --tail=40
  got=$(diagnose_finding "$POD")
  [ "$(jq -r 'select(.title | startswith("Previous")) | "\(.ok) \(.output)"' <<<"$got")" = \
    "true No previous run to show: this container hasn't restarted." ]
}

@test "a node gets describe, its events and the pods on it" {
  fake 0 "x" "" kubectl
  got=$(diagnose_finding '{"type":"node","cluster":"prod","name":"ip-10-0-1-1"}')
  [ "$(jq -r .title <<<"$got" | tr '\n' '|')" = "Node ip-10-0-1-1|Events for ip-10-0-1-1|Pods on ip-10-0-1-1|" ]
  grep -q "field-selector spec.nodeName=ip-10-0-1-1" "$FAKE_DIR/calls"
}

@test "a cluster that's no longer configured says so" {
  [[ "$(diagnose_finding '{"type":"pod","cluster":"gone","ns":"x","pod":"y"}' | jq -r .output)" == *"no longer in your config"* ]]
}

@test "every finding gets a stable id" {
  : >"$PMGR_TMP/findings.jsonl"
  for f in a b; do finding test.check error workload "prod/$f" "m" >>"$PMGR_TMP/findings.jsonl"; done
  printf '[]' >"$PMGR_TMP/clusters.json"; printf '[]' >"$PMGR_TMP/accounts.json"
  r1=$(report_build | jq -c '[.findings[].id]')
  r2=$(report_build | jq -c '[.findings[].id]')
  [ "$r1" = "$r2" ]
  [ "$(jq -r '.[0] != .[1]' <<<"$r1")" = true ]
  [[ "$(jq -r '.[0]' <<<"$r1")" =~ ^f[0-9]+$ ]]
}

serve_setup() {
  SERVE_DIR="$BATS_TEST_TMPDIR/live"; mkdir -p "$SERVE_DIR"
  SERVE_HOST="127.0.0.1:8765"; SERVE_TOKEN="t0ken"
  export SERVE_DIR SERVE_HOST SERVE_TOKEN
  jq -cn --argjson d "$POD" '{findings: [{id: "f123", check: "workload.crashloopbackoff", resource: "prod/shop/Deployment/api", message: "m", diag: $d}]}' \
    >"$SERVE_DIR/report.json"
}
post() { # BODY [TOKEN]
  {
    printf 'POST /api/diagnose HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nContent-Length: %s\r\n' "${#1}"
    [ -z "${2:-}" ] || printf 'X-Pmgr-Token: %s\r\n' "$2"
    printf '\r\n%s' "$1"
  } | serve_handle
}

@test "the dashboard's Diagnose route needs the token header and runs only findings pmgr produced" {
  serve_setup
  fake 0 "Name: api" "" kubectl
  [[ "$(post '{"id":"f123"}' | head -1)" == *"403"* ]]
  got=$(post '{"id":"f123"}' t0ken | sed '1,/^\r$/d')
  [ "$(jq -r '.[0].title' <<<"$got")" = "Pod api-7d4b9c8f6-aaaaa" ]
  # An unknown id, or anything that isn't an id, runs nothing.
  : >"$FAKE_DIR/calls"
  [ "$(post '{"id":"f999"}' t0ken | sed '1,/^\r$/d')" = "[]" ]
  [ "$(post '{"id":"$(rm -rf /)"}' t0ken | sed '1,/^\r$/d')" = "[]" ]
  ! grep -q kubectl "$FAKE_DIR/calls"
}

@test "pmgr diagnose finds the finding by name, or lists the choices" {
  mkdir -p "$XDG_CACHE_HOME/platform-manager"
  jq -cn --argjson d "$POD" '{findings: [
    {id: "f1", check: "workload.crashloopbackoff", resource: "prod/shop/Deployment/api", message: "api crashing", diag: $d},
    {id: "f2", check: "workload.restarts", resource: "prod/shop/Deployment/api-worker", message: "restarts", diag: $d},
    {id: "f3", check: "workflow.unpinned", resource: "infra:ci.yml", message: "unpinned"}]}' >"$XDG_CACHE_HOME/platform-manager/last-report.json"
  fake 0 "Name: api" "" kubectl
  run cmd_diagnose api
  [ "$status" -eq 2 ]
  [[ "$output" == *"f1"*"f2"* ]]
  run cmd_diagnose crashing
  [ "$status" -eq 0 ]
  [[ "$output" == *"── Pod api-7d4b9c8f6-aaaaa"* ]]
  [[ "$output" == *'$ kubectl --context ctx-prod describe pod api-7d4b9c8f6-aaaaa -n shop'* ]]
  run cmd_diagnose unpinned
  [ "$status" -eq 2 ]   # nothing to diagnose for a workflow-file finding
}
