#!/usr/bin/env bats
# The ui server's request handler: token, Host check, routes, and starting a sync.

load helpers

setup() {
  setup_pmgr
  SERVE_DIR="$BATS_TEST_TMPDIR/live"
  mkdir -p "$SERVE_DIR"
  SERVE_HOST="127.0.0.1:8765"
  SERVE_TOKEN="t0ken"
  export SERVE_DIR SERVE_HOST SERVE_TOKEN
  printf '<html>dashboard</html>' >"$SERVE_DIR/dashboard.html"
  printf '{"findings":[]}' >"$SERVE_DIR/report.json"
  printf '{"generated_at":"2026-11-11T12:00:00Z","error":""}' >"$SERVE_DIR/state.json"
}

req() { # METHOD PATH [HOST] [TOKEN_HEADER]
  {
    printf '%s %s HTTP/1.1\r\nHost: %s\r\n' "$1" "$2" "${3:-127.0.0.1:8765}"
    [ -z "${4:-}" ] || printf 'X-Pmgr-Token: %s\r\n' "$4"
    printf '\r\n'
  } | serve_handle
}
status() { head -1 | tr -d '\r'; }

@test "the page needs the token" {
  [ "$(req GET / | status)" = "HTTP/1.1 403 Forbidden" ]
  [ "$(req GET "/?t=nope" | status)" = "HTTP/1.1 403 Forbidden" ]
  run req GET "/?t=t0ken"
  [[ "${lines[0]}" == "HTTP/1.1 200 OK"* ]]
  [[ "$output" == *"<html>dashboard</html>"* ]]
  [[ "$output" == *"Cache-Control: no-store"* ]]
  [[ "$output" != *"Access-Control-Allow-Origin"* ]]
}

@test "a different Host header is refused, which blocks DNS rebinding" {
  [ "$(req GET "/?t=t0ken" evil.example:8765 | status)" = "HTTP/1.1 421 Misdirected Request" ]
}

@test "state and report are served with the token header" {
  run req GET /api/state "" t0ken
  [[ "$output" == *'"running":false'* ]]
  run req GET /api/report "" t0ken
  [[ "$output" == *'{"findings":[]}'* ]]
}

@test "syncing needs the token header, not just the URL token" {
  [ "$(req POST "/api/sync?t=t0ken" | status)" = "HTTP/1.1 403 Forbidden" ]
}

@test "a sync starts once, and is reported as running" {
  # Stand in for the real render so the test doesn't run every check.
  serve_render() { sleep 2; rm -f "$SERVE_DIR/sync.running"; }
  [ "$(req POST /api/sync "" t0ken | status)" = "HTTP/1.1 202 Accepted" ]
  [ -f "$SERVE_DIR/sync.running" ]
  [[ "$(req GET /api/state "" t0ken)" == *'"running":true'* ]]
  [ "$(req POST /api/sync "" t0ken | status)" = "HTTP/1.1 202 Accepted" ]   # no second sync while one runs
}

@test "unknown routes are 404" {
  [ "$(req GET /etc/passwd "" t0ken | status)" = "HTTP/1.1 404 Not Found" ]
  [ "$(req DELETE / "" t0ken | status)" = "HTTP/1.1 404 Not Found" ]
}

@test "the live page may call back to its own server, and only it" {
  html=$(report_html '{"findings":[]}' live)
  [[ "$html" == *"default-src 'none'; connect-src 'self';"* ]]
  [[ "$html" == *'id="pmgr-live"'* ]]
  html=$(report_html '{"findings":[]}')
  [[ "$html" != *"connect-src"* ]]
  [[ "$html" != *'id="pmgr-live"'* ]]
}
