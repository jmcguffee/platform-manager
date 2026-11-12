#!/usr/bin/env bats
# Watch: the LaunchAgent, its schedule, and notifications that fire once per new problem.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []'
  export PMGR_LAUNCH_DIR="$BATS_TEST_TMPDIR/LaunchAgents"
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  printf '#!/usr/bin/env bash\necho "$*" >>"%s"\n' "$BATS_TEST_TMPDIR/launchctl.calls" >"$BATS_TEST_TMPDIR/bin/launchctl"
  printf '#!/usr/bin/env bash\nprintf "%%s | %%s\\n" "$1" "$2" >>"%s"\n' "$BATS_TEST_TMPDIR/notified" >"$BATS_TEST_TMPDIR/bin/notify"
  chmod +x "$BATS_TEST_TMPDIR/bin/launchctl" "$BATS_TEST_TMPDIR/bin/notify"
  export PMGR_LAUNCHCTL="$BATS_TEST_TMPDIR/bin/launchctl" PMGR_NOTIFY="$BATS_TEST_TMPDIR/bin/notify"
}

@test "watch on writes a private LaunchAgent with today's PATH and loads it; off removes it" {
  PATH="/opt/homebrew/bin:/a&b<c>:$PATH" run cmd_watch on
  [ "$status" -eq 0 ]
  [[ "$output" == *"Watching: every 60 minutes, 8-18, weekdays."* ]]
  plist=$(watch_plist)
  grep -q "<string>$PMGR_ROOT/bin/pmgr</string><string>__scheduled</string>" "$plist"
  grep -q "<integer>3600</integer>" "$plist"
  grep -q "/a&amp;b&lt;c&gt;:" "$plist"   # escaped, so the plist stays valid
  [ "$(stat -c %a "$plist" 2>/dev/null || stat -f %Lp "$plist")" = 600 ]
  if command -v plutil >/dev/null; then plutil -lint "$plist" >/dev/null; fi
  grep -q "^load $plist" "$BATS_TEST_TMPDIR/launchctl.calls"
  run cmd_watch off
  [ ! -f "$plist" ] && grep -q "^unload $plist" "$BATS_TEST_TMPDIR/launchctl.calls"
}

@test "watch refuses to run more often than every 15 minutes" {
  config 'clusters: []
watch: {every_minutes: 5}'
  run cmd_watch on
  [ "$status" -ne 0 ] && [[ "$output" == *"at least 15"* ]]
  config 'clusters: []
watch: {hours: "morning"}'
  run cmd_watch on
  [ "$status" -ne 0 ] && [[ "$output" == *"watch.hours must look like 8-18"* ]]
}

@test "notifications: new errors once, never info; expired sessions once, again only after they recover" {
  r() { jq -cn --argjson new "$1" --arg aws "${2:-ok}" '{changes: {new: $new}, clusters: [{name: "prd", aws: $aws}], accounts: []}'; }
  E='{"id": "f1", "severity": "error", "resource": "acct/us-east-2/rds/orders", "message": "Production database orders runs in one zone"}'
  I='{"id": "f2", "severity": "info", "resource": "acct/role/x", "message": "unused"}'
  watch_alert "$(r "[$E, $I]")"
  watch_alert "$(r "[$E]")"   # same one again: quiet
  [ "$(cat "$BATS_TEST_TMPDIR/notified")" = "pmgr: something new broke | acct/us-east-2/rds/orders: Production database orders runs in one zone" ]
  : >"$BATS_TEST_TMPDIR/notified"
  watch_alert "$(r "[]" expired)"
  watch_alert "$(r "[]" expired)"
  [ "$(wc -l <"$BATS_TEST_TMPDIR/notified" | tr -d ' ')" = 1 ]
  [[ "$(cat "$BATS_TEST_TMPDIR/notified")" == "pmgr: sessions expired | AWS sessions ran out for prd. Run pmgr login"* ]]
  watch_alert "$(r "[]" ok)"
  watch_alert "$(r "[]" expired)"
  [ "$(wc -l <"$BATS_TEST_TMPDIR/notified" | tr -d ' ')" = 2 ]
}

@test "the scheduled run does nothing outside watch hours" {
  config 'clusters: []
watch: {hours: "0-0"}'
  run cmd_scheduled
  [ "$status" -eq 0 ] && [ -z "$output" ]
  config 'clusters: []
watch: {hours: "0-24", weekends: true}'
  watch_in_hours
}
