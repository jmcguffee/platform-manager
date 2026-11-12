# shellcheck shell=bash
# Watch: run the checks in the background on a schedule (a macOS LaunchAgent you turn on with
# pmgr watch on), keep each run in history, and send a notification only when something new breaks
# or the AWS sessions run out, each problem once. Nothing is installed until you ask.

WATCH_LABEL=com.github.jmcguffee.platform-manager.watch

# One LaunchAgent per workspace, so each contract is watched (and paused) on its own.
watch_label() { local ws; ws=$(pmgr_workspace); printf '%s%s' "$WATCH_LABEL" "${ws:+.$ws}"; }
watch_plist() { printf '%s/%s.plist' "${PMGR_LAUNCH_DIR:-$HOME/Library/LaunchAgents}" "$(watch_label)"; }
watch_state() { printf '%s' "$(pmgr_cache)/watch-notified.json"; }

# xml_escape : stdin to stdout, safe inside a plist <string>.
xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# watch_plist_text MINUTES : the LaunchAgent. PATH is today's, so launchd finds aws, kubectl, jq and gh.
watch_plist_text() {
  local every=$1 log
  log="$(pmgr_cache)/watch.log"
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$(watch_label)</string>
  <key>ProgramArguments</key>
  <array><string>$(printf '%s' "$PMGR_ROOT/bin/pmgr" | xml_escape)</string><string>__scheduled</string></array>
  <key>StartInterval</key><integer>$((every * 60))</integer>
  <key>RunAtLoad</key><false/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>$(printf '%s' "$PATH" | xml_escape)</string>
    <key>HOME</key><string>$(printf '%s' "$HOME" | xml_escape)</string>$(if [ -n "$(pmgr_workspace)" ]; then printf '\n    <key>PMGR_WORKSPACE</key><string>%s</string>' "$(pmgr_workspace)"; fi)$(if [ -n "${PMGR_CONFIG:-}" ]; then printf '\n    <key>PMGR_CONFIG</key><string>%s</string>' "$(printf '%s' "$PMGR_CONFIG" | xml_escape)"; fi)
  </dict>
  <key>StandardOutPath</key><string>$(printf '%s' "$log" | xml_escape)</string>
  <key>StandardErrorPath</key><string>$(printf '%s' "$log" | xml_escape)</string>
</dict>
</plist>
EOF
}

# notify TITLE MESSAGE : a macOS notification. The text is passed as arguments, never as script.
notify() {
  if [ -n "${PMGR_NOTIFY:-}" ]; then "$PMGR_NOTIFY" "$1" "$2"; return; fi
  command -v osascript >/dev/null 2>&1 || return 0
  osascript -e 'on run argv' -e 'display notification (item 2 of argv) with title (item 1 of argv)' -e 'end run' "$1" "$2" >/dev/null 2>&1
}

# watch_in_hours : 0 when now is inside watch.hours (default 8-18) on a weekday (unless watch.weekends).
watch_hours() { # prints watch.hours, or stops if it isn't like 8-18
  local hours
  hours=$(cfg '.watch.hours // "8-18"')
  case $hours in [0-9]-[0-9] | [0-9]-[0-9][0-9] | [0-9][0-9]-[0-9][0-9]) printf '%s' "$hours" ;; *) die "watch.hours must look like 8-18 (24-hour clock)" ;; esac
}
watch_in_hours() {
  local hours from to h dow
  hours=$(watch_hours) || exit 1
  from=${hours%-*} to=${hours#*-}
  h=$(date +%H | sed 's/^0//') dow=$(date +%u)
  [ "$(cfg '.watch.weekends // false')" = true ] || [ "$dow" -le 5 ] || return 1
  [ "${h:-0}" -ge "$from" ] && [ "${h:-0}" -lt "$to" ]
}

# watch_alert REPORT : notify about what's new and urgent, and about expired sessions, once each.
watch_alert() {
  local report=$1 state seen msg n expired
  state=$(watch_state)
  seen=$(cat "$state" 2>/dev/null || printf '{"ids": [], "expired": []}')
  n=$(jq '[.changes.new[]? | select(.severity == "critical" or .severity == "error")] | length' <<<"$report")
  if [ "$n" -gt 0 ]; then
    msg=$(jq -r --argjson seen "$seen" '[.changes.new[] | select(.severity == "critical" or .severity == "error")
      | select(.id as $i | $seen.ids | index($i) | not)] | if length == 0 then empty
        elif length == 1 then "\(.[0].resource): \(.[0].message[0:150])"
        else "\(length) new problems, including \(.[0].resource): \(.[0].message[0:100])" end' <<<"$report")
    [ -z "$msg" ] || notify "pmgr$(ws=$(pmgr_workspace); printf '%s' "${ws:+ ($ws)}"): something new broke" "$msg"
  fi
  # Sessions that ran out since the last notice (and not before): one notice, with the fix.
  expired=$(jq -c '[.clusters[]?, .accounts[]? | select(.aws == "expired" or .aws == "no_session") | .name] | unique' <<<"$report")
  msg=$(jq -r --argjson seen "$seen" --argjson now "$expired" '($now - $seen.expired) | if length == 0 then empty
    else "AWS sessions ran out for \(join(", ")). Run pmgr login (PIM first if the role expired)." end' <<<"$report")
  [ -z "$msg" ] || notify "pmgr$(ws=$(pmgr_workspace); printf '%s' "${ws:+ ($ws)}"): sessions expired" "$msg"
  mkdir -p "$(dirname "$state")"
  jq -cn --argjson seen "$seen" --argjson r "$report" --argjson expired "$expired" \
    '{ids: (($seen.ids + [$r.changes.new[]?.id]) | unique | .[-500:]), expired: $expired}' >"$state"
}

# cmd_scheduled : one background run (called by launchd).
cmd_scheduled() {
  watch_in_hours || return 0
  printf '%s: checking\n' "$(date '+%Y-%m-%d %H:%M')"
  sweep access security posture workloads apps traffic lifecycle utilization oncall argo pipelines workflows >/dev/null 2>&1
  local report
  report=$(report_finalize "$(code_locate "$(report_build)")")
  watch_alert "$report"
  printf '%s: done, %s findings, %s new\n' "$(date '+%Y-%m-%d %H:%M')" "$(jq '.findings | length' <<<"$report")" "$(jq '.changes.new | length // 0' <<<"$report")"
}

cmd_watch() {
  local plist every launchctl=${PMGR_LAUNCHCTL:-launchctl}
  plist=$(watch_plist)
  case ${1:-status} in
    on)
      every=$(cfg '.watch.every_minutes // 60')
      case $every in '' | *[!0-9]*) die "watch.every_minutes must be a whole number" ;; esac
      [ "$every" -ge 15 ] || die "watch.every_minutes must be at least 15 (each run reads every account and cluster)"
      watch_hours >/dev/null
      mkdir -p "$(dirname "$plist")"
      [ -f "$plist" ] && "$launchctl" unload "$plist" >/dev/null 2>&1
      (umask 077 && watch_plist_text "$every" >"$plist")
      "$launchctl" load "$plist" || die "launchctl couldn't load $plist"
      printf 'Watching: every %s minutes, %s, %s.\n' "$every" "$(cfg '.watch.hours // "8-18"')" \
        "$([ "$(cfg '.watch.weekends // false')" = true ] && echo "every day" || echo "weekdays")"
      printf 'You get a notification when something new breaks or sessions expire. Log: %s\n' \
        "$(pmgr_cache)/watch.log"
      ;;
    off)
      if [ -f "$plist" ]; then "$launchctl" unload "$plist" >/dev/null 2>&1; rm -f "$plist"; printf 'Stopped watching.\n'
      else printf 'Not watching.\n'; fi
      ;;
    status)
      if [ -f "$plist" ]; then
        printf 'Watching (%s). Last runs:\n' "$plist"
        tail -n 4 "$(pmgr_cache)/watch.log" 2>/dev/null || printf '  none yet\n'
      else
        printf 'Not watching. Start with: pmgr watch on\n'
      fi
      ;;
    *) die "Usage: pmgr watch [on | off | status]" ;;
  esac
}
