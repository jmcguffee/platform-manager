# shellcheck shell=bash
# On-call from Datadog through Pup (Datadog's CLI): open pages, active incidents, alerting
# monitors. Runs only when the config has a `datadog:` section.
#
# Every Pup call passes --read-only, which blocks writes whoever runs it, and uses Pup's JSON
# envelope ({status, data, metadata}).

# The Datadog web app for a site: datadoghq.com and datadoghq.eu live under "app.", other
# sites and vanity hosts (yourorg.datadoghq.com) are their own host.
dd_app_url() {
  case $1 in
    datadoghq.com | datadoghq.eu) printf 'https://app.%s' "$1" ;;
    *) printf 'https://%s' "$1" ;;
  esac
}

# dd_classify TEXT : auth | unreachable | error
dd_classify() {
  case $(lower "$1") in
    *"not logged in"* | *"no credentials"* | *unauthorized* | *"401"* | *forbidden* | *"403"* | *expired* | \
      *"auth login"* | *keychain* | *"api key"* | *"app key"*) echo auth ;;
    *"connection"* | *"timed out"* | *"timeout"* | *"dns"* | *"resolve"* | *"network"*) echo unreachable ;;
    *) echo error ;;
  esac
}

# dd_read KEY ARGS... : one read-only Pup call into $PMGR_TMP/dd/KEY.json ("null" if it failed).
# Returns 0 ok, 2 auth problem, 3 unreachable, 1 other error. The error text is in KEY.err.
dd_read() {
  local key=$1 code=0
  shift
  capture "dd-$key" env DD_SITE="$DD_SITE_NAME" "$PUP" "$@" --read-only -o json ${DD_ORG:+--org "$DD_ORG"} || code=$?
  if [ "$code" -eq 0 ] && jq -e '(.status // "success") == "success"' "$PMGR_TMP/dd-$key.out" >/dev/null 2>&1; then
    cp "$PMGR_TMP/dd-$key.out" "$PMGR_TMP/dd/$key.json"
    return 0
  fi
  printf 'null' >"$PMGR_TMP/dd/$key.json"
  first_line "$(err "dd-$key") $(jq -r '.error // .message // empty' "$PMGR_TMP/dd-$key.out" 2>/dev/null)" >"$PMGR_TMP/dd/$key.err"
  case $(dd_classify "$(cat "$PMGR_TMP/dd/$key.err")") in auth) return 2 ;; unreachable) return 3 ;; *) return 1 ;; esac
}

# iso_add ISO SECONDS : an RFC 3339 time shifted by SECONDS.
iso_add() { jq -rn --arg t "$1" --argjson d "$2" '$t | sub("\\.[0-9]+"; "") | fromdateiso8601 + $d | todateiso8601'; }
iso_epoch() { jq -rn --arg t "$1" '$t | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601'; }

# oncall_schedules : who's on call over the next datadog.oncall_days (default 7), for the configured
# schedules (names with * wildcards, or IDs; empty = every schedule). Walks each schedule shift by
# shift: ask who's on call at a time, then jump to when that shift ends. Writes shift rows as
# metrics and prints a finding for any gap with nobody on call.
oncall_schedules() {
  local days now stop patterns pattern list="[]" key
  days=$(cfg '.datadog.oncall_days // 7')
  now=$(jq -rn --arg n "${PMGR_NOW:-}" '(if $n == "" then now else ($n | tonumber) end) | floor | todateiso8601')
  stop=$(iso_add "$now" $((days * 86400)))
  patterns=$(cfg '.datadog.schedules // [] | .[]')

  if [ -z "$patterns" ]; then
    dd_read sched-list api v2/on-call/schedules -F 'page[size]=100' || return 0
    list=$(jq -c '[.data // [] | .[] | {id, name: (.attributes.name // .id)}]' "$PMGR_TMP/dd/sched-list.json")
  else
    while IFS= read -r pattern; do
      [ -n "$pattern" ] || continue
      key="sched-$(safe_key "$pattern")"
      if printf '%s' "$pattern" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
        dd_read "$key" api "v2/on-call/schedules/$pattern" || continue
        list=$(jq -c --argjson have "$list" '$have + [.data | {id, name: (.attributes.name // .id)}]' "$PMGR_TMP/dd/$key.json")
      else
        dd_read "$key" api v2/on-call/schedules -F "filter[query]=$pattern" -F 'page[size]=100' || continue
        list=$(jq -c --argjson have "$list" '$have + [.data // [] | .[] | {id, name: (.attributes.name // .id)}]' "$PMGR_TMP/dd/$key.json")
      fi
    done <<<"$patterns"
  fi
  list=$(jq -c 'unique_by(.id)' <<<"$list")
  [ "$(jq length <<<"$list")" -gt 0 ] || {
    printf "Datadog: no on-call schedules matched %s\n" "$(cfg '.datadog.schedules // [] | join(", ")')" >>"$PMGR_TMP/unseen.txt"
    return 0
  }

  local sid name at i rows next
  while IFS=$'\t' read -r sid name; do
    at=$now
    rows="$PMGR_TMP/dd/shifts-$(safe_key "$sid").jsonl"
    : >"$rows"
    i=0
    while [ "$i" -lt 60 ] && [ "$(iso_epoch "$at")" -lt "$(iso_epoch "$stop")" ]; do
      key="resp-$(safe_key "$sid")-$i"
      dd_read "$key" api "v2/on-call/schedules/$sid/responders" -F "filter[at_ts]=$at" \
        -F 'filter[position]=current,next' -F 'include=responders.shifts.user' || break
      jq -c --arg schedule "$name" --arg sid "$sid" -f "$PMGR_JQ/oncall_shifts.jq" "$PMGR_TMP/dd/$key.json" >>"$rows"
      # Jump to the end of the current shift, or to the start of the next one if nobody is on now.
      next=$(jq -rs --arg at "$at" '
        (map(select(.position == "current") | .end) | max) // (map(select(.position == "next") | .start) | min) // empty' \
        <(jq -c --arg schedule "$name" --arg sid "$sid" -f "$PMGR_JQ/oncall_shifts.jq" "$PMGR_TMP/dd/$key.json"))
      [ -n "$next" ] || break
      [ "$(iso_epoch "$next")" -gt "$(iso_epoch "$at")" ] || break
      at=$(jq -rn --arg t "$next" '$t | sub("\\.[0-9]+"; "")')
      i=$((i + 1))
    done
    # One row per shift, then any gap with nobody on call inside the window.
    jq -sc 'unique_by([.start, .end, .user_id]) | sort_by(.start) | .[]' "$rows" | metric_rows
    jq -sc --arg now "$now" --arg stop "$stop" --arg name "$name" '
      def e: sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601;
      unique_by([.start, .end, .user_id]) | sort_by(.start)
      | [range(0; length - 1) as $i | {from: .[$i].end, to: .[$i + 1].start}
         | select((.from | e) < (.to | e) and (.from | e) < ($stop | e) and (.to | e) > ($now | e))] as $gaps
      | $gaps[] | {check: "oncall.schedule_gap", severity: "warning", area: "oncall",
          resource: "schedule/\($name)", link: "", evidence: {},
          message: "Nobody is on call for \($name) from \(.from[0:16] | sub("T"; " ")) to \(.to[0:16] | sub("T"; " ")) UTC",
          fix: "Add a layer or an override in Datadog On-Call so the gap is covered."}' "$rows"
  done < <(jq -r '.[] | [.id, .name] | @tsv' <<<"$list")
  return 0
}

oncall_sweep() {
  [ "$(cfg '.datadog | type')" = object ] || return 0
  PUP=$(cfg '.datadog.pup // "pup"')
  DD_SITE_NAME=$(cfg '.datadog.site // "datadoghq.com"')
  DD_ORG=$(cfg '.datadog.org // ""')
  local app login
  app=$(dd_app_url "$DD_SITE_NAME")
  login="pup auth login --site $DD_SITE_NAME${DD_ORG:+ --org $DD_ORG}"
  mkdir -p "$PMGR_TMP/dd"

  if ! command -v "$PUP" >/dev/null 2>&1; then
    finding datadog.no_cli error auth "datadog" "Pup, Datadog's CLI, isn't installed" \
      'Install it with `brew install datadog-labs/pack/pup`, then run `'"$login"'`.'
    source_row datadog "$DD_SITE_NAME" false "Pup isn't installed" 'brew install datadog-labs/pack/pup'
    return 0
  fi

  # Pages: per configured team, or all of them.
  local code=0 teams team pages="[]"
  teams=$(cfg '.datadog.teams // [] | .[]')
  if [ -n "$teams" ]; then
    for team in $teams; do
      code=0
      dd_read "pages-$(safe_key "$team")" on-call pages list --team "$team" --page-size 200 || code=$?
      [ "$code" -eq 2 ] && break
      [ "$code" -eq 0 ] && pages=$(jq -c --argjson have "$pages" '$have + [.data // [] | if type == "array" then .[] else . end]' \
        "$PMGR_TMP/dd/pages-$(safe_key "$team").json")
    done
  else
    dd_read pages on-call pages list --page-size 200 || code=$?
    [ "$code" -eq 0 ] && pages=$(jq -c '[.data // [] | if type == "array" then .[] else . end]' "$PMGR_TMP/dd/pages.json")
  fi

  if [ "$code" -eq 2 ]; then
    local why
    why=$(cat "$PMGR_TMP"/dd/pages*.err 2>/dev/null | head -1)
    finding datadog.auth error auth "datadog" "Pup isn't logged in to Datadog ($DD_SITE_NAME): $why" "Run \`$login\`." "$app"
    source_row datadog "$DD_SITE_NAME" false "Not logged in: $why" "Run \`$login\`."
    return 0
  fi
  if [ "$code" -eq 3 ]; then
    finding datadog.unreachable error auth "datadog" "Can't reach Datadog ($DD_SITE_NAME): $(cat "$PMGR_TMP"/dd/pages*.err | head -1)" \
      "Check VPN and proxy settings, and that datadog.site in your config is right."
    source_row datadog "$DD_SITE_NAME" false "Unreachable" "Check VPN, proxy, and datadog.site."
    return 0
  fi

  local unread="" n
  [ "$code" -eq 0 ] || unread="$unread pages"
  dd_read incidents incidents list --query 'state:(active OR stable)' --limit 100 || unread="$unread incidents"
  dd_read monitors monitors search --query 'status:(alert OR warn OR "no data")' --per-page 200 || unread="$unread monitors"
  oncall_schedules

  jq -cn --argjson pages "{\"data\": $pages}" --slurpfile incidents "$PMGR_TMP/dd/incidents.json" \
    --slurpfile monitors "$PMGR_TMP/dd/monitors.json" '{pages: $pages, incidents: $incidents[0], monitors: $monitors[0]}' |
    jq -c --arg app "$app" --arg now "${PMGR_NOW:-}" -f "$PMGR_JQ/oncall.jq" >"$PMGR_TMP/dd/rows.jsonl"
  jq -c 'select(has("kind"))' "$PMGR_TMP/dd/rows.jsonl" | metric_rows
  jq -c 'select(has("check"))' "$PMGR_TMP/dd/rows.jsonl"

  n=$(jq -sr 'group_by(.kind) | map("\(length) \(.[0].kind)\(if length == 1 then "" else "s" end)") | join(", ")' \
    <(jq -c 'select(has("kind"))' "$PMGR_TMP/dd/rows.jsonl"))
  if [ -n "$unread" ]; then
    source_row datadog "$DD_SITE_NAME" false "Read ${n:-nothing open}, but couldn't read:$unread ($(cat "$PMGR_TMP"/dd/*.err 2>/dev/null | head -1))" \
      "Your Datadog role may not include those products. Run the pup command by hand to see the full error."
  else
    source_row datadog "$DD_SITE_NAME" true "${n:-No open pages, active incidents or alerting monitors}"
  fi
  return 0
}
