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
