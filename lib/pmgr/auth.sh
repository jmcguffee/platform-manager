# shellcheck shell=bash
# AWS session checks for SSO roles (optionally activated through Entra PIM).
#
# `aws sts get-caller-identity` says whether a profile works. When it doesn't, the
# error text says why: an expired session needs a login, a role that was never
# granted needs a PIM activation or an Identity Center assignment.

# auth_classify TEXT : the failure state an AWS CLI error describes.
auth_classify() {
  local t
  t=$(lower "$1")
  case $t in
    *"config profile"*"could not be found"*) echo no_profile ;;
    *"token has expired"* | *expiredtoken* | *"sso session associated with this profile has expired"* | \
      *"error loading sso token"* | *"unable to locate credentials"* | \
      *"security token included in the request is expired"* | *"session token not found or invalid"* | \
      *unauthorizedexception* | *invalid_grant*) echo expired ;;
    *forbiddenexception* | *"no access"* | *"not authorized to perform: sts:assumerole"* | *accessdenied*) echo no_access ;;
    *"could not connect to the endpoint url"* | *"connect timeout"* | *"read timeout"* | *"name resolution"* | \
      *"network is unreachable"* | *"connection refused"*) echo unreachable ;;
    *) echo unknown ;;
  esac
}

# aws_setting PROFILE KEY : a key from the profile's block in ~/.aws/config, or nothing.
aws_setting() {
  local file="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  [ -f "$file" ] || return 0
  awk -v p="$1" -v k="$2" '
    BEGIN { want = (p == "default") ? "[default]" : "[profile " p "]" }
    /^[ \t]*\[/ { line = $0; gsub(/^[ \t]+|[ \t]+$/, "", line); inside = (line == want); next }
    inside {
      split($0, kv, "=")
      key = kv[1]; gsub(/^[ \t]+|[ \t]+$/, "", key)
      if (key == k) { sub(/^[^=]*=[ \t]*/, ""); sub(/[ \t]+$/, ""); print; exit }
    }' "$file"
}

# SSO and assume-role profiles get fresh role credentials from the CLI as they expire, so the
# role credentials' expiry says nothing about when you'll be locked out.
renews_itself() {
  [ -n "$(aws_setting "$1" sso_session)$(aws_setting "$1" sso_start_url)$(aws_setting "$1" role_arn)" ]
}

# minutes_until ISO8601 : whole minutes from now (PMGR_NOW, epoch seconds, overrides "now" in tests).
minutes_until() {
  jq -rn --arg e "$1" --arg now "${PMGR_NOW:-}" '
    ($e | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601)
    - (if $now == "" then now else ($now | tonumber) end) | . / 60 | floor' 2>/dev/null
}

# auth_check PROFILE [EXPECTED_ROLE] : one JSON status line for the profile.
auth_check() {
  local profile=$1 expected=${2:-} key code state arn="" account="" detail="" expires=""
  key="sts-$(printf '%s' "$profile" | tr -c 'A-Za-z0-9_-' '_')"
  code=0
  capture "$key" aws sts get-caller-identity --profile "$profile" --output json \
    --cli-connect-timeout 5 --cli-read-timeout 15 || code=$?
  if [ "$code" -eq 127 ]; then
    state=no_cli detail="The aws CLI is not on PATH"
  elif [ "$code" -ne 0 ]; then
    state=$(auth_classify "$(err "$key") $(out "$key")")
    detail=$(first_line "$(err "$key")")
  else
    state=ok
    arn=$(out "$key" | jq -r '.Arn // ""')
    account=$(out "$key" | jq -r '.Account // ""')
    if [ -n "$expected" ] && ! printf '%s' "$(lower "$arn")" | grep -qF -- "$(lower "$expected")"; then
      state=wrong_role detail="Signed in as $arn, expected a role matching '$expected'"
    elif ! renews_itself "$profile"; then
      if capture "$key-exp" aws configure export-credentials --profile "$profile" --format process; then
        # Read only the expiry. The credentials themselves stay in the temp file, which is removed on exit.
        expires=$(out "$key-exp" | jq -r '.Expiration // ""' 2>/dev/null)
        : >"$PMGR_TMP/$key-exp.out"
        local left
        left=$(minutes_until "$expires")
        if [ -n "$left" ] && [ "$left" -le "$(cfg '.pim.warn_minutes // 30')" ]; then
          state=expiring detail="Session ends in $((left < 0 ? 0 : left)) min"
        fi
      fi
    fi
  fi
  jq -cn --arg profile "$profile" --arg state "$state" --arg arn "$arn" --arg account "$account" \
    --arg expires "$expires" --arg detail "$detail" \
    '{profile: $profile, state: $state, arn: $arn, account: $account,
      expires_at: (if $expires == "" then null else $expires end), detail: $detail}'
}

# auth_findings NAME PIM_GROUP STATUS_JSON : the finding for a broken session (nothing when ok).
auth_findings() {
  jq -c --arg name "$1" --arg group "$2" --arg pim "$(pim_url)" --arg path "$(config_path)" \
    --arg hours "$(cfg '.pim.session_hours // 8')" '
    . as $s
    | ("pmgr login " + $name) as $login
    | (if $group == "" then "" else " (PIM group: \($group))" end) as $g
    | ($pim != "") as $has_pim
    | {area: "auth", resource: $name, evidence: {profile: $s.profile}, link: $pim} as $base
    | if $s.state == "ok" then empty
      elif $s.state == "expiring" then $base + {check: "auth.expiring", severity: "warning",
          message: "AWS session for \($name) ends soon: \($s.detail)",
          fix: (if $has_pim then "Re-activate in PIM\($g) before it lapses, then run `\($login)`." else "Run `\($login)`." end)}
      elif $s.state == "expired" then $base + {check: "auth.expired", severity: "error",
          message: "AWS session for \($name) has expired or is missing: \($s.detail)",
          fix: ("Run `\($login)`." + (if $has_pim then " If it still fails, your \($hours)h PIM window has probably ended: activate it again\($g)." else "" end))}
      elif $s.state == "no_access" then $base + {check: "auth.no_access", severity: "error",
          message: "Signed in, but the role for \($name) isn'"'"'t granted: \($s.detail)",
          fix: (if $has_pim then "Activate the role in Azure PIM\($g). It can take a few minutes to reach AWS. Then run `\($login)`."
                else "Your SSO user isn'"'"'t assigned this role in this account. Check the permission set assignment in IAM Identity Center, then run `\($login)`." end)}
      elif $s.state == "wrong_role" then $base + {check: "auth.wrong_role", severity: "warning", message: $s.detail,
          fix: "Check aws_profile for \($name) in your config\(if $has_pim then ", or activate the right PIM group\($g)" else "" end)."}
      elif $s.state == "unreachable" then $base + {check: "auth.unreachable", severity: "error", link: "",
          message: "Can'"'"'t reach AWS for \($name): \($s.detail)", fix: "Check VPN and proxy settings, then retry."}
      elif $s.state == "no_profile" then $base + {check: "auth.no_profile", severity: "error", link: "",
          message: "AWS profile '"'"'\($s.profile)'"'"' isn'"'"'t in ~/.aws/config", fix: "Fix aws_profile for \($name) in \($path)."}
      elif $s.state == "no_cli" then $base + {check: "auth.no_cli", severity: "critical", link: "",
          message: $s.detail, fix: "Install AWS CLI v2."}
      else $base + {check: "auth.unknown", severity: "error", link: "",
          message: "AWS check for \($name) failed: \($s.detail)",
          fix: "Run `aws sts get-caller-identity --profile \($s.profile)` to see the full error."}
      end' <<<"$3"
}

# auth_collapse : stdin JSON array of findings -> same, with expired findings that share an SSO session
# merged into one. One login fixes them all, so it's one finding.
auth_collapse() {
  local findings sessions="{}" profile session
  findings=$(cat)
  for profile in $(jq -r '.[] | select(.check == "auth.expired") | .evidence.profile' <<<"$findings" | sort -u); do
    session=$(aws_setting "$profile" sso_session)
    [ -n "$session" ] && sessions=$(jq -c --arg p "$profile" --arg s "$session" '. + {($p): $s}' <<<"$sessions")
  done
  jq -c --argjson sessions "$sessions" '
    . as $all
    | [ $all[] | select(.check == "auth.expired" and ($sessions[.evidence.profile] // null) != null) ]
    | group_by($sessions[.evidence.profile]) | map(select(length > 1)) as $groups
    | ($groups | map(.[]) | map(.resource + "|" + .evidence.profile)) as $merged
    | [ $all[] | select((.resource + "|" + (.evidence.profile // "")) as $k | $merged | index($k) | not) ]
      + [ $groups[] | . as $g | ($sessions[$g[0].evidence.profile]) as $session
          | ($g | map(.resource) | sort) as $names
          | ($g | sort_by(.resource) | .[0].resource) as $first
          | {check: "auth.expired", severity: "error", area: "auth", resource: "sso-session \($session)",
             message: "SSO session '"'"'\($session)'"'"' has expired, so \($g | length) profiles can'"'"'t sign in (\($names | join(", ")))",
             fix: "Run `pmgr login \($first)` (or `aws sso login --sso-session \($session)`). One login covers all of them.",
             link: $g[0].link, evidence: {profiles: ($g | map(.evidence.profile) | unique), detail: $g[0].message}} ]' <<<"$findings"
}
