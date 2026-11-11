# shellcheck shell=bash
# Read-only GitHub access through `gh` and the login you already have. Only GET requests.
#
# gh_get return codes: 0 ok, 3 not visible (403/404), 4 SAML SSO not authorized,
# 5 rate limited, 6 auth failure, 127 gh missing, 1 anything else.

GH_UNSEEN=3 GH_SAML=4 GH_RATE=5 GH_AUTH=6

gh_slug() {
  case $1 in */*) printf '%s' "$1" ;; *) printf '%s/%s' "$(cfg '.github.org // ""')" "$1" ;; esac
}

# gh_get KEY PATH [raw] : GET an API path. Output lands in $PMGR_TMP/KEY.out.
gh_get() {
  local key=$1 path=$2 code text
  code=0
  if [ "${3:-}" = raw ]; then
    capture "$key" gh api --method GET -H "Accept: application/vnd.github.raw" "$path" || code=$?
  else
    capture "$key" gh api --method GET "$path" || code=$?
  fi
  [ "$code" -eq 0 ] && return 0
  [ "$code" -eq 127 ] && return 127
  text=$(lower "$(err "$key") $(out "$key")")
  case $text in
    *"saml enforcement"* | *"saml sso"* | *"organization saml"*) return $GH_SAML ;;
    *"rate limit"*) return $GH_RATE ;;
    *"http 401"* | *"bad credentials"* | *"gh auth login"*) return $GH_AUTH ;;
    *"http 403"* | *"http 404"*) return $GH_UNSEEN ;;
  esac
  return 1
}

# github_access_finding OWNER CODE KEY : the finding for an org we can't read.
github_access_finding() {
  local owner=$1 code=$2 detail
  detail=$(first_line "$(err "$3")")
  case $code in
    "$GH_SAML") finding github.saml error auth "github:$owner" \
      "GitHub token isn't authorized for $owner's SAML SSO" \
      'Run `gh auth refresh -h github.com` and approve SSO for the org in the browser.' \
      "https://github.com/orgs/$owner/sso" ;;
    "$GH_RATE") finding github.rate_limit warning auth "github:$owner" "GitHub API rate limit hit" \
      "Wait for the limit to reset, or lower lookback_days / max_runs_per_repo." ;;
    127) finding github.no_cli critical auth "github:$owner" "The gh CLI is not on PATH" "Install it: brew install gh" ;;
    "$GH_AUTH" | "$GH_UNSEEN") finding github.auth error auth "github:$owner" \
      "Can't read $owner on GitHub: $detail" \
      'Run `gh auth login` (or `gh auth status` to see which account is active).' ;;
    *) finding github.error error auth "github:$owner" "GitHub request failed: $detail" ;;
  esac
}

# gh_workflow_files REPO DIR : save each workflow file into DIR. Returns 3 if they can't be read.
# A 404 on a repo we *can* read means it has no workflows directory: that's "none", not "unseen".
gh_workflow_files() {
  local repo=$1 dir=$2 slug key code path
  slug=$(gh_slug "$repo")
  key="wfl-$(safe_key "$repo")"
  mkdir -p "$dir"
  code=0
  gh_get "$key" "repos/$slug/contents/.github/workflows" || code=$?
  if [ "$code" -eq "$GH_UNSEEN" ]; then
    gh_get "$key-repo" "repos/$slug" && return 0
    return "$GH_UNSEEN"
  fi
  [ "$code" -eq 0 ] || return "$code"
  out "$key" | jq -r '.[] | select(.type == "file" and (.name | test("\\.ya?ml$"))) | .path' |
    while IFS= read -r path; do
      if gh_get "$key-f" "repos/$slug/contents/$path" raw; then
        cp "$PMGR_TMP/$key-f.out" "$dir/$(basename "$path")"
      fi
    done
  return 0
}

# gh_source_failure REPO SLUG CODE KEY : record why a repo couldn't be read, in plain terms.
gh_source_failure() {
  local repo=$1 slug=$2 code=$3 detail fix
  detail=$(first_line "$(err "$4")")
  case $code in
    "$GH_SAML") detail="Your gh token isn't authorized for this org's SAML SSO"
      fix='Run `gh auth refresh -h github.com`, then approve SSO for the org in the browser.' ;;
    "$GH_UNSEEN") detail="GitHub says $slug doesn't exist for this token"
      fix='Check the repo name in your config. On an org with SAML SSO, also run `gh auth refresh -h github.com` and authorize the org.' ;;
    "$GH_AUTH") fix='Run `gh auth login`, or `gh auth status` to see which account is active.' ;;
    "$GH_RATE") detail="GitHub API rate limit hit"; fix="Wait for the limit to reset, or lower max_runs_per_repo." ;;
    127) detail="The gh CLI isn't installed"; fix="brew install gh" ;;
    *) fix='Run `gh api repos/'"$slug"'` to see the full error.' ;;
  esac
  source_row repo "$repo" false "$detail" "$fix"
}

# github_sweep AREA... : pipelines and/or workflow checks for every configured repo.
github_sweep() {
  local areas=" $* " repos owner code
  repos=$(jq -c --arg only "${SWEEP_REPOS:-}" '
    ($only | split("\n") | map(select(. != ""))) as $o
    | [.github.repos // [] | .[] | select(($o | length) == 0 or (.name as $n | $o | index($n))
        or ((.name | split("/") | last) as $n | $o | index($n)))]' <<<"$PMGR_CONFIG_JSON")
  [ "$(jq length <<<"$repos")" -gt 0 ] || return 0
  local default_org
  default_org=$(cfg '.github.org // ""')

  # Check each owner separately, so a SAML block on one org doesn't hide the others.
  local readable="[]"
  for owner in $(jq -r --arg d "$default_org" '[.[] | .name | if contains("/") then split("/")[0] else $d end] | unique[]' <<<"$repos"); do
    code=0
    gh_get "org-$owner" "orgs/$owner" || code=$?
    # Only a 404 means "not an org, maybe a user". A SAML or auth error must not be hidden by
    # a users/ lookup, which can succeed for an org.
    if [ "$code" -eq "$GH_UNSEEN" ]; then
      code=0
      gh_get "org-$owner" "users/$owner" || code=$?
    fi
    if [ "$code" -eq 0 ]; then
      readable=$(jq -c --arg o "$owner" --arg d "$default_org" --argjson all "$repos" \
        '. + [$all[] | select((.name | if contains("/") then split("/")[0] else $d end) == $o)]' <<<"$readable")
    else
      github_access_finding "$owner" "$code" "org-$owner"
      # Every repo of this owner gets a source row, so the Pipelines view can say why it's empty.
      while IFS= read -r r; do
        gh_source_failure "$r" "$(gh_slug "$r")" "$code" "org-$owner"
      done < <(jq -r --arg o "$owner" --arg d "$default_org" \
        '.[] | select((.name | if contains("/") then split("/")[0] else $d end) == $o) | .name' <<<"$repos")
    fi
  done

  # One background job per repo, four at a time.
  local i=0 n repo kind running=0
  n=$(jq length <<<"$readable")
  mkdir -p "$PMGR_TMP/repos"
  while [ "$i" -lt "$n" ]; do
    repo=$(jq -r ".[$i].name" <<<"$readable")
    kind=$(jq -r ".[$i].kind // \"other\"" <<<"$readable")
    repo_sweep "$repo" "$kind" "$areas" >"$PMGR_TMP/repos/$i.jsonl" &
    running=$((running + 1))
    if [ "$running" -ge 4 ]; then wait; running=0; fi
    i=$((i + 1))
  done
  wait
  [ "$n" -gt 0 ] && cat "$PMGR_TMP"/repos/*.jsonl 2>/dev/null
  return 0
}

# repo_sweep REPO KIND " AREAS " : one repo's findings; usage and unseen go to their files.
repo_sweep() {
  local repo=$1 kind=$2 areas=$3 code
  case $areas in *" pipelines "*)
    code=0
    pipelines_sweep "$repo" || code=$?
    [ "$code" -eq 0 ] || printf '%s: Actions runs\n' "$repo" >>"$PMGR_TMP/unseen.txt"
    ;;
  esac
  case $areas in *" workflows "*)
    local dir
    dir="$PMGR_TMP/wf/$(safe_key "$repo")"
    if gh_workflow_files "$repo" "$dir"; then
      workflows_assess_repo "$repo" "$kind" "$dir"
    else
      printf '%s: workflow files\n' "$repo" >>"$PMGR_TMP/unseen.txt"
    fi
    ;;
  esac
}
