# shellcheck shell=bash
# Core helpers: config, findings, and running other programs.
#
# Written for bash 3.2 (the macOS default): no associative arrays, no mapfile,
# no ${var,,}. Structured data lives in JSON and goes through jq.

# shellcheck disable=SC2034  # used by the other modules
PMGR_VERSION="0.2.0"
# shellcheck disable=SC2034
PMGR_JQ="$PMGR_ROOT/lib/pmgr/jq"
SEVERITIES='["critical","error","warning","info"]'

die() {
  printf 'pmgr: %s\n' "$*" >&2
  exit 2
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required. Install it with: brew install ${2:-$1}"
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

first_line() {
  # First non-empty line, trimmed and capped, for error details.
  printf '%s\n' "$1" | awk 'NF { sub(/^[ \t]+/, ""); print substr($0, 1, 300); exit }'
}

# --- temp space -----------------------------------------------------------

pmgr_tmp_init() {
  PMGR_TMP=$(mktemp -d "${TMPDIR:-/tmp}/pmgr.XXXXXX") || die "Can't create a temp directory"
  chmod 700 "$PMGR_TMP"
  # shellcheck disable=SC2064  # expand now, so the trap removes this exact directory
  trap "rm -rf '$PMGR_TMP'" EXIT
  export PMGR_TMP
}

# capture NAME CMD... : runs CMD with output in $PMGR_TMP/NAME.out and .err, returns its exit code.
# No shell is involved: arguments are passed as-is, so values from config or APIs can't inject.
capture() {
  local name=$1
  shift
  if ! command -v "$1" >/dev/null 2>&1; then
    : >"$PMGR_TMP/$name.out"
    printf '%s: command not found\n' "$1" >"$PMGR_TMP/$name.err"
    return 127
  fi
  "$@" >"$PMGR_TMP/$name.out" 2>"$PMGR_TMP/$name.err"
}

out() { cat "$PMGR_TMP/$1.out" 2>/dev/null; }
err() { cat "$PMGR_TMP/$1.err" 2>/dev/null; }

# --- config ---------------------------------------------------------------

config_path() { printf '%s' "${PMGR_CONFIG:-$HOME/.config/platform-manager/config.yaml}"; }

# Load the YAML config once as JSON into $PMGR_CONFIG_JSON and validate it.
config_load() {
  local path
  path=$(config_path)
  [ -f "$path" ] || die "No config at $path. Run 'pmgr init' to create one."
  PMGR_CONFIG_JSON=$(yq -o=json '.' "$path" 2>&1) || die "$path: $PMGR_CONFIG_JSON"
  [ -n "$PMGR_CONFIG_JSON" ] && [ "$PMGR_CONFIG_JSON" != "null" ] || PMGR_CONFIG_JSON='{}'
  local problem
  problem=$(jq -r '
    def keys_ok($allowed; $where): (keys - $allowed) as $bad
      | if ($bad | length) > 0 then "\($where): unknown keys \($bad | join(", "))" else empty end;
    [
      (.clusters // [] | to_entries[] | .key as $i | .value
        | keys_ok(["name","context","aws_profile","expected_role","pim_group","region","eks_cluster","argocd_namespace"];
                  "clusters[\($i)]"),
          (if (.name // "") == "" or (.context // "") == "" or (.aws_profile // "") == ""
           then "clusters[\($i)]: name, context and aws_profile are required" else empty end)),
      (.github.repos // [] | to_entries[] | .key as $i | .value
        | keys_ok(["name","kind"]; "github.repos[\($i)]"),
          (if ((.kind // "other") | IN("terraform","gitops","app","other")) | not
           then "github.repos[\($i)]: kind must be terraform, gitops, app or other" else empty end)),
      (if ([.clusters // [] | .[].name] | length) != ([.clusters // [] | .[].name] | unique | length)
       then "Cluster names must be unique" else empty end),
      (if (.aws.refresh_command // ["aws"]) | (type != "array" or length == 0 or any(type != "string"))
       then "aws.refresh_command must be a list of strings" else empty end)
    ] | first // empty' <<<"$PMGR_CONFIG_JSON")
  [ -z "$problem" ] || die "Config error in $path: $problem"
  export PMGR_CONFIG_JSON
}

# cfg JQ_FILTER : read a value from the loaded config.
cfg() { jq -r "$1" <<<"$PMGR_CONFIG_JSON"; }

pim_url() {
  jq -r 'if (.pim | has("activation_url")) then .pim.activation_url // ""
         else "https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup" end' \
    <<<"$PMGR_CONFIG_JSON"
}

# --- findings -------------------------------------------------------------

# finding CHECK SEVERITY AREA RESOURCE MESSAGE [FIX] [LINK] [EVIDENCE_JSON] : one finding as a JSON line.
finding() {
  jq -cn --arg check "$1" --arg severity "$2" --arg area "$3" --arg resource "$4" --arg message "$5" \
    --arg fix "${6:-}" --arg link "${7:-}" --argjson evidence "${8:-"{}"}" \
    '{check: $check, severity: $severity, area: $area, resource: $resource, message: $message,
      fix: $fix, link: $link, evidence: $evidence}'
}

# Sort findings (a JSON array) most severe first, then by area and resource.
sort_findings() {
  jq --argjson order "$SEVERITIES" 'sort_by((.severity as $s | $order | index($s)), .area, .resource)'
}

# --- sources and metrics --------------------------------------------------
# A source row says what pmgr tried to read and what happened, so "nothing shows up" always
# has an explanation on screen. A metric row is one measured thing (a workflow, a database, a
# cluster) for the detailed tables.

# source_row TYPE NAME OK DETAIL [FIX] [EXTRA_JSON]
source_row() {
  jq -cn --arg type "$1" --arg name "$2" --argjson ok "$3" --arg detail "$4" --arg fix "${5:-}" \
    --argjson extra "${6:-"{}"}" '{type: $type, name: $name, ok: $ok, detail: $detail, fix: $fix} + $extra' \
    >>"$PMGR_TMP/sources.jsonl"
}

# metric_rows : append JSON lines from stdin to the metrics file.
metric_rows() { cat >>"$PMGR_TMP/metrics.jsonl"; }
