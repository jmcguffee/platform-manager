# shellcheck shell=bash
# History: every report is kept (the last HISTORY_KEEP, private to you), so each new one can say
# what changed since the last comparable run: what's new, what got fixed, and what couldn't be
# checked this time. A finding that vanished because its account or cluster wasn't readable is
# "not checked", never "fixed".

HISTORY_KEEP=90

history_dir() { printf '%s' "$(pmgr_cache)/history"; }

# The finding areas each sweep area produces, so runs of different scope compare fairly.
HISTORY_AREAS='{"access": ["auth", "cluster"], "security": ["security"], "posture": ["edge", "data", "identity", "compute"],
  "workloads": ["workload"], "apps": ["apps"], "traffic": ["traffic"], "lifecycle": ["lifecycle"], "utilization": ["utilization"],
  "oncall": ["oncall"], "argo": ["argo"], "pipelines": ["pipeline"], "workflows": ["workflow"]}'

# history_previous REPORT : the newest saved report that covered at least the same sweep areas.
history_previous() {
  local f files i
  files=("$(history_dir)"/*.json)   # timestamped names, so the glob's order is oldest first
  [ -e "${files[0]}" ] || return 1
  i=$((${#files[@]} - 1))
  while [ "$i" -ge 0 ]; do
    f=${files[$i]}
    i=$((i - 1))
    if jq -e --argjson cur "$(jq -c '.areas // []' <<<"$1")" '(.areas // []) as $a | ($cur - $a) | length == 0' "$f" >/dev/null 2>&1; then
      printf '%s' "$f"
      return 0
    fi
  done
  return 1
}

# history_changes CURRENT PREVIOUS_FILE : {since, new, fixed, unchecked} for the areas both covered.
history_changes() {
  jq -c --slurpfile prev "$2" --argjson map "$HISTORY_AREAS" '
    . as $cur | $prev[0] as $p
    | ([($cur.areas // [])[] as $a | select(($p.areas // []) | index($a)) | $map[$a][]?] | unique) as $areas
    | def scoped: [.[] | select(.area as $a | $areas | index($a))];
      def unseen_for($f): ($f.resource | split("/")[0]) as $who | any($cur.unseen[]?; startswith($who + ":") or startswith($who + " ("));
    ($cur.findings | scoped) as $now | ($p.findings | scoped) as $was
    | ([$now[].id]) as $now_ids | ([$was[].id]) as $was_ids
    | [$was[] | select(.id as $i | $now_ids | index($i) | not)] as $gone
    | {since: $p.generated_at,
       new: [$now[] | select(.id as $i | $was_ids | index($i) | not) | {id, severity, area, resource, message}],
       fixed: [$gone[] | select(unseen_for(.) | not) | {id, severity, area, resource, message}],
       unchecked: [$gone[] | select(unseen_for(.)) | {id, severity, area, resource, message}]}' <<<"$1"
}

# report_finalize REPORT : add what changed since the last comparable run, save it as the last
# report and in history, and print it.
report_finalize() {
  local report=$1 prev dir name
  if prev=$(history_previous "$report"); then
    report=$(jq -c --argjson ch "$(history_changes "$report" "$prev")" '. + {changes: $ch}' <<<"$report")
  fi
  save_last_report "$report"
  dir=$(history_dir)
  mkdir -p "$dir" && chmod 700 "$dir"
  name=$(date -u +%Y%m%dT%H%M%SZ)
  (umask 077 && printf '%s\n' "$report" >"$dir/$name.json")
  # Keep the newest HISTORY_KEEP.
  local files n=0
  files=("$dir"/*.json)
  while [ $((${#files[@]} - n)) -gt "$HISTORY_KEEP" ]; do rm -f "${files[$n]}"; n=$((n + 1)); done
  printf '%s' "$report"
}

# changes_text REPORT : the changes, for the terminal.
changes_text() {
  jq -r '
    def ago: (now - (.[0:19] + "Z" | fromdateiso8601)) / 60 | if . < 90 then "\(floor) min" elif . < 2880 then "\(. / 60 | floor) h" else "\(. / 1440 | floor) days" end;
    def line: "  \(.severity | ascii_upcase | .[0:4])  \(.resource): \(.message[0:110])";
    if .changes == null then "No earlier run to compare with yet. The next run will show what changed."
    else .changes as $c
      | "Since the last run (\($c.since | ago) ago): \($c.new | length) new, \($c.fixed | length) fixed\(if ($c.unchecked | length) > 0 then ", \($c.unchecked | length) not checked this time" else "" end).",
        (if ($c.new | length) > 0 then "", "New", ($c.new[] | line) else empty end),
        (if ($c.fixed | length) > 0 then "", "Fixed", ($c.fixed[] | line) else empty end),
        (if ($c.unchecked | length) > 0 then "", "Not checked this time (still there, as far as pmgr knows)", ($c.unchecked[] | line) else empty end)
    end' <<<"$1"
}

# weekly_report [DAYS] : a Markdown summary of the last DAYS (7) for a status update: what got fixed,
# what's new and still open, what still needs attention, savings found and saved, and status.
weekly_report() {
  local days=${1:-7} latest dir
  dir=$(history_dir)
  latest="$(pmgr_cache)/last-report.json"
  [ -f "$latest" ] || die "No report yet. Run pmgr doctor or pmgr ui first."
  # shellcheck disable=SC2086  # the glob is meant to expand
  cat "$dir"/*.json 2>/dev/null | jq -rs --slurpfile latest "$latest" --argjson days "$days" \
    --argjson now "$(jq -n --arg n "${PMGR_NOW:-}" 'if $n == "" then now else ($n | tonumber) end | floor')" '
    def ymd: fromdateiso8601? // . | if type == "number" then strftime("%B %-d, %Y") else . end;
    def usd: . * 100 | round / 100 | tostring | if test("\\.") then (split(".") | .[0] + "." + (.[1] + "0")[0:2]) else . + ".00" end | "$\(.)";
    def item: "- **\(.resource)**: \(.message)";
    def pl($n; $one; $many): "\($n) \(if $n == 1 then $one else $many end)";
    {auth: "Access", cluster: "Clusters", workload: "Workloads", apps: "Apps", traffic: "Load balancing", lifecycle: "Lifecycle",
     edge: "Edge", data: "Data stores", identity: "Identity", compute: "Compute", utilization: "Utilization", oncall: "On-call",
     security: "Security", argo: "Argo CD", pipeline: "Pipelines", workflow: "Workflow gaps"} as $titles
    | ($now - $days * 86400) as $from
    | [.[] | select((.generated_at // "1970-01-01T00:00:00Z" | fromdateiso8601) >= $from)] as $window
    | $latest[0] as $last
    | ([$last.findings[].id]) as $open_ids
    | ([$window[].changes.fixed[]?] | unique_by(.id) | map(select(.id as $i | $open_ids | index($i) | not))) as $fixed
    | ([$window[].changes.new[]?] | unique_by(.id)) as $new_all
    | ($new_all | map(select(.id as $i | $open_ids | index($i)))) as $new_open
    | ([$last.findings[] | select(.severity == "critical" or .severity == "error")]) as $urgent
    | ([$last.findings[] | select(.severity == "warning")] | length) as $warnings
    | ([$last.findings[] | .savings_usd_month // 0] | add // 0) as $saving_found
    | ([$window[].findings[]? | select(.savings_usd_month > 0)] | unique_by(.id) | map(select(.id as $i | $fixed | map(.id) | index($i))) | map(.savings_usd_month) | add // 0) as $saved
    | ([$last.metrics[]? | select(.kind == "workflow" and .success_rate != null)]) as $wfs
    | "# Platform update: \($from | strftime("%B %-d")) to \($now | strftime("%B %-d, %Y"))", "",
      "**\($fixed | length) fixed**, \($new_all | length) new (\($new_open | length) still open), \(pl($urgent | length; "error"; "errors")) open, \(pl($warnings; "warning"; "warnings")).\(if $saving_found > 0 then " \($saving_found | usd)/month in savings identified\(if $saved > 0 then ", \($saved | usd)/month already saved" else "" end)." else "" end)",
      (if ($window | length) == 0 then "", "_No runs in this period: run `pmgr doctor` (or leave `pmgr ui` syncing) during the week to build history._" else empty end),
      (if ($fixed | length) > 0 then "", "## Fixed", "",
         ($fixed | group_by(.area)[] | "**\($titles[.[0].area] // .[0].area)**", (.[] | item), "") else empty end),
      (if ($urgent | length) > 0 then "", "## Needs attention", "", ($urgent | .[0:15][] | item),
         (if ($urgent | length) > 15 then "- and \($urgent | length - 15) more" else empty end) else empty end),
      (if ($new_open | length) > 0 then "", "## New this period, still open", "", ($new_open | .[0:10][] | item) else empty end),
      ([$last.findings[] | select(.savings_usd_month > 0)] | sort_by(-.savings_usd_month) | .[0:8]) as $top
      | (if ($top | length) > 0 then "", "## Savings", "", "| Where | What | $/month |", "|---|---|---:|",
          ($top[] | "| \(.resource) | \(.message[0:90] | gsub("\\|"; "/")) | \(.savings_usd_month | usd) |") else empty end),
      ([$last.metrics[]? | select(.kind == "eks_version")]) as $eks
      | (if ($eks | length) > 0 or ($wfs | length) > 0 then "", "## Status", "" else empty end),
      (if ($eks | length) > 0 then "| Cluster | Kubernetes | Support |", "|---|---|---|",
          ($eks[] | "| \(.cluster) | \(.version) | \(.status // "unknown" | ascii_downcase | gsub("_"; " "))\(if .standard_end then ", standard support ends \(.standard_end | . + "T00:00:00Z" | ymd)" else "" end) |"), "" else empty end),
      (if ($wfs | length) > 0 then
         ([$wfs[] | .runs] | add) as $runs | ([$wfs[] | .success_rate * .runs] | add) as $ok
         | "CI: \($ok / $runs * 100 | round)% of \($runs) workflow runs succeeded." else empty end),
      "", "_From pmgr (\(pl($window | length; "run"; "runs")) in this period)._"'
}
