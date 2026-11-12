# shellcheck shell=bash
# History: every report is kept (the last HISTORY_KEEP, private to you), so each new one can say
# what changed since the last comparable run: what's new, what got fixed, and what couldn't be
# checked this time. A finding that vanished because its account or cluster wasn't readable is
# "not checked", never "fixed".

HISTORY_KEEP=90

history_dir() { printf '%s' "${XDG_CACHE_HOME:-$HOME/.cache}/platform-manager/history"; }

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
