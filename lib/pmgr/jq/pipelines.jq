def ts: if . == null then null else (sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601) end;
def secs($a; $b): (.[$a] | ts) as $x | (.[$b] | ts) as $y
  | if $x == null or $y == null or $y < $x then null else $y - $x end;
def pct($q): sort as $v | if ($v | length) == 0 then null
  else $v[([($q * (($v | length) - 1)) | round, ($v | length) - 1] | min)] end;
def mins: if . == null then "n/a" else "\(. / 60 | round) min" end;
def wf_label: (.path // "") as $p
  | if ($p | startswith("dynamic/")) then ($p | split("/")[1] | gsub("-"; " ") | (.[0:1] | ascii_upcase) + .[1:])
    else (.name // $p) end;
def failed: .conclusion | IN("failure", "timed_out", "startup_failure");
def counted: .status == "completed"
  and (.conclusion | IN("cancelled", "skipped", "neutral", "action_required", "stale", null) | not);
def by_workflow: group_by(.path // .name) | map(sort_by(.created_at) | reverse);
def broken($branch): [.[] | select(counted and .head_branch == $branch)] as $done
  | if ($done | length) == 0 or ($done[0] | failed | not) then null
    else {latest: $done[0], streak: ([$done[] | failed] | index(false) // length),
          last_success: ([$done[] | select(.conclusion == "success")] | first)} end;
