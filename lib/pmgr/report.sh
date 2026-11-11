# shellcheck shell=bash
# One report (JSON) and its renderings: terminal text, Markdown, and the HTML dashboard.
#
# Senses write to $PMGR_TMP: findings.jsonl (one finding per line), usage.jsonl
# ({repo, usage}), unseen.txt (one line per thing we couldn't read), and the
# clusters.json / accounts.json status files from access_sweep.

report_build() {
  local findings usage unseen
  findings=$(cat "$PMGR_TMP/findings.jsonl" 2>/dev/null | jq -cs . | sort_findings)
  findings=$(printf '%s' "$findings" | auth_collapse | sort_findings)
  usage=$(cat "$PMGR_TMP/usage.jsonl" 2>/dev/null | jq -cs 'map({(.repo): .usage}) | add // {}')
  unseen=$(jq -R . "$PMGR_TMP/unseen.txt" 2>/dev/null | jq -cs .)
  local sources metrics
  sources=$(cat "$PMGR_TMP/sources.jsonl" 2>/dev/null | jq -cs .)
  metrics=$(cat "$PMGR_TMP/metrics.jsonl" 2>/dev/null | jq -cs .)
  jq -n --argjson findings "$findings" --argjson usage "$usage" --argjson unseen "${unseen:-[]}" \
    --argjson sources "${sources:-[]}" --argjson metrics "${metrics:-[]}" \
    --argjson config "$PMGR_CONFIG_JSON" --arg pim "$(pim_url)" \
    --slurpfile clusters "$PMGR_TMP/clusters.json" --slurpfile accounts "$PMGR_TMP/accounts.json" '
    {
      generated_at: (now | todateiso8601),
      settings: {
        lookback_days: ($config.github.lookback_days // 14),
        utilization_days: ($config.utilization.lookback_days // 14),
        ci_usd_per_minute: ($config.cost.actions_usd_per_minute // 0.008),
        github_org: ($config.github.org // ""),
        pim_url: $pim,
        repos: [$config.github.repos // [] | .[] | {name, kind: (.kind // "other")}]
      },
      clusters: [$clusters[0][] | {name, context, current, aws: .auth.state, arn: .auth.arn,
                 kubernetes, expires_at: .auth.expires_at}],
      accounts: [$accounts[0][] | {name, profile: .aws_profile, aws: .auth.state, arn: .auth.arn,
                 account: .auth.account}],
      findings: $findings,
      usage_minutes: $usage,
      unseen: $unseen,
      metrics: $metrics,
      # Clusters and accounts first, from the access results, then what each sense recorded.
      sources: (
        [$clusters[0][] | {type: "cluster", name, ok: (.kubernetes == "ok"),
           detail: ({ok: "Reachable", gone: .detail, not_active: .detail, skipped: "Not checked: the AWS session for \(.aws_profile) is \(.auth.state | gsub("_"; " "))"}[.kubernetes]
                    // "Kubernetes: \(.kubernetes | gsub("_"; " ")). \(.detail)"),
           fix: "", context}]
        + [($clusters[0][], $accounts[0][]) | select(.auth.state != "ok" and .auth.state != "expiring") | {type: "account", name: .aws_profile,
           ok: false, detail: "AWS session is \(.auth.state | gsub("_"; " ")): \(.auth.detail)", fix: "Run pmgr login \(.name)"}]
        | unique_by([.type, .name])) + $sources
    }'
}

# report_exit REPORT : 1 when anything is error or critical, else 0.
report_exit() {
  jq -e '[.findings[] | select(.severity == "error" or .severity == "critical")] | length == 0' <<<"$1" >/dev/null
}

report_text() {
  local color=0 all=${2:-0}
  [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && color=1
  jq -r --argjson color "$color" --argjson all "$all" '
    def c($code; $s): if $color == 1 then "\u001b[\($code)m\($s)\u001b[0m" else $s end;
    def pad($n): . + (" " * ([$n - length, 0] | max));
    def session: if .aws == "ok" then "ok" else (.aws | gsub("_"; " ")) end;
    {critical: "35", error: "31", warning: "33", info: "36"} as $colors
    | {critical: "CRIT", error: "ERR ", warning: "WARN", info: "INFO"} as $labels
    | {auth: "Access", cluster: "Clusters", workload: "Workloads", utilization: "Utilization", argo: "Argo CD", pipeline: "Pipelines", workflow: "Workflow gaps"} as $titles
    | ([.clusters[] | [(if .current then "*" else "" end), .name, session,
          (if .kubernetes == "skipped" then "-" else (.kubernetes | gsub("_"; " ")) end), .context]]
       + [.accounts[] | ["", .name, session, "-", "(account \(if .account == "" then .profile else .account end))"]]) as $rows
    | (if $all == 1 then .findings else [.findings[] | select(.severity != "info")] end) as $shown
    | ((.findings | length) - ($shown | length)) as $hidden
    | (if ($rows | length) > 0 then
        ([["", "NAME", "AWS SESSION", "KUBERNETES", "CONTEXT"]] + $rows) as $t
        | [range(0; 5) as $i | [$t[][$i] | length] | max] as $w
        | ($t[] | [range(0; 5) as $i | .[$i] | pad($w[$i])] | join("  ") | sub(" +$"; "")), ""
       else empty end),
      (if ($shown | length) == 0 then c("32"; if $hidden > 0 then "No warnings or errors." else "No problems found." end)
       else empty end),
      ($shown | group_by(.area) | sort_by(.[0].area as $a | ["auth","cluster","workload","utilization","argo","pipeline","workflow"] | index($a))[]
        | c("1"; $titles[.[0].area] // .[0].area),
          (.[] | "  \(c($colors[.severity]; $labels[.severity])) \(.resource): \(.message)",
                 (if .fix != "" then "       fix: \(.fix)" else empty end),
                 (if .link != "" then "       \(c("4"; .link))" else empty end))),
      (if (.usage_minutes | length) > 0 then
         c("1"; "\nWhere CI time goes (approximate minutes)"),
         (.usage_minutes | to_entries[] | select(.value | length > 0) | "  \(.key): " + ([.value | to_entries | sort_by(-.value)[:3][]
           | "\(.key) \(.value | round)"] | join(", ")))
       else empty end),
      (if $hidden > 0 then c("2"; "\n\($hidden) info-level finding(s) hidden. Use --all to show them.") else empty end),
      (if (.unseen | length) > 0 then c("2"; "\nCouldn'"'"'t read (no findings reported for these): " + (.unseen | join("; ")))
       else empty end)
  ' <<<"$1"
}

report_md() {
  jq -r '
    {auth: "Access", cluster: "Clusters", workload: "Workloads", utilization: "Utilization", argo: "Argo CD", pipeline: "Pipelines", workflow: "Workflow gaps"} as $titles
    | (.findings | group_by(.severity) | map({(.[0].severity): length}) | add // {}) as $n
    | "# Platform report, \(.generated_at | fromdateiso8601 | strftime("%B %-d, %Y %H:%M")) UTC", "",
      ([["critical","error","warning","info"][] as $s | "**\($n[$s] // 0)** \($s)"] | join(", ")),
      (if ((.clusters | length) + (.accounts | length)) > 0 then
        "", "## Access", "", "| | Name | AWS session | Kubernetes |", "|---|---|---|---|",
        (.clusters[] | "| \(if .current then "*" else "" end) | \(.name) | \(.aws | gsub("_"; " ")) | \(.kubernetes | gsub("_"; " ")) |"),
        (.accounts[] | "| | \(.name) | \(.aws | gsub("_"; " ")) | - |")
       else empty end),
      (.findings | group_by(.area) | sort_by(.[0].area as $a | ["auth","cluster","workload","utilization","argo","pipeline","workflow"] | index($a))[]
        | "", "## \($titles[.[0].area] // .[0].area)", "",
          (.[] | "- **\(.severity)** `\(.resource)`: \(.message)"
                 + (if .fix != "" then "  \n  Fix: \(.fix)" else "" end)
                 + (if .link != "" then "  \n  \(.link)" else "" end))),
      (if (.usage_minutes | length) > 0 then
        "", "## Where CI time goes", "", "| Repo | Workflow | Minutes |", "|---|---|---|",
        (.usage_minutes | to_entries[] | .key as $r | .value | to_entries | sort_by(-.value)[:5][]
          | "| \($r) | \(.key) | \(.value | round) |")
       else empty end),
      (if (.unseen | length) > 0 then "", "## Not checked", "", (.unseen[] | "- \(.)") else empty end)
  ' <<<"$1"
}

# report_html REPORT [live] : the dashboard as one self-contained file with the report embedded.
# "live" is for `pmgr ui`'s server: the page may then call back to it (and only it) to sync.
report_html() {
  local ui="$PMGR_ROOT/share/pmgr/ui" data="$PMGR_TMP/report-embed.json" live=0
  [ "${2:-}" = live ] && live=1
  # Keep the JSON from closing the <script> element it sits in.
  jq -c . <<<"$1" | sed 's#</#<\\/#g' >"$data"
  awk -v css="$ui/app.css" -v js="$ui/app.js" -v data="$data" -v live="$live" \
    -v csp_from="default-src 'none';" -v csp_to="default-src 'none'; connect-src 'self';" '
    /<link rel="stylesheet" href="app.css">/ {
      print "<style>"; while ((getline line < css) > 0) print line; print "</style>"; next
    }
    /Content-Security-Policy/ && live == 1 { sub(csp_from, csp_to) }
    /<script src="app.js" defer><\/script>/ {
      if (live == 1) print "<script id=\"pmgr-live\" type=\"application/json\">true</script>"
      printf "<script id=\"pmgr-data\" type=\"application/json\">"
      while ((getline line < data) > 0) print line
      print "</script>"
      print "<script>"; while ((getline line < js) > 0) print line; print "</script>"; next
    }
    { print }' "$ui/index.html"
}
