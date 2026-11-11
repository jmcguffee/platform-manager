# On-call state from Datadog: open pages, active incidents, alerting monitors.
#
# Input: {pages, incidents, monitors} as Pup JSON envelopes (or null when not read).
# Args: $app (Datadog app base URL), $now (epoch seconds, "" = now).
#
# Built from Datadog's documented API shapes, read defensively: objects are found wherever they
# sit in the payload, and fields fall back across the names Datadog has used.

def now_s: if $now == "" then now else ($now | tonumber) end;
def ts: if . == null then null
  elif type == "number" then (if . > 1e11 then . / 1000 else . end)
  else (tostring | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601? // null) end;
def age: (ts) as $t | if $t == null then null else ((now_s - $t) / 60 | floor) end;
def since: if . == null then "" elif . < 60 then "\(.) min" elif . < 2880 then "\(. / 60 | floor)h" else "\(. / 1440 | floor)d" end;
def low: (. // "") | tostring | ascii_downcase;
def payload: (. // {}) | (.data // .);
def objs($want): [.. | objects | select(((.type? // "") == $want) and ((.attributes? | type) == "object"))];
def base($what): {area: "oncall", resource: $what, link: "", evidence: {}};

. as $in

# --- pages ---------------------------------------------------------------------------------
| [ $in.pages | payload | objs("pages")[] | .attributes as $a
    | {id, title: ($a.title // $a.summary // "Untitled page"),
       status: ($a.status // $a.state // "" | low),
       urgency: ($a.urgency // $a.priority // "" | low),
       team: ($a.team_handle // $a.team // ""),
       opened_min: (($a.created_at // $a.created // $a.triggered_at) | age),
       url: ($a.url // $a.page_url // "\($app)/on-call")} ] as $pages

# --- incidents -------------------------------------------------------------------------------
| [ $in.incidents | payload | objs("incidents")[] | .attributes as $a
    | {id, number: ($a.public_id // null), title: ($a.title // "Untitled incident"),
       severity: ($a.severity // $a.fields.severity.value // "UNKNOWN" | tostring),
       state: ($a.state // $a.fields.state.value // "" | low),
       customer_impacted: ($a.customer_impacted // false),
       opened_min: (($a.created // $a.created_at) | age),
       url: (if $a.public_id then "\($app)/incidents/\($a.public_id)" else "\($app)/incidents" end)} ] as $incidents

# --- monitors (search returns {monitors: [...]}) -----------------------------------------------
| [ $in.monitors | payload | (.monitors? // (if type == "array" then . else [] end))[] | objects
    | {id, name: (.name // "Unnamed monitor"), status: (.status // .overall_state // "" | low),
       type: (.type // ""), priority: (.priority // null), tags: (.tags // []),
       triggered_min: ((.last_triggered_ts // .overall_state_modified) | age),
       url: "\($app)/monitors/\(.id)"} ] as $monitors

| (
  # Metric rows for the On-call tables.
  ($pages[] | {kind: "page"} + .),
  ($incidents[] | {kind: "incident"} + .),
  ($monitors[] | select(.status | IN("alert", "warn", "no data")) | {kind: "monitor"} + .),

  ( $pages[] | select(.status | IN("resolved", "acknowledged", "closed") | not)
    | base("page/\(.id)") + {check: "oncall.page_open", severity: "error", link: .url,
        message: "Unacknowledged \(if .urgency != "" then "\(.urgency)-urgency " else "" end)page: \(.title)"
          + (if .opened_min then " (open \(.opened_min | since))" else "" end) + (if .team != "" then ", team \(.team)" else "" end),
        fix: "Acknowledge it in Datadog On-Call so the escalation stops, then work it."} ),
  ( $pages[] | select(.status == "acknowledged")
    | base("page/\(.id)") + {check: "oncall.page_acknowledged", severity: "warning", link: .url,
        message: "Acknowledged page still open: \(.title)" + (if .opened_min then " (open \(.opened_min | since))" else "" end),
        fix: "Resolve it when the issue is fixed, or hand it off if you're stepping away."} ),

  ( $incidents[] | select(.state | IN("active", "stable"))
    | base("incident/\(.number // .id)") + {check: "oncall.incident_\(.state)",
        severity: (if .state == "active" and (.severity | test("SEV-?[12]"; "i")) then "error"
                   elif .state == "active" then "warning" else "info" end),
        link: .url,
        message: "\(.severity) incident\(if .number then " #\(.number)" else "" end) is \(.state): \(.title)"
          + (if .opened_min then " (since \(.opened_min | since) ago)" else "" end)
          + (if .customer_impacted then ", customers affected" else "" end),
        fix: (if .state == "active" then "Check the incident channel and timeline in Datadog; make sure it has a commander."
              else "It's stable: confirm the fix and resolve it, or keep monitoring." end)} ),

  ( $monitors[] | select(.status == "alert")
    | base("monitor/\(.id)") + {check: "oncall.monitor_alert", severity: "error", link: .url,
        message: "Monitor alerting: \(.name)" + (if .triggered_min then " (since \(.triggered_min | since) ago)" else "" end)
          + (if .priority then ", P\(.priority)" else "" end),
        fix: "Open the monitor to see which group is alerting and its runbook link."} ),
  ( $monitors[] | select(.status == "warn")
    | base("monitor/\(.id)") + {check: "oncall.monitor_warn", severity: "warning", link: .url,
        message: "Monitor warning: \(.name)", fix: "Check it before it crosses into alert."} ),
  ( $monitors[] | select(.status == "no data")
    | base("monitor/\(.id)") + {check: "oncall.monitor_no_data", severity: "info", link: .url,
        message: "Monitor has no data: \(.name)",
        fix: "The metric stopped arriving: check the agent or integration that sends it, or mute the monitor if the service is gone."} )
)
