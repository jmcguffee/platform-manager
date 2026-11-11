def ts: sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601;
    (if $now == "" then now else ($now | tonumber) end) as $t
    | (.items // [])[] | .metadata as $m | (.spec // {}) as $spec | (.status // {}) as $st
    | ($m.name // "?") as $name
    | {area: "argo", resource: "\($cluster)/\($m.namespace // "argocd")/\($name)", link: "", evidence: {}} as $base
    | ($st.sync.status // "") as $sync | ($st.health.status // "") as $health
    | ($st.operationState // {}) as $op
    # `automated: {}` means auto-sync with defaults, so presence counts, not truthiness.
    | (($spec.syncPolicy // {}) | has("automated") and (.automated != null) and (.automated.enabled? != false)) as $auto
    | (($st.sync.revision // "")[0:8]) as $rev
    | ( ($st.conditions // [])[] | select(.type | IN("ComparisonError", "InvalidSpecError", "SyncError", "UnknownError"))
          | $base + {check: "argo.condition", severity: "error",
              message: "\($name): \(.type): \((.message // "")[0:400])",
              fix: "A ComparisonError usually means the manifests don't render. Run `kustomize build` on this app's overlay at the target revision.",
              evidence: {condition: .}} ),
      ( if ($op.phase // "") | IN("Failed", "Error") then
          $base + {check: "argo.sync_failed", severity: "error",
            message: "\($name): last sync \($op.phase | ascii_downcase): \(($op.message // "")[0:400])",
            fix: "The failing resource is named in the message. Check it with `kubectl describe`."}
        elif ($op.phase // "") == "Running" and $op.startedAt != null and (($t - ($op.startedAt | ts)) / 60) >= 15 then
          $base + {check: "argo.stuck", severity: "warning",
            message: "\($name): sync has been running for \((($t - ($op.startedAt | ts)) / 60) | floor) min",
            fix: "Usually a hook Job that never finishes, or a resource waiting on a finalizer. Look at the app's resource tree for what is still Progressing."}
        else empty end ),
      ( if $health | IN("Degraded", "Missing") then
          [($st.resources // [])[] | select(.health.status? | IN("Degraded", "Missing"))
            | "\(.kind)/\(.name)" + (if (.health.message // "") != "" then " (\(.health.message[0:120]))" else "" end)] as $bad
          | $base + {check: "argo.\($health | ascii_downcase)", severity: "error",
              message: "\($name) is \($health)" + (if ($bad | length) > 0 then ": \($bad[:5] | join("; "))" else "" end),
              fix: "Check pod events and logs for the resources listed.", evidence: {resources: $bad}}
        else empty end ),
      ( if $sync == "OutOfSync" and (($op.phase // "") | IN("Failed", "Error", "Running") | not) then
          $base + {check: "argo.out_of_sync", severity: (if $auto then "warning" else "info" end),
            message: "\($name) is OutOfSync" + (if $rev != "" then " at \($rev)" else "" end)
              + (if $auto then " even though auto-sync is on" else " (manual sync)" end),
            fix: (if $auto then "With auto-sync on, something keeps it from converging: an ignored diff, a mutating webhook, or a field another controller owns. Compare in the Argo diff view."
                  else "Changes are waiting for a manual sync." end)}
        else empty end )
