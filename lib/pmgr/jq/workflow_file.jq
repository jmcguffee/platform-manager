include "workflows";
. as $wf | triggers as $on | jobs as $jobs | runs as $body
    | {area: "workflow", resource: $where, link: "", evidence: {}} as $base
    | ([uses[].u | select(contains("@") and (startswith("./") or startswith("docker://") | not)
         and (startswith("actions/") or startswith("github/") | not) and (test("@[0-9a-f]{40}$") | not))] | unique) as $unpinned
    | ($unpinned | if length > 0 then $base + {check: "workflow.unpinned", severity: "warning",
        message: "Third-party actions pinned to a movable tag: \(join(", "))",
        fix: "Pin each to a full commit SHA (keep the tag in a comment) and let Dependabot or Renovate bump them. A retagged action runs with this workflow's secrets.",
        evidence: {actions: .}} else empty end),
      (if ($wf | has("permissions")) or (($jobs | length) > 0 and ([$jobs[] | has("permissions")] | all)) then empty
       else $base + {check: "workflow.permissions", severity: "warning",
        message: "No `permissions:` block, so GITHUB_TOKEN gets the repository default (possibly write-all)",
        fix: "Add `permissions: contents: read` at the top and grant more per job only where needed."} end),
      (if ($text | contains("aws-access-key-id")) or ($text | test("secrets\\.AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)"))
       then $base + {check: "workflow.static_aws_keys", severity: "warning",
        message: "Uses long-lived AWS access keys from secrets",
        fix: "Switch to GitHub OIDC with `aws-actions/configure-aws-credentials` and `role-to-assume`, then delete the keys."}
       else empty end),
      (if ($on | index("pull_request_target")) and ($text | test("ref:\\s*\\$\\{\\{\\s*github\\.event\\.pull_request\\.head"))
       then $base + {check: "workflow.prt_checkout", severity: "critical",
        message: "`pull_request_target` checks out the pull request's code, which runs untrusted code with secrets",
        fix: "Use `pull_request` instead, or never execute the checked-out head in this workflow."} else empty end),
      ([$jobs[] | steps[] | (.run // "") | tostring | [match(injectable; "g").string] | .[]] | unique
        | if length > 0 then $base + {check: "workflow.script_injection", severity: "error",
            message: "User-controlled values are expanded straight into shell: \(join(", "))",
            fix: "Pass them through `env:` and reference the variable (\"$TITLE\") instead.",
            evidence: {expressions: .}} else empty end),
      (if ($body | tf_apply) and (($on | index("pull_request")) or ($on | index("pull_request_target"))) and ($on | index("push") | not)
       then $base + {check: "workflow.apply_on_pr", severity: "error",
        message: "Runs `terraform apply` on pull requests, before review and merge",
        fix: "Plan on pull requests, apply on push to the default branch (or with an environment approval)."} else empty end),
      (if ($body | deploys) and ($wf | has("concurrency") | not) and ([$jobs[] | has("concurrency")] | any | not)
       then $base + {check: "workflow.no_concurrency", severity: "warning",
        message: "Deploys or applies with no `concurrency:` group, so two runs can overlap",
        fix: "Add `concurrency: {group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: false}`."}
       else empty end),
      ([$jobs | to_entries[] | select((.value | type) == "object" and (.value | has("uses") | not)
          and (.value | has("timeout-minutes") | not)) | .key] | sort
        | if length > 0 then $base + {check: "workflow.no_timeout", severity: "info",
            message: "Jobs without `timeout-minutes` (a hung job runs for 6 hours): \(join(", "))",
            fix: "Set `timeout-minutes` a little above each job's normal duration.", evidence: {jobs: .}}
          else empty end),
      ([$jobs | to_entries[] | select((.value | type) == "object" and (.value["continue-on-error"] == true
          or ([.value | steps[] | .["continue-on-error"] == true] | any))) | .key] | sort
        | if length > 0 then $base + {check: "workflow.continue_on_error", severity: "info",
            message: "`continue-on-error: true` hides failures in: \(join(", "))",
            fix: "Remove it, or make sure something reports the failure."} else empty end),
      ([uses[] | (.u | split("@")[0]) as $a
          | select(($a | IN("actions/setup-node", "actions/setup-python", "actions/setup-java")) and (.w | has("cache") | not))
          | $a] | unique
        | if length > 0 then $base + {check: "workflow.no_cache", severity: "info",
            message: "Dependency caching is off for: \(join(", "))",
            fix: "Set `cache:` on the setup action (for example `cache: pip` or `cache: npm`)."} else empty end)
