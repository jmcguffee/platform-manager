include "workflows";
{area: "workflow", resource: $repo, link: "", evidence: {}} as $base
    | [.[] | select(triggers | (index("pull_request") or index("merge_group")))] as $pr
    | ([$pr[] | runs] + [$pr[] | uses[].u] | join("\n")) as $pr_text
    | ([$pr[] | uses[].u | select(contains("/.github/workflows/"))] | length > 0) as $delegates
    | (if $count == 0 then $base + {check: "workflow.none", severity: "warning",
         message: "No GitHub Actions workflows", fix: "Add at least a pull request check."}
       elif ($pr | length) == 0 then $base + {check: "workflow.no_pr_checks", severity: "warning",
         message: "No workflow runs on pull requests, so nothing checks a change before merge",
         fix: "Add a `pull_request` workflow for the checks below."}
       else empty end),
      (if $kind == "terraform" and $count > 0 and ($delegates | not) then
         (if ($pr_text | tf_plan) then empty else $base + {check: "workflow.no_plan_on_pr", severity: "warning",
            message: "No `terraform plan` on pull requests, so reviewers approve changes without seeing the plan",
            fix: "Run `terraform plan` on `pull_request` and post it as a comment or job summary."} end),
         (if ($pr_text | test("\\bterraform\\s+(fmt\\s+-check|validate)\\b")) then empty
          else $base + {check: "workflow.no_tf_validate", severity: "info",
            message: "No `terraform fmt -check` or `terraform validate` on pull requests",
            fix: "Both are fast and catch errors before plan."} end)
       else empty end),
      (if $kind == "gitops" and $count > 0 and ($delegates | not)
          and ($pr_text | test("\\bkustomize\\s+build\\b|\\bkubectl\\s+kustomize\\b|\\bkubeconform\\b|\\bkubeval\\b|tgb-check") | not)
       then $base + {check: "workflow.no_manifest_check", severity: "warning",
         message: "Pull requests don't render or validate manifests, so a broken overlay is found by Argo",
         fix: "Run `kustomize build` on every overlay in CI. contrib/tgb-check also checks TargetGroupBindings against their Services and target groups."}
       else empty end)
