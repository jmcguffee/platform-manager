include "pipelines";
by_workflow[] | . as $rows | ($rows[0] | wf_label) as $name
    | {area: "pipeline", resource: "\($repo):\($rows[0].path // $name)", link: "", evidence: {}} as $base
    | broken($branch) as $b
    | [$rows[] | select(counted and .head_branch == $branch)] as $main
    | [$rows[] | select(.status == "completed")] as $done
    | (
        (if $b != null then
          ($why[($b.latest.id | tostring)] // []) as $ex | ($ex[0] // {}) as $first
          | ($first.diagnosis // {}) as $d
          | $base + {check: "pipeline.broken", severity: "error", link: ($b.latest.html_url // ""),
              message: ("'\($name)' is failing on \($branch): \($b.streak) failed run(s) in a row (last pass: "
                + (if $b.last_success then $b.last_success.created_at[0:10] else "over \($days) days" end) + ")"
                + (if ($first.step // "") != "" then ". Fails at '\($first.job) › \($first.step)'" else "" end)
                + (if ($first.error // "") != "" then ": \($first.error)" else "" end)),
              fix: (if $b.latest.conclusion == "startup_failure" and ($d | length) == 0 then
                      "The run never started. That's either an error in the workflow file (GitHub shows it on the run page) or a GitHub outage: check githubstatus.com, then re-run it."
                    else ([$d.cause, $d.fix] | map(select(. != null and . != "")) | join(" ")) end),
              evidence: {streak: $b.streak, failures: $ex}}
        else empty end),
        (if $b == null and ($main | length) >= 6 then
          ([$main[] | select(failed)] | length) as $f | ($f / ($main | length)) as $rate
          | if $rate >= 0.15 then $base + {check: "pipeline.unreliable",
              severity: (if $rate >= 0.30 then "warning" else "info" end),
              message: "'\($name)' failed \($f) of \($main | length) runs on \($branch) in the last \($days) days (\($rate * 100 | round)%)",
              fix: "Open the failed runs to see whether one step or cause dominates.",
              evidence: {failed: $f, runs: ($main | length), rate: $rate}}
            else empty end
        else empty end),
        ([$done[] | select((.run_attempt // 1) > 1 and .conclusion == "success")] as $re
          | if ($re | length) >= 3 and (($re | length) / ([$done | length, 1] | max)) >= 0.10 then
              $base + {check: "pipeline.flaky", severity: "warning",
                message: "'\($name)' passed only after a rerun \($re | length) times in \($done | length) runs",
                fix: "Reruns that pass point to flaky tests or a dependency that times out. Find the job that fails on attempt 1.",
                evidence: {reruns: ($re | length), runs: ($done | length)}}
            else empty end),
        ([$done[] | secs("created_at"; "run_started_at") | select(. != null)] as $q
          | ($q | pct(0.95)) as $q95
          | if ($q | length) >= 6 and $q95 != null and $q95 >= 300 then
              $base + {check: "pipeline.queued", severity: "warning",
                message: "'\($name)' waits up to \($q95 | mins) for a runner (p95 queue time)",
                fix: "Runners are short. Check self-hosted runner scaling, or the org's concurrency limit.",
                evidence: {queue_p95_s: $q95}}
            else empty end),
        ([$done[] | select(.conclusion == "success") | secs("run_started_at"; "updated_at") | select(. != null)] as $d
          | ($d | pct(0.5)) as $p50
          | if ($d | length) >= 6 and $p50 != null and $p50 >= 1200 then
              $base + {check: "pipeline.slow", severity: "info",
                message: "'\($name)' typically takes \($p50 | mins) (p95 \($d | pct(0.95) | mins))",
                fix: "Look for missing dependency caching, work that could run in parallel jobs, or steps that could be skipped with `paths:` filters.",
                evidence: {p50_s: $p50, p95_s: ($d | pct(0.95))}}
            else empty end)
      )
