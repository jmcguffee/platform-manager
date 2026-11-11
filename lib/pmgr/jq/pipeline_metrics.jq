include "pipelines";

# One row per workflow: what a platform person wants to scan. Args: $repo, $branch.
# "minutes" is run wall-clock time, a close proxy for billed minutes when jobs don't run in parallel.
by_workflow[] | . as $rows | ($rows[0] | wf_label) as $name
| [$rows[] | select(.status == "completed")] as $done
| [$done[] | select(counted)] as $counted
| [$counted[] | select(.head_branch == $branch)] as $main
| def rate($xs): if ($xs | length) > 0 then ([$xs[] | select(.conclusion == "success")] | length) / ($xs | length) else null end;
  [$done[] | select(.conclusion == "success") | secs("run_started_at"; "updated_at") | select(. != null)] as $durations
| {kind: "workflow", repo: $repo, workflow: $name, path: ($rows[0].path // ""), default_branch: $branch,
   runs: ($rows | length),
   success_rate: rate($counted), main_success_rate: rate($main),
   failures: ([$counted[] | select(failed)] | length),
   reruns: ([$done[] | select((.run_attempt // 1) > 1)] | length),
   duration_p50_s: ($durations | pct(0.5)), duration_p95_s: ($durations | pct(0.95)),
   queue_p95_s: ([$done[] | secs("created_at"; "run_started_at") | select(. != null)] | pct(0.95)),
   minutes: (([$rows[] | secs("run_started_at"; "updated_at") | select(. != null)] | add // 0) / 60),
   broken: (broken($branch) != null),
   last: ($rows[0] | {status, conclusion, at: .created_at, url: .html_url, branch: .head_branch, event}),
   last_failure: ([$rows[] | select(failed)] | first | if . == null then null
                  else {at: .created_at, url: .html_url, branch: .head_branch} end)}
