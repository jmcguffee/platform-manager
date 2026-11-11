include "pipelines";
reduce (.[] | {k: wf_label, s: secs("run_started_at"; "updated_at")} | select(.s != null)) as $r
      ({}; .[$r.k] += ($r.s / 60))
