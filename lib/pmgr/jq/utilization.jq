# Over- and under-utilization for one account's RDS, Redshift, ElastiCache and MSK resources.
#
# Input: {resources: {rds, redshift, cache, msk}, queries: [from utilization_queries.jq],
#         results: [MetricDataResults], days, t: thresholds, label: account label}
#
# Underuse is a suggestion (idle is a warning). Saturation is a warning, or an error when it's
# about to fail. Underuse claims need a day of data; a new resource isn't "oversized".

def avg: if length == 0 then null else add / length end;
def p95: sort as $v | if length == 0 then null else $v[((0.95 * (length - 1)) | round)] end;
def r1: if . == null then null else (. * 10 | round) / 10 end;
def pct: "\(r1)%";

# One size down for an instance class like db.r6g.2xlarge or cache.m7g.large.
def sizes: ["nano", "micro", "small", "medium", "large", "xlarge", "2xlarge", "4xlarge", "8xlarge",
            "12xlarge", "16xlarge", "24xlarge", "32xlarge", "48xlarge"];
def burstable: (split(".")[1] // "") | startswith("t");
# Burstable classes go down to micro; others stop at large, the smallest size most families have.
def size_down: (split(".")) as $p | ($p | last) as $s | (sizes | index($s)) as $i
  | (if burstable then 1 else 4 end) as $floor
  | if $i == null or $i <= $floor then null else ($p[:-1] + [sizes[$i - 1]] | join(".")) end;
# Worth saying only when there's somewhere smaller to go.
def can_shrink: (size_down != null) or (burstable | not);

. as $in
| $in.t as $t
| ($in.results | map({key: .Id, value: {ts: (.Timestamps // []), v: (.Values // [])}}) | from_entries) as $byid
| ($in.queries | map({key: "\(.service)|\(.resource)|\(.broker // "")|\(.metric)|\(.stat)", value: ($byid[.id] // {ts: [], v: []})})
   | from_entries) as $s
| def vals($svc; $res; $metric; $stat): ($s["\($svc)|\($res)||\($metric)|\($stat)"] // {v: []}).v;
  def base($svc; $res): {area: "utilization", resource: "\($in.label)/\($svc)/\($res)", link: "", evidence: {}};
  def enough($v): ($v | length) >= 24;
  def window: "\($in.days) days";

(
  # --- RDS -----------------------------------------------------------------------------------
  ( $in.resources.rds.DBInstances // [] | .[] | . as $db | .DBInstanceIdentifier as $id
    | (.DBInstanceClass == "db.serverless") as $sls
    | (if $sls then "ACUUtilization" else "CPUUtilization" end) as $m
    | vals("rds"; $id; $m; "Average") as $cpu | vals("rds"; $id; $m; "Maximum") as $cpu_max
    | vals("rds"; $id; "DatabaseConnections"; "Maximum") as $conns
    | base("rds"; "\($id) (\($db.DBInstanceClass))") as $b
    | ( if enough($conns) and ($conns | max) == 0 then
          $b + {check: "rds.idle", severity: "warning",
            message: "No connections to \($id) in \(window)",
            fix: "If nothing needs it, take a final snapshot and delete it. Stopping it only lasts 7 days before RDS starts it again.",
            evidence: {connections_max: 0}}
        elif enough($cpu) and ($cpu | avg) < $t.cpu_low and ($cpu_max | p95) < $t.cpu_low_peak
             and ($sls or ($db.DBInstanceClass | can_shrink)) then
          ($db.DBInstanceClass | size_down) as $down
          | $b + {check: (if $sls then "rds.acu_low" else "rds.oversized" end), severity: "info",
            message: "\($id) averages \($cpu | avg | pct) \(if $sls then "of its max ACUs" else "CPU" end) and peaks around \($cpu_max | p95 | pct) over \(window)",
            fix: (if $sls then "Lower the minimum ACU so it can scale down when it's quiet."
                  elif $down then "Try one size down, \($down). Check FreeableMemory first: memory, not CPU, is often why a database is this size."
                  else "It's already small for its class. For low, spiky load, a burstable db.t4g class costs less." end),
            evidence: {cpu_avg: ($cpu | avg | r1), cpu_peak_p95: ($cpu_max | p95 | r1)}}
        else empty end ),
      ( if ($cpu | p95) != null and ($cpu | p95) > $t.cpu_high then
          $b + {check: (if $sls then "rds.acu_high" else "rds.cpu_high" end), severity: "warning",
            message: "\($id) runs hot: \($m) p95 is \($cpu | p95 | pct) (peak \($cpu_max | max | pct)) over \(window)",
            fix: (if $sls then "Raise the maximum ACU, or find the heavy queries in Performance Insights."
                  else "Find the heavy queries in Performance Insights, send reads to a replica, or move up a size." end),
            evidence: {cpu_p95: ($cpu | p95 | r1), cpu_max: ($cpu_max | max | r1)}}
        else empty end ),
      ( vals("rds"; $id; "FreeStorageSpace"; "Minimum") as $free
        | select(($free | length) > 0 and ($db.AllocatedStorage // 0) > 0)
        | (($free | min) / ($db.AllocatedStorage * 1073741824) * 100) as $pfree
        | select($pfree < $t.storage_low)
        | ($db.MaxAllocatedStorage != null and $db.MaxAllocatedStorage > $db.AllocatedStorage) as $auto
        | $b + {check: "rds.storage_low",
            severity: (if $auto then "info" elif $pfree < 5 then "error" else "warning" end),
            message: "\($id) is down to \($pfree | pct) free storage of \($db.AllocatedStorage) GiB",
            fix: (if $auto then "Storage autoscaling is on (up to \($db.MaxAllocatedStorage) GiB), so it will grow. Check the growth is expected."
                  else "Turn on storage autoscaling (set a maximum storage size) or increase allocated storage before it fills." end),
            evidence: {free_pct: ($pfree | r1)}} ),
      ( vals("rds"; $id; "CPUCreditBalance"; "Minimum") as $credits
        | select(($credits | length) > 0 and ($credits | min) < 10)
        | $b + {check: "rds.cpu_credits", severity: "warning",
            message: "\($id) ran out of CPU credits (low of \($credits | min | r1)), so it gets throttled",
            fix: "It needs more CPU than a burstable class gives. Move to a db.m class, or turn on unlimited credits."} ),
      ( vals("rds"; $id; "FreeableMemory"; "Minimum") as $mem
        | select(($mem | length) > 0 and ($mem | min) < 268435456)
        | $b + {check: "rds.memory_low", severity: "warning",
            message: "\($id) dropped to \(($mem | min) / 1048576 | round) MiB of free memory, close to swapping",
            fix: "Move to a class with more memory, or lower memory-hungry settings (for example work_mem or shared_buffers)."} )
  ),

  # --- Redshift ------------------------------------------------------------------------------
  ( $in.resources.redshift.Clusters // [] | .[] | . as $c | .ClusterIdentifier as $id
    | vals("redshift"; $id; "CPUUtilization"; "Average") as $cpu | vals("redshift"; $id; "CPUUtilization"; "Maximum") as $cpu_max
    | vals("redshift"; $id; "PercentageDiskSpaceUsed"; "Maximum") as $disk
    | vals("redshift"; $id; "DatabaseConnections"; "Maximum") as $conns
    | base("redshift"; "\($id) (\($c.NumberOfNodes) × \($c.NodeType))") as $b
    | ( if enough($conns) and ($conns | max) == 0 then
          $b + {check: "redshift.idle", severity: "warning", message: "No connections to \($id) in \(window)",
            fix: "Pause it (you stop paying for compute) or, if it's unused, snapshot and delete it."}
        elif enough($cpu) and ($cpu | avg) < $t.cpu_low and ($cpu_max | p95) < $t.cpu_low_peak then
          $b + {check: "redshift.oversized", severity: "info",
            message: "\($id) averages \($cpu | avg | pct) CPU and peaks around \($cpu_max | p95 | pct) over \(window)",
            fix: "Use elastic resize to drop nodes (check disk use first), or schedule pause and resume outside working hours."}
        else empty end ),
      ( if ($cpu | p95) != null and ($cpu | p95) > $t.cpu_high then
          $b + {check: "redshift.cpu_high", severity: "warning",
            message: "\($id) runs hot: CPU p95 is \($cpu | p95 | pct) over \(window)",
            fix: "Check WLM queues and long-running queries, turn on concurrency scaling, or add nodes."}
        else empty end ),
      ( select(($disk | length) > 0 and ($disk | max) > $t.disk_high)
        | $b + {check: "redshift.disk_high", severity: (if ($disk | max) > 90 then "error" else "warning" end),
            message: "\($id) disk reached \($disk | max | pct) used",
            fix: "Vacuum and drop unused tables, or resize. RA3 nodes keep data in managed storage, which removes the limit."} )
  ),

  # --- ElastiCache (nodes of one replication group are one finding, judged by the busiest node) ---
  ( $in.resources.cache.CacheClusters // [] | group_by(.ReplicationGroupId // .CacheClusterId)[]
    | .[0] as $c | ($c.ReplicationGroupId // $c.CacheClusterId) as $id
    | (if $c.Engine == "memcached" then "CPUUtilization" else "EngineCPUUtilization" end) as $m
    | [ .[] | .CacheClusterId as $n
        | {cpu: vals("elasticache"; $n; $m; "Average"), cpu_max: vals("elasticache"; $n; $m; "Maximum"),
           mem: vals("elasticache"; $n; "DatabaseMemoryUsagePercentage"; "Maximum"),
           ev: vals("elasticache"; $n; "Evictions"; "Sum"), conns: vals("elasticache"; $n; "CurrConnections"; "Maximum")} ] as $nodes
    | ([$nodes[] | .cpu | avg | select(. != null)] | max) as $cpu_avg
    | ([$nodes[] | .cpu | p95 | select(. != null)] | max) as $cpu_p95
    | ([$nodes[].mem[]] | max) as $mem_max
    | ([$nodes[].ev[]] | add // 0) as $evictions
    | ([$nodes[].conns[]]) as $conns
    | base("elasticache"; "\($id) (\($nodes | length) × \($c.CacheNodeType))") as $b
    | ( if enough($conns) and ($conns | max) == 0 then
          $b + {check: "elasticache.idle", severity: "warning", message: "No client connections to \($id) in \(window)",
            fix: "If nothing uses it, delete it (take a backup first for Redis)."}
        elif ([$nodes[].cpu[]] | length) >= 24 and $cpu_avg < $t.cpu_low and ($mem_max == null or $mem_max < 30)
             and ($c.CacheNodeType | can_shrink) then
          ($c.CacheNodeType | size_down) as $down
          | $b + {check: "elasticache.oversized", severity: "info",
            message: "\($id) averages \($cpu_avg | pct) CPU" + (if $mem_max != null then " and peaks at \($mem_max | pct) memory" else "" end) + " over \(window)",
            fix: (if $down then "Try one size down, \($down)." else "A burstable cache.t4g node costs less for light use." end)}
        else empty end ),
      ( select($evictions > 0)
        | $b + {check: "elasticache.evictions", severity: "warning",
            message: "\($id) evicted \($evictions | round) keys in \(window) to stay within memory",
            fix: "Scale up or add shards, or set TTLs on keys that don't need to live forever."} ),
      ( select($mem_max != null and $mem_max > $t.memory_high and $evictions == 0)
        | $b + {check: "elasticache.memory_high", severity: "warning",
            message: "\($id) memory reached \($mem_max | pct)", fix: "Scale up or add shards before it starts evicting."} ),
      ( if $cpu_p95 != null and $cpu_p95 > $t.cpu_high then
          $b + {check: "elasticache.cpu_high", severity: "warning",
            message: "\($id) engine CPU p95 is \($cpu_p95 | pct)",
            fix: "Look for slow or O(N) commands (SLOWLOG), add read replicas, or add shards."}
        else empty end )
  ),

  # --- MSK (per broker, then the busiest broker speaks for the cluster) ---------------------
  ( $in.resources.msk // [] | .[] | . as $k | .ClusterName as $name
    | [ .brokers[] | tostring as $bid
        | ($s["msk|\($name)|\($bid)|CpuUser|Average"] // {ts: [], v: []}) as $u
        | ($s["msk|\($name)|\($bid)|CpuSystem|Average"] // {ts: [], v: []}) as $y
        | ([$y.ts, $y.v] | transpose | map({key: .[0], value: .[1]}) | from_entries) as $ys
        | {broker: $bid,
           cpu: [[$u.ts, $u.v] | transpose[] | .[1] + ($ys[.[0]] // 0)],
           disk: (($s["msk|\($name)|\($bid)|KafkaDataLogsDiskUsed|Maximum"] // {v: []}).v)} ] as $brokers
    | base("msk"; "\($name) (\($brokers | length) brokers)") as $b
    | ([$brokers[] | .cpu | p95 | select(. != null)] | max) as $cpu_p95
    | ([$brokers[].cpu[]] | avg) as $cpu_avg
    | ([$brokers[].disk[]] | max) as $disk
    | ( if $cpu_p95 != null and $cpu_p95 > $t.msk_cpu_high then
          $b + {check: "msk.cpu_high", severity: "warning",
            message: "\($name): the busiest broker's CPU p95 is \($cpu_p95 | pct) over \(window)",
            fix: "Add brokers or move up a broker size. AWS recommends staying under 60% so the cluster can absorb a broker failure."}
        elif ([$brokers[].cpu[]] | length) >= 24 and $cpu_avg < $t.cpu_low and $cpu_p95 < 25 then
          $b + {check: "msk.oversized", severity: "info",
            message: "\($name) brokers average \($cpu_avg | pct) CPU (busiest p95 \($cpu_p95 | pct)) over \(window)",
            fix: "A smaller broker size would likely do. Check partition counts and disk throughput before resizing."}
        else empty end ),
      ( select($disk != null and $disk > 75)
        | $b + {check: "msk.disk_high", severity: (if $disk > 85 then "error" else "warning" end),
            message: "\($name) broker data disk reached \($disk | pct) used",
            fix: "Shorten topic retention, expand broker storage, or turn on storage auto scaling."} )
  )
)
