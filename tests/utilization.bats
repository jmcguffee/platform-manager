#!/usr/bin/env bats
# Over- and under-utilization for RDS, Redshift, ElastiCache, MSK and EKS.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []'
  T=$(util_thresholds)
}

# assess RESOURCES_JSON VALUES_JSON : run the assessment with every query answered by a flat series.
# VALUES maps "metric/stat" (or "metric/stat/resource") to the value each of 336 hourly points gets.
assess() {
  local queries
  queries=$(jq -c -f "$PMGR_JQ/utilization_queries.jq" <<<"$1")
  jq -cn --argjson q "$queries" --argjson v "$2" --argjson r "$1" --argjson t "$T" '
    {resources: $r, queries: $q, days: 14, t: $t, label: "acct",
     results: [$q[] | ($v["\(.metric)/\(.stat)/\(.resource)"] // $v["\(.metric)/\(.stat)"]) as $x | select($x != null)
               | {Id: .id, Timestamps: [range(336) | . * 3600 | todateiso8601], Values: [range(336) | $x]}]}' |
    jq -c -f "$PMGR_JQ/utilization.jq"
}

rds() { jq -cn --arg id "$1" --arg class "$2" --arg engine "${3:-postgres}" --argjson extra "${4:-"{}"}" \
  '{rds: {DBInstances: [{DBInstanceIdentifier: $id, DBInstanceClass: $class, Engine: $engine, AllocatedStorage: 100} + $extra]}}'; }

@test "an oversized RDS instance gets a named size to move to" {
  got=$(assess "$(rds orders db.r6g.2xlarge)" '{"CPUUtilization/Average": 4, "CPUUtilization/Maximum": 11,
    "DatabaseConnections/Maximum": 30, "FreeableMemory/Minimum": 8e9, "FreeStorageSpace/Minimum": 6e10}')
  [ "$(jq -r .check <<<"$got")" = rds.oversized ]
  [[ "$(jq -r .fix <<<"$got")" == *"db.r6g.xlarge"* ]]
  [ "$(jq -r .resource <<<"$got")" = "acct/rds/orders (db.r6g.2xlarge)" ]
}

@test "the smallest burstable size isn't called oversized" {
  [ -z "$(assess "$(rds tiny db.t4g.micro)" '{"CPUUtilization/Average": 1, "CPUUtilization/Maximum": 3,
    "DatabaseConnections/Maximum": 2, "CPUCreditBalance/Minimum": 100, "FreeableMemory/Minimum": 5e8, "FreeStorageSpace/Minimum": 6e10}')" ]
}

@test "an idle database, a hot one, low storage and spent credits" {
  [ "$(assess "$(rds ghost db.m6g.large)" '{"CPUUtilization/Average": 2, "CPUUtilization/Maximum": 3,
    "DatabaseConnections/Maximum": 0, "FreeableMemory/Minimum": 4e9, "FreeStorageSpace/Minimum": 6e10}' | jq -r .check)" = rds.idle ]
  got=$(assess "$(rds busy db.t3.medium)" '{"CPUUtilization/Average": 92, "CPUUtilization/Maximum": 99,
    "DatabaseConnections/Maximum": 40, "CPUCreditBalance/Minimum": 0, "FreeableMemory/Minimum": 1e8, "FreeStorageSpace/Minimum": 3e9}')
  [ "$(checks <<<"$got")" = "rds.cpu_credits rds.cpu_high rds.memory_low rds.storage_low " ]
  [ "$(jq -r 'select(.check == "rds.storage_low") | .severity' <<<"$got")" = error ]   # under 5% free
}

@test "low storage with autoscaling on is only a note" {
  got=$(assess "$(rds grows db.m6g.large postgres '{"MaxAllocatedStorage": 500}')" '{"CPUUtilization/Average": 40,
    "CPUUtilization/Maximum": 60, "DatabaseConnections/Maximum": 10, "FreeableMemory/Minimum": 4e9, "FreeStorageSpace/Minimum": 1e10}')
  [ "$(jq -r 'select(.check == "rds.storage_low") | .severity' <<<"$got")" = info ]
}

@test "Aurora skips storage checks; Serverless v2 is judged by ACUs" {
  got=$(assess "$(rds sls db.serverless aurora-postgresql)" '{"ACUUtilization/Average": 95, "ACUUtilization/Maximum": 100,
    "DatabaseConnections/Maximum": 10, "FreeableMemory/Minimum": 4e9}')
  [ "$(checks <<<"$got")" = "rds.acu_high " ]
}

@test "Redshift: a nearly full disk is an error" {
  got=$(assess '{"redshift": {"Clusters": [{"ClusterIdentifier": "wh", "NodeType": "ra3.4xlarge", "NumberOfNodes": 2}]}}' \
    '{"CPUUtilization/Average": 30, "CPUUtilization/Maximum": 50, "PercentageDiskSpaceUsed/Maximum": 93, "DatabaseConnections/Maximum": 5}')
  [ "$(jq -r '"\(.check) \(.severity)"' <<<"$got")" = "redshift.disk_high error" ]
  [[ "$(jq -r .resource <<<"$got")" == *"2 × ra3.4xlarge"* ]]
}

@test "ElastiCache: nodes of one replication group are one finding" {
  res='{"cache": {"CacheClusters": [
    {"CacheClusterId": "sess-001", "ReplicationGroupId": "sess", "CacheNodeType": "cache.r6g.xlarge", "Engine": "redis"},
    {"CacheClusterId": "sess-002", "ReplicationGroupId": "sess", "CacheNodeType": "cache.r6g.xlarge", "Engine": "redis"}]}}'
  got=$(assess "$res" '{"EngineCPUUtilization/Average": 2, "EngineCPUUtilization/Maximum": 4,
    "DatabaseMemoryUsagePercentage/Maximum": 10, "Evictions/Sum": 0, "CurrConnections/Maximum": 20}')
  [ "$(jq -s length <<<"$got")" = 1 ]
  [[ "$(jq -r .fix <<<"$got")" == *"cache.r6g.large"* ]]
  got=$(assess "$res" '{"EngineCPUUtilization/Average": 20, "EngineCPUUtilization/Maximum": 30,
    "DatabaseMemoryUsagePercentage/Maximum": 97, "Evictions/Sum": 3, "CurrConnections/Maximum": 20}')
  [ "$(checks <<<"$got")" = "elasticache.evictions " ]   # evictions already say memory is full
}

@test "MSK: CPU is user plus system on the busiest broker" {
  got=$(assess '{"msk": [{"ClusterName": "events", "brokers": [1, 2, 3]}]}' \
    '{"CpuUser/Average": 40, "CpuSystem/Average": 25, "KafkaDataLogsDiskUsed/Maximum": 50}')
  [ "$(jq -r .check <<<"$got")" = msk.cpu_high ]
  [[ "$(jq -r .message <<<"$got")" == *"65%"* ]]
  [[ "$(jq -r .resource <<<"$got")" == *"3 brokers"* ]]
}

@test "a resource with less than a day of data isn't judged oversized" {
  queries=$(jq -c -f "$PMGR_JQ/utilization_queries.jq" <<<"$(rds newdb db.r6g.2xlarge)")
  got=$(jq -cn --argjson q "$queries" --argjson r "$(rds newdb db.r6g.2xlarge)" --argjson t "$T" '
    {resources: $r, queries: $q, days: 14, t: $t, label: "acct",
     results: [$q[] | {Id: .id, Timestamps: [range(6) | . * 3600 | todateiso8601], Values: [range(6) | 3]}]}' |
    jq -c -f "$PMGR_JQ/utilization.jq")
  [[ "$got" != *oversized* ]]
}

# --- EKS ---------------------------------------------------------------------------------

eks() {
  jq -c --arg cluster prod --argjson ignore '[]' -f "$PMGR_JQ/eks_utilization.jq"
}

node() { jq -cn --arg n "$1" --arg cpu "$2" --arg mem "$3" '{metadata: {name: $n}, status: {allocatable: {cpu: $cpu, memory: $mem}}}'; }
podj() { # name owner-rs cpu-request mem-request [mem-limit]
  jq -cn --arg n "$1" --arg rs "$2" --arg c "$3" --arg m "$4" --arg l "${5:-}" '{metadata: {name: $n, namespace: "shop",
    ownerReferences: [{kind: "ReplicaSet", name: $rs}]}, status: {phase: "Running"},
    spec: {containers: [{name: "app", resources: ({requests: ({cpu: $c, memory: $m} | with_entries(select(.value != "")))}
      + (if $l == "" then {} else {limits: {memory: $l}} end))}]}}'
}

@test "EKS: nodes mostly empty by requests" {
  got=$(jq -n --argjson n1 "$(node a 4 16Gi)" --argjson n2 "$(node b 4 16Gi)" --argjson p "$(podj api-6b7c8d9f5-x api-6b7c8d9f5 500m 1Gi)" \
    '{nodes: {items: [$n1, $n2]}, pods: {items: [$p]}, podmetrics: null, nodemetrics: null}' | eks)
  [ "$(jq -r .check <<<"$got")" = eks.overprovisioned ]
  [[ "$(jq -r .message <<<"$got")" == *"6% of CPU and 3% of memory across 2 nodes"* ]]
}

@test "EKS: a nearly full cluster" {
  got=$(jq -n --argjson n1 "$(node a 2 8Gi)" --argjson n2 "$(node b 2 8Gi)" \
    --argjson p "$(podj big-6b7c8d9f5-x big-6b7c8d9f5 3800m 4Gi)" \
    '{nodes: {items: [$n1, $n2]}, pods: {items: [$p]}, podmetrics: null, nodemetrics: null}' | eks)
  [ "$(jq -r .check <<<"$got")" = eks.near_full ]
}

@test "EKS with metrics-server: over-requested workloads, memory near its limit, idle nodes, pods without requests" {
  pods=$(jq -cs '{items: .}' <<<"$(podj api-6b7c8d9f5-a api-6b7c8d9f5 2 4Gi)
$(podj api-6b7c8d9f5-b api-6b7c8d9f5 2 4Gi)
$(podj cache-7f8e9d0c1-a cache-7f8e9d0c1 100m 512Mi 512Mi)
$(podj loose-5d6e7f8a9-a loose-5d6e7f8a9 "" "")")
  pm='{"items": [
    {"metadata": {"namespace": "shop", "name": "api-6b7c8d9f5-a"}, "containers": [{"name": "app", "usage": {"cpu": "50000000n", "memory": "300Mi"}}]},
    {"metadata": {"namespace": "shop", "name": "api-6b7c8d9f5-b"}, "containers": [{"name": "app", "usage": {"cpu": "40m", "memory": "280Mi"}}]},
    {"metadata": {"namespace": "shop", "name": "cache-7f8e9d0c1-a"}, "containers": [{"name": "app", "usage": {"cpu": "60m", "memory": "490Mi"}}]}]}'
  nm='{"items": [{"metadata": {"name": "a"}, "usage": {"cpu": "200m", "memory": "2Gi"}},
                 {"metadata": {"name": "b"}, "usage": {"cpu": "3", "memory": "10Gi"}}]}'
  got=$(jq -n --argjson n1 "$(node a 4 16Gi)" --argjson n2 "$(node b 4 16Gi)" --argjson pods "$pods" --argjson pm "$pm" --argjson nm "$nm" \
    '{nodes: {items: [$n1, $n2]}, pods: $pods, podmetrics: $pm, nodemetrics: $nm}' | eks)
  [ "$(checks <<<"$got")" = "eks.idle_nodes eks.memory_near_limit eks.no_requests eks.over_requested " ]
  [[ "$(jq -r 'select(.check == "eks.over_requested") | .message' <<<"$got")" == *"requests 4 CPU and 8Gi across 2 pod(s), but uses 90m CPU and 580Mi right now"* ]]
  [[ "$(jq -r 'select(.check == "eks.idle_nodes") | .message' <<<"$got")" == *"1 of 2 nodes"* ]]
}

@test "the account sweep reads describe calls and CloudWatch, and says what it couldn't list" {
  fake 0 '{"DBInstances": [{"DBInstanceIdentifier": "orders", "DBInstanceClass": "db.r6g.2xlarge", "Engine": "postgres", "AllocatedStorage": 100}]}' "" aws rds describe-db-instances
  fake 254 "" "An error occurred (AccessDenied) when calling the DescribeClusters operation" aws redshift describe-clusters
  fake 0 '{"CacheClusters": []}' "" aws elasticache describe-cache-clusters
  fake 0 '{"ClusterInfoList": []}' "" aws kafka list-clusters-v2
  fake 0 "$(jq -cn '{MetricDataResults: [range(6) | {Id: "m\(.)", Timestamps: [range(48) | . * 3600 | todateiso8601],
      Values: [range(48) | (if . < 0 then 0 else 3 end)]}]}')" "" aws cloudwatch get-metric-data
  : >"$PMGR_TMP/unseen.txt"
  run util_account_sweep shared shared
  [ "$status" -eq 0 ]
  [[ "$output" == *rds.oversized* ]]
  [ "$(cat "$PMGR_TMP/unseen.txt")" = "shared: couldn't list Redshift" ]
  grep -q "cloudwatch get-metric-data --metric-data-queries file://" "$FAKE_DIR/calls"
  ! grep -qE $'\t(.* )?(create|delete|modify|put|update|start|stop)' "$FAKE_DIR/calls"
}
