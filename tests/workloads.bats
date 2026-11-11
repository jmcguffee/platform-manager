#!/usr/bin/env bats
# Workload health: pods, controllers, nodes, volumes, jobs and Warning events.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []'
  PMGR_NOW=$(jq -n '"2026-11-11T12:00:00Z" | fromdateiso8601')
  export PMGR_NOW
  D="$BATS_TEST_TMPDIR/wl"
  mkdir -p "$D"
  for kind in $WORKLOAD_RESOURCES; do printf '{"items":[]}' >"$D/$kind.json"; done
}

list() { jq -s '{items: .}' >"$D/$1.json"; }

# pod NAME OWNER_KIND OWNER_NAME : a pod JSON with these fields merged in from stdin's JSON.
pod() {
  jq -c --arg n "$1" --arg ok "$2" --arg on "$3" '{
    metadata: {name: $n, namespace: "shop", creationTimestamp: "2026-11-11T11:00:00Z",
               ownerReferences: [{kind: $ok, name: $on}]},
    spec: {nodeName: "node-a"}, status: {phase: "Running"}} * .'
}

assess() { workloads_assess prod "$D"; }

@test "crash-looping pods become one finding per workload, with the OOM cause" {
  for n in api-7d4b9c8f6-aaaaa api-7d4b9c8f6-bbbbb; do
    pod "$n" ReplicaSet api-7d4b9c8f6 <<<'{"status": {"containerStatuses": [{"name": "app", "restartCount": 12,
      "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed container"}},
      "lastState": {"terminated": {"reason": "OOMKilled"}}}]}}'
  done | list pods
  got=$(assess)
  [ "$(jq -s length <<<"$got")" = 1 ]
  [ "$(jq -r .check <<<"$got")" = workload.crashloopbackoff ]
  [ "$(jq -r .resource <<<"$got")" = prod/shop/Deployment/api ]
  [[ "$(jq -r .message <<<"$got")" == *"2 pods in CrashLoopBackOff (last exit: OOMKilled), 12 restarts"* ]]
  [[ "$(jq -r .fix <<<"$got")" == *"memory limit"* ]]
}

@test "image pull and missing config get their own fixes" {
  {
    pod web-1 StatefulSet web <<<'{"status": {"containerStatuses": [{"name": "app", "restartCount": 0,
      "state": {"waiting": {"reason": "ImagePullBackOff", "message": "manifest unknown"}}}]}}'
    pod worker-x Job worker <<<'{"status": {"containerStatuses": [{"name": "app", "restartCount": 0,
      "state": {"waiting": {"reason": "CreateContainerConfigError", "message": "secret \"db\" not found"}}}]}}'
  } | list pods
  got=$(assess)
  [[ "$(jq -r 'select(.check == "workload.imagepullbackoff") | .fix' <<<"$got")" == *registry* ]]
  [[ "$(jq -r 'select(.check == "workload.createcontainerconfigerror") | .fix' <<<"$got")" == *ExternalSecret* ]]
}

@test "unschedulable pods explain why, and the Deployment isn't reported twice" {
  pod api-7d4b9c8f6-ccccc ReplicaSet api-7d4b9c8f6 <<<'{"status": {"phase": "Pending", "conditions": [{"type": "PodScheduled",
    "status": "False", "reason": "Unschedulable", "message": "0/3 nodes are available: 3 Insufficient cpu."}]}}' | list pods
  jq -n '{metadata: {name: "api", namespace: "shop"}, spec: {replicas: 3}, status: {availableReplicas: 2}}' | list deployments
  jq -n '{metadata: {name: "e1", namespace: "shop"}, involvedObject: {kind: "Pod", namespace: "shop", name: "api-7d4b9c8f6-ccccc"},
    reason: "FailedScheduling", message: "0/3 nodes are available", count: 4, lastTimestamp: "2026-11-11T11:55:00Z"}' | list events
  got=$(assess)
  [ "$(jq -sr 'map(.check) | join(",")' <<<"$got")" = workload.unschedulable ]
  [[ "$(jq -r .fix <<<"$got")" == *Karpenter* ]]
}

@test "a running pod that was OOM-killed recently, and one that keeps restarting" {
  {
    pod cache-1 StatefulSet cache <<<'{"status": {"containerStatuses": [{"name": "redis", "restartCount": 1,
      "state": {"running": {}}, "lastState": {"terminated": {"reason": "OOMKilled", "finishedAt": "2026-11-11T09:00:00Z"}}}]}}'
    pod agent-abc DaemonSet agent <<<'{"status": {"containerStatuses": [{"name": "agent", "restartCount": 40,
      "state": {"running": {}}, "lastState": {"terminated": {"reason": "Error"}}}]}}'
  } | list pods
  [ "$(assess | checks)" = "workload.oom_killed workload.restarts " ]
}

@test "controllers missing replicas, a stalled rollout, a pending PVC and a failed CronJob run" {
  {
    jq -n '{metadata: {name: "down", namespace: "shop"}, spec: {replicas: 2}, status: {availableReplicas: 0}}'
    jq -n '{metadata: {name: "slow", namespace: "shop"}, spec: {replicas: 4}, status: {availableReplicas: 3,
      conditions: [{type: "Progressing", status: "False", reason: "ProgressDeadlineExceeded", message: "ReplicaSet has timed out progressing."}]}}'
    jq -n '{metadata: {name: "fine", namespace: "shop"}, spec: {replicas: 2}, status: {availableReplicas: 2}}'
    jq -n '{metadata: {name: "off", namespace: "shop"}, spec: {replicas: 0}, status: {}}'
  } | list deployments
  jq -n '{metadata: {name: "data", namespace: "shop"}, spec: {storageClassName: "gp3"}, status: {phase: "Pending"}}' | list pvcs
  jq -n '{metadata: {name: "nightly-123", namespace: "shop", ownerReferences: [{kind: "CronJob", name: "nightly"}]},
    status: {conditions: [{type: "Failed", status: "True", reason: "BackoffLimitExceeded", message: "Job has reached the specified backoff limit",
    lastTransitionTime: "2026-11-11T06:00:00Z"}]}}' | list jobs
  got=$(assess)
  [ "$(jq -r 'select(.resource | endswith("/down")) | "\(.check) \(.severity)"' <<<"$got")" = "workload.unavailable error" ]
  [ "$(jq -r 'select(.resource | endswith("/slow")) | "\(.check) \(.severity)"' <<<"$got")" = "workload.rollout_stalled error" ]
  [ -z "$(jq -r 'select(.resource | endswith("/fine") or endswith("/off"))' <<<"$got")" ]
  [[ "$(assess | checks)" == *workload.pvc_pending* ]]
  [ "$(jq -r 'select(.check == "workload.job_failed") | .resource' <<<"$got")" = prod/shop/CronJob/nightly ]
}

@test "nodes: NotReady, disk pressure and cordoned" {
  {
    jq -n '{metadata: {name: "ip-10-0-1-1"}, spec: {}, status: {conditions: [{type: "Ready", status: "False", reason: "KubeletNotReady", message: "PLEG is not healthy"}]}}'
    jq -n '{metadata: {name: "ip-10-0-1-2"}, spec: {unschedulable: true}, status: {conditions: [{type: "Ready", status: "True"},
      {type: "DiskPressure", status: "True", message: "kubelet has disk pressure"}]}}'
  } | list nodes
  [ "$(assess | checks)" = "node.cordoned node.diskpressure node.not_ready " ]
}

@test "Warning events status can't see: mounts, CNI IPs, webhooks, probes, HPA, TargetGroupBinding" {
  ev() { jq -n --arg k "$1" --arg n "$2" --arg r "$3" --argjson c "$4" '{metadata: {name: "e", namespace: "shop"},
    involvedObject: {kind: $k, namespace: "shop", name: $n}, reason: $r, message: "details", count: $c,
    lastTimestamp: "2026-11-11T11:50:00Z"}'; }
  {
    ev Pod api-1 FailedMount 3
    ev Pod api-2 FailedCreatePodSandBox 2
    ev ReplicaSet api-7d4b9c8f6 FailedCreate 9
    ev Pod api-1 Unhealthy 30
    ev Pod api-1 Unhealthy 5
    ev HorizontalPodAutoscaler api FailedGetResourceMetric 12
    ev TargetGroupBinding api FailedNetworkReconcile 6
    ev Pod api-1 BackOff 50
    ev Pod api-1 SomethingNew 1
  } | list events
  got=$(assess)
  [ "$(jq -r 'select(.check == "event.unhealthy") | .evidence.count' <<<"$got")" = 35 ]
  [ "$(jq -r 'select(.check == "event.failednetworkreconcile") | .severity' <<<"$got")" = warning ]
  [[ "$(jq -r 'select(.check == "event.failednetworkreconcile") | .fix' <<<"$got")" == *"target group"* ]]
  [[ "$(jq -r 'select(.check == "event.failedcreatepodsandbox") | .fix' <<<"$got")" == *"out of IPs"* ]]
  [ "$(jq -r 'select(.check == "event.somethingnew") | .severity' <<<"$got")" = info ]
  [ -z "$(jq -r 'select(.check == "event.backoff")' <<<"$got")" ]  # pod status already covers BackOff
}

@test "old events and ignored namespaces are left out" {
  config 'clusters: []
workloads: {ignore_namespaces: [sandbox], event_window_minutes: 30}'
  {
    jq -n '{metadata: {namespace: "shop"}, involvedObject: {kind: "Pod", name: "a"}, reason: "FailedMount", message: "old",
      lastTimestamp: "2026-11-11T11:00:00Z"}'
    jq -n '{metadata: {namespace: "sandbox"}, involvedObject: {kind: "Pod", name: "b"}, reason: "FailedMount", message: "ignored",
      lastTimestamp: "2026-11-11T11:59:00Z"}'
  } | list events
  [ -z "$(assess)" ]
}

@test "the sweep reads every resource read-only and says what it couldn't read" {
  printf '[{"name":"prod","context":"ctx-prod","aws_profile":"prd","kubernetes":"ok"}]' >"$PMGR_TMP/clusters.json"
  : >"$PMGR_TMP/unseen.txt"
  fake 0 '{"items":[]}' "" kubectl --context ctx-prod --request-timeout=20s get
  fake 1 "" 'Error from server (Forbidden): nodes is forbidden' kubectl --context ctx-prod --request-timeout=20s get nodes
  workloads_sweep >/dev/null
  [ "$(cat "$PMGR_TMP/unseen.txt")" = "prod: couldn't read nodes" ]
  ! grep -vE $'\t(--context ctx-prod --request-timeout=20s get )' "$FAKE_DIR/calls" | grep -q kubectl
  grep -q "get events --field-selector type=Warning -A -o json" "$FAKE_DIR/calls"
}
