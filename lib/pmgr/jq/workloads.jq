# Workload health from one cluster's resources and Warning events.
#
# Input: {pods, nodes, deployments, statefulsets, daemonsets, pvcs, jobs, events}, each a kubectl
# list (or null when it couldn't be read). Args: $cluster, $now (epoch seconds, "" = now),
# $window (minutes of events to consider), $ignore (namespaces to skip).
#
# One cause, one finding: pod problems are grouped by the workload that owns the pods, and a
# controller or event finding is dropped when a pod finding already explains it.

def ts: if . == null or . == "" then null else (sub("\\.[0-9]+"; "") | fromdateiso8601) end;
def now_s: if $now == "" then now else ($now | tonumber) end;
def minutes_ago: if . == null then null else ((now_s - (. | ts)) / 60) end;
def items: (. // {}).items // [];
def kept: (.metadata.namespace // "") as $ns | ($ignore | index($ns)) | not;
def plural($n; $one; $many): "\($n) \(if $n == 1 then $one else $many end)";

# The workload a pod belongs to: Deployments own pods through a ReplicaSet with a hash suffix.
def owner: ((.metadata.ownerReferences // [])[0]) as $o
  | if $o == null then {kind: "Pod", name: .metadata.name}
    elif $o.kind == "ReplicaSet" then {kind: "Deployment", name: ($o.name | sub("-[a-z0-9]{5,10}$"; ""))}
    else {kind: $o.kind, name: $o.name} end;
def wl_key: "\(.ns)/\(.owner.kind)/\(.owner.name)";

def base($what): {area: "workload", resource: "\($cluster)/\($what)", link: "", evidence: {}};
def base($what; $diag): base($what) + {diag: ($diag + {cluster: $cluster})};

def waiting_fix($reason; $last; $ns; $pod; $container):
  if $reason == "CrashLoopBackOff" and $last == "OOMKilled" then
    "It's being OOM-killed: raise the container's memory limit, or fix what's growing. Diagnose shows the crashed run's last logs."
  elif $reason == "CrashLoopBackOff" then
    "It keeps exiting. Diagnose shows the crashed run's last logs, the pod's events and its description."
  elif $reason | IN("ImagePullBackOff", "ErrImagePull", "InvalidImageName") then
    "The image can't be pulled: check that the tag exists and that the node role (or pull secret) can read the registry. Diagnose shows the exact pull error."
  elif $reason == "CreateContainerConfigError" then
    "A ConfigMap or Secret it references is missing, often an ExternalSecret that hasn't synced. Diagnose shows which one."
  else "Diagnose shows the pod's description and events with the full error." end;

. as $in
| [$in.pods | items[] | select(kept)] as $pods

# --- pods with a container stuck waiting ------------------------------------------------
| [ $pods[] | . as $p
    | ((.status.initContainerStatuses // []) + (.status.containerStatuses // []))[]
    | select((.state.waiting.reason // "") | IN("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull",
        "CreateContainerConfigError", "CreateContainerError", "InvalidImageName", "RunContainerError"))
    | {ns: $p.metadata.namespace, owner: ($p | owner), pod: $p.metadata.name, container: .name,
       reason: .state.waiting.reason, message: (.state.waiting.message // ""), restarts: (.restartCount // 0),
       last: (.lastState.terminated.reason // "")} ] as $waiting

# --- pods that can't be scheduled -------------------------------------------------------
| [ $pods[] | select(.status.phase == "Pending" and ((.metadata.creationTimestamp | minutes_ago) // 0) >= 5)
    | . as $p | ([.status.conditions // [] | .[] | select(.type == "PodScheduled" and .status == "False")] | first) as $c
    | select($c != null)
    | {ns: .metadata.namespace, owner: ($p | owner), pod: .metadata.name, message: ($c.message // $c.reason // "")} ] as $pending

| ([$waiting[], $pending[] | wl_key] | unique) as $explained

# --- running pods that were recently OOM-killed or keep restarting ----------------------
| [ $pods[] | . as $p | (.status.containerStatuses // [])[]
    | select(.state.running != null)
    | select((.lastState.terminated.reason // "") == "OOMKilled"
        and ((.lastState.terminated.finishedAt | minutes_ago) // 99999) <= 1440)
    | {ns: $p.metadata.namespace, owner: ($p | owner), pod: $p.metadata.name, container: .name, restarts: (.restartCount // 0)}
    | select(wl_key as $k | $explained | index($k) | not) ] as $oom
| [ $pods[] | . as $p | (.status.containerStatuses // [])[]
    | select(.state.running != null and (.restartCount // 0) >= 10 and (.lastState.terminated.reason // "") != "OOMKilled")
    | {ns: $p.metadata.namespace, owner: ($p | owner), pod: $p.metadata.name, container: .name,
       restarts: .restartCount, last: (.lastState.terminated.reason // "")}
    | select(wl_key as $k | $explained | index($k) | not) ] as $restarts

| ([$explained[], ($oom[] | wl_key)] | unique) as $explained

# --- nodes --------------------------------------------------------------------------------
| [$in.nodes | items[]] as $nodes

| (
  # Waiting containers, one finding per workload and reason.
  ( $waiting | group_by([wl_key, .reason])[] | .[0] as $f | (map(.pod) | unique) as $podnames
    | base("\($f.ns)/\($f.owner.kind)/\($f.owner.name)"; {type: "pod", ns: $f.ns, pod: $f.pod, container: $f.container, kind: $f.owner.kind, name: $f.owner.name})
    + {check: "workload.\($f.reason | ascii_downcase)", severity: "error",
       message: "\($f.owner.kind) \($f.owner.name) has \(plural($podnames | length; "pod"; "pods")) in \($f.reason)"
         + (if $f.last != "" then " (last exit: \($f.last))" else "" end)
         + (if $f.restarts > 0 then ", \($f.restarts) restarts" else "" end)
         + (if $f.message != "" then ": \($f.message[0:240])" else "" end),
       fix: waiting_fix($f.reason; $f.last; $f.ns; $f.pod; $f.container),
       evidence: {pods: $podnames, container: $f.container}} ),

  # Unschedulable pods.
  ( $pending | group_by(wl_key)[] | .[0] as $f
    | base("\($f.ns)/\($f.owner.kind)/\($f.owner.name)"; {type: "pod", ns: $f.ns, pod: $f.pod, kind: $f.owner.kind, name: $f.owner.name})
    + {check: "workload.unschedulable", severity: "error",
       message: "\($f.owner.kind) \($f.owner.name) has \(plural(length; "pod"; "pods")) stuck Pending: \($f.message[0:300])",
       fix: (if ($f.message | test("Insufficient|Too many pods"; "i")) then
               "The nodes are full. Check the autoscaler (Karpenter NodePool limits or the node group's max size) and the pods' resource requests."
             elif ($f.message | test("taint|affinity|selector|topology"; "i")) then
               "No node matches the pod's tolerations, node selector or affinity. Compare them with the nodes' labels and taints."
             elif ($f.message | test("persistentvolumeclaim|volume"; "i")) then
               "A volume it needs isn't bound or is in another zone. Check its PVC."
             else "Diagnose shows the scheduler's full reason in the pod's events." end),
       evidence: {pods: map(.pod)}} ),

  ( $oom | group_by(wl_key)[] | .[0] as $f
    | base("\($f.ns)/\($f.owner.kind)/\($f.owner.name)"; {type: "pod", ns: $f.ns, pod: $f.pod, container: $f.container, kind: $f.owner.kind, name: $f.owner.name})
    + {check: "workload.oom_killed", severity: "warning",
       message: "\($f.owner.kind) \($f.owner.name) was OOM-killed in the last 24 hours (\(plural(length; "container"; "containers")))",
       fix: "It recovered, but it's running near its memory limit: raise the limit. Diagnose shows the killed run's last logs."} ),

  ( $restarts | group_by(wl_key)[] | .[0] as $f
    | base("\($f.ns)/\($f.owner.kind)/\($f.owner.name)"; {type: "pod", ns: $f.ns, pod: $f.pod, container: $f.container, kind: $f.owner.kind, name: $f.owner.name})
    + {check: "workload.restarts", severity: "warning",
       message: "\($f.owner.kind) \($f.owner.name) keeps restarting: \(map(.restarts) | max) restarts"
         + (if $f.last != "" then " (last exit: \($f.last))" else "" end),
       fix: "Diagnose shows the previous run's logs, which say why it exited."} ),

  # Evicted pods, one finding per node.
  ( [$pods[] | select(.status.phase == "Failed" and .status.reason == "Evicted")]
    | group_by(.spec.nodeName // "unknown")[] | .[0] as $f
    | base("node/\($f.spec.nodeName // "unknown")"; {type: "node", name: ($f.spec.nodeName // "")})
    + {check: "workload.evicted", severity: "info",
       message: "\(plural(length; "pod was"; "pods were")) evicted from \($f.spec.nodeName // "a node"): \(($f.status.message // "")[0:200])",
       fix: "Evictions mean node pressure. The evicted pods stay around until removed: `kubectl delete pods -A --field-selector=status.phase=Failed`."} ),

  # Nodes.
  ( $nodes[] | . as $n | ([.status.conditions // [] | .[] | {key: .type, value: .}] | from_entries) as $c
    | ( if ($c.Ready.status // "Unknown") != "True" then
          base("node/\(.metadata.name)"; {type: "node", name: .metadata.name})
          + {check: "node.not_ready", severity: "error",
             message: "Node \(.metadata.name) is NotReady: \($c.Ready.reason // "") \(($c.Ready.message // "")[0:200])",
             fix: "If it's been NotReady for a while, drain and replace it. With Karpenter, a node that never became Ready usually failed to join: check its NodeClaim. Diagnose shows the node's conditions, events and pods."}
        else empty end ),
      ( ["MemoryPressure", "DiskPressure", "PIDPressure"][] as $t | select(($c[$t].status // "") == "True")
        | base("node/\($n.metadata.name)"; {type: "node", name: $n.metadata.name})
        + {check: "node.\($t | ascii_downcase)", severity: "warning",
           message: "Node \($n.metadata.name) has \($t): \(($c[$t].message // "")[0:200])",
           fix: (if $t == "DiskPressure" then "Images and logs are filling the disk. Raise the root volume size, or prune unused images."
                 else "Pods on it are using more than the node has. Check requests versus actual use with `kubectl top pods`." end)} ),
      ( if .spec.unschedulable == true then
          base("node/\(.metadata.name)"; {type: "node", name: .metadata.name})
          + {check: "node.cordoned", severity: "info", message: "Node \(.metadata.name) is cordoned",
             fix: "Expected during a drain or upgrade. If not, `kubectl uncordon \(.metadata.name)`."}
        else empty end ) ),

  # Controllers missing replicas, unless a pod finding already explains it.
  ( ($in.deployments | items[] | select(kept) | {kind: "Deployment", o: .,
       want: (.spec.replicas // 1), have: (.status.availableReplicas // 0)}),
    ($in.statefulsets | items[] | select(kept) | {kind: "StatefulSet", o: .,
       want: (.spec.replicas // 1), have: (.status.readyReplicas // 0)}),
    ($in.daemonsets | items[] | select(kept) | {kind: "DaemonSet", o: .,
       want: (.status.desiredNumberScheduled // 0), have: (.status.numberAvailable // 0)})
    | select(.want > 0 and .have < .want)
    | "\(.o.metadata.namespace)/\(.kind)/\(.o.metadata.name)" as $k | select($explained | index($k) | not)
    | ([.o.status.conditions // [] | .[] | select(.type == "Progressing" and .reason == "ProgressDeadlineExceeded")] | first) as $stalled
    | base($k; {type: "workload", ns: .o.metadata.namespace, kind: .kind, name: .o.metadata.name})
    + {check: (if $stalled then "workload.rollout_stalled" else "workload.unavailable" end),
       severity: (if .have == 0 or $stalled then "error" else "warning" end),
       message: "\(.kind) \(.o.metadata.name) has \(.have) of \(.want) replicas available"
         + (if $stalled then ". Its rollout passed the progress deadline: \(($stalled.message // "")[0:200])" else "" end),
       fix: "Diagnose shows its rollout status, events and the pods that aren't ready."} ),

  # Pending PVCs.
  ( $in.pvcs | items[] | select(kept and .status.phase == "Pending")
    | base("\(.metadata.namespace)/PersistentVolumeClaim/\(.metadata.name)"; {type: "object", ns: .metadata.namespace, kind: "PersistentVolumeClaim", name: .metadata.name})
    + {check: "workload.pvc_pending", severity: "warning",
       message: "PVC \(.metadata.name) is Pending (storage class: \(.spec.storageClassName // "default"))",
       fix: "Check that the storage class exists and the EBS CSI driver is healthy. Diagnose shows the PVC's events with the provisioning error."} ),

  # Jobs that failed in the last 24 hours, grouped by CronJob when there is one.
  ( [ $in.jobs | items[] | select(kept) | . as $j
      | ([.status.conditions // [] | .[] | select(.type == "Failed" and .status == "True")] | first) as $c
      | select($c != null and (($c.lastTransitionTime | minutes_ago) // 99999) <= 1440)
      | {ns: .metadata.namespace, job: .metadata.name, reason: ($c.reason // ""), message: ($c.message // ""),
         owner: (((.metadata.ownerReferences // [])[0]) // {kind: "Job", name: .metadata.name})} ]
    | group_by([.ns, .owner.kind, .owner.name])[] | .[0] as $f
    | base("\($f.ns)/\($f.owner.kind)/\($f.owner.name)"; {type: "workload", ns: $f.ns, kind: "Job", name: $f.job})
    + {check: "workload.job_failed", severity: "warning",
       message: "\($f.owner.kind) \($f.owner.name): \(plural(length; "job"; "jobs")) failed in the last 24 hours (\($f.reason)): \($f.message[0:200])",
       fix: "Diagnose shows the job's description, events and pods."} ),

  # Warning events that status doesn't already explain.
  ( ($pods | map({key: "\(.metadata.namespace)/\(.metadata.name)", value: (owner)}) | from_entries) as $pod_owner
    | [ $in.events | items[] | select(kept)
        | select(((.lastTimestamp // .series.lastObservedTime // .eventTime // .metadata.creationTimestamp | minutes_ago) // 99999) <= ($window | tonumber))
        | .involvedObject as $o
        | (if $o.kind == "Pod" then ($pod_owner["\($o.namespace)/\($o.name)"] // {kind: "Pod", name: $o.name})
           else {kind: $o.kind, name: $o.name} end) as $ow
        | {ns: (.metadata.namespace // ""), owner: $ow, reason: (.reason // ""), message: (.message // ""),
           pod: (if $o.kind == "Pod" then $o.name else null end),
           count: (.count // .series.count // 1)}
        # Reasons that pod or node status above already reports.
        | select(.reason | IN("BackOff", "Failed", "Evicted", "NodeNotReady", "BackoffLimitExceeded", "DeadlineExceeded",
            "ProgressDeadlineExceeded", "OOMKilling") | not)
        | select(.reason != "FailedScheduling" or (wl_key as $k | $explained | index($k) | not)) ]
    | group_by([.ns, .owner.kind, .owner.name, .reason])[]
    | (map(.count) | add) as $n | .[0] as $f
    | {
        FailedMount: ["error", "A volume can't mount: a missing Secret or ConfigMap, or an EBS volume that's in another zone or still attached elsewhere."],
        FailedAttachVolume: ["error", "An EBS volume can't attach: it's in another zone or still attached to another node."],
        FailedCreatePodSandBox: ["error", "Pod networking couldn't be set up, usually the VPC CNI running out of IPs. Check subnet free IPs and prefix delegation."],
        FailedCreate: ["error", "The controller can't create pods: a ResourceQuota, LimitRange or admission webhook is rejecting them. The message says which."],
        ProvisioningFailed: ["error", "The volume couldn't be provisioned. Check the storage class and the EBS CSI driver's IAM permissions."],
        Unhealthy: ["warning", "Probes are failing: the app isn't answering its readiness or liveness probe. Check the probe's path, port and timing (a startupProbe helps slow starts)."],
        FailedScheduling: ["warning", "Pods waited to be scheduled. If it keeps happening, the cluster is short on capacity."],
        FailedGetResourceMetric: ["warning", "The HPA can't read metrics: metrics-server is down, or the pods have no resource requests."],
        FailedComputeMetricsReplicas: ["warning", "The HPA can't read metrics: metrics-server is down, or the pods have no resource requests."],
        FailedGetScale: ["warning", "The HPA can't find its target. Check scaleTargetRef."]
      } as $known
    | (if $f.owner.kind == "TargetGroupBinding" then
         ["warning", "The load balancer controller can't register targets. Check the target group name or ARN, the Service and port, and the controller's IAM permissions."]
       else ($known[$f.reason] // ["info", "Diagnose shows the object's description and every event."]) end) as $how
    | base("\(if $f.ns == "" then "" else "\($f.ns)/" end)\($f.owner.kind)/\($f.owner.name)"; (if $f.pod != null then {type: "pod", ns: $f.ns, pod: $f.pod, kind: $f.owner.kind, name: $f.owner.name} else {type: "object", ns: $f.ns, kind: $f.owner.kind, name: $f.owner.name} end))
    + {check: "event.\($f.reason | ascii_downcase)", severity: $how[0],
       message: "\($f.reason) on \($f.owner.kind) \($f.owner.name) (\(plural($n; "time"; "times")) in the last \($window) min): \($f.message[0:240])",
       fix: $how[1], evidence: {count: $n}} )
)
