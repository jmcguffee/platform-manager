# EKS capacity: requests against node capacity, and (with metrics-server) usage against requests.
#
# Input: {pods, nodes, podmetrics, nodemetrics} as kubectl lists (metrics may be null when
# metrics-server isn't installed). Args: $cluster, $ignore (namespaces to skip).
# Usage numbers are a snapshot from metrics-server, so messages say "right now".

def cpu: if . == null then 0 else tostring
  | if endswith("n") then (.[:-1] | tonumber) / 1e9 elif endswith("u") then (.[:-1] | tonumber) / 1e6
    elif endswith("m") then (.[:-1] | tonumber) / 1000 else tonumber end end;
def mem: if . == null then 0 else tostring | capture("^(?<n>[0-9.e+]+)(?<u>[A-Za-z]*)$")
  | (.n | tonumber) * ({"": 1, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "m": 0.001,
      "Ki": 1024, "Mi": 1048576, "Gi": 1073741824, "Ti": 1099511627776}[.u] // 1) end;
def cores: if . >= 1 then "\(. * 10 | round / 10) CPU" else "\(. * 1000 | round)m CPU" end;
def bytes: if . >= 1073741824 then "\(. / 1073741824 * 10 | round / 10)Gi" else "\(. / 1048576 | round)Mi" end;
def pctof($a; $b): if $b > 0 then ($a / $b * 100 | round) else 0 end;
def items: (. // {}).items // [];
def kept: (.metadata.namespace // "") as $ns | ($ignore | index($ns)) | not;
def owner: ((.metadata.ownerReferences // [])[0]) as $o
  | if $o == null then {kind: "Pod", name: .metadata.name}
    elif $o.kind == "ReplicaSet" then {kind: "Deployment", name: ($o.name | sub("-[a-z0-9]{5,10}$"; ""))}
    else {kind: $o.kind, name: $o.name} end;
def base($what): {area: "utilization", resource: "\($cluster)/eks/\($what)", link: "", evidence: {}, diag: {type: "capacity", cluster: $cluster}};

. as $in
| [$in.nodes | items[]] as $nodes
| [$in.pods | items[] | select(.status.phase | IN("Running", "Pending"))] as $live
| ($in.podmetrics != null and $in.nodemetrics != null) as $has_metrics
| ($in.podmetrics | items | map({key: "\(.metadata.namespace)/\(.metadata.name)",
     value: (.containers // [] | map({key: .name, value: {cpu: (.usage.cpu | cpu), mem: (.usage.memory | mem)}}) | from_entries)})
   | from_entries) as $usage

| ($nodes | map(.status.allocatable.cpu | cpu) | add // 0) as $alloc_cpu
| ($nodes | map(.status.allocatable.memory | mem) | add // 0) as $alloc_mem
| ($live | map(.spec.containers[]?.resources.requests.cpu | cpu) | add // 0) as $req_cpu
| ($live | map(.spec.containers[]?.resources.requests.memory | mem) | add // 0) as $req_mem
| ($in.nodemetrics | items | map({key: .metadata.name, value: .usage}) | from_entries) as $nu
| def ntype: .metadata.labels["node.kubernetes.io/instance-type"] // .metadata.labels["beta.kubernetes.io/instance-type"] // "unknown";
  def spot: ((.metadata.labels["karpenter.sh/capacity-type"] // .metadata.labels["eks.amazonaws.com/capacityType"] // "") | ascii_downcase) == "spot";
  def fargate: (.metadata.labels["eks.amazonaws.com/compute-type"] // "") == "fargate";
  ([ $nodes[] | . as $n | ($nu[.metadata.name] // null) as $u | select($has_metrics and $u != null)
     | select(pctof($u.cpu | cpu; $n.status.allocatable.cpu | cpu) < 10 and pctof($u.memory | mem; $n.status.allocatable.memory | mem) < 30)
     | .metadata.name ]) as $idle

| (
  # Requests against capacity, cluster-wide.
  ( select(($nodes | length) >= 2 and $alloc_cpu > 0)
    | if pctof($req_cpu; $alloc_cpu) < 40 and pctof($req_mem; $alloc_mem) < 40 then
        base("nodes") + {check: "eks.overprovisioned", severity: "info", svc: "eks", target: $cluster,
          message: "Pods request \(pctof($req_cpu; $alloc_cpu))% of CPU and \(pctof($req_mem; $alloc_mem))% of memory across \($nodes | length) nodes (\($alloc_cpu | cores), \($alloc_mem | bytes))",
          fix: "The nodes are mostly empty. With Karpenter, use consolidationPolicy WhenEmptyOrUnderutilized; with managed node groups, lower the minimum size.",
          evidence: {requests_cpu_pct: pctof($req_cpu; $alloc_cpu), requests_mem_pct: pctof($req_mem; $alloc_mem)}}
      elif pctof($req_cpu; $alloc_cpu) > 90 or pctof($req_mem; $alloc_mem) > 90 then
        base("nodes") + {check: "eks.near_full", severity: "warning",
          message: "Pods request \(pctof($req_cpu; $alloc_cpu))% of CPU and \(pctof($req_mem; $alloc_mem))% of memory: the cluster is nearly full",
          fix: "New pods will wait for nodes. Check the autoscaler's limits (Karpenter NodePool limits or the node group's max size).",
          evidence: {requests_cpu_pct: pctof($req_cpu; $alloc_cpu), requests_mem_pct: pctof($req_mem; $alloc_mem)}}
      else empty end ),

  # Pods with no requests at all, per namespace.
  ( [$live[] | select(kept) | select([.spec.containers[]? | .resources.requests // {} | length] | all(. == 0))]
    | group_by(.metadata.namespace)[] | .[0].metadata.namespace as $ns
    | base("\($ns)") + {check: "eks.no_requests", severity: "info",
        message: "\(length) pod(s) in \($ns) have no CPU or memory requests (for example \(.[0].metadata.name))",
        fix: "Without requests, the scheduler packs them blindly and they're the first to be evicted. Set requests near their normal usage."} ),

  # With metrics-server: workloads that request far more than they use, and containers near their memory limit.
  ( select($has_metrics)
    | [ $live[] | select(kept and .status.phase == "Running") | . as $p | (owner) as $o
        | "\(.metadata.namespace)/\(.metadata.name)" as $key
        | {ns: .metadata.namespace, owner: $o,
           req_cpu: ([.spec.containers[]?.resources.requests.cpu | cpu] | add // 0),
           req_mem: ([.spec.containers[]?.resources.requests.memory | mem] | add // 0),
           use_cpu: ([($usage[$key] // {})[] | .cpu] | add // 0),
           use_mem: ([($usage[$key] // {})[] | .mem] | add // 0),
           measured: ($usage[$key] != null)} | select(.measured) ]
    | group_by([.ns, .owner.kind, .owner.name])[]
    | {ns: .[0].ns, owner: .[0].owner, pods: length, req_cpu: (map(.req_cpu) | add), req_mem: (map(.req_mem) | add),
       use_cpu: (map(.use_cpu) | add), use_mem: (map(.use_mem) | add)}
    | select((.req_cpu >= 0.1 and .use_cpu < .req_cpu * 0.2) and (.req_mem == 0 or .use_mem < .req_mem * 0.5)
          or (.req_mem >= 268435456 and .use_mem < .req_mem * 0.2 and (.req_cpu == 0 or .use_cpu < .req_cpu * 0.5)))
    | base("\(.ns)/\(.owner.kind)/\(.owner.name)") + {check: "eks.over_requested", severity: "info",
        message: "\(.owner.kind) \(.owner.name) requests \(.req_cpu | cores) and \(.req_mem | bytes) across \(.pods) pod(s), but uses \(.use_cpu | cores) and \(.use_mem | bytes) right now",
        fix: "Lower its requests toward real use with some headroom (about 1.5× its busy-hour usage), so the nodes can pack more. Check a busy period first: this is one snapshot.",
        evidence: {requests: {cpu: .req_cpu, memory: .req_mem}, usage: {cpu: .use_cpu, memory: .use_mem}}} ),

  ( select($has_metrics)
    | $live[] | select(kept) | . as $p | "\(.metadata.namespace)/\(.metadata.name)" as $key
    | .spec.containers[]? | select(.resources.limits.memory != null) | . as $c
    | (($usage[$key] // {})[$c.name].mem // null) as $used | select($used != null)
    | ($c.resources.limits.memory | mem) as $limit | select($limit > 0 and $used / $limit > 0.9)
    | ($p | owner) as $o
    | base("\($p.metadata.namespace)/\($o.kind)/\($o.name)") + {check: "eks.memory_near_limit", severity: "warning",
        message: "Container \($c.name) in \($p.metadata.name) uses \($used | bytes) of its \($limit | bytes) memory limit (\(pctof($used; $limit))%)",
        fix: "It's close to being OOM-killed. Raise the memory limit, or find what's growing."} ),

  # With metrics-server: nodes doing almost nothing.
  ( select($has_metrics and ($nodes | length) >= 2 and ($idle | length) > 0)
    | base("nodes") + {check: "eks.idle_nodes", severity: "info", svc: "eks", target: $cluster,
        message: "\($idle | length) of \($nodes | length) nodes are under 10% CPU and 30% memory right now: \($idle[:5] | join(", "))",
        fix: "If this holds at busy times too, let the autoscaler consolidate them (Karpenter consolidation, or a lower node group minimum).",
        evidence: {nodes: $idle}} ),

  # The cluster's numbers for the metrics table (priced afterwards from EC2 list prices).
  ( {kind: "eks", name: $cluster, nodes: ($nodes | length), pods: ($live | length),
     version: ([$nodes[].status.nodeInfo.kubeletVersion // empty | sub("-eks.*"; "")] | unique | join(", ")),
     node_types: ([$nodes[] | select(fargate | not) | {type: ntype, region: (.metadata.labels["topology.kubernetes.io/region"] // $region), spot: spot}]
                  | group_by([.type, .region, .spot]) | map(.[0] + {count: length})),
     node_type_of: ([$nodes[] | {key: .metadata.name, value: {type: ntype, region: (.metadata.labels["topology.kubernetes.io/region"] // $region), spot: spot}}] | from_entries),
     cpu: ($alloc_cpu * 10 | round / 10), memory_gib: ($alloc_mem / 1073741824 | round),
     requests_cpu_pct: pctof($req_cpu; $alloc_cpu), requests_mem_pct: pctof($req_mem; $alloc_mem),
     usage_cpu_pct: (if $has_metrics then pctof([$nu[] | .cpu | cpu] | add // 0; $alloc_cpu) else null end),
     usage_mem_pct: (if $has_metrics then pctof([$nu[] | .memory | mem] | add // 0; $alloc_mem) else null end),
     idle_nodes: $idle} )
)
