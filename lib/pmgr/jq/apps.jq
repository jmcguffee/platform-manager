# Apps: how workloads are configured. Security context (privileged, hostPath, root), images (:latest),
# resilience (memory limits, readiness probes, replicas, PDBs, spreading), and PDBs that block drains.
#
# Input: {deployments, statefulsets, daemonsets, pdbs}  Args: $cluster, $env (the cluster's), $system (namespaces), $prd (env names)
# Output: findings, one per controller and rule.

def low: (. // "") | ascii_downcase;
def is_prd($e): $e != null and ($prd | map(low) | index($e | low)) != null;
def ns_env: low | (capture("(^|[-_])(?<e>prd|prod|production|uat|rc|stg|staging|dev|qa)([-_]|$)") // {}).e;
def plural($n; $one; $many): "\($n) \(if $n == 1 then $one else $many end)";
def names: if length <= 4 then join(", ") else (.[0:4] | join(", ")) + " and \(length - 4) more" end;
def matches($sel; $labels): ($sel.matchLabels // {}) as $m | ($m | length) > 0 and ($m | to_entries | all(. as $e | $labels[$e.key] == $e.value));

. as $in
| ($env | if . == "" then null else . end) as $env
| ($in.pdbs.items // []) as $pdbs
| (
  # Each controller, its rules.
  ( ( (($in.deployments.items // []) | map(. + {kind: "Deployment"})) + (($in.statefulsets.items // []) | map(. + {kind: "StatefulSet"}))
    + (($in.daemonsets.items // []) | map(. + {kind: "DaemonSet"})) )[]
  | . as $w
  | ($w.metadata.namespace) as $ns
  | select(($system | index($ns)) == null)
  | ($w.spec.template.spec // {}) as $pod
  | ($w.spec.template.metadata.labels // {}) as $labels
  | ([$pod.containers[]?]) as $cs
  | ($ns | ns_env // $env) as $e
  | ($w.spec.replicas // 1) as $replicas
  | {area: "apps", resource: "\($cluster)/\($ns)/\($w.kind)/\($w.metadata.name)", link: "", evidence: {},
     diag: {type: "workload", cluster: $cluster, ns: $ns, kind: $w.kind, name: $w.metadata.name}} as $b
  | "\($w.kind) \($w.metadata.name)" as $what
  | (
    # Security context.
    ([$cs[] | select(.securityContext.privileged == true) | .name]) as $priv
    | (select(($priv | length) > 0)
       | $b + {check: "apps.privileged", severity: "error",
           message: "\($what) runs privileged containers (\($priv | names)): root on the node, with every device and capability",
           fix: "Drop privileged and add only the capabilities it needs (securityContext.capabilities.add). If it's a node agent that truly needs it, add its namespace to apps.system_namespaces."}),
    ([$pod.volumes[]? | select(.hostPath != null) | .hostPath.path]) as $hp
    | (select(($hp | length) > 0)
       | $b + {check: "apps.host_path", severity: "warning",
           message: "\($what) mounts the node's filesystem (\($hp | unique | names))",
           fix: "Use a PVC, an emptyDir or a projected volume instead; a hostPath mount lets the pod read or change the node."}),
    (select(($pod.securityContext.runAsNonRoot // false) != true and ([$cs[] | select((.securityContext.runAsNonRoot // false) != true)] | length) > 0)
     | ([$cs[] | select(.securityContext.runAsUser == 0) | .name]) as $root
     | $b + {check: "apps.may_run_as_root", severity: (if ($root | length) > 0 then "warning" else "info" end),
         message: (if ($root | length) > 0 then "\($what) runs \($root | names) as root (runAsUser 0)" else "\($what) doesn't require a non-root user, so it runs as whatever the image says (often root)" end),
         fix: "Set securityContext.runAsNonRoot: true (and runAsUser) on the pod, and build the image with a non-root USER."}),
    # Images.
    ([$cs[] | .image | select((contains("@sha256:") | not) and (test(":[^/]+$") | not) or test(":latest$"))]) as $latest
    | (select(($latest | length) > 0)
       | $b + {check: "apps.latest_tag", severity: "warning",
           message: "\($what) uses \($latest | unique | names), so what runs changes whenever the image is pushed, and a rollback can't go back",
           fix: "Pin a version tag (or a digest) and let Argo CD roll it out."}),
    # Resilience.
    ([$cs[] | select(.resources.limits.memory == null) | .name]) as $nolimit
    | (select($w.kind != "DaemonSet" and ($nolimit | length) > 0)
       | $b + {check: "apps.no_memory_limit", severity: "info",
           message: "\($what) has no memory limit on \($nolimit | names), so a leak can starve everything else on the node",
           fix: "Set resources.limits.memory (equal to the request is the safe default for memory)."}),
    ([$cs[] | select(.readinessProbe == null) | .name]) as $noready
    | (select($w.kind == "Deployment" and ($noready | length) > 0)
       | $b + {check: "apps.no_readiness_probe", severity: (if is_prd($e) then "warning" else "info" end),
           message: "\($what) has no readiness probe on \($noready | names), so it gets traffic before it's ready and during shutdown",
           fix: "Add a readinessProbe on the app's health endpoint (and a preStop sleep so the load balancer drains it first)."}),
    (select($w.kind == "Deployment" and is_prd($e) and $replicas < 2)
     | $b + {check: "apps.single_replica", severity: "warning",
         message: "\($what) runs one replica in \($e), so a node drain, a deploy or a crash means downtime",
         fix: "Run at least 2 replicas (or an HPA with minReplicas 2), with a PodDisruptionBudget."}),
    ([$pdbs[] | select(.metadata.namespace == $ns and matches(.spec.selector // {}; $labels))]) as $mine
    | (select($w.kind != "DaemonSet" and is_prd($e) and $replicas >= 2 and ($mine | length) == 0)
       | $b + {check: "apps.no_pdb", severity: "info",
           message: "\($what) has no PodDisruptionBudget, so a node upgrade can evict all \($replicas) replicas at once",
           fix: "Add a PDB with maxUnavailable: 1."}),
    (select($w.kind != "DaemonSet" and is_prd($e) and $replicas >= 2 and ($pod.topologySpreadConstraints == null) and ($pod.affinity.podAntiAffinity == null))
     | $b + {check: "apps.not_spread", severity: "info",
         message: "\($what) doesn't ask to spread its \($replicas) replicas, so they can all land on one node or zone",
         fix: "Add topologySpreadConstraints across topology.kubernetes.io/zone and kubernetes.io/hostname (whenUnsatisfiable: ScheduleAnyway)."})
  )),

  # PDBs that allow no disruption block node drains, which stalls node group and Karpenter upgrades.
  ( $pdbs[] | .metadata.namespace as $pns | select(($system | index($pns)) == null)
    | select((.status.disruptionsAllowed // 1) == 0 and (.status.currentHealthy // 0) >= (.status.desiredHealthy // 0) and (.status.expectedPods // 0) > 0)
    | {area: "apps", resource: "\($cluster)/\(.metadata.namespace)/PodDisruptionBudget/\(.metadata.name)", link: "", evidence: {},
       diag: {type: "object", cluster: $cluster, ns: .metadata.namespace, kind: "PodDisruptionBudget", name: .metadata.name},
       check: "apps.pdb_blocks_drain", severity: "warning",
       message: "PodDisruptionBudget \(.metadata.name) allows no evictions even with every pod healthy (\(if .spec.maxUnavailable != null then "maxUnavailable \(.spec.maxUnavailable)" else "minAvailable \(.spec.minAvailable)" end), \(plural(.status.expectedPods; "pod"; "pods"))), so node drains and upgrades hang on it",
       fix: "Use maxUnavailable: 1 (or raise replicas above minAvailable)."})
)
