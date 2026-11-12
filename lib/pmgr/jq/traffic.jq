# TargetGroupBindings on one cluster, checked against the AWS target groups they name.
#
# Input: {cluster, region, profile, tgbs, svcs, slices, tgs: [TargetGroup], health: {arn: [TargetHealthDescription]}}
# Output: findings, and one metric row per binding (kind "tgb").

def plural($n; $one; $many): "\($n) \(if $n == 1 then $one else $many end)";
def tg_name_of_arn: split(":") | last | split("/")[1] // .;
def lb_name_of_arn: split(":") | last | split("/")[2] // .;

# How alike two names are, 0 to 1 (Dice coefficient on letter pairs), for "did you mean".
def pairs: ascii_downcase | [range(0; (length - 1)) as $i | .[$i:$i + 2]] | unique;
def alike($a; $b): ($a | pairs) as $x | ($b | pairs) as $y
  | if ($x | length) + ($y | length) == 0 then 0
    else (2 * ([$x[] | select(. as $p | $y | index([$p]))] | length)) / (($x | length) + ($y | length)) end;

# What each target health reason means, and what usually fixes it.
def reason_fix: {
  "Target.Timeout": "The health check timed out: the load balancer can't reach the target on that port. Usually the node or pod security group doesn't allow the load balancer's security group on the target port, or nothing listens there.",
  "Target.FailedHealthChecks": "The app didn't pass the health check. Compare the target group's health check path and port with what the app serves.",
  "Target.ResponseCodeMismatch": "The health check got an unexpected status code (often 301, 401 or 404). Point the health check at a path that returns 200, or widen the matcher in Terraform.",
  "Target.NotInUse": "The target group isn't used by a listener, or the target's zone isn't enabled on the load balancer.",
  "Target.NotRegistered": "Nothing is registered. The load balancer controller registers targets: check the binding's events.",
  "Target.InvalidState": "The instance is stopped or terminated.",
  "Target.IpUnusable": "The IP is in use by a load balancer, so it can't be a target.",
  "Target.DeregistrationInProgress": "The target is draining.",
  "Elb.InitialHealthChecking": "Health checks are still starting.",
  "Elb.RegistrationInProgress": "Registration is in progress."
};
def settling: IN("Elb.InitialHealthChecking", "Elb.RegistrationInProgress", "Target.DeregistrationInProgress");

. as $in
| ($in.tgs // []) as $tgs
| ($tgs | map({key: .TargetGroupArn, value: .}) | from_entries) as $by_arn
| ($tgs | map({key: .TargetGroupName, value: .}) | from_entries) as $by_name
| ($in.svcs.items // []) as $svcs
| ($in.slices.items // []) as $slices
| ($in.tgbs.items // [])[]
| . as $b
| ($b.metadata.namespace) as $ns
| ($b.metadata.name) as $name
| ($b.spec.targetGroupARN // "") as $want_arn
| ($b.spec.targetGroupName // "") as $want_name
| (if $want_arn != "" then $by_arn[$want_arn] else $by_name[$want_name] end) as $tg
| ($want_name | if . == "" then ($want_arn | tg_name_of_arn) else . end) as $tg_label
| ($b.spec.serviceRef // {}) as $ref
| ([$svcs[] | select(.metadata.namespace == $ns and .metadata.name == $ref.name)] | first) as $svc
| ($svc.spec.ports // [] | map(select(.port == $ref.port or .name == $ref.port)) | first) as $port
| ([$slices[] | select(.metadata.namespace == $ns and .metadata.labels["kubernetes.io/service-name"] == $ref.name)
   | .endpoints[]? | select(.conditions.ready != false)] | length) as $ready
| (if $tg then ($in.health[$tg.TargetGroupArn] // []) else [] end) as $targets
| ([$targets[] | select(.TargetHealth.State == "healthy")] | length) as $healthy
| ([$targets[] | select(.TargetHealth.State != "healthy" and (.TargetHealth.Reason // "" | settling | not))]) as $bad
| {area: "traffic", resource: "\($in.cluster)/\($ns)/tgb/\($name)", link: "", evidence: {},
   diag: {type: "tgb", cluster: $in.cluster, ns: $ns, name: $name, profile: $in.profile, region: $in.region,
          tg_arn: ($tg.TargetGroupArn // ""), svc: ($ref.name // "")}} as $base
| "\($ns)/\($name) (service \($ref.name // "?"):\($ref.port // "?"))" as $what
| ($tg != null and ($b.spec.targetType // null) != null and ($tg.TargetType | ascii_downcase) != ($b.spec.targetType | ascii_downcase)) as $type_mismatch
| (
    # One row per binding for the dashboard's table.
    {kind: "tgb", cluster: $in.cluster, region: $in.region, ns: $ns, name: $name,
     service: "\($ref.name // "?"):\($ref.port // "?")", target_group: $tg_label,
     tg_arn: ($tg.TargetGroupArn // null), multi: ($b.spec.multiClusterTargetGroup // false),
     target_type: ($b.spec.targetType // null), load_balancers: [($tg.LoadBalancerArns // [])[] | lb_name_of_arn],
     healthy: $healthy, targets: ($targets | length), ready_endpoints: $ready,
     state: (if $tg == null then "missing" elif ($tg.LoadBalancerArns // [] | length) == 0 then "detached"
             elif ($targets | length) == 0 then "empty" elif ($bad | length) > 0 then "unhealthy" else "ok" end)},

    # The target group it names doesn't exist here. Usually a name mismatch with Terraform.
    (select($tg == null)
     | ([$tgs[] | {n: .TargetGroupName, s: alike(.TargetGroupName; $tg_label)} | select(.s >= 0.5)] | sort_by(-.s) | first) as $close
     | $base + {check: "tgb.target_group_missing", severity: "error",
         message: "Binding \($what) names target group \($tg_label), which doesn't exist in \($in.region)\(if $close then ". The closest one there is \($close.n)" else "" end)",
         fix: (if $close then "If \($close.n) is the one Terraform made, set the binding's \(if $want_arn != "" then "targetGroupARN to its ARN" else "targetGroupName to \($close.n)" end) (or rename it in Terraform). Names must match exactly and stay within 32 characters."
               else "Create the target group in Terraform, or fix the binding's \(if $want_arn != "" then "targetGroupARN" else "targetGroupName" end). It must be in the same account and region as the cluster." end),
         evidence: {wanted: $tg_label, closest: ($close.n // null)}}),

    # It exists but no listener sends traffic to it.
    (select($tg != null and ($tg.LoadBalancerArns // [] | length) == 0)
     | $base + {check: "tgb.not_attached", severity: "error",
         message: "Target group \($tg_label) for \($what) isn't attached to any load balancer, so no traffic reaches it",
         fix: "Add a listener or listener rule that forwards to it in Terraform."}),

    # The Service it points at, and its port.
    (select($svc == null)
     | $base + {check: "tgb.service_missing", severity: "error",
         message: "Binding \($ns)/\($name) points at service \($ref.name // "?"), which doesn't exist in \($ns)",
         fix: "Fix serviceRef.name, or deploy the service."}),
    (select($svc != null and $port == null)
     | $base + {check: "tgb.service_port_missing", severity: "error",
         message: "Binding \($ns)/\($name) points at port \($ref.port) of service \($ref.name), which has ports \([$svc.spec.ports[]? | "\(.name // "")\(if .name then " " else "" end)\(.port)"] | join(", "))",
         fix: "Set serviceRef.port to one of the service's port numbers or names."}),
    (select($svc != null and $port != null and $ready == 0)
     | $base + {check: "tgb.no_endpoints", severity: "error",
         message: "Service \($ref.name) behind \($what) has no ready pods, so there's nothing to register",
         fix: "Diagnose shows the service and its endpoints; the Workloads view shows why the pods aren't ready."}),

    # Target type must match what Terraform created.
    (select($type_mismatch)
     | $base + {check: "tgb.target_type_mismatch", severity: "error",
         message: "Binding \($ns)/\($name) uses targetType \($b.spec.targetType), but target group \($tg_label) is \($tg.TargetType | ascii_downcase)",
         fix: "Make them match: targetType in the binding, or target_type in Terraform (changing it in Terraform replaces the target group)."}),

    # Registered targets and their health.
    # (Only when nothing above already explains it.)
    (select($tg != null and ($tg.LoadBalancerArns // [] | length) > 0 and $port != null and $ready > 0 and ($type_mismatch | not) and ($targets | length) == 0)
     | $base + {check: "tgb.no_targets", severity: "error",
         message: "Target group \($tg_label) has no registered targets, though \($what) has \(plural($ready; "ready pod"; "ready pods"))",
         fix: "The load balancer controller isn't registering them. Diagnose shows the binding's events; common causes are the controller's IAM permissions and a VPC or target type mismatch."}),
    (select($tg != null and ($bad | length) > 0)
     | ($bad | group_by(.TargetHealth.Reason // "unknown") | map({reason: (.[0].TargetHealth.Reason // "unknown"),
         description: (.[0].TargetHealth.Description // ""), n: length})) as $why
     | $base + {check: "tgb.unhealthy_targets", severity: (if $healthy == 0 then "error" else "warning" end),
         message: "Target group \($tg_label) for \($what): \($healthy) of \($targets | length) targets healthy\(if $healthy == 0 then ", so requests to it fail" else "" end). \($why | map("\(.n) \(.reason)\(if .description != "" then " (\(.description))" else "" end)") | join("; "))",
         fix: ($why | map(reason_fix[.reason] // empty) | unique | join(" ")) | (if . == "" then "Diagnose shows each target's health and the health check settings." else . end),
         evidence: {healthy: $healthy, targets: ($targets | length), reasons: $why}}),

    # The controller hasn't caught up with a change to the binding.
    (select(($b.status.observedGeneration // 0) < ($b.metadata.generation // 0))
     | $base + {check: "tgb.not_reconciled", severity: "warning",
         message: "The load balancer controller hasn't applied the latest change to binding \($ns)/\($name) (generation \($b.metadata.generation), applied \($b.status.observedGeneration // "none"))",
         fix: "Diagnose shows the binding's events, which say why. Check the controller is running."})
  )
