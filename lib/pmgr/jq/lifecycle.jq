# EKS lifecycle for one cluster: Kubernetes version support and cost, add-ons, node groups.
#
# Input: {cluster, region, profile, now, cost: {standard, extended}, eks: Cluster, versions: [ClusterVersion],
#         addons: [{addon: Addon, versions: [AddonVersion]}], nodegroups: [{ng: Nodegroup, latest: release|null, ssm: path}]}
# Output: findings, and one metric row (kind "eks_version") for the cluster.

def day: .[0:10] + "T00:00:00Z" | fromdateiso8601;
def ymd: todate[0:10];
def minor: split(".") | (.[1] // "0") | tonumber;

. as $in
| def days_until($t): (($t - $in.now) / 86400) | floor;
  $in.eks as $c
| $c.version as $v
| ($in.versions | map(select(.clusterVersion == $v)) | first) as $info
| ($info.versionStatus // $info.status // "") as $status
| ($info.endOfStandardSupportDate // null | if . then day else null end) as $std_end
| ($info.endOfExtendedSupportDate // null | if . then day else null end) as $ext_end
| ($in.versions | map(.clusterVersion) | sort_by(minor) | last) as $newest
| ([$in.versions[] | select((.clusterVersion | minor) > ($v | minor))] | sort_by(.clusterVersion | minor) | map(.clusterVersion)) as $newer
| ($c.upgradePolicy.supportType // "EXTENDED") as $policy
| ($status == "UNSUPPORTED" or ($ext_end != null and $ext_end < $in.now)) as $unsupported
| ((($in.cost.extended // 0.60) - ($in.cost.standard // 0.10)) * 730 | . * 100 | round / 100) as $extra_month
| {area: "lifecycle", link: "", evidence: {}} as $b0
| ($b0 + {resource: "\($in.cluster)/eks/\($c.name)", diag: {type: "eks", profile: $in.profile, region: $in.region, id: $c.name}}) as $base
| (
    {kind: "eks_version", cluster: $in.cluster, name: $c.name, region: $in.region, version: $v, platform: ($c.platformVersion // null),
     status: $status, policy: $policy, standard_end: ($std_end // null | if . then ymd else null end),
     extended_end: ($ext_end // null | if . then ymd else null end), newest: $newest,
     addons_outdated: ([$in.addons[] | select(.versions[0].addonVersion != null and .addon.addonVersion != .versions[0].addonVersion)] | length),
     nodegroups: ($in.nodegroups | length)},

    # Support and what it costs.
    (select($unsupported)
     | $base + {check: "eks.unsupported", severity: "error",
         message: "\($c.name) runs Kubernetes \($v), past the end of extended support\(if $ext_end then " (\($ext_end | ymd))" else "" end). AWS upgrades it on its own schedule",
         fix: "Upgrade one minor version at a time\(if ($newer | length) > 0 then ": \($newer | join(" → "))" else "" end). Upgrade add-ons and node groups between steps."}),
    (select(($unsupported | not) and ($status == "EXTENDED_SUPPORT" or ($std_end != null and $std_end < $in.now)))
     | $base + {check: "eks.extended_support", severity: "warning",
         message: "\($c.name) runs Kubernetes \($v), in extended support since \($std_end // 0 | ymd). That's $\($in.cost.extended // 0.60)/hour instead of $\($in.cost.standard // 0.10), about $\($extra_month | round)/month more\(if $ext_end then ", and extended support ends \($ext_end | ymd)" else "" end)",
         fix: "Upgrade to a version in standard support\(if ($newer | length) > 0 then ": \($newer | join(" → "))" else "" end), one minor version at a time.",
         savings_usd_month: $extra_month, evidence: {version: $v, standard_end: ($std_end // 0 | ymd)}}),
    (select($status == "STANDARD_SUPPORT" and $std_end != null and $std_end >= $in.now and days_until($std_end) <= 180)
     | days_until($std_end) as $d
     | $base + {check: "eks.support_ending", severity: (if $d <= 90 then "warning" else "info" end),
         message: "Standard support for Kubernetes \($v) on \($c.name) ends \($std_end | ymd) (\($d) days). \(if $policy == "STANDARD" then "Its upgrade policy is STANDARD, so AWS upgrades it automatically then" else "After that it moves to extended support, about $\($extra_month | round)/month more" end)",
         fix: "Plan the upgrade to \($newer[0] // "the next version"): check deprecated APIs, then upgrade add-ons and node groups after the control plane."}),
    (select(($newer | length) >= 2 and ($status == "STANDARD_SUPPORT"))
     | $base + {check: "eks.versions_behind", severity: "info",
         message: "\($c.name) is \($newer | length) minor versions behind (\($v); newest is \($newest))",
         fix: "Each upgrade is one minor version, so the gap is \($newer | length) upgrades."}),

    # Add-ons: health, and newer versions for this Kubernetes version.
    ($in.addons[] | .addon as $a | .versions as $vers
     | ($b0 + {resource: "\($in.cluster)/eks/\($c.name)/addon/\($a.addonName)",
               diag: {type: "eks_addon", profile: $in.profile, region: $in.region, cluster: $c.name, addon: $a.addonName}}) as $ab
     | (select(($a.health.issues // []) | length > 0)
        | $ab + {check: "eks.addon_unhealthy", severity: "error",
            message: "Add-on \($a.addonName) on \($c.name) reports: \($a.health.issues | map("\(.code): \(.message)") | join("; "))",
            fix: "Diagnose shows the add-on's status and configuration. IRSA or Pod Identity role problems and conflicting manual changes are the usual causes."}),
       (select(($vers | length) > 0 and $a.addonVersion != $vers[0].addonVersion)
        | ([$vers[].addonVersion] | index($a.addonVersion)) as $behind
        | $ab + {check: "eks.addon_outdated", severity: (if ($behind // 99) >= 3 then "warning" else "info" end),
            message: "Add-on \($a.addonName) on \($c.name) is \($a.addonVersion); the newest for Kubernetes \($v) is \($vers[0].addonVersion)\(if $behind then " (\($behind) releases behind)" else "" end)",
            fix: "Update it to \($vers[0].addonVersion) (in Terraform, the aws_eks_addon's addon_version)."})),

    # Node groups: health, version skew, AMI release.
    ($in.nodegroups[] | .ng as $n
     | ($b0 + {resource: "\($in.cluster)/eks/\($c.name)/nodegroup/\($n.nodegroupName)",
               diag: {type: "eks_nodegroup", profile: $in.profile, region: $in.region, cluster: $c.name, nodegroup: $n.nodegroupName}}) as $nb
     | (select(($n.health.issues // []) | length > 0)
        | $nb + {check: "eks.nodegroup_unhealthy", severity: "error",
            message: "Node group \($n.nodegroupName) on \($c.name) reports: \($n.health.issues | map("\(.code): \(.message)") | join("; "))",
            fix: ($n.health.issues | map({Ec2LaunchTemplateNotFound: "Its launch template is gone: recreate it in Terraform.", Ec2LaunchTemplateVersionMismatch: "The launch template version changed outside the node group: update it through the node group.",
                AsgInstanceLaunchFailures: "Instances fail to launch: often capacity for that instance type, a subnet out of IPs, or an AMI or KMS key problem.", InsufficientFreeAddresses: "The subnets are out of IP addresses.",
                NodeCreationFailure: "Instances launch but don't join: check the node role, the aws-auth or access entries, and that the subnets can reach the API server.",
                AccessDenied: "EKS can't manage the node group's resources: check the node group and cluster roles.", IamInstanceProfileNotFound: "The node role's instance profile is gone: recreate it in Terraform."}[.code] // empty) | unique | join(" "))
                | (if . == "" then "Diagnose shows the node group's status and the Auto Scaling activity." else . end)}),
       (select(($n.version | minor) < ($v | minor))
        | (($v | minor) - ($n.version | minor)) as $skew
        | $nb + {check: "eks.nodegroup_version_skew", severity: (if $skew >= 3 then "error" else "warning" end),
            message: "Node group \($n.nodegroupName) on \($c.name) runs Kubernetes \($n.version), \($skew) minor \(if $skew == 1 then "version" else "versions" end) behind the control plane (\($v))",
            fix: "Upgrade the node group to \($v) before the next control plane upgrade; kubelets may be at most three minor versions behind."}),
       (select(.latest != null and ($n.releaseVersion // "") != "" and $n.releaseVersion != .latest and ($n.version == $v))
        | $nb + {check: "eks.nodegroup_ami_outdated", severity: "info",
            message: "Node group \($n.nodegroupName) on \($c.name) runs AMI release \($n.releaseVersion); AWS recommends \(.latest) for \($n.amiType)",
            fix: "Update the node group's AMI release (a rolling replacement of its nodes). Newer releases carry kernel and runtime security fixes."}),
       (select(.latest == null and .ssm != null and ($n.amiType // "CUSTOM") != "CUSTOM")
        | $nb + {check: "eks.nodegroup_no_ami", severity: "warning",
            message: "AWS publishes no \($n.amiType) AMI for Kubernetes \($n.version), so node group \($n.nodegroupName) on \($c.name) can't be upgraded as it is",
            fix: "Move it to a supported AMI type (for example AL2023 instead of AL2) in Terraform."}))
  )
