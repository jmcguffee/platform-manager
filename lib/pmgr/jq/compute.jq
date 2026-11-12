# Compute: EC2 instance metadata (IMDSv1), unencrypted EBS, unattached volumes, gp2 that should be gp3,
# idle Elastic IPs, old snapshots, previous-generation instance types, long-stopped instances.
# Instances in an Auto Scaling group or node group are reported once per group, not per instance.
include "posture";

. as $in
| def base($what; $diag): {area: "compute", resource: "\($in.label)/\($in.region)/\($what)", link: "", evidence: {}} + (if $diag then {diag: $diag} else {} end);
  def tag($k): [(.Tags // [])[] | select(.Key == $k) | .Value] | first;
  # The thing that launched an instance: its node group, Auto Scaling group, or the instance itself.
  def owner: (tag("eks:nodegroup-name") | if . then "nodegroup \(.)" else null end)
    // (tag("karpenter.sh/nodepool") | if . then "Karpenter pool \(.)" else null end)
    // (tag("aws:autoscaling:groupName") | if . then "ASG \(.)" else null end)
    // "instance \(tag("Name") // .InstanceId)";
  ([$in.instances.Reservations // [] | .[].Instances[]]) as $all
  | ($all | map(select(.State.Name == "running" or .State.Name == "stopped"))) as $live
  | ($in.volumes.Volumes // []) as $vols
  | ($cfg.ebs_gb_month) as $gb
  | (
  # --- IMDSv1 ---------------------------------------------------------------------------------
  ( $live | map(select(.MetadataOptions.HttpTokens == "optional" and (.MetadataOptions.HttpEndpoint // "enabled") == "enabled"))
    | group_by(owner)[] | . as $group
    | ($group[0] | owner) as $who
    | base("ec2/\($who | gsub(" "; ":"))"; {type: "ec2", profile: $in.label, region: $in.region, id: $group[0].InstanceId}) + {
        check: "compute.imdsv1", severity: "warning",
        message: "\($who) (\(plural($group | length; "instance"; "instances"))) allows IMDSv1, so an SSRF bug in anything running there can read the instance role's credentials",
        fix: "Require IMDSv2: http_tokens = \"required\" in the launch template's metadata_options (for EKS nodes, keep http_put_response_hop_limit = 2 so pods can still reach it).",
        evidence: {instances: [$group[].InstanceId]}}),

  # --- EBS volumes ----------------------------------------------------------------------------
  ( $vols | map(select(.Encrypted | not)) | select(length > 0) | . as $u
    | base("ebs/unencrypted"; null) + {check: "compute.ebs_unencrypted", severity: "warning",
        message: "\(plural($u | length; "EBS volume is"; "EBS volumes are")) unencrypted (\([$u[] | .VolumeId] | names(4)))",
        fix: "Turn on EBS encryption by default, then replace these: snapshot, copy the snapshot encrypted, and create new volumes from it (for node groups, roll the nodes).",
        evidence: {volumes: [$u[].VolumeId]}}),
  ( $vols[] | select(.State == "available") | . as $v
    | (($gb[$v.VolumeType] // 0.10) * $v.Size | money) as $cost
    | base("ebs/\($v.VolumeId)"; {type: "ebs", profile: $in.label, region: $in.region, id: $v.VolumeId}) + {
        check: "compute.ebs_unattached", severity: "warning",
        message: "EBS volume \($v.VolumeId) (\($v.Size) GiB \($v.VolumeType)\(if ($v | tag("Name")) then ", \($v | tag("Name"))" else "" end)) isn't attached to anything, created \($v.CreateTime[0:10])",
        fix: "Snapshot it if the data might matter, then delete it. Volumes left behind by deleted PVCs are common: check the StorageClass reclaimPolicy.",
        savings_usd_month: $cost}),
  ( $vols | map(select(.VolumeType == "gp2")) | select(length > 0) | . as $g2
    | ([$g2[].Size] | add) as $size
    | ((($gb.gp2 // 0.10) - ($gb.gp3 // 0.08)) * $size | money) as $save
    | base("ebs/gp2"; null) + {check: "compute.ebs_gp2", severity: "info",
        message: "\(plural($g2 | length; "volume"; "volumes")) (\($size) GiB) still use gp2; gp3 is 20% cheaper per GiB with a 3,000 IOPS baseline",
        fix: "Change them to gp3 in place (no downtime), and make gp3 the default in launch templates and the EBS CSI StorageClass.",
        savings_usd_month: $save, evidence: {volumes: [$g2[].VolumeId]}}),

  # --- Elastic IPs ----------------------------------------------------------------------------
  ( $in.addresses.Addresses // [] | .[] | select(.AssociationId == null) | . as $a
    | base("eip/\($a.PublicIp)"; null) + {check: "compute.eip_idle", severity: "info",
        message: "Elastic IP \($a.PublicIp)\(if ($a | tag("Name")) then " (\($a | tag("Name")))" else "" end) isn't attached to anything",
        fix: "Release it if nothing needs that address (every public IPv4 address costs $\($cfg.ipv4_month | usd) a month).",
        savings_usd_month: $cfg.ipv4_month}),

  # --- snapshots ------------------------------------------------------------------------------
  ( $in.snapshots.Snapshots // [] | map(select(days_ago($in.now; .StartTime) > $cfg.snapshot_old_days)) | select(length > 0) | . as $old
    | ([$old[].VolumeSize] | add) as $size
    | base("ebs/snapshots"; null) + {check: "compute.snapshots_old", severity: "info",
        message: "\(plural($old | length; "EBS snapshot is"; "EBS snapshots are")) older than \($cfg.snapshot_old_days) days (\($size) GiB of source volumes)",
        fix: "Delete the ones no one will restore, and let Data Lifecycle Manager or AWS Backup expire snapshots from now on. (Snapshots are incremental, so the saving is up to this.)",
        savings_usd_month: ($size * $cfg.snapshot_gb_month | money), savings_note: "up to", evidence: {snapshots: [$old[].SnapshotId]}}),

  # --- instance types and stopped instances ---------------------------------------------------
  ( $live | map(select(.InstanceType | test("^(t2|m3|m4|c3|c4|r3|r4|i2|d2|x1)\\.")))
    | group_by(owner)[] | . as $group
    | base("ec2/\($group[0] | owner | gsub(" "; ":"))/type"; null) + {check: "compute.previous_generation", severity: "info",
        message: "\($group[0] | owner) runs previous-generation \($group | map(.InstanceType) | unique | join(", ")) (\(plural($group | length; "instance"; "instances")))",
        fix: "Move to a current generation (t3 or t4g, m7i or m7g, c7i, r7i): usually cheaper for the same capacity, and Graviton (g) about 20% cheaper again."}),
  ( $all[] | select(.State.Name == "stopped") | . as $i
    | ($i.StateTransitionReason // "" | capture("\\((?<d>[0-9]{4}-[0-9]{2}-[0-9]{2})") .d // null) as $since
    | select($since != null and days_ago($in.now; $since) > 30)
    | base("ec2/\($i.InstanceId)"; {type: "ec2", profile: $in.label, region: $in.region, id: $i.InstanceId}) + {
        check: "compute.stopped_long", severity: "info",
        message: "Instance \($i | tag("Name") // $i.InstanceId) has been stopped since \($since); its EBS volumes are still billed",
        fix: "Terminate it (snapshot first if needed), or start using it again."})
)
