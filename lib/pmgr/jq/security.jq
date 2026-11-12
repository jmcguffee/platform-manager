# Internet exposure for one account and region, judged by environment.
#
# The rule: everything lives in private VPCs, and 0.0.0.0/0 (or ::/0) belongs only on an
# internet-facing load balancer in a public environment (prd by default), on web ports.
#
# Input: {label, region, sgs, vpcs, lbs, lb_tags, rds, redshift, msk, eks: [clusters], instances, s3pab}
# Args: $cfg {tag, public_envs, allowed, account_env, web_ports}
# Output: exposure rows ({kind: "exposure"}) for the table, then findings.

def low: (. // "") | tostring | ascii_downcase;
def tagv($tags): ($cfg.tag | low) as $k
  | if ($tags | type) == "array" then ([$tags[]? | select((.Key // .key | low) == $k) | (.Value // .value)] | first)
    elif ($tags | type) == "object" then ([$tags | to_entries[] | select(.key | low == $k) | .value] | first)
    else null end;
def is_public_env($e): ($e != null) and ([$cfg.public_envs[] | low] | index($e | low)) != null;
def allowed($ids): [$ids[]? | select(. != null)] as $i | any($cfg.allowed[]?; . as $a | $i | index($a));
def open_cidrs: [(.IpRanges[]? | select(.CidrIp == "0.0.0.0/0") | .CidrIp), (.Ipv6Ranges[]? | select(.CidrIpv6 == "::/0") | .CidrIpv6)];
def ports: if (.IpProtocol // "") == "-1" then "all traffic"
  elif .FromPort == .ToPort then "\(.IpProtocol)/\(.FromPort)" else "\(.IpProtocol)/\(.FromPort)-\(.ToPort)" end;
def web_only: .FromPort as $f | (.IpProtocol // "") == "tcp" and $f == .ToPort and ($cfg.web_ports | index($f)) != null;

. as $in
| ($in.vpcs.Vpcs // [] | map({key: .VpcId, value: tagv(.Tags)}) | from_entries) as $vpc_env
| ($cfg.account_env[$in.label] // null) as $acct_env
| def env($tags; $vpc): (tagv($tags) // $vpc_env[$vpc // ""] // $acct_env);
  def base($what): {area: "security", resource: "\($in.label)/\($in.region)/\($what)", link: "", evidence: {}};
  def where($e): if $e == null then "an untagged environment" else $e end;

# Load balancers and their environment, by ARN.
([$in.lb_tags.TagDescriptions // [] | .[] | {key: .ResourceArn, value: .Tags}] | from_entries) as $lbtags
| [$in.lbs.LoadBalancers // [] | .[] | . + {env: env($lbtags[.LoadBalancerArn] // []; .VpcId)}] as $lbs
| ([$lbs[] | select(.Scheme == "internet-facing") | .SecurityGroups[]?] | unique) as $public_lb_sgs

| (
  # --- security group rules open to the internet ---------------------------------------------
  ( $in.sgs.SecurityGroups // [] | .[] | . as $g | env(.Tags; .VpcId) as $e
    | .IpPermissions[]? | . as $p | open_cidrs as $c | select(($c | length) > 0)
    | ($public_lb_sgs | index($g.GroupId) != null) as $on_lb
    | (allowed([$g.GroupId, $g.GroupName])) as $ok_listed
    | (if $ok_listed then "allowed"
       elif is_public_env($e) and $on_lb and ($p | web_only) then "allowed"
       elif is_public_env($e) and $on_lb then "port"
       elif is_public_env($e) then "not_lb"
       elif $e == null then "untagged"
       else "private_env" end) as $verdict
    | ( {kind: "exposure", account: $in.label, region: $in.region, env: $e, type: "Security group",
         id: $g.GroupId, name: $g.GroupName, detail: "\($c | join(", ")) on \($p | ports)", allowed: ($verdict == "allowed")} ),
      ( base("sg/\($g.GroupId)") + {evidence: {group: $g.GroupId, rule: ($p | ports), vpc: $g.VpcId},
          diag: {type: "sg", profile: $in.label, region: $in.region, id: $g.GroupId}} +
        ( if $verdict == "private_env" then {check: "security.public_ingress", severity: "error",
            message: "\($g.GroupName) (\($g.GroupId)) allows \($c | join(", ")) on \($p | ports) in \($e), which should be private",
            fix: "Remove the rule, or narrow it to your VPN or VPC CIDRs. Only the \($cfg.public_envs | join("/")) load balancer should accept the internet."}
          elif $verdict == "not_lb" then {check: "security.public_ingress_not_lb", severity: "error",
            message: "\($g.GroupName) (\($g.GroupId)) allows \($c | join(", ")) on \($p | ports) in \($e), but it isn't on an internet-facing load balancer",
            fix: "Only the public load balancer's security group should allow the internet. Put this behind the load balancer and allow only the load balancer's group."}
          elif $verdict == "port" then {check: "security.public_lb_port", severity: "warning",
            message: "The public load balancer group \($g.GroupName) (\($g.GroupId)) allows \($c | join(", ")) on \($p | ports), not just web ports",
            fix: "Allow only \($cfg.web_ports | map(tostring) | join(" and ")) from the internet on the load balancer."}
          elif $verdict == "untagged" then {check: "security.public_ingress_untagged", severity: "warning",
            message: "\($g.GroupName) (\($g.GroupId)) allows \($c | join(", ")) on \($p | ports), and its environment isn't tagged",
            fix: "Tag it (or its VPC) with \($cfg.tag), so pmgr can tell whether this is allowed. If it isn't the production load balancer, remove the rule."}
          else empty end) ) ),

  # --- load balancers -----------------------------------------------------------------------
  ( $lbs[] | select(.Scheme == "internet-facing") | . as $lb
    | (is_public_env(.env) or allowed([.LoadBalancerName, .LoadBalancerArn])) as $ok
    | ( {kind: "exposure", account: $in.label, region: $in.region, env: .env, type: "Load balancer (\(.Type // "lb"))",
         id: .LoadBalancerName, name: .DNSName, detail: "internet-facing", allowed: $ok} ),
      ( select($ok | not) | base("lb/\(.LoadBalancerName)") + {diag: {type: "lb", profile: $in.label, region: $in.region, id: .LoadBalancerName},
          check: "security.public_lb", severity: (if .env == null then "warning" else "error" end),
          message: "Load balancer \(.LoadBalancerName) is internet-facing in \(where(.env))",
          fix: (if .env == null then "Tag it (or its VPC) with \($cfg.tag). If it isn't production, recreate it as internal."
                else "Only \($cfg.public_envs | join("/")) should have an internet-facing load balancer. Recreate it with scheme internal, and reach it over VPN." end)} ) ),

  # --- data services that shouldn't be public anywhere -------------------------------------------
  ( $in.rds.DBInstances // [] | .[] | select(.PubliclyAccessible == true) | . as $db
    | env(.TagList; .DBSubnetGroup.VpcId) as $e
    | ( {kind: "exposure", account: $in.label, region: $in.region, env: $e, type: "RDS instance", id: .DBInstanceIdentifier,
         name: .Endpoint.Address, detail: "publicly accessible", allowed: allowed([.DBInstanceIdentifier])} ),
      ( select(allowed([$db.DBInstanceIdentifier]) | not) | base("rds/\(.DBInstanceIdentifier)")
        + {check: "security.public_database", severity: "error",
           message: "RDS instance \(.DBInstanceIdentifier) is publicly accessible (\(where($e)))",
           fix: "Turn off Publicly accessible (modify-db-instance --no-publicly-accessible) and keep it in private subnets."} ) ),
  ( $in.redshift.Clusters // [] | .[] | select(.PubliclyAccessible == true) | . as $c | env(.Tags; .VpcId) as $e
    | ( {kind: "exposure", account: $in.label, region: $in.region, env: $e, type: "Redshift cluster", id: .ClusterIdentifier,
         name: (.Endpoint.Address // ""), detail: "publicly accessible", allowed: allowed([.ClusterIdentifier])} ),
      ( select(allowed([$c.ClusterIdentifier]) | not) | base("redshift/\(.ClusterIdentifier)")
        + {check: "security.public_database", severity: "error",
           message: "Redshift cluster \(.ClusterIdentifier) is publicly accessible (\(where($e)))",
           fix: "Turn off public accessibility on the cluster and keep it in private subnets."} ) ),
  ( $in.msk.ClusterInfoList // [] | .[] | select(((.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type) // "DISABLED") != "DISABLED")
    | . as $k | env(.Tags; null) as $e
    | ( {kind: "exposure", account: $in.label, region: $in.region, env: $e, type: "MSK cluster", id: .ClusterName,
         name: .ClusterName, detail: "public access on", allowed: allowed([.ClusterName])} ),
      ( select(allowed([$k.ClusterName]) | not) | base("msk/\(.ClusterName)")
        + {check: "security.public_kafka", severity: "error", message: "MSK cluster \(.ClusterName) has public access turned on (\(where($e)))",
           fix: "Turn public access off, and reach the brokers through the VPC (VPN or PrivateLink)."} ) ),

  # --- EKS API endpoints ---------------------------------------------------------------------
  ( $in.eks[]? | .cluster // . | select(.resourcesVpcConfig.endpointPublicAccess == true) | . as $k
    | (.resourcesVpcConfig.publicAccessCidrs // ["0.0.0.0/0"]) as $cidrs | env(.tags; .resourcesVpcConfig.vpcId) as $e
    | (($cidrs | index("0.0.0.0/0")) != null) as $open
    | ( {kind: "exposure", account: $in.label, region: $in.region, env: $e, type: "EKS API endpoint", id: .name,
         name: .endpoint, detail: "public, from \($cidrs | join(", "))", allowed: (($open | not) or allowed([.name]))} ),
      ( select($open and (allowed([$k.name]) | not)) | base("eks/\(.name)")
        + {check: "security.public_eks_api", severity: (if is_public_env($e) then "warning" else "error" end),
           message: "EKS cluster \(.name)'s API endpoint is public to 0.0.0.0/0 (\(where($e)))",
           fix: "Turn on private access and turn off public access, or limit publicAccessCidrs to your VPN egress IPs."} ) ),

  # --- instances with public IPs ------------------------------------------------------------------
  ( $in.instances.Reservations // [] | .[].Instances[]? | select(.PublicIpAddress != null) | . as $i
    | env(.Tags; .VpcId) as $e | ([.Tags[]? | select(.Key == "Name") | .Value] | first // .InstanceId) as $name
    | select(is_public_env($e) | not)
    | ( {kind: "exposure", account: $in.label, region: $in.region, env: $e, type: "EC2 instance", id: .InstanceId,
         name: $name, detail: "public IP \(.PublicIpAddress)", allowed: allowed([.InstanceId, $name])} ),
      ( select(allowed([$i.InstanceId, $name]) | not) | base("ec2/\(.InstanceId)")
        + {check: "security.public_instance", severity: "warning",
           message: "Instance \($name) (\(.InstanceId)) has a public IP in \(where($e))",
           fix: "Launch it in a private subnet without a public IP, and reach it through SSM Session Manager or VPN."} ) ),

  # --- S3 Block Public Access for the account ---------------------------------------------------
  ( $in.s3pab | select(. != null) | (.PublicAccessBlockConfiguration // {}) as $b
    | [["BlockPublicAcls", $b.BlockPublicAcls], ["IgnorePublicAcls", $b.IgnorePublicAcls],
       ["BlockPublicPolicy", $b.BlockPublicPolicy], ["RestrictPublicBuckets", $b.RestrictPublicBuckets]]
    | map(select(.[1] != true) | .[0]) as $off
    | select(($off | length) > 0)
    | base("s3/account") + {check: "security.s3_public_access_block", severity: "warning",
        message: "S3 Block Public Access isn't fully on for the account: \($off | join(", ")) off",
        fix: "Turn on all four settings at the account level (S3 console, Block Public Access settings for this account)."} )
)
