#!/usr/bin/env bats
# Internet exposure by environment: only the prd internet-facing load balancer may take 0.0.0.0/0.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []
security: {environment_tag: Environment, public_environments: [prd], allowed_public: [sg-nlb-exception], account_environments: {legacy: uat}}'
}

sg() { # ID NAME ENV(or "") VPC PROTO FROM TO CIDR
  jq -cn --arg id "$1" --arg n "$2" --arg e "$3" --arg vpc "$4" --arg p "$5" --argjson f "$6" --argjson t "$7" --arg c "$8" '
    {GroupId: $id, GroupName: $n, VpcId: $vpc, Tags: (if $e == "" then [] else [{Key: "Environment", Value: $e}] end),
     IpPermissions: [{IpProtocol: $p, FromPort: $f, ToPort: $t,
       IpRanges: (if ($c | contains(":")) then [] else [{CidrIp: $c}] end),
       Ipv6Ranges: (if ($c | contains(":")) then [{CidrIpv6: $c}] else [] end)}]}'
}

assess() { # INPUT_JSON
  jq -c --argjson cfg "$(security_cfg)" -f "$PMGR_JQ/security.jq" <<<"$1"
}

input() { # SGS_JSON LBS_JSON [LB_TAGS] [EXTRA]
  jq -cn --argjson sgs "$1" --argjson lbs "${2:-[]}" --argjson tags "${3:-[]}" --argjson extra "${4:-"{}"}" '
    {label: "acct", region: "us-east-1", sgs: {SecurityGroups: $sgs}, lbs: {LoadBalancers: $lbs}, lb_tags: {TagDescriptions: $tags},
     vpcs: {Vpcs: [{VpcId: "vpc-dev", Tags: [{Key: "Environment", Value: "dev"}]}, {VpcId: "vpc-prd", Tags: [{Key: "Environment", Value: "prd"}]}]}} + $extra'
}

PRD_LB='[{"LoadBalancerArn": "arn:lb/prd", "LoadBalancerName": "prd-public", "DNSName": "prd.example", "Scheme": "internet-facing",
          "Type": "application", "VpcId": "vpc-prd", "SecurityGroups": ["sg-lb"]}]'

@test "0.0.0.0/0 on the prd internet-facing load balancer, on 443, is allowed and quiet" {
  got=$(assess "$(input "[$(sg sg-lb prd-alb prd vpc-prd tcp 443 443 0.0.0.0/0)]" "$PRD_LB")")
  [ -z "$(checks <<<"$got")" ]
  [ "$(jq -r 'select(.kind == "exposure") | "\(.type) \(.allowed)"' <<<"$got" | sort | tr '\n' ',')" = \
    "Load balancer (application) true,Security group true," ]
}

@test "0.0.0.0/0 in dev, rc or uat is an error" {
  for e in dev rc uat; do
    got=$(assess "$(input "[$(sg sg-1 web $e vpc-x tcp 443 443 0.0.0.0/0)]")")
    [ "$(jq -r 'select(has("check")) | "\(.check) \(.severity)"' <<<"$got")" = "security.public_ingress error" ]
    [[ "$(jq -r 'select(has("check")) | .message' <<<"$got")" == *"in $e, which should be private"* ]]
  done
}

@test "::/0 counts too, and the environment can come from the VPC tag" {
  got=$(assess "$(input "[$(sg sg-6 v6 "" vpc-dev tcp 22 22 ::/0)]")")
  [[ "$(jq -r 'select(has("check")) | .message' <<<"$got")" == *"::/0 on tcp/22 in dev"* ]]
}

@test "in prd, the internet only belongs on the load balancer, and only on web ports" {
  got=$(assess "$(input "[$(sg sg-lb prd-alb prd vpc-prd tcp 22 22 0.0.0.0/0), $(sg sg-app app prd vpc-prd -1 0 0 0.0.0.0/0)]" "$PRD_LB")")
  [ "$(jq -r 'select(.evidence.group == "sg-lb") | "\(.check) \(.severity)"' <<<"$got")" = "security.public_lb_port warning" ]
  [ "$(jq -r 'select(.evidence.group == "sg-app") | "\(.check) \(.severity)"' <<<"$got")" = "security.public_ingress_not_lb error" ]
  [[ "$(jq -r 'select(.evidence.group == "sg-app") | .message' <<<"$got")" == *"all traffic"* ]]
}

@test "an internet-facing load balancer outside prd is an error" {
  lb='[{"LoadBalancerArn": "arn:lb/uat", "LoadBalancerName": "uat-public", "DNSName": "uat.example", "Scheme": "internet-facing", "Type": "application", "VpcId": "vpc-x", "SecurityGroups": []}]'
  tags='[{"ResourceArn": "arn:lb/uat", "Tags": [{"Key": "environment", "Value": "UAT"}]}]'
  got=$(assess "$(input "[]" "$lb" "$tags")")
  [ "$(jq -r 'select(has("check")) | "\(.check) \(.severity)"' <<<"$got")" = "security.public_lb error" ]
  [[ "$(jq -r 'select(has("check")) | .message' <<<"$got")" == *"internet-facing in UAT"* ]]
}

@test "an untagged environment says so instead of guessing; the account fallback fills it in" {
  got=$(assess "$(input "[$(sg sg-u mystery "" vpc-none tcp 443 443 0.0.0.0/0)]")")
  [ "$(jq -r 'select(has("check")) | .check' <<<"$got")" = security.public_ingress_untagged ]
  got=$(assess "$(input "[$(sg sg-u mystery "" vpc-none tcp 443 443 0.0.0.0/0)]" | jq -c '.label = "legacy"')")
  [[ "$(jq -r 'select(has("check")) | .message' <<<"$got")" == *"in uat"* ]]
}

@test "deliberate exceptions in allowed_public are listed as allowed, not flagged" {
  got=$(assess "$(input "[$(sg sg-nlb-exception nlb-targets prd vpc-prd tcp 8443 8443 0.0.0.0/0)]")")
  [ -z "$(checks <<<"$got")" ]
  [ "$(jq -r 'select(.kind == "exposure") | .allowed' <<<"$got")" = true ]
}

@test "public databases, Kafka, EKS API and instances" {
  extra='{"rds": {"DBInstances": [{"DBInstanceIdentifier": "orders", "PubliclyAccessible": true, "Endpoint": {"Address": "orders.example"},
            "TagList": [{"Key": "Environment", "Value": "prd"}], "DBSubnetGroup": {"VpcId": "vpc-prd"}}]},
          "redshift": {"Clusters": [{"ClusterIdentifier": "wh", "PubliclyAccessible": false}]},
          "msk": {"ClusterInfoList": [{"ClusterName": "events", "Tags": {"Environment": "rc"},
            "Provisioned": {"BrokerNodeGroupInfo": {"ConnectivityInfo": {"PublicAccess": {"Type": "SERVICE_PROVIDED_EIPS"}}}}}]},
          "eks": [{"name": "dev-eks", "endpoint": "https://x", "tags": {"Environment": "dev"},
                   "resourcesVpcConfig": {"endpointPublicAccess": true, "publicAccessCidrs": ["0.0.0.0/0"], "vpcId": "vpc-dev"}},
                  {"name": "prd-eks", "endpoint": "https://y", "tags": {"Environment": "prd"},
                   "resourcesVpcConfig": {"endpointPublicAccess": true, "publicAccessCidrs": ["203.0.113.10/32"], "vpcId": "vpc-prd"}}],
          "instances": {"Reservations": [{"Instances": [{"InstanceId": "i-1", "PublicIpAddress": "198.51.100.7", "VpcId": "vpc-dev",
            "Tags": [{"Key": "Name", "Value": "bastion"}]}]}]}}'
  got=$(assess "$(input "[]" "[]" "[]" "$extra")")
  [ "$(checks <<<"$got")" = "security.public_database security.public_eks_api security.public_instance security.public_kafka " ]
  [ "$(jq -r 'select(.check == "security.public_database") | .severity' <<<"$got")" = error ]   # public DB is wrong even in prd
  [ -z "$(jq -r 'select(.check == "security.public_eks_api") | select(.message | contains("prd-eks"))' <<<"$got")" ]   # limited CIDRs are fine
  [[ "$(jq -r 'select(.check == "security.public_instance") | .message' <<<"$got")" == *"bastion"*"in dev"* ]]
  # Each can be diagnosed: the describe call for that resource.
  [ "$(jq -r 'select(has("diag")) | "\(.diag.type)=\(.diag.id)"' <<<"$got" | sort | tr '\n' ' ')" = "ec2=i-1 eks=dev-eks msk=events rds=orders " ]
}

@test "S3 Block Public Access: any setting off is flagged" {
  got=$(assess "$(input "[]" "[]" "[]" '{"s3pab": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": false, "RestrictPublicBuckets": true}}}')")
  [[ "$(jq -r 'select(has("check")) | .message' <<<"$got")" == *"BlockPublicPolicy off"* ]]
  [ -z "$(assess "$(input "[]" "[]" "[]" '{"s3pab": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": true, "RestrictPublicBuckets": true}}}')" | jq -r 'select(has("check"))')" ]
}

@test "the account sweep uses only describe/list/get calls" {
  for c in "ec2 describe-security-groups" "ec2 describe-vpcs" "elbv2 describe-load-balancers" "rds describe-db-instances" \
           "redshift describe-clusters" "kafka list-clusters-v2" "eks list-clusters" "ec2 describe-instances"; do
    set -- $c
    fake 0 '{}' "" aws "$1" "$2"
  done
  fake 254 "" "An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation" aws s3control
  : >"$PMGR_TMP/sources.jsonl"
  got=$(security_account acct acct 111111111111)
  [[ "$got" == *security.s3_public_access_block* ]]   # no configuration means every setting is off
  ! grep -vE $'^aws\t[^\t]*\t[a-z0-9]+ (describe|list|get)-' "$FAKE_DIR/calls" | grep -q '^aws'
}

@test "every region is checked; S3 Block Public Access, which is account-wide, only once" {
  config 'clusters: []
aws: {regions: [us-east-1, eu-west-1]}'
  for c in "ec2 describe-security-groups" "ec2 describe-vpcs" "elbv2 describe-load-balancers" "rds describe-db-instances" \
           "redshift describe-clusters" "kafka list-clusters-v2" "eks list-clusters" "ec2 describe-instances"; do
    set -- $c
    fake 0 '{}' "" aws "$1" "$2"
  done
  fake 0 "$(sg sg-open web dev vpc-dev tcp 22 22 0.0.0.0/0 | jq -c '{SecurityGroups: [.]}')" "" aws ec2 describe-security-groups --profile acct --region eu-west-1
  fake 254 "" "An error occurred (NoSuchPublicAccessBlockConfiguration)" aws s3control
  : >"$PMGR_TMP/sources.jsonl"
  got=$(security_account acct acct 111111111111)
  [ "$(jq -r 'select(.check == "security.public_ingress") | .resource' <<<"$got")" = "acct/eu-west-1/sg/sg-open" ]
  [ "$(jq -r 'select(.check == "security.s3_public_access_block") | .check' <<<"$got" | wc -l | tr -d ' ')" = 1 ]
  [ "$(grep -c "s3control" "$FAKE_DIR/calls")" = 1 ]
  grep -q "describe-security-groups --profile acct --region us-east-1" "$FAKE_DIR/calls"
}

@test "accounts with a broken session are listed as not checked, not silently skipped" {
  printf '%s' '[{"name": "prod", "aws_profile": "prd", "auth": {"state": "expired"}},
                {"name": "dev", "aws_profile": "dev", "auth": {"state": "ok", "account": "111111111111"}}]' >"$PMGR_TMP/clusters.json"
  printf '%s' '[{"name": "shared", "aws_profile": "shared", "auth": {"state": "no_access"}}]' >"$PMGR_TMP/accounts.json"
  : >"$PMGR_TMP/unseen.txt"
  util_skipped; util_skipped   # both sweeps call it; each account is noted once
  [ "$(cat "$PMGR_TMP/unseen.txt")" = "prd: AWS session expired, so its accounts weren't checked for utilization or security
shared: no access, so its accounts weren't checked for utilization or security" ]
}
