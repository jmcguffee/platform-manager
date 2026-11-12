#!/usr/bin/env bats
# AWS posture: edge, data, identity and compute rules, and the read-only collector.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []
security: {environment_tag: Environment, public_environments: [prd]}
posture: {trusted_accounts: ["222222222222"]}'
  NOW=$(jq -n '"2026-11-12T00:00:00Z" | fromdateiso8601')
  EMPTY=$(jq -cn --argjson now "$NOW" '{label: "acct", region: "us-east-2", first: true, now: $now,
    iam: {RoleDetailList: [], Policies: []}, summary: {SummaryMap: {AccountMFAEnabled: 1, AccountAccessKeysPresent: 0}}, oidc: {},
    cf: {DistributionList: {Items: []}}, trails: {trailList: [{IsMultiRegionTrail: true}]}, trail_status: [{IsLogging: true}], waf_cf: [],
    users: [], buckets: [], lbs: {LoadBalancers: []}, sgs: {SecurityGroups: []}, vpcs: {Vpcs: []}, lb_detail: [], waf: [], acm: [],
    rds: {DBInstances: []}, aurora: {DBClusters: []}, redshift: {Clusters: []}, rs_detail: [], cache: {ReplicationGroups: []},
    secrets: {SecretList: []}, instances: {Reservations: []}, volumes: {Volumes: []}, addresses: {Addresses: []},
    snapshots: {Snapshots: []}, ebs_default: {EbsEncryptionByDefault: true}, guardduty: {DetectorIds: ["d"]}, gd_detector: {Status: "ENABLED"}}')
}

# rules AREA PATCH_JSON : run one rule set on the empty account with PATCH merged in.
rules() {
  jq -c --argjson patch "$2" '. * $patch' <<<"$EMPTY" |
    jq -c -L "$PMGR_JQ" --argjson cfg "$(posture_cfg acct us-east-2)" --arg account 111111111111 -f "$PMGR_JQ/$1.jq"
}
msg() { jq -r --arg c "$1" 'select(.check == $c) | .message' ; }

@test "an account with nothing wrong is quiet in every area" {
  for a in edge data identity compute; do [ -z "$(rules "$a" '{}')" ]; done
}

# --- edge -----------------------------------------------------------------------------------
@test "edge: a prd ALB without WAF, an HTTP listener that doesn't redirect, an old TLS policy" {
  got=$(rules edge '{"lbs": {"LoadBalancers": [{"LoadBalancerArn": "arn:lb/a", "LoadBalancerName": "prd-public", "Scheme": "internet-facing", "Type": "application", "DNSName": "prd-public.elb.amazonaws.com", "VpcId": "v", "SecurityGroups": []}]},
    "lb_detail": [{"arn": "arn:lb/a", "tags": [{"Key": "Environment", "Value": "prd"}],
      "attrs": {"deletion_protection.enabled": "true", "routing.http.drop_invalid_header_fields.enabled": "true", "access_logs.s3.enabled": "true"},
      "listeners": [{"Protocol": "HTTP", "Port": 80, "DefaultActions": [{"Type": "forward"}]}, {"Protocol": "HTTPS", "Port": 443, "SslPolicy": "ELBSecurityPolicy-2016-08"}]}]}')
  [ "$(checks <<<"$got")" = "edge.alb_no_waf edge.http_not_redirected edge.old_tls_policy " ]
  [ "$(jq -r 'select(.check == "edge.alb_no_waf") | .severity' <<<"$got")" = warning ]
}

@test "edge: an ALB behind CloudFront that's still open to the world can skip CloudFront's WAF" {
  got=$(rules edge '{"lbs": {"LoadBalancers": [{"LoadBalancerArn": "arn:lb/o", "LoadBalancerName": "origin", "Scheme": "internet-facing", "Type": "application", "DNSName": "origin-1.us-east-2.elb.amazonaws.com", "SecurityGroups": ["sg-1"]}]},
    "sgs": {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]},
    "lb_detail": [{"arn": "arn:lb/o", "tags": [], "listeners": [], "attrs": {"routing.http.drop_invalid_header_fields.enabled": "true"}}],
    "cf": {"DistributionList": {"Items": [{"Id": "E1", "DomainName": "d.cloudfront.net", "Aliases": {"Items": ["shop.example.com"]}, "WebACLId": "arn:waf",
      "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"}, "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"},
      "Origins": {"Items": [{"DomainName": "origin-1.us-east-2.elb.amazonaws.com", "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"}}]}}]}}}')
  [ "$(checks <<<"$got")" = "edge.cf_origin_bypass " ]   # behind CloudFront: no "ALB without WAF" too
}

@test "edge: CloudFront without WAF, plain HTTP, old TLS, and a public S3 origin" {
  got=$(rules edge '{"cf": {"DistributionList": {"Items": [{"Id": "E2", "DomainName": "x.cloudfront.net", "Aliases": {"Items": ["assets-prd.example.com"]}, "WebACLId": "",
    "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"}, "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1"},
    "Origins": {"Items": [{"DomainName": "assets.s3.us-east-2.amazonaws.com", "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": ""}]}}]}}}')
  [ "$(checks <<<"$got")" = "edge.cf_allows_http edge.cf_no_waf edge.cf_old_tls edge.cf_s3_origin_public " ]
  # Account-wide checks run once, with the first region only.
  [ -z "$(rules edge '{"first": false, "cf": {"DistributionList": {"Items": [{"Id": "E2", "WebACLId": "", "DefaultCacheBehavior": {}, "ViewerCertificate": {}, "Origins": {"Items": []}}]}}}')" ]
}

@test "edge: WAF rules left counting; a certificate stuck on DNS validation names the records to add" {
  got=$(rules edge '{"waf": [{"Name": "prd-acl", "resources": ["arn:lb/a"], "logging": true,
      "Rules": [{"Name": "AWS-AWSManagedRulesCommonRuleSet", "Statement": {"ManagedRuleGroupStatement": {"Name": "AWSManagedRulesCommonRuleSet"}}, "OverrideAction": {"Count": {}}}]}],
    "acm": [{"CertificateArn": "arn:acm/1", "DomainName": "api.example.com", "Status": "ISSUED", "Type": "AMAZON_ISSUED", "NotAfter": "2026-12-01T00:00:00Z",
      "InUseBy": ["arn:lb/a"], "RenewalEligibility": "ELIGIBLE",
      "RenewalSummary": {"RenewalStatus": "PENDING_VALIDATION", "DomainValidationOptions": [{"ValidationStatus": "PENDING_VALIDATION",
        "ResourceRecord": {"Name": "_abc.api.example.com.", "Type": "CNAME", "Value": "_xyz.acm-validations.aws."}}]}}]}')
  [ "$(checks <<<"$got")" = "edge.cert_not_renewing edge.waf_count_only " ]
  [ "$(jq -r 'select(.check == "edge.cert_not_renewing") | .severity' <<<"$got")" = error ]   # 19 days left
  [[ "$(jq -r 'select(.check == "edge.cert_not_renewing") | .fix' <<<"$got")" == *"in the dns repo: _abc.api.example.com. CNAME _xyz.acm-validations.aws."* ]]
  # Expired and still in use is the worst kind.
  got=$(rules edge '{"acm": [{"CertificateArn": "arn:acm/2", "DomainName": "old.example.com", "Status": "EXPIRED", "Type": "IMPORTED", "NotAfter": "2026-10-01T00:00:00Z", "InUseBy": ["arn:aws:elasticloadbalancing:us-east-2:1:loadbalancer/app/legacy/abc"]}]}')
  [ "$(jq -r 'select(.check) | .severity' <<<"$got")" = critical ]
}

# --- data -----------------------------------------------------------------------------------
@test "data: public, plain-HTTP, unversioned prd and lifecycle-less buckets" {
  got=$(rules data '{"buckets": [{"name": "shop-prd-uploads", "region": "us-east-2", "public": true, "policy": {"Statement": []}, "policy_read": true,
      "grants": [], "versioning": "Off", "lifecycle": [], "tags": []},
    {"name": "logs-dev", "region": "us-east-2", "public": false, "policy_read": true, "versioning": "Off", "lifecycle": [{"ID": "x"}], "tags": [], "grants": [],
     "policy": {"Statement": [{"Effect": "Deny", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}]}')
  [ "$(checks <<<"$got")" = "data.s3_no_lifecycle data.s3_no_tls_required data.s3_no_versioning data.s3_public " ]
  [ -z "$(jq -r 'select(.resource | endswith("logs-dev"))' <<<"$got")" ]
}

@test "data: RDS without encryption or backups, single-AZ prd without deletion protection, expired CA" {
  got=$(rules data '{"rds": {"DBInstances": [{"DBInstanceIdentifier": "orders-prd", "StorageEncrypted": false, "IAMDatabaseAuthenticationEnabled": false,
      "BackupRetentionPeriod": 0, "DeletionProtection": false, "MultiAZ": false, "CACertificateIdentifier": "rds-ca-2019", "TagList": []}]}}')
  [ "$(checks <<<"$got")" = "data.rds_no_deletion_protection data.rds_no_iam_auth data.rds_old_ca data.rds_password_unmanaged data.rds_short_backups data.rds_single_az data.rds_unencrypted " ]
  [ "$(jq -r 'select(.check == "data.rds_short_backups") | .severity' <<<"$got")" = error ]
}

@test "data: Redshift without require_ssl or logs; ElastiCache without TLS or AUTH; failing rotation; an unread secret" {
  got=$(rules data '{"redshift": {"Clusters": [{"ClusterIdentifier": "wh", "Encrypted": true, "EnhancedVpcRouting": true, "AutomatedSnapshotRetentionPeriod": 7, "IamRoles": [{}]}]},
    "rs_detail": [{"id": "wh", "require_ssl": "false", "logging": false}],
    "cache": {"ReplicationGroups": [{"ReplicationGroupId": "sessions-prd", "TransitEncryptionEnabled": false, "AtRestEncryptionEnabled": true, "AuthTokenEnabled": false,
      "AutomaticFailover": "enabled", "SnapshotRetentionLimit": 3}]},
    "secrets": {"SecretList": [{"Name": "db/orders", "ARN": "arn:s/1", "RotationEnabled": true, "RotationRules": {"AutomaticallyAfterDays": 30}, "LastRotatedDate": "2026-07-01T00:00:00Z"},
      {"Name": "old/token", "ARN": "arn:s/2", "LastAccessedDate": "2026-01-01T00:00:00Z"}]}}')
  [ "$(checks <<<"$got")" = "data.cache_no_auth data.cache_no_tls data.redshift_no_audit_log data.redshift_no_ssl data.secret_rotation_failing data.secret_unused " ]
  [ "$(jq -r 'select(.check == "data.cache_no_tls") | .severity' <<<"$got")" = error ]   # prd by name
  jq -e 'select(.check == "data.secret_unused") | .savings_usd_month == 0.4' <<<"$got" >/dev/null
}

# --- identity -------------------------------------------------------------------------------
role() { # NAME TRUST_JSON [EXTRA]
  jq -cn --arg n "$1" --argjson t "$2" --argjson x "${3:-"{}"}" \
    '{RoleName: $n, Path: "/", CreateDate: "2026-10-01T00:00:00Z", RoleLastUsed: {LastUsedDate: "2026-11-10T00:00:00Z"},
      AssumeRolePolicyDocument: {Statement: $t}, AttachedManagedPolicies: [], RolePolicyList: []} + $x'
}
GH='"Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Effect": "Allow"'

@test "identity: GitHub OIDC trust with no sub, a wildcard sub, a whole org, and any branch" {
  roles=$( {
    role ci-none "[{$GH, \"Condition\": {\"StringEquals\": {\"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\"}}}]"
    role ci-star "[{$GH, \"Condition\": {\"StringLike\": {\"token.actions.githubusercontent.com:sub\": \"repo:*\"}}}]"
    role ci-org "[{$GH, \"Condition\": {\"StringLike\": {\"token.actions.githubusercontent.com:sub\": \"repo:my-org/*\"}}}]"
    role ci-branch "[{$GH, \"Condition\": {\"StringLike\": {\"token.actions.githubusercontent.com:sub\": \"repo:my-org/infra:*\"}}}]"
    role ci-good "[{$GH, \"Condition\": {\"StringEquals\": {\"token.actions.githubusercontent.com:sub\": \"repo:my-org/infra:environment:prd\"}}}]"
  } | jq -cs '{iam: {RoleDetailList: .}}')
  got=$(rules identity "$roles")
  [ "$(jq -r 'select(.check) | "\(.resource | split("/") | last)=\(.check)"' <<<"$got" | sort | tr '\n' ' ')" = \
    "ci-branch=identity.github_oidc_any_ref ci-none=identity.github_oidc_unpinned ci-org=identity.github_oidc_org_wide ci-star=identity.github_oidc_unpinned " ]
  [[ "$(msg identity.github_oidc_unpinned <<<"$got" | head -1)" == *"any GitHub repository, anyone's, can assume it"* ]]
}

@test "identity: IRSA wildcards, unknown accounts, anyone, admin, PassRole on *, and unused roles" {
  roles=$( {
    role irsa '[{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::1:oidc-provider/oidc.eks.us-east-2.amazonaws.com/id/ABC"}, "Condition": {"StringLike": {"oidc.eks.us-east-2.amazonaws.com/id/ABC:sub": "system:serviceaccount:*"}}}]'
    role vendor '[{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]'
    role ours '[{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::222222222222:root"}}]'
    role open '[{"Effect": "Allow", "Principal": {"AWS": "*"}}]'
    role deployer '[]' '{"AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}'
    role passer '[]' '{"RolePolicyList": [{"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}}]}'
    role stale '[]' '{"CreateDate": "2025-01-01T00:00:00Z", "RoleLastUsed": {}}'
    role AWSReservedSSO_Admin_x '[{"Effect": "Allow", "Principal": {"AWS": "*"}}]'
  } | jq -cs '{iam: {RoleDetailList: .}}')
  got=$(rules identity "$roles")
  [ "$(jq -r 'select(.check) | "\(.resource | split("/") | last)=\(.check)"' <<<"$got" | sort | tr '\n' ' ')" = \
    "deployer=identity.role_admin irsa=identity.irsa_wildcard open=identity.trust_anyone passer=identity.passrole_any stale=identity.role_unused vendor=identity.trust_unknown_account " ]
}

@test "identity: console users without MFA, old keys, root keys, no CloudTrail; GuardDuty per region" {
  got=$(rules identity '{"users": [{"user": "jenkins", "console": true, "mfa": [], "keys": [{"AccessKeyId": "AKIAEXAMPLE000000000", "Status": "Active", "CreateDate": "2025-06-01T00:00:00Z"}], "last_used": [{"at": null}]}],
    "summary": {"SummaryMap": {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 1}}, "trail_status": [{"IsLogging": false}]}')
  [ "$(checks <<<"$got")" = "identity.access_key_old identity.no_cloudtrail identity.root_access_keys identity.user_no_mfa " ]
  [[ "$(msg identity.access_key_old <<<"$got")" == *"AKIAEXAM… is 529 days old and has never been used"* ]]
  # Regional checks run in every region; account-wide ones only in the first.
  [ "$(rules identity '{"first": false, "guardduty": {"DetectorIds": []}, "summary": {"SummaryMap": {"AccountAccessKeysPresent": 1}}}' | checks)" = "identity.no_guardduty " ]
}

# --- compute --------------------------------------------------------------------------------
@test "compute: IMDSv1 once per node group, unattached and gp2 volumes and idle IPs with their cost, old snapshots" {
  inst() { jq -cn --arg id "$1" --arg ng "$2" '{InstanceId: $id, InstanceType: "m7i.large", State: {Name: "running"}, MetadataOptions: {HttpTokens: "optional"},
    Tags: [{Key: "eks:nodegroup-name", Value: $ng}]}'; }
  got=$(rules compute "{\"instances\": {\"Reservations\": [{\"Instances\": [$(inst i-1 general), $(inst i-2 general), $(inst i-3 batch)]}]},
    \"volumes\": {\"Volumes\": [{\"VolumeId\": \"vol-1\", \"Size\": 100, \"VolumeType\": \"gp2\", \"State\": \"available\", \"Encrypted\": true, \"CreateTime\": \"2026-01-01T00:00:00Z\"},
                            {\"VolumeId\": \"vol-2\", \"Size\": 200, \"VolumeType\": \"gp2\", \"State\": \"in-use\", \"Encrypted\": false, \"CreateTime\": \"2026-01-01T00:00:00Z\"}]},
    \"addresses\": {\"Addresses\": [{\"PublicIp\": \"198.51.100.9\"}]},
    \"snapshots\": {\"Snapshots\": [{\"SnapshotId\": \"snap-1\", \"VolumeSize\": 50, \"StartTime\": \"2024-01-01T00:00:00Z\"}]}}")
  [ "$(checks <<<"$got")" = "compute.ebs_gp2 compute.ebs_unattached compute.ebs_unencrypted compute.eip_idle compute.imdsv1 compute.snapshots_old " ]
  [ "$(jq -r 'select(.check == "compute.imdsv1") | .message' <<<"$got" | sort | head -1)" = \
    "nodegroup batch (1 instance) allows IMDSv1, so an SSRF bug in anything running there can read the instance role's credentials" ]
  [ "$(jq -r 'select(.check == "compute.ebs_unattached") | .savings_usd_month' <<<"$got")" = 10 ]
  [ "$(jq -r 'select(.check == "compute.ebs_gp2") | .savings_usd_month' <<<"$got")" = 6 ]
  [ "$(jq -r 'select(.check == "compute.snapshots_old") | .savings_note' <<<"$got")" = "up to" ]
}

# --- the collector --------------------------------------------------------------------------
@test "the collector makes only describe, list and get calls, per region, and says what it couldn't read" {
  config 'clusters: []
aws: {regions: [us-east-2]}'
  fake 0 '{}' "" aws
  fake 0 '{"Buckets": [{"Name": "b1"}]}' "" aws s3api list-buckets
  fake 0 '{"LocationConstraint": "us-west-2"}' "" aws s3api get-bucket-location
  fake 254 "" "An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation" aws s3api get-bucket-policy
  fake 254 "" "An error occurred (NoSuchLifecycleConfiguration)" aws s3api get-bucket-lifecycle-configuration
  fake 254 "" "An error occurred (AccessDenied) when calling the ListSecrets operation" aws secretsmanager list-secrets
  : >"$PMGR_TMP/unseen.txt"
  export PMGR_NOW=$NOW
  got=$(posture_account acct acct 111111111111)
  [[ "$(checks <<<"$got")" == *"data.s3_no_lifecycle"* ]]   # "no lifecycle configuration" is an answer, not an error
  grep -q "s3api get-bucket-versioning --bucket b1 --profile acct --region us-west-2" "$FAKE_DIR/calls"   # the bucket's own region
  grep -q "elbv2 describe-load-balancers --profile acct --region us-east-2" "$FAKE_DIR/calls"
  ! grep -E $'^aws\t' "$FAKE_DIR/calls" | grep -vqE $'\t(\\S+) (describe|list|get)-'
  [[ "$(cat "$PMGR_TMP/unseen.txt")" == *"acct (us-east-2): Secrets Manager secrets (An error occurred (AccessDenied)"* ]]
}
