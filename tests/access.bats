#!/usr/bin/env bats
# AWS sessions, cluster access, deleted clusters, and SSO session grouping.

load helpers

setup() {
  setup_pmgr
  config '
pim: {activation_url: "https://pim.example/activate"}
clusters:
  - {name: staging, context: ctx-staging, aws_profile: stg, expected_role: PlatformAdmin, pim_group: AWS-Staging}
  - {name: prod, context: ctx-prod, aws_profile: prd, expected_role: PlatformAdmin}
'
}

@test "AWS CLI errors map to the right state" {
  [ "$(auth_classify "Error when retrieving token from sso: Token has expired and refresh failed")" = expired ]
  [ "$(auth_classify "The SSO session associated with this profile has expired or is otherwise invalid.")" = expired ]
  [ "$(auth_classify "Unable to locate credentials. You can configure credentials by running aws configure.")" = expired ]
  [ "$(auth_classify "An error occurred (ForbiddenException) when calling the GetRoleCredentials operation: No access")" = no_access ]
  [ "$(auth_classify "The config profile (nope) could not be found")" = no_profile ]
  [ "$(auth_classify 'Could not connect to the endpoint URL: "https://sts.amazonaws.com/"')" = unreachable ]
  [ "$(auth_classify "something new and strange")" = unknown ]
}

@test "a working profile reports its account" {
  fake 0 "$(identity)" "" aws sts get-caller-identity --profile stg
  fake 0 '{"Version":1,"Expiration":"2026-11-11T17:00:00Z"}' "" aws configure export-credentials
  PMGR_NOW=$(jq -n '"2026-11-11T12:00:00Z" | fromdateiso8601')
  export PMGR_NOW
  run auth_check stg PlatformAdmin
  [ "$(jq -r .state <<<"$output")" = ok ]
  [ "$(jq -r .account <<<"$output")" = 111111111111 ]
}

@test "a session with a visible expiry warns when it's nearly over" {
  fake 0 "$(identity)" "" aws sts get-caller-identity
  fake 0 '{"Version":1,"Expiration":"2026-11-11T12:12:00Z"}' "" aws configure export-credentials
  PMGR_NOW=$(jq -n '"2026-11-11T12:00:00Z" | fromdateiso8601')
  export PMGR_NOW
  run auth_check stg
  [ "$(jq -r .state <<<"$output")" = expiring ]
}

@test "SSO profiles ignore the role credentials' one-hour expiry" {
  printf '[profile stg]\nsso_session = corp\nsso_role_name = Admin\n' >"$AWS_CONFIG_FILE"
  fake 0 "$(identity)" "" aws sts get-caller-identity
  fake 0 '{"Version":1,"Expiration":"2026-11-11T12:12:00Z"}' "" aws configure export-credentials
  run auth_check stg
  [ "$(jq -r .state <<<"$output")" = ok ]
  ! grep -q "export-credentials" "$FAKE_DIR/calls"
}

@test "the wrong role is caught" {
  fake 0 "$(identity AWSReservedSSO_ReadOnly_x)" "" aws sts get-caller-identity
  run auth_check stg PlatformAdmin
  [ "$(jq -r .state <<<"$output")" = wrong_role ]
  [[ "$(jq -r .detail <<<"$output")" == *ReadOnly* ]]
}

@test "expired and missing roles link to PIM with the group to activate" {
  for state in expired no_access; do
    f=$(auth_findings staging AWS-Staging "{\"profile\":\"stg\",\"state\":\"$state\",\"detail\":\"x\"}")
    [ "$(jq -r .link <<<"$f")" = "https://pim.example/activate" ]
    [[ "$(jq -r .fix <<<"$f")" == *AWS-Staging* ]]
    [[ "$(jq -r .fix <<<"$f")" == *"pmgr login staging"* ]]
  done
}

@test "without PIM, hints point at Identity Center and SSO login" {
  config '
pim: {activation_url: ""}
clusters: [{name: a, context: c, aws_profile: p}]
'
  f=$(auth_findings a "" '{"profile":"p","state":"no_access","detail":"No access"}')
  [[ "$(jq -r .fix <<<"$f")" == *"IAM Identity Center"* ]]
  [[ "$(jq -r .fix <<<"$f")" != *PIM* ]]
  [ "$(jq -r .link <<<"$f")" = "" ]
  f=$(auth_findings a "" '{"profile":"p","state":"expired","detail":"x"}')
  [ "$(jq -r .fix <<<"$f")" = 'Run `pmgr login a`.' ]
}

@test "Kubernetes isn't checked when the AWS session is broken, and kubectl gets the cluster's profile" {
  fake 0 "$(identity)" "" aws sts get-caller-identity --profile stg
  fake 255 "" "Token has expired" aws sts get-caller-identity --profile prd
  fake 1 "" "" aws configure
  fake 0 $'yes\n' "" kubectl --context ctx-staging
  fake 0 "ctx-staging" "" kubectl config current-context
  access_sweep >/dev/null
  [ "$(jq -r '.[0].kubernetes' "$PMGR_TMP/clusters.json")" = ok ]
  [ "$(jq -r '.[0].current' "$PMGR_TMP/clusters.json")" = true ]
  [ "$(jq -r '.[1].kubernetes' "$PMGR_TMP/clusters.json")" = skipped ]
  ! grep -q "ctx-prod" "$FAKE_DIR/calls"
  grep -q $'^kubectl\tstg\t--context ctx-staging' "$FAKE_DIR/calls"
}

@test "kubectl failures are classified" {
  [ "$(k8s_classify "Unable to connect to the server: dial tcp 10.0.0.1:443: i/o timeout")" = unreachable ]
  [ "$(k8s_classify "error: You must be logged in to the server (Unauthorized)")" = unauthorized ]
  [ "$(k8s_classify 'error: context "ctx" does not exist')" = no_context ]
  [ "$(k8s_classify "Error from server (Forbidden): namespaces is forbidden")" = forbidden ]
}

@test "a deleted cluster isn't reported as a VPN problem" {
  config '
pim: {activation_url: ""}
clusters:
  - {name: old, context: "arn:aws:eks:us-east-1:111:cluster/old", aws_profile: p}
  - {name: demo, context: demo, aws_profile: p, eks_cluster: demo-eks, region: us-east-2}
'
  fake 0 "$(identity)" "" aws sts get-caller-identity
  fake 1 "" "" aws configure
  fake 1 "" "Unable to connect to the server: dial tcp: lookup x: no such host" kubectl --context
  fake 254 "" "An error occurred (ResourceNotFoundException) when calling the DescribeCluster operation" \
    aws eks describe-cluster --name old
  fake 0 $'ACTIVE\n' "" aws eks describe-cluster --name demo-eks --region us-east-2
  fake 0 "old" "" kubectl config current-context
  run access_sweep
  [ "$(jq -r '.[0].kubernetes' "$PMGR_TMP/clusters.json")" = gone ]
  [ "$(jq -r '.[1].kubernetes' "$PMGR_TMP/clusters.json")" = unreachable ]  # ACTIVE: really a network problem
  [[ "$output" == *'"check":"cluster.gone"'* ]]
  [[ "$output" == *"kubectl config delete-context arn:aws:eks:us-east-1:111:cluster/old"* ]]
}

@test "a cluster mid-operation says so" {
  config '
clusters: [{name: demo, context: demo, aws_profile: p, eks_cluster: demo-eks, region: us-east-2}]
'
  fake 0 "$(identity)" "" aws sts get-caller-identity
  fake 1 "" "" aws configure
  fake 1 "" "dial tcp: i/o timeout" kubectl --context
  fake 0 $'DELETING\n' "" aws eks describe-cluster
  fake 0 "x" "" kubectl config current-context
  access_sweep >/dev/null
  [ "$(jq -r '.[0].kubernetes' "$PMGR_TMP/clusters.json")" = not_active ]
  [[ "$(jq -r '.[0].detail' "$PMGR_TMP/clusters.json")" == *DELETING* ]]
}

@test "account profiles are checked without a cluster" {
  config '
pim: {activation_url: ""}
aws: {profiles: [shared, corp]}
'
  fake 0 "$(identity x 333333333333)" "" aws sts get-caller-identity --profile shared
  fake 255 "" "Error when retrieving token from sso: Token has expired and refresh failed" \
    aws sts get-caller-identity --profile corp
  fake 1 "" "" aws configure
  fake 0 "" "" kubectl config current-context
  run access_sweep
  [ "$(jq -r '[.[] | "\(.name)=\(.auth.state)"] | join(",")' "$PMGR_TMP/accounts.json")" = "shared=ok,corp=expired" ]
  [ "$(printf '%s\n' "$output" | jq -r .resource)" = corp ]
}

@test "profiles that share an expired SSO session become one finding" {
  printf '[profile a]\nsso_session = corp\n[profile b]\nsso_session = corp\n[profile solo]\nsso_session = other\n' \
    >"$AWS_CONFIG_FILE"
  config '
pim: {activation_url: ""}
'
  all=$(for p in a b solo; do auth_findings "$p" "" "{\"profile\":\"$p\",\"state\":\"expired\",\"detail\":\"x\"}"; done | jq -cs .)
  got=$(auth_collapse <<<"$all")
  [ "$(jq -r '[.[].resource] | sort | join(",")' <<<"$got")" = "solo,sso-session corp" ]
  [[ "$(jq -r '.[] | select(.resource == "sso-session corp") | .fix' <<<"$got")" == *"--sso-session corp"* ]]
}

@test "the config rejects unknown keys" {
  printf 'clusters: [{name: a, context: c, aws_profile: p, typo: 1}]\n' >"$PMGR_CONFIG"
  run config_load
  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown keys typo"* ]]
}
