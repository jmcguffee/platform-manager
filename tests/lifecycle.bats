#!/usr/bin/env bats
# Lifecycle: EKS version support and cost, add-ons, node groups.

load helpers

setup() {
  setup_pmgr
  config 'clusters: [{name: prod, context: "arn:aws:eks:us-east-2:111111111111:cluster/prod-eks", aws_profile: prd}]'
  NOW=$(jq -n '"2026-11-12T00:00:00Z" | fromdateiso8601')
  VERSIONS='[{"clusterVersion":"1.30","versionStatus":"EXTENDED_SUPPORT","endOfStandardSupportDate":"2025-07-23T00:00:00Z","endOfExtendedSupportDate":"2026-07-23T00:00:00Z"},
             {"clusterVersion":"1.31","versionStatus":"EXTENDED_SUPPORT","endOfStandardSupportDate":"2025-11-26T00:00:00Z","endOfExtendedSupportDate":"2026-11-26T00:00:00Z"},
             {"clusterVersion":"1.32","versionStatus":"EXTENDED_SUPPORT","endOfStandardSupportDate":"2026-03-23T00:00:00Z","endOfExtendedSupportDate":"2027-03-23T00:00:00Z"},
             {"clusterVersion":"1.33","versionStatus":"STANDARD_SUPPORT","endOfStandardSupportDate":"2026-07-29T00:00:00Z","endOfExtendedSupportDate":"2027-07-29T00:00:00Z"},
             {"clusterVersion":"1.34","versionStatus":"STANDARD_SUPPORT","endOfStandardSupportDate":"2027-01-02T00:00:00Z","endOfExtendedSupportDate":"2028-01-02T00:00:00Z"},
             {"clusterVersion":"1.35","versionStatus":"STANDARD_SUPPORT","endOfStandardSupportDate":"2027-11-01T00:00:00Z","endOfExtendedSupportDate":"2028-11-01T00:00:00Z"}]'
}

# assess VERSION [POLICY] [ADDONS] [NODEGROUPS]
assess() {
  jq -cn --argjson now "$NOW" --argjson versions "$VERSIONS" --arg v "$1" --arg policy "${2:-EXTENDED}" \
    --argjson addons "${3:-[]}" --argjson ngs "${4:-[]}" \
    '{cluster: "prod", region: "us-east-2", profile: "prd", now: $now, cost: {standard: 0.10, extended: 0.60},
      eks: {name: "prod-eks", version: $v, upgradePolicy: {supportType: $policy}}, versions: $versions, addons: $addons, nodegroups: $ngs}' |
    jq -c -f "$PMGR_JQ/lifecycle.jq"
}

@test "extended support is a warning with what it costs and the upgrade path" {
  got=$(assess 1.32)
  f=$(jq -c 'select(.check == "eks.extended_support")' <<<"$got")
  [[ "$(jq -r .message <<<"$f")" == *'Kubernetes 1.32, in extended support since 2026-03-23. That'"'"'s $0.6/hour instead of $0.1, about $365/month more, and extended support ends 2027-03-23'* ]]
  [ "$(jq -r .savings_usd_month <<<"$f")" = 365 ]
  [[ "$(jq -r .fix <<<"$f")" == *"1.33 → 1.34 → 1.35"* ]]
  [ "$(jq -c 'select(.kind) | [.version, .status, .newest]' <<<"$got")" = '["1.32","EXTENDED_SUPPORT","1.35"]' ]
}

@test "past extended support is an error; standard support ending says what happens next" {
  [ "$(assess 1.30 | checks)" = "eks.unsupported " ]
  got=$(assess 1.34 STANDARD)
  [[ "$(jq -r 'select(.check == "eks.support_ending") | .message' <<<"$got")" == *"ends 2027-01-02 (51 days). Its upgrade policy is STANDARD, so AWS upgrades it automatically then"* ]]
  [ "$(jq -r 'select(.check == "eks.support_ending") | .severity' <<<"$got")" = warning ]
  [[ "$(assess 1.34 EXTENDED | jq -r 'select(.check == "eks.support_ending") | .message')" == *"moves to extended support, about \$365/month more"* ]]
  [ -z "$(assess 1.35 | jq -r 'select(.check)')" ]   # newest, far from the end: quiet
}

@test "add-ons: health issues are errors; versions behind say by how much" {
  addons='[{"addon": {"addonName": "vpc-cni", "addonVersion": "v1.18.0", "health": {"issues": [{"code": "ConfigurationConflict", "message": "Conflicts found"}]}},
            "versions": [{"addonVersion": "v1.19.2"}, {"addonVersion": "v1.19.0"}, {"addonVersion": "v1.18.5"}, {"addonVersion": "v1.18.0"}]},
           {"addon": {"addonName": "coredns", "addonVersion": "v1.11.4", "health": {"issues": []}}, "versions": [{"addonVersion": "v1.11.4"}]}]'
  got=$(assess 1.35 EXTENDED "$addons")
  [ "$(checks <<<"$got")" = "eks.addon_outdated eks.addon_unhealthy " ]
  [[ "$(jq -r 'select(.check == "eks.addon_outdated") | "\(.severity) \(.message)"' <<<"$got")" == "warning Add-on vpc-cni on prod-eks is v1.18.0; the newest for Kubernetes 1.35 is v1.19.2 (3 releases behind)" ]]
  [ "$(jq -r 'select(.check == "eks.addon_unhealthy") | .diag.type' <<<"$got")" = eks_addon ]
}

@test "node groups: health with the usual cause, version skew, an outdated AMI, and an AMI type AWS no longer publishes" {
  ngs='[{"ng": {"nodegroupName": "general", "version": "1.35", "releaseVersion": "1.35.0-20260901", "amiType": "AL2023_x86_64_STANDARD",
                "health": {"issues": [{"code": "AsgInstanceLaunchFailures", "message": "Could not launch On-Demand Instances"}]}},
         "latest": "1.35.0-20261101", "ssm": "/aws/service/eks/optimized-ami/1.35/amazon-linux-2023/x86_64/standard/recommended/release_version"},
        {"ng": {"nodegroupName": "legacy", "version": "1.33", "releaseVersion": "1.33.5-20250801", "amiType": "AL2_x86_64"}, "latest": null,
         "ssm": "/aws/service/eks/optimized-ami/1.33/amazon-linux-2/recommended/release_version"}]'
  got=$(assess 1.35 EXTENDED "[]" "$ngs")
  [ "$(checks <<<"$got")" = "eks.nodegroup_ami_outdated eks.nodegroup_no_ami eks.nodegroup_unhealthy eks.nodegroup_version_skew " ]
  [[ "$(jq -r 'select(.check == "eks.nodegroup_unhealthy") | .fix' <<<"$got")" == *"capacity for that instance type, a subnet out of IPs"* ]]
  [[ "$(jq -r 'select(.check == "eks.nodegroup_version_skew") | .message' <<<"$got")" == *"runs Kubernetes 1.33, 2 minor versions behind the control plane (1.35)"* ]]
  [[ "$(jq -r 'select(.check == "eks.nodegroup_no_ami") | .message' <<<"$got")" == *"no AL2_x86_64 AMI for Kubernetes 1.33"* ]]
}

@test "the sweep reads describe, list and SSM calls only, with the cluster's profile and region" {
  printf '[{"name": "prod", "context": "arn:aws:eks:us-east-2:111111111111:cluster/prod-eks", "aws_profile": "prd", "auth": {"state": "ok"}}]' >"$PMGR_TMP/clusters.json"
  fake 0 '{"cluster": {"name": "prod-eks", "version": "1.32", "upgradePolicy": {"supportType": "EXTENDED"}}}' "" aws eks describe-cluster
  fake 0 "{\"clusterVersions\": $VERSIONS}" "" aws eks describe-cluster-versions
  fake 0 '{"addons": ["coredns"]}' "" aws eks list-addons
  fake 0 '{"addon": {"addonName": "coredns", "addonVersion": "v1.11.1"}}' "" aws eks describe-addon
  fake 0 '{"addons": [{"addonVersions": [{"addonVersion": "v1.11.4"}, {"addonVersion": "v1.11.1"}]}]}' "" aws eks describe-addon-versions
  fake 0 '{"nodegroups": ["general"]}' "" aws eks list-nodegroups
  fake 0 '{"nodegroup": {"nodegroupName": "general", "version": "1.32", "releaseVersion": "1.32.9-20261001", "amiType": "AL2023_x86_64_STANDARD"}}' "" aws eks describe-nodegroup
  fake 0 '{"Parameter": {"Value": "1.32.9-20261101"}}' "" aws ssm get-parameter --name /aws/service/eks/optimized-ami/1.32/amazon-linux-2023/x86_64/standard/recommended/release_version
  export PMGR_NOW=$NOW
  got=$(lifecycle_sweep)
  [ "$(checks <<<"$got")" = "eks.addon_outdated eks.extended_support eks.nodegroup_ami_outdated " ]
  grep -q "eks describe-cluster --name prod-eks --profile prd --region us-east-2" "$FAKE_DIR/calls"
  ! grep -E $'^aws\t' "$FAKE_DIR/calls" | grep -vqE ' (describe|list|get)-'
  [[ "$(jq -r 'select(.type == "lifecycle") | .detail' "$PMGR_TMP/sources.jsonl")" == "Kubernetes 1.32 (extended support), 1 node groups, 1 add-ons with newer versions" ]]
}

@test "an account whose session is broken is listed as not checked" {
  printf '[{"name": "prod", "context": "arn:aws:eks:us-east-2:111111111111:cluster/prod-eks", "aws_profile": "prd", "auth": {"state": "expired"}}]' >"$PMGR_TMP/clusters.json"
  : >"$PMGR_TMP/unseen.txt"
  [ -z "$(lifecycle_sweep)" ]
  [ "$(cat "$PMGR_TMP/unseen.txt")" = "prod: EKS version and support (AWS session not working)" ]
}
