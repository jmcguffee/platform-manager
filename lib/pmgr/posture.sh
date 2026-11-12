# shellcheck shell=bash
# Posture: how each AWS account is set up, beyond internet exposure. One collector reads every
# account (and each of its regions) with describe/list/get calls only; four rule sets judge it:
#   edge      WAF, CloudFront, load balancer listeners and attributes, ACM certificates
#   data      S3 buckets, RDS, Redshift, ElastiCache, Secrets Manager
#   identity  IAM roles, users and trust policies; the account baseline (CloudTrail, GuardDuty, root)
#   compute   EC2 instance metadata, EBS volumes and snapshots, Elastic IPs
# A call that fails for permissions is reported as not checked; "no such configuration" answers
# (no bucket policy, no lifecycle rules) are saved as {"_none": true} so the rules can tell them apart.

POSTURE_PARALLEL=8

posture_cfg() { # LABEL REGION
  cfg '{tag: (.security.environment_tag // "Environment"),
        public_envs: (.security.public_environments // ["prd", "prod", "production"]),
        allowed: (.security.allowed_public // []) + (.posture.ignore // []),
        account_env: (.security.account_environments // {}),
        trusted_accounts: (.posture.trusted_accounts // []),
        unused_days: (.posture.unused_days // 90), key_age_days: (.posture.access_key_max_days // 90),
        cert_warn_days: (.posture.cert_warn_days // 30), snapshot_old_days: (.posture.snapshot_old_days // 365),
        ebs_gb_month: ({gp2: 0.10, gp3: 0.08, io1: 0.125, io2: 0.125, st1: 0.045, sc1: 0.015, standard: 0.05} + (.cost.ebs_gb_month // {})),
        snapshot_gb_month: (.cost.snapshot_gb_month // 0.05), ipv4_month: (.cost.public_ipv4_month // 3.65),
        secret_month: (.cost.secret_month // 0.40)} | tojson' | jq -c --arg l "$1" --arg r "$2" '. + {label: $l, region: $r}'
}

# pwait N : wait until fewer than N background jobs are running (bash 3.2 has no wait -n).
pwait() { while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$1" ]; do sleep 0.05; done; }

# pread FILE LABEL WHAT PROFILE REGION ARGS... : one read-only call into FILE.
pread() {
  local file=$1 label=$2 what=$3 profile=$4 region=$5 key
  shift 5
  key="pr-$(printf '%s' "$file" | cksum | cut -d' ' -f1)"
  if capture "$key" aws "$@" --profile "$profile" --region "$region" --output json --cli-connect-timeout 5 --cli-read-timeout 30; then
    if [ -s "$PMGR_TMP/$key.out" ]; then cp "$PMGR_TMP/$key.out" "$file"; else printf '{}' >"$file"; fi
  elif err "$key" | grep -qE 'NoSuch|NotFound|ServerSideEncryptionConfigurationNotFound|WAFNonexistentItem|OwnershipControlsNotFound'; then
    printf '{"_none": true}' >"$file"
  else
    printf 'null' >"$file"
    [ -z "$what" ] || printf '%s (%s): %s (%s)\n' "$label" "$region" "$what" "$(first_line "$(err "$key")" | cut -c1-120)" >>"$PMGR_TMP/unseen.txt"
  fi
}

# slurp DIR PATTERN : the JSON files matching DIR/PATTERN as one array (missing files skipped).
# shellcheck disable=SC2086  # $2 is a glob on purpose
# (A missing file mustn't fail the pipe: under pipefail, "|| printf" would add a second value.)
slurp() { { cat "$1"/$2 2>/dev/null || true; } | jq -cs . 2>/dev/null || printf '[]'; }

# posture_global LABEL PROFILE DIR : the account-wide reads (IAM, S3, CloudFront, WAF for CloudFront).
posture_global() {
  local label=$1 p=$2 dir=$3 g="us-east-1" b u
  mkdir -p "$dir/s3" "$dir/users"
  pread "$dir/iam.json" "$label" "IAM roles and policies" "$p" "$g" iam get-account-authorization-details --filter Role User LocalManagedPolicy &
  pread "$dir/iam_summary.json" "$label" "IAM account summary" "$p" "$g" iam get-account-summary &
  pread "$dir/oidc.json" "$label" "" "$p" "$g" iam list-open-id-connect-providers &
  pread "$dir/cf.json" "$label" "CloudFront distributions" "$p" "$g" cloudfront list-distributions &
  pread "$dir/waf_cf.json" "$label" "WAF web ACLs for CloudFront" "$p" "$g" wafv2 list-web-acls --scope CLOUDFRONT &
  pread "$dir/trails.json" "$label" "CloudTrail trails" "$p" "$g" cloudtrail describe-trails --include-shadow-trails &
  pread "$dir/buckets.json" "$label" "S3 buckets" "$p" "$g" s3api list-buckets &
  wait

  # Each trail's status (is it logging?).
  local i=0 arn
  for arn in $(jq -r '.trailList[]? | select(.IsMultiRegionTrail) | .TrailARN' "$dir/trails.json" 2>/dev/null); do
    pread "$dir/trail_$i.json" "$label" "" "$p" "$g" cloudtrail get-trail-status --name "$arn" &
    i=$((i + 1))
  done
  # IAM users: access keys, their last use, MFA, console password.
  for u in $(jq -r '.UserDetailList[]?.UserName' "$dir/iam.json" 2>/dev/null); do
    pwait "$POSTURE_PARALLEL"
    (
      d="$dir/users/$(safe_key "$u")"
      mkdir -p "$d"
      pread "$d/keys.json" "$label" "" "$p" "$g" iam list-access-keys --user-name "$u"
      pread "$d/mfa.json" "$label" "" "$p" "$g" iam list-mfa-devices --user-name "$u"
      pread "$d/login.json" "$label" "" "$p" "$g" iam get-login-profile --user-name "$u"
      local k=0 id
      for id in $(jq -r '.AccessKeyMetadata[]?.AccessKeyId' "$d/keys.json" 2>/dev/null); do
        pread "$d/used_$k.json" "$label" "" "$p" "$g" iam get-access-key-last-used --access-key-id "$id"
        k=$((k + 1))
      done
      jq -cn --arg u "$u" --slurpfile keys "$d/keys.json" --slurpfile mfa "$d/mfa.json" --slurpfile login "$d/login.json" \
        --argjson used "$(slurp "$d" 'used_*.json')" \
        '{user: $u, keys: ($keys[0].AccessKeyMetadata // []), mfa: ($mfa[0].MFADevices // null), console: ($login[0] | . != null and (has("_none") | not)),
          last_used: [$used[] | {id: .UserName, at: (.AccessKeyLastUsed.LastUsedDate // null)}]}' >"$d/user.json"
    ) &
  done
  # S3: each bucket's region first, then its policy status and settings there.
  for b in $(jq -r '.Buckets[]?.Name' "$dir/buckets.json" 2>/dev/null); do
    pwait "$POSTURE_PARALLEL"
    (
      d="$dir/s3/$(safe_key "$b")"
      mkdir -p "$d"
      pread "$d/loc.json" "$label" "" "$p" "$g" s3api get-bucket-location --bucket "$b"
      r=$(jq -r '.LocationConstraint // "us-east-1" | if . == "EU" then "eu-west-1" else . end' "$d/loc.json" 2>/dev/null)
      [ -n "$r" ] && [ "$r" != null ] || r=us-east-1
      pread "$d/status.json" "$label" "" "$p" "$r" s3api get-bucket-policy-status --bucket "$b" &
      pread "$d/policy.json" "$label" "" "$p" "$r" s3api get-bucket-policy --bucket "$b" &
      pread "$d/pab.json" "$label" "" "$p" "$r" s3api get-public-access-block --bucket "$b" &
      pread "$d/acl.json" "$label" "" "$p" "$r" s3api get-bucket-acl --bucket "$b" &
      pread "$d/versioning.json" "$label" "" "$p" "$r" s3api get-bucket-versioning --bucket "$b" &
      pread "$d/lifecycle.json" "$label" "" "$p" "$r" s3api get-bucket-lifecycle-configuration --bucket "$b" &
      pread "$d/tags.json" "$label" "" "$p" "$r" s3api get-bucket-tagging --bucket "$b" &
      wait
      jq -cn --arg b "$b" --arg r "$r" --slurpfile status "$d/status.json" --slurpfile policy "$d/policy.json" \
        --slurpfile pab "$d/pab.json" --slurpfile acl "$d/acl.json" --slurpfile ver "$d/versioning.json" \
        --slurpfile lc "$d/lifecycle.json" --slurpfile tags "$d/tags.json" \
        '{name: $b, region: $r, public: ($status[0].PolicyStatus.IsPublic // false),
          policy: ($policy[0].Policy // null | if type == "string" then (fromjson? // null) else . end),
          policy_read: ($policy[0] != null), pab: ($pab[0].PublicAccessBlockConfiguration // null),
          grants: ($acl[0].Grants // []), versioning: ($ver[0].Status // "Off"),
          lifecycle: (if $lc[0] == null then null else ($lc[0].Rules // []) end), tags: ($tags[0].TagSet // [])}' >"$d/bucket.json"
    ) &
  done
  # CloudFront's WAF ACLs and their rules.
  i=0
  while IFS=$'\t' read -r name id; do
    [ -n "$id" ] || continue
    pread "$dir/wafcf_$i.json" "$label" "" "$p" "$g" wafv2 get-web-acl --scope CLOUDFRONT --name "$name" --id "$id" &
    i=$((i + 1))
  done < <(jq -r '.WebACLs[]? | [.Name, .Id] | @tsv' "$dir/waf_cf.json" 2>/dev/null)
  wait
}

# posture_region LABEL PROFILE REGION DIR : one region's reads.
posture_region() {
  local label=$1 p=$2 r=$3 dir=$4 arn i name id
  mkdir -p "$dir/lb" "$dir/waf" "$dir/acm" "$dir/rs"
  pread "$dir/lbs.json" "$label" "load balancers" "$p" "$r" elbv2 describe-load-balancers &
  pread "$dir/sgs.json" "$label" "security groups" "$p" "$r" ec2 describe-security-groups &
  pread "$dir/vpcs.json" "$label" "" "$p" "$r" ec2 describe-vpcs &
  pread "$dir/waf.json" "$label" "WAF web ACLs" "$p" "$r" wafv2 list-web-acls --scope REGIONAL &
  pread "$dir/certs.json" "$label" "ACM certificates" "$p" "$r" acm list-certificates &
  pread "$dir/rds.json" "$label" "RDS instances" "$p" "$r" rds describe-db-instances &
  pread "$dir/aurora.json" "$label" "RDS clusters" "$p" "$r" rds describe-db-clusters &
  pread "$dir/redshift.json" "$label" "Redshift clusters" "$p" "$r" redshift describe-clusters &
  pread "$dir/cache.json" "$label" "ElastiCache replication groups" "$p" "$r" elasticache describe-replication-groups &
  pread "$dir/secrets.json" "$label" "Secrets Manager secrets" "$p" "$r" secretsmanager list-secrets &
  pread "$dir/instances.json" "$label" "EC2 instances" "$p" "$r" ec2 describe-instances &
  pread "$dir/volumes.json" "$label" "EBS volumes" "$p" "$r" ec2 describe-volumes &
  pread "$dir/addresses.json" "$label" "Elastic IPs" "$p" "$r" ec2 describe-addresses &
  pread "$dir/snapshots.json" "$label" "EBS snapshots" "$p" "$r" ec2 describe-snapshots --owner-ids self &
  pread "$dir/ebs_default.json" "$label" "" "$p" "$r" ec2 get-ebs-encryption-by-default &
  pread "$dir/guardduty.json" "$label" "GuardDuty" "$p" "$r" guardduty list-detectors &
  wait

  # Load balancers: listeners, attributes and tags.
  i=0
  for arn in $(jq -r '.LoadBalancers[]?.LoadBalancerArn' "$dir/lbs.json" 2>/dev/null); do
    pwait "$POSTURE_PARALLEL"
    (
      pread "$dir/lb/$i.listeners.json" "$label" "" "$p" "$r" elbv2 describe-listeners --load-balancer-arn "$arn"
      pread "$dir/lb/$i.attrs.json" "$label" "" "$p" "$r" elbv2 describe-load-balancer-attributes --load-balancer-arn "$arn"
      pread "$dir/lb/$i.tags.json" "$label" "" "$p" "$r" elbv2 describe-tags --resource-arns "$arn"
      jq -cn --arg arn "$arn" --slurpfile l "$dir/lb/$i.listeners.json" --slurpfile a "$dir/lb/$i.attrs.json" --slurpfile t "$dir/lb/$i.tags.json" \
        '{arn: $arn, listeners: ($l[0].Listeners // []), attrs: (($a[0].Attributes // []) | map({key: .Key, value: .Value}) | from_entries),
          tags: ($t[0].TagDescriptions[0].Tags // [])}' >"$dir/lb/$i.json"
    ) &
    i=$((i + 1))
  done
  # Regional WAF ACLs: rules, logging, and what they're attached to.
  i=0
  while IFS=$'\t' read -r name id arn; do
    [ -n "$id" ] || continue
    pwait "$POSTURE_PARALLEL"
    (
      pread "$dir/waf/$i.acl.json" "$label" "" "$p" "$r" wafv2 get-web-acl --scope REGIONAL --name "$name" --id "$id"
      pread "$dir/waf/$i.res.json" "$label" "" "$p" "$r" wafv2 list-resources-for-web-acl --web-acl-arn "$arn" --resource-type APPLICATION_LOAD_BALANCER
      pread "$dir/waf/$i.log.json" "$label" "" "$p" "$r" wafv2 get-logging-configuration --resource-arn "$arn"
      jq -cn --slurpfile a "$dir/waf/$i.acl.json" --slurpfile res "$dir/waf/$i.res.json" --slurpfile log "$dir/waf/$i.log.json" \
        '($a[0].WebACL // {}) + {resources: ($res[0].ResourceArns // []), logging: ($log[0] | . != null and (has("_none") | not))}' >"$dir/waf/$i.json"
    ) &
    i=$((i + 1))
  done < <(jq -r '.WebACLs[]? | [.Name, .Id, .ARN] | @tsv' "$dir/waf.json" 2>/dev/null)
  # ACM certificates.
  i=0
  for arn in $(jq -r '.CertificateSummaryList[]?.CertificateArn' "$dir/certs.json" 2>/dev/null); do
    pwait "$POSTURE_PARALLEL"
    pread "$dir/acm/$i.json" "$label" "" "$p" "$r" acm describe-certificate --certificate-arn "$arn" &
    i=$((i + 1))
  done
  # Redshift: require_ssl from each parameter group, and audit logging.
  for id in $(jq -r '.Clusters[]?.ClusterIdentifier' "$dir/redshift.json" 2>/dev/null); do
    pwait "$POSTURE_PARALLEL"
    (
      pg=$(jq -r --arg id "$id" '.Clusters[] | select(.ClusterIdentifier == $id) | .ClusterParameterGroups[0].ParameterGroupName // ""' "$dir/redshift.json")
      [ -z "$pg" ] || pread "$dir/rs/$id.params.json" "$label" "" "$p" "$r" redshift describe-cluster-parameters --parameter-group-name "$pg"
      pread "$dir/rs/$id.log.json" "$label" "" "$p" "$r" redshift describe-logging-status --cluster-identifier "$id"
      jq -cn --arg id "$id" --slurpfile pp "$dir/rs/$id.params.json" --slurpfile lg "$dir/rs/$id.log.json" \
        '{id: $id, require_ssl: ([$pp[0].Parameters[]? | select(.ParameterName == "require_ssl") | .ParameterValue] | first),
          logging: ($lg[0].LoggingEnabled // null)}' >"$dir/rs/$id.json" 2>/dev/null ||
        jq -cn --arg id "$id" '{id: $id, require_ssl: null, logging: null}' >"$dir/rs/$id.json"
    ) &
  done
  # GuardDuty detector status.
  id=$(jq -r '.DetectorIds[0] // ""' "$dir/guardduty.json" 2>/dev/null)
  [ -z "$id" ] || pread "$dir/guardduty_detector.json" "$label" "" "$p" "$r" guardduty get-detector --detector-id "$id" &
  wait
}

# posture_input LABEL REGION GLOBAL_DIR REGION_DIR FIRST : one region's assembled input for the rules.
posture_input() {
  local label=$1 region=$2 g=$3 d=$4 first=$5
  jq -cn --arg label "$label" --arg region "$region" --argjson first "$first" \
    --argjson now "$(jq -n --arg n "${PMGR_NOW:-}" 'if $n == "" then now else ($n | tonumber) end | floor')" \
    --slurpfile iam "$g/iam.json" --slurpfile summary "$g/iam_summary.json" --slurpfile oidc "$g/oidc.json" \
    --slurpfile cf "$g/cf.json" --slurpfile trails "$g/trails.json" \
    --argjson trail_status "$(slurp "$g" 'trail_*.json')" --argjson waf_cf "$(slurp "$g" 'wafcf_*.json')" \
    --argjson users "$(cat "$g"/users/*/user.json 2>/dev/null | jq -cs .)" \
    --argjson buckets "$(cat "$g"/s3/*/bucket.json 2>/dev/null | jq -cs .)" \
    --slurpfile lbs "$d/lbs.json" --slurpfile sgs "$d/sgs.json" --slurpfile vpcs "$d/vpcs.json" \
    --argjson lb_detail "$(cat "$d"/lb/[0-9]*.json 2>/dev/null | jq -cs 'map(select(has("arn")))')" \
    --argjson waf "$(cat "$d"/waf/[0-9]*.json 2>/dev/null | jq -cs 'map(select(has("resources")))')" \
    --argjson acm "$(slurp "$d/acm" '*.json')" \
    --slurpfile rds "$d/rds.json" --slurpfile aurora "$d/aurora.json" --slurpfile redshift "$d/redshift.json" \
    --argjson rs_detail "$(slurp "$d/rs" '*.json' | jq -c 'map(select(has("require_ssl")))')" \
    --slurpfile cache "$d/cache.json" --slurpfile secrets "$d/secrets.json" \
    --slurpfile instances "$d/instances.json" --slurpfile volumes "$d/volumes.json" --slurpfile addresses "$d/addresses.json" \
    --slurpfile snapshots "$d/snapshots.json" --slurpfile ebs_default "$d/ebs_default.json" --slurpfile guardduty "$d/guardduty.json" \
    --argjson gd_detector "$(cat "$d/guardduty_detector.json" 2>/dev/null || printf 'null')" \
    '{label: $label, region: $region, first: $first, now: $now,
      iam: $iam[0], summary: $summary[0], oidc: $oidc[0], cf: $cf[0], trails: $trails[0], trail_status: $trail_status,
      waf_cf: [$waf_cf[] | .WebACL // empty], users: $users, buckets: $buckets,
      lbs: $lbs[0], sgs: $sgs[0], vpcs: $vpcs[0], lb_detail: $lb_detail, waf: $waf, acm: [$acm[] | .Certificate // empty],
      rds: $rds[0], aurora: $aurora[0], redshift: $redshift[0], rs_detail: $rs_detail, cache: $cache[0], secrets: $secrets[0],
      instances: $instances[0], volumes: $volumes[0], addresses: $addresses[0], snapshots: $snapshots[0],
      ebs_default: $ebs_default[0], guardduty: $guardduty[0], gd_detector: $gd_detector}'
}

# posture_account LABEL PROFILE ACCOUNT : read everything, then run each rule set per region.
posture_account() {
  local label=$1 profile=$2 account=$3 base g region first=true area cfgj
  base="$PMGR_TMP/posture/$(safe_key "$profile")"
  g="$base/global"
  mkdir -p "$g"
  posture_global "$label" "$profile" "$g"
  while IFS= read -r region; do
    mkdir -p "$base/$region"
    posture_region "$label" "$profile" "$region" "$base/$region"
    cfgj=$(posture_cfg "$label" "$region")
    posture_input "$label" "$region" "$g" "$base/$region" "$first" >"$base/$region/input.json"
    for area in edge data identity compute; do
      jq -c -L "$PMGR_JQ" --argjson cfg "$cfgj" --arg account "$account" -f "$PMGR_JQ/$area.jq" "$base/$region/input.json"
    done >"$base/$region/rows.jsonl"
    jq -c 'select(.kind)' "$base/$region/rows.jsonl" | metric_rows
    jq -c 'select(has("check"))' "$base/$region/rows.jsonl"
    source_row posture "$label" true "$(jq -rs --arg r "$region" 'map(select(has("check"))) | "Checked edge, data, identity and compute in \($r): \(length) findings"' "$base/$region/rows.jsonl")"
    first=false
  done < <(util_regions "$profile" "$account")
}

posture_sweep() {
  local a
  util_skipped
  while IFS= read -r a; do
    [ -n "$a" ] || continue
    posture_account "$(jq -r .label <<<"$a")" "$(jq -r .profile <<<"$a")" "$(jq -r .account <<<"$a")"
  done < <(util_accounts | jq -c '.[]')
  return 0
}
