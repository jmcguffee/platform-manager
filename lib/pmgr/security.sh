# shellcheck shell=bash
# Internet exposure by environment: security groups, load balancers, public data services, EKS API
# endpoints, instances with public IPs, and S3 Block Public Access. Read-only describe/list calls.

security_cfg() {
  cfg '{tag: (.security.environment_tag // "Environment"),
        public_envs: (.security.public_environments // ["prd", "prod", "production"]),
        allowed: (.security.allowed_public // []),
        account_env: (.security.account_environments // {}),
        web_ports: (.security.web_ports // [80, 443])} | tojson'
}

# sec_read KEY PROFILE REGION ARGS... : one aws describe call into $dir/KEY.json ("null" when it fails).
sec_read() {
  local key=$1 profile=$2 region=$3
  shift 3
  if capture "sec-$key" aws "$@" --profile "$profile" --region "$region" --output json \
    --cli-connect-timeout 5 --cli-read-timeout 30; then
    cp "$PMGR_TMP/sec-$key.out" "$SEC_DIR/$key.json"
  else
    printf 'null' >"$SEC_DIR/$key.json"
    return 1
  fi
}

# security_account LABEL PROFILE ACCOUNT_ID : findings for one account (its configured region).
security_account() {
  local label=$1 profile=$2 account=$3 region missing="" svc
  region=$(util_region "$profile")
  SEC_DIR="$PMGR_TMP/sec/$(safe_key "$profile")"
  mkdir -p "$SEC_DIR"

  sec_read sgs "$profile" "$region" ec2 describe-security-groups &
  sec_read vpcs "$profile" "$region" ec2 describe-vpcs &
  sec_read lbs "$profile" "$region" elbv2 describe-load-balancers &
  sec_read rds "$profile" "$region" rds describe-db-instances &
  sec_read redshift "$profile" "$region" redshift describe-clusters &
  sec_read msk "$profile" "$region" kafka list-clusters-v2 &
  sec_read eks-list "$profile" "$region" eks list-clusters &
  sec_read instances "$profile" "$region" ec2 describe-instances --filters Name=instance-state-name,Values=running &
  wait
  for svc in sgs lbs instances; do [ "$(cat "$SEC_DIR/$svc.json")" = null ] && missing="$missing $svc"; done

  # S3 Block Public Access: "no configuration" means every setting is off.
  if capture "sec-s3pab" aws s3control get-public-access-block --account-id "$account" --profile "$profile" \
    --region "$region" --output json --cli-connect-timeout 5 --cli-read-timeout 15; then
    cp "$PMGR_TMP/sec-s3pab.out" "$SEC_DIR/s3pab.json"
  elif err sec-s3pab | grep -q NoSuchPublicAccessBlockConfiguration; then
    printf '{"PublicAccessBlockConfiguration": {}}' >"$SEC_DIR/s3pab.json"
  else
    printf 'null' >"$SEC_DIR/s3pab.json"
  fi

  # Load balancer tags (20 ARNs per call) and each EKS cluster's endpoint settings.
  printf '{"TagDescriptions": []}' >"$SEC_DIR/lb_tags.json"
  local arns=() arn
  while IFS= read -r arn; do [ -n "$arn" ] && arns+=("$arn"); done < <(jq -r '.LoadBalancers[]?.LoadBalancerArn' "$SEC_DIR/lbs.json" 2>/dev/null)
  local i=0
  while [ "$i" -lt "${#arns[@]}" ]; do
    if sec_read "lbtags-$i" "$profile" "$region" elbv2 describe-tags --resource-arns "${arns[@]:$i:20}"; then
      jq -s '{TagDescriptions: (.[0].TagDescriptions + .[1].TagDescriptions)}' "$SEC_DIR/lb_tags.json" "$SEC_DIR/lbtags-$i.json" \
        >"$SEC_DIR/lb_tags.tmp" && mv "$SEC_DIR/lb_tags.tmp" "$SEC_DIR/lb_tags.json"
    fi
    i=$((i + 20))
  done
  printf '[]' >"$SEC_DIR/eks.json"
  local name
  for name in $(jq -r '.clusters[]?' "$SEC_DIR/eks-list.json" 2>/dev/null); do
    if sec_read "eks-$(safe_key "$name")" "$profile" "$region" eks describe-cluster --name "$name"; then
      jq -s '.[0] + [.[1].cluster]' "$SEC_DIR/eks.json" "$SEC_DIR/eks-$(safe_key "$name").json" >"$SEC_DIR/eks.tmp" &&
        mv "$SEC_DIR/eks.tmp" "$SEC_DIR/eks.json"
    fi
  done

  jq -cn --arg label "$label" --arg region "$region" \
    --slurpfile sgs "$SEC_DIR/sgs.json" --slurpfile vpcs "$SEC_DIR/vpcs.json" --slurpfile lbs "$SEC_DIR/lbs.json" \
    --slurpfile lb_tags "$SEC_DIR/lb_tags.json" --slurpfile rds "$SEC_DIR/rds.json" --slurpfile redshift "$SEC_DIR/redshift.json" \
    --slurpfile msk "$SEC_DIR/msk.json" --slurpfile eks "$SEC_DIR/eks.json" --slurpfile instances "$SEC_DIR/instances.json" \
    --slurpfile s3pab "$SEC_DIR/s3pab.json" \
    '{label: $label, region: $region, sgs: $sgs[0], vpcs: $vpcs[0], lbs: $lbs[0], lb_tags: $lb_tags[0], rds: $rds[0],
      redshift: $redshift[0], msk: $msk[0], eks: $eks[0], instances: $instances[0], s3pab: $s3pab[0]}' |
    jq -c --argjson cfg "$(security_cfg)" -f "$PMGR_JQ/security.jq" >"$SEC_DIR/rows.jsonl"
  jq -c 'select(.kind == "exposure")' "$SEC_DIR/rows.jsonl" | metric_rows
  jq -c 'select(has("check"))' "$SEC_DIR/rows.jsonl"

  local n_exposed n_flagged
  n_exposed=$(jq -s 'map(select(.kind == "exposure")) | length' "$SEC_DIR/rows.jsonl")
  n_flagged=$(jq -s 'map(select(has("check"))) | length' "$SEC_DIR/rows.jsonl")
  if [ -n "$missing" ]; then
    source_row security "$label" false "Checked $region, but couldn't read:$missing" \
      "Your role needs ec2:Describe*, elasticloadbalancing:Describe*, rds/redshift/kafka/eks describe and list permissions."
  else
    source_row security "$label" true "$n_exposed internet-reachable resources in $region, $n_flagged flagged"
  fi
}

# security_sweep : every account with a working session, once per AWS account.
security_sweep() {
  local a
  while IFS= read -r a; do
    [ -n "$a" ] || continue
    security_account "$(jq -r .label <<<"$a")" "$(jq -r .profile <<<"$a")" "$(jq -r .account <<<"$a")"
  done < <(util_accounts | jq -c '.[]')
  return 0
}
