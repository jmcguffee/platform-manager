# shellcheck shell=bash
# Lifecycle: what ages out. EKS versions (from AWS's own support calendar, describe-cluster-versions),
# extended support cost, add-on versions and health, node group AMIs, version skew and health.
# Needs only the AWS session, not cluster access. Read with describe/list/get calls only.

# aws_json KEY PROFILE REGION ARGS... : one read-only AWS call; JSON in $PMGR_TMP/KEY.out.
aws_json() {
  local key=$1 profile=$2 region=$3
  shift 3
  capture "$key" aws "$@" --profile "$profile" --region "$region" --output json --cli-connect-timeout 5 --cli-read-timeout 30
}

# The SSM parameter holding AWS's recommended AMI release for a node group's AMI type and version.
lifecycle_ami_param() { # AMI_TYPE VERSION
  case $1 in
    AL2023_x86_64_STANDARD) printf '/aws/service/eks/optimized-ami/%s/amazon-linux-2023/x86_64/standard/recommended/release_version' "$2" ;;
    AL2023_ARM_64_STANDARD) printf '/aws/service/eks/optimized-ami/%s/amazon-linux-2023/arm64/standard/recommended/release_version' "$2" ;;
    AL2023_x86_64_NVIDIA) printf '/aws/service/eks/optimized-ami/%s/amazon-linux-2023/x86_64/nvidia/recommended/release_version' "$2" ;;
    AL2_x86_64) printf '/aws/service/eks/optimized-ami/%s/amazon-linux-2/recommended/release_version' "$2" ;;
    AL2_x86_64_GPU) printf '/aws/service/eks/optimized-ami/%s/amazon-linux-2-gpu/recommended/release_version' "$2" ;;
    AL2_ARM_64) printf '/aws/service/eks/optimized-ami/%s/amazon-linux-2-arm64/recommended/release_version' "$2" ;;
    BOTTLEROCKET_x86_64) printf '/aws/service/bottlerocket/aws-k8s-%s/x86_64/latest/image_version' "$2" ;;
    BOTTLEROCKET_ARM_64) printf '/aws/service/bottlerocket/aws-k8s-%s/arm64/latest/image_version' "$2" ;;
  esac
}

# lifecycle_cluster CLUSTER_JSON : findings for one EKS cluster.
lifecycle_cluster() {
  local c=$1 label target name region profile dir key a n i ver
  label=$(jq -r .name <<<"$c") profile=$(jq -r .aws_profile <<<"$c")
  target=$(eks_target "$c")
  [ -n "$target" ] || return 0
  name=${target%%$'\t'*} region=${target#*$'\t'}
  dir="$PMGR_TMP/lifecycle/$(safe_key "$label")"
  mkdir -p "$dir/addons" "$dir/ngs"
  key="lc-$(safe_key "$label")"

  if ! aws_json "$key" "$profile" "$region" eks describe-cluster --name "$name"; then
    printf '%s: EKS version and support (%s)\n' "$label" "$(first_line "$(err "$key")")" >>"$PMGR_TMP/unseen.txt"
    return 0
  fi
  jq '.cluster' "$PMGR_TMP/$key.out" >"$dir/eks.json"
  ver=$(jq -r .version "$dir/eks.json")

  # AWS's support calendar for this region (once per region and profile).
  local vkey
  vkey="lc-versions-$(safe_key "$profile-$region")"
  if [ ! -f "$PMGR_TMP/$vkey.json" ]; then
    if aws_json "$vkey" "$profile" "$region" eks describe-cluster-versions; then
      jq '.clusterVersions // []' "$PMGR_TMP/$vkey.out" >"$PMGR_TMP/$vkey.json"
    else
      printf '[]' >"$PMGR_TMP/$vkey.json"
      printf '%s: EKS support dates (%s; needs AWS CLI 2.22 or later)\n' "$label" "$(first_line "$(err "$vkey")")" >>"$PMGR_TMP/unseen.txt"
    fi
  fi

  # Add-ons and their newest versions for this Kubernetes version; node groups and their AMIs.
  aws_json "$key-addons" "$profile" "$region" eks list-addons --cluster-name "$name" || true
  i=0
  for a in $(jq -r '.addons[]?' "$PMGR_TMP/$key-addons.out" 2>/dev/null); do
    (
      aws_json "$key-a$i" "$profile" "$region" eks describe-addon --cluster-name "$name" --addon-name "$a" || exit 0
      aws_json "$key-av$i" "$profile" "$region" eks describe-addon-versions --addon-name "$a" --kubernetes-version "$ver" || true
      jq -c --slurpfile v "$PMGR_TMP/$key-av$i.out" '{addon: .addon, versions: ($v[0].addons[0].addonVersions // [])}' \
        "$PMGR_TMP/$key-a$i.out" >"$dir/addons/$i.json" 2>/dev/null ||
        jq -c '{addon: .addon, versions: []}' "$PMGR_TMP/$key-a$i.out" >"$dir/addons/$i.json"
    ) &
    i=$((i + 1))
  done
  aws_json "$key-ngs" "$profile" "$region" eks list-nodegroups --cluster-name "$name" || true
  i=0
  for n in $(jq -r '.nodegroups[]?' "$PMGR_TMP/$key-ngs.out" 2>/dev/null); do
    (
      aws_json "$key-n$i" "$profile" "$region" eks describe-nodegroup --cluster-name "$name" --nodegroup-name "$n" || exit 0
      local param latest=""
      param=$(lifecycle_ami_param "$(jq -r '.nodegroup.amiType // ""' "$PMGR_TMP/$key-n$i.out")" "$(jq -r '.nodegroup.version // ""' "$PMGR_TMP/$key-n$i.out")")
      if [ -n "$param" ] && aws_json "$key-ssm$i" "$profile" "$region" ssm get-parameter --name "$param"; then
        latest=$(jq -r '.Parameter.Value // ""' "$PMGR_TMP/$key-ssm$i.out")
      fi
      jq -c --arg latest "$latest" --arg ssm "$param" '{ng: .nodegroup, latest: (if $latest == "" then null else $latest end),
        ssm: (if $ssm == "" then null else $ssm end)}' "$PMGR_TMP/$key-n$i.out" >"$dir/ngs/$i.json"
    ) &
    i=$((i + 1))
  done
  wait

  jq -cn --arg cluster "$label" --arg region "$region" --arg profile "$profile" \
    --argjson now "$(jq -n --arg n "${PMGR_NOW:-}" 'if $n == "" then now else ($n | tonumber) end | floor')" \
    --argjson cost "$(cfg '{standard: (.cost.eks_standard_usd_hour // 0.10), extended: (.cost.eks_extended_usd_hour // 0.60)} | tojson')" \
    --slurpfile eks "$dir/eks.json" --slurpfile versions "$PMGR_TMP/$vkey.json" \
    --argjson addons "$(cat "$dir"/addons/*.json 2>/dev/null | jq -cs .)" \
    --argjson ngs "$(cat "$dir"/ngs/*.json 2>/dev/null | jq -cs .)" \
    '{cluster: $cluster, region: $region, profile: $profile, now: $now, cost: $cost, eks: $eks[0], versions: $versions[0],
      addons: $addons, nodegroups: $ngs}' |
    jq -c -f "$PMGR_JQ/lifecycle.jq" >"$dir/rows.jsonl"
  jq -c 'select(.kind)' "$dir/rows.jsonl" | metric_rows
  jq -c 'select(has("check"))' "$dir/rows.jsonl"
  source_row lifecycle "$label" true "$(jq -rs 'map(select(.kind == "eks_version"))[0] | "Kubernetes \(.version) (\(.status // "status unknown" | ascii_downcase | gsub("_"; " "))), \(.nodegroups) node groups, \(.addons_outdated) add-ons with newer versions"' "$dir/rows.jsonl")"
}

# lifecycle_sweep : every configured EKS cluster whose AWS session works.
lifecycle_sweep() {
  local c
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    case $(jq -r '.auth.state // ""' <<<"$c") in
      ok | expiring) lifecycle_cluster "$c" ;;
      *) [ -n "$(eks_target "$c")" ] && printf '%s: EKS version and support (AWS session not working)\n' "$(jq -r .name <<<"$c")" >>"$PMGR_TMP/unseen.txt" ;;
    esac
  done < <(jq -c '.[]' "$PMGR_TMP/clusters.json")
  return 0
}
