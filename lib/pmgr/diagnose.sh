# shellcheck shell=bash
# Diagnose: for one finding, run the read-only commands you'd run by hand (describe, events,
# logs, the failing job's log) and return their output as sections.
#
# The finding's `diag` spec says what to look at. It comes from pmgr's own report, never from the
# browser, so the dashboard can only ask to diagnose findings pmgr produced.
#
# Output: JSON lines {title, command, output, ok}.

DIAG_MAX_LINES=150

# shell_words ARGS... : the args as you'd type them: single-quoted only when they need it.
shell_words() {
  local a out=""
  for a in "$@"; do
    case $a in
      *[[:space:]\'\"\`\$\|\&\;\(\)\<\>\*\?\[\]\{\}]* | "") out="$out'$(printf '%s' "$a" | sed "s/'/'\\\\''/g")' " ;;
      *) out="$out$a " ;;
    esac
  done
  printf '%s' "${out% }"
}

# diag_section TITLE CMD... : run a read-only command and print one section.
diag_section() {
  local title=$1 key code=0 text show
  shift
  key="diag-$(printf '%s' "$title" | tr -c 'A-Za-z0-9' '_' | cut -c1-40)-$RANDOM"
  capture "$key" "$@" || code=$?
  text=$( { out "$key"; err "$key"; } | tail -n "$DIAG_MAX_LINES")
  # Show the command as you'd type it, not pmgr's internal helper.
  case $1 in
    diag_k8s) show="kubectl --context $(jq -r .context <<<"$2") $(shell_words "${@:3}")" ;;
    diag_argo_status) show="kubectl --context $(jq -r .context <<<"$2") get applications.argoproj.io $4 -n $3 -o json  (summarized)" ;;
    diag_lb_listeners) show="aws elbv2 describe-listeners --load-balancer-arn <arn of $(jq -r .id <<<"$2")>" ;;
    *) show=$(shell_words "$@") ;;
  esac
  # A container that never restarted has no previous logs: say that plainly.
  if [ "$code" -ne 0 ] && printf '%s' "$text" | grep -q 'previous terminated container .* not found'; then
    text="No previous run to show: this container hasn't restarted." code=0
  fi
  jq -cn --arg title "$title" --arg command "${show% }" \
    --arg output "${text:-"(no output)"}" --argjson ok "$([ "$code" -eq 0 ] && echo true || echo false)" \
    '{title: $title, command: $command, output: $output, ok: $ok}'
}

# A cluster's context and profile from the config, by name.
diag_cluster() {
  jq -c --arg n "$1" '[.clusters // [] | .[] | select(.name == $n)] | first // empty' <<<"$PMGR_CONFIG_JSON"
}

diag_k8s() { # CLUSTER_JSON ARGS... : kubectl against that cluster with its AWS profile
  local c=$1
  shift
  env AWS_PROFILE="$(jq -r .aws_profile <<<"$c")" kubectl --context "$(jq -r .context <<<"$c")" --request-timeout=20s "$@"
}

diag_events() { # CLUSTER_JSON NS KIND NAME
  local c=$1 ns=$2 kind=$3 name=$4
  local args=(get events --sort-by=.lastTimestamp --field-selector "involvedObject.name=$name${kind:+,involvedObject.kind=$kind}")
  if [ -n "$ns" ]; then args+=(-n "$ns"); else args+=(-A); fi
  diag_section "Events for $name" diag_k8s "$c" "${args[@]}"
}

diagnose_finding() { # DIAG_JSON
  local d=$1 type c
  type=$(jq -r '.type // ""' <<<"$d")
  case $type in
    pod | workload | node | object | argo | capacity | tgb)
      c=$(diag_cluster "$(jq -r .cluster <<<"$d")")
      [ -n "$c" ] || { jq -cn '{title: "Cluster", command: "", output: "This cluster is no longer in your config.", ok: false}'; return 0; }
      ;;
  esac
  local ns kind name pod container
  ns=$(jq -r '.ns // ""' <<<"$d") kind=$(jq -r '.kind // ""' <<<"$d") name=$(jq -r '.name // ""' <<<"$d")
  pod=$(jq -r '.pod // ""' <<<"$d") container=$(jq -r '.container // ""' <<<"$d")
  case $type in
    pod)
      diag_section "Pod $pod" diag_k8s "$c" describe pod "$pod" -n "$ns"
      diag_events "$c" "$ns" Pod "$pod"
      if [ -n "$container" ]; then
        diag_section "Previous logs of $container (the run that crashed)" diag_k8s "$c" logs "$pod" -n "$ns" -c "$container" --previous --tail=80
        diag_section "Current logs of $container" diag_k8s "$c" logs "$pod" -n "$ns" -c "$container" --tail=40
      fi
      if [ -n "$kind" ] && [ "$kind" != Pod ]; then
        diag_section "$kind $name" diag_k8s "$c" describe "$(lower "$kind")" "$name" -n "$ns"
      fi
      ;;
    workload)
      diag_section "$kind $name" diag_k8s "$c" describe "$(lower "$kind")" "$name" -n "$ns"
      diag_events "$c" "$ns" "$kind" "$name"
      diag_section "Pods in $ns" diag_k8s "$c" get pods -n "$ns" -o wide
      ;;
    node)
      diag_section "Node $name" diag_k8s "$c" describe node "$name"
      diag_events "$c" "" Node "$name"
      diag_section "Pods on $name" diag_k8s "$c" get pods -A -o wide --field-selector "spec.nodeName=$name"
      ;;
    object)
      diag_section "$kind $name" diag_k8s "$c" describe "$(lower "$kind")" "$name" ${ns:+-n "$ns"}
      diag_events "$c" "$ns" "$kind" "$name"
      ;;
    argo)
      diag_section "Argo CD status for $name" diag_argo_status "$c" "$ns" "$name"
      diag_events "$c" "$ns" Application "$name"
      ;;
    run) diag_run "$d" ;;
    sg)
      diag_section "Security group $(jq -r .id <<<"$d")" aws ec2 describe-security-groups --group-ids "$(jq -r .id <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" --output table
      diag_section "What uses it" aws ec2 describe-network-interfaces --filters "Name=group-id,Values=$(jq -r .id <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" \
        --query 'NetworkInterfaces[].{Type:InterfaceType,Description:Description,PrivateIp:PrivateIpAddress,PublicIp:Association.PublicIp}' --output table
      ;;
    lb)
      diag_section "Load balancer $(jq -r .id <<<"$d")" aws elbv2 describe-load-balancers --names "$(jq -r .id <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" \
        --query 'LoadBalancers[].{Scheme:Scheme,Type:Type,DNS:DNSName,VPC:VpcId,SecurityGroups:join(`, `,SecurityGroups || `[]`)}' --output table
      diag_section "Listeners" diag_lb_listeners "$d"
      ;;
    auth)
      diag_section "AWS error for profile $(jq -r .profile <<<"$d")" aws sts get-caller-identity --profile "$(jq -r .profile <<<"$d")"
      diag_section "How the profile is set up" aws configure list --profile "$(jq -r .profile <<<"$d")"
      ;;
    monitor)
      diag_section "Monitor $(jq -r .id <<<"$d")" "$(cfg '.datadog.pup // "pup"')" monitors get "$(jq -r .id <<<"$d")" --read-only -o yaml
      ;;
    page)
      diag_section "Page $(jq -r .id <<<"$d")" "$(cfg '.datadog.pup // "pup"')" on-call pages get "$(jq -r .id <<<"$d")" --read-only -o yaml
      ;;
    incident)
      diag_section "Incident $(jq -r .id <<<"$d")" "$(cfg '.datadog.pup // "pup"')" incidents get "$(jq -r .id <<<"$d")" --read-only -o yaml
      ;;
    rds | redshift | elasticache | msk | ec2 | eks | s3 | cloudfront | acm | secret | iam_role | iam_user | ebs) diag_aws "$d" ;;
    cluster) diag_cluster_access "$d" ;;
    eks_addon)
      diag_section "Add-on $(jq -r .addon <<<"$d")" aws eks describe-addon --cluster-name "$(jq -r .cluster <<<"$d")" --addon-name "$(jq -r .addon <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" --output yaml
      diag_section "Versions for this cluster" aws eks describe-addon-versions --addon-name "$(jq -r .addon <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" --output table \
        --query 'addons[0].addonVersions[0:8].{Version:addonVersion,Default:compatibilities[0].defaultVersion}'
      ;;
    eks_nodegroup)
      diag_section "Node group $(jq -r .nodegroup <<<"$d")" aws eks describe-nodegroup --cluster-name "$(jq -r .cluster <<<"$d")" --nodegroup-name "$(jq -r .nodegroup <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" --output yaml \
        --query 'nodegroup.{status:status,version:version,releaseVersion:releaseVersion,amiType:amiType,capacityType:capacityType,instanceTypes:instanceTypes,scaling:scalingConfig,health:health,launchTemplate:launchTemplate,asg:resources.autoScalingGroups}'
      local asg
      asg=$(aws eks describe-nodegroup --cluster-name "$(jq -r .cluster <<<"$d")" --nodegroup-name "$(jq -r .nodegroup <<<"$d")" \
        --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" --query 'nodegroup.resources.autoScalingGroups[0].name' --output text 2>/dev/null)
      [ -z "$asg" ] || [ "$asg" = None ] || diag_section "Recent Auto Scaling activity" aws autoscaling describe-scaling-activities --auto-scaling-group-name "$asg" \
        --max-items 8 --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" --output table \
        --query 'Activities[].{When:StartTime,Status:StatusCode,What:Description,Why:StatusMessage}'
      ;;
    tgb)
      local p r arn svc
      p=$(jq -r .profile <<<"$d") r=$(jq -r .region <<<"$d") arn=$(jq -r '.tg_arn // ""' <<<"$d") svc=$(jq -r '.svc // ""' <<<"$d")
      diag_section "Binding $name (with its events)" diag_k8s "$c" describe "$TGB_RESOURCE" "$name" -n "$ns"
      if [ -n "$arn" ]; then
        diag_section "Target health" aws elbv2 describe-target-health --target-group-arn "$arn" --profile "$p" --region "$r" --output table \
          --query 'TargetHealthDescriptions[].{Target:Target.Id,Port:Target.Port,Zone:Target.AvailabilityZone,State:TargetHealth.State,Reason:TargetHealth.Reason,Description:TargetHealth.Description}'
        diag_section "Target group settings" aws elbv2 describe-target-groups --target-group-arns "$arn" --profile "$p" --region "$r" --output table \
          --query 'TargetGroups[].{Name:TargetGroupName,Type:TargetType,Protocol:Protocol,Port:Port,HealthPath:HealthCheckPath,HealthPort:HealthCheckPort,Matcher:Matcher.HttpCode,Healthy:HealthyThresholdCount,Unhealthy:UnhealthyThresholdCount,LoadBalancers:join(`, `,LoadBalancerArns)}'
      fi
      if [ -n "$svc" ]; then
        diag_section "Service $svc" diag_k8s "$c" get service "$svc" -n "$ns" -o wide
        diag_section "Endpoints of $svc" diag_k8s "$c" get endpointslices.discovery.k8s.io -n "$ns" -l "kubernetes.io/service-name=$svc" -o wide
      fi
      diag_section "Load balancer controller logs (last 40 lines)" diag_k8s "$c" logs -n kube-system deployment/aws-load-balancer-controller --tail=40
      ;;
    capacity)
      diag_section "Node usage right now" diag_k8s "$c" top nodes
      diag_section "Nodes" diag_k8s "$c" get nodes -o wide -L node.kubernetes.io/instance-type,karpenter.sh/capacity-type,eks.amazonaws.com/capacityType
      ;;
    workflow_file)
      diag_section "$(jq -r .path <<<"$d") in $(jq -r .repo <<<"$d")" gh api --method GET -H "Accept: application/vnd.github.raw" \
        "repos/$(gh_slug "$(jq -r .repo <<<"$d")")/contents/$(jq -r .path <<<"$d")"
      ;;
    runs)
      diag_section "Last 15 runs of $(jq -r .workflow <<<"$d")" gh run list -R "$(gh_slug "$(jq -r .repo <<<"$d")")" \
        --workflow "$(jq -r 'if (.path // "") != "" then .path | split("/") | last else .workflow end' <<<"$d")" --limit 15 --json status,conclusion,headBranch,event,attempt,createdAt,startedAt,updatedAt,databaseId \
        --template '{{tablerow "WHEN" "BRANCH" "EVENT" "RESULT" "ATTEMPT" "RUN"}}{{range .}}{{tablerow (timeago .createdAt) .headBranch .event (or .conclusion .status) .attempt .databaseId}}{{end}}'
      ;;
    *) jq -cn '{title: "Diagnose", command: "", output: "There is nothing more to look up for this finding.", ok: false}' ;;
  esac
}

# AWS resources: the settings that matter, and the last day of AWS events for it.
diag_aws() {
  local d=$1 type id p r
  type=$(jq -r .type <<<"$d") id=$(jq -r '.id // .name' <<<"$d") p=$(jq -r .profile <<<"$d") r=$(jq -r '.region // "us-east-1"' <<<"$d")
  case $type in
    rds)
      diag_section "RDS instance $id" aws rds describe-db-instances --db-instance-identifier "$id" --profile "$p" --region "$r" --output table \
        --query 'DBInstances[].{Class:DBInstanceClass,Engine:Engine,Version:EngineVersion,Status:DBInstanceStatus,MultiAZ:MultiAZ,Public:PubliclyAccessible,StorageGB:AllocatedStorage,MaxStorageGB:MaxAllocatedStorage,Endpoint:Endpoint.Address}'
      diag_section "RDS events, last 24 hours" aws rds describe-events --source-type db-instance --source-identifier "$id" --duration 1440 \
        --profile "$p" --region "$r" --output table --query 'Events[].{When:Date,Message:Message}' ;;
    redshift)
      diag_section "Redshift cluster $id" aws redshift describe-clusters --cluster-identifier "$id" --profile "$p" --region "$r" --output table \
        --query 'Clusters[].{NodeType:NodeType,Nodes:NumberOfNodes,Status:ClusterStatus,Public:PubliclyAccessible,Endpoint:Endpoint.Address}'
      diag_section "Redshift events, last 24 hours" aws redshift describe-events --source-type cluster --source-identifier "$id" --duration 1440 \
        --profile "$p" --region "$r" --output table --query 'Events[].{When:Date,Message:Message}' ;;
    elasticache)
      diag_section "ElastiCache $id" aws elasticache describe-replication-groups --replication-group-id "$id" --profile "$p" --region "$r" --output table \
        --query 'ReplicationGroups[].{Status:Status,NodeType:CacheNodeType,Nodes:length(MemberClusters),Failover:AutomaticFailover,MultiAZ:MultiAZ}'
      diag_section "ElastiCache events, last 24 hours" aws elasticache describe-events --duration 1440 --profile "$p" --region "$r" --output table \
        --query "Events[?starts_with(SourceIdentifier, '$id')].{When:Date,Source:SourceIdentifier,Message:Message}" ;;
    msk)
      diag_section "MSK cluster $id" aws kafka list-clusters-v2 --cluster-name-filter "$id" --profile "$p" --region "$r" --output table \
        --query 'ClusterInfoList[].{State:State,Brokers:Provisioned.NumberOfBrokerNodes,Type:Provisioned.BrokerNodeGroupInfo.InstanceType,Storage:Provisioned.BrokerNodeGroupInfo.StorageInfo.EbsStorageInfo.VolumeSize,Version:Provisioned.CurrentBrokerSoftwareInfo.KafkaVersion}' ;;
    ec2)
      diag_section "Instance $id" aws ec2 describe-instances --instance-ids "$id" --profile "$p" --region "$r" --output table \
        --query 'Reservations[].Instances[].{Type:InstanceType,State:State.Name,PublicIp:PublicIpAddress,PrivateIp:PrivateIpAddress,Subnet:SubnetId,Groups:join(`, `,SecurityGroups[].GroupId),IMDS:MetadataOptions.HttpTokens,HopLimit:MetadataOptions.HttpPutResponseHopLimit,Role:IamInstanceProfile.Arn}' ;;
    ebs)
      diag_section "Volume $id" aws ec2 describe-volumes --volume-ids "$id" --profile "$p" --region "$r" --output table \
        --query 'Volumes[].{Size:Size,Type:VolumeType,State:State,Encrypted:Encrypted,Created:CreateTime,Zone:AvailabilityZone,Snapshot:SnapshotId,Tags:join(`, `,Tags[].join(`=`,[Key,Value]) || `[]`)}' ;;
    s3)
      diag_section "Is it public? (AWS's evaluation)" aws s3api get-bucket-policy-status --bucket "$id" --profile "$p" --region "$r" --output table
      diag_section "Block Public Access for the bucket" aws s3api get-public-access-block --bucket "$id" --profile "$p" --region "$r" --output table
      diag_section "Bucket policy" aws s3api get-bucket-policy --bucket "$id" --profile "$p" --region "$r" --query Policy --output text
      diag_section "ACL grants" aws s3api get-bucket-acl --bucket "$id" --profile "$p" --region "$r" --output table \
        --query 'Grants[].{Grantee:Grantee.URI || Grantee.DisplayName || Grantee.ID,Permission:Permission}'
      diag_section "Versioning" aws s3api get-bucket-versioning --bucket "$id" --profile "$p" --region "$r" --output table
      diag_section "Lifecycle rules" aws s3api get-bucket-lifecycle-configuration --bucket "$id" --profile "$p" --region "$r" --output yaml ;;
    cloudfront)
      diag_section "Distribution $id" aws cloudfront get-distribution --id "$id" --profile "$p" --output yaml \
        --query 'Distribution.DistributionConfig.{Aliases:Aliases.Items,WebACL:WebACLId,Viewer:ViewerCertificate,Default:DefaultCacheBehavior.ViewerProtocolPolicy,Origins:Origins.Items[].{Domain:DomainName,OAC:OriginAccessControlId,Protocol:CustomOriginConfig.OriginProtocolPolicy},Logging:Logging}' ;;
    acm)
      diag_section "Certificate" aws acm describe-certificate --certificate-arn "$id" --profile "$p" --region "$r" --output yaml \
        --query 'Certificate.{Domain:DomainName,Names:SubjectAlternativeNames,Status:Status,Type:Type,NotAfter:NotAfter,Renewal:RenewalSummary,Eligible:RenewalEligibility,InUseBy:InUseBy,Validation:DomainValidationOptions[].{Domain:DomainName,Status:ValidationStatus,Record:ResourceRecord}}' ;;
    secret)
      diag_section "Secret (metadata only, never the value)" aws secretsmanager describe-secret --secret-id "$id" --profile "$p" --region "$r" --output yaml \
        --query '{Name:Name,Rotation:RotationEnabled,Rules:RotationRules,Lambda:RotationLambdaARN,LastRotated:LastRotatedDate,NextRotation:NextRotationDate,LastAccessed:LastAccessedDate,Versions:VersionIdsToStages}' ;;
    iam_role)
      diag_section "Role $id" aws iam get-role --role-name "$id" --profile "$p" --output yaml \
        --query 'Role.{Arn:Arn,Created:CreateDate,LastUsed:RoleLastUsed,MaxSession:MaxSessionDuration,Trust:AssumeRolePolicyDocument}'
      diag_section "Attached policies" aws iam list-attached-role-policies --role-name "$id" --profile "$p" --output table
      diag_section "Inline policies" aws iam list-role-policies --role-name "$id" --profile "$p" --output table ;;
    iam_user)
      diag_section "Access keys" aws iam list-access-keys --user-name "$id" --profile "$p" --output table
      diag_section "MFA devices" aws iam list-mfa-devices --user-name "$id" --profile "$p" --output table
      diag_section "Groups" aws iam list-groups-for-user --user-name "$id" --profile "$p" --output table --query 'Groups[].GroupName'
      diag_section "Attached policies" aws iam list-attached-user-policies --user-name "$id" --profile "$p" --output table ;;
    eks)
      diag_section "EKS cluster $id" aws eks describe-cluster --name "$id" --profile "$p" --region "$r" --output table \
        --query 'cluster.{Status:status,Version:version,PublicEndpoint:resourcesVpcConfig.endpointPublicAccess,PrivateEndpoint:resourcesVpcConfig.endpointPrivateAccess,PublicCIDRs:join(`, `,resourcesVpcConfig.publicAccessCidrs || `[]`),Endpoint:endpoint}' ;;
  esac
}

# A cluster pmgr couldn't use: what EKS says about it, whether its endpoint resolves, and your
# kubeconfig entry for it.
diag_cluster_access() {
  local d=$1 c target name region profile ctx endpoint
  c=$(diag_cluster "$(jq -r .cluster <<<"$d")")
  [ -n "$c" ] || { jq -cn '{title: "Cluster", command: "", output: "This cluster is no longer in your config.", ok: false}'; return 0; }
  profile=$(jq -r .aws_profile <<<"$c") ctx=$(jq -r .context <<<"$c")
  target=$(eks_target "$c")
  if [ -n "$target" ]; then
    name=${target%%$'\t'*} region=${target#*$'\t'}
    diag_section "What EKS says about $name" aws eks describe-cluster --name "$name" --profile "$profile" --region "$region" --output table \
      --query 'cluster.{Status:status,Version:version,PublicEndpoint:resourcesVpcConfig.endpointPublicAccess,PrivateEndpoint:resourcesVpcConfig.endpointPrivateAccess,PublicCIDRs:join(`, `,resourcesVpcConfig.publicAccessCidrs || `[]`),Endpoint:endpoint}'
    diag_section "Node groups" aws eks list-nodegroups --cluster-name "$name" --profile "$profile" --region "$region" --output table
  fi
  diag_section "Your kubeconfig entry" kubectl config view --minify --context "$ctx" -o 'jsonpath={.clusters[0].cluster.server}{"\n"}{.users[0].user.exec.command} {.users[0].user.exec.args}{"\n"}'
  endpoint=$(kubectl config view --minify --context "$ctx" -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null | sed -E 's#^https?://##; s#[:/].*##')
  [ -z "$endpoint" ] || diag_section "Does the endpoint resolve? (a private endpoint only resolves on VPN)" nslookup "$endpoint"
}

# The parts of an Argo CD Application's status that explain a failure, readable.
diag_argo_status() {
  local c=$1 ns=$2 name=$3
  diag_k8s "$c" get applications.argoproj.io "$name" -n "$ns" -o json | jq -r '
    .status as $s
    | "Sync: \($s.sync.status // "?") at \(($s.sync.revision // "")[0:12])    Health: \($s.health.status // "?")",
      (if $s.operationState then "Last operation: \($s.operationState.phase) – \($s.operationState.message // "")" else empty end),
      "",
      (($s.conditions // [])[] | "Condition \(.type): \(.message)"),
      (($s.operationState.syncResult.resources // [])[] | select(.status != "Synced")
        | "Sync \(.status): \(.kind)/\(.name) in \(.namespace // "-"): \(.message // "")"),
      (($s.resources // [])[] | select((.health.status // "Healthy") | IN("Healthy", "Suspended") | not)
        | "Health \(.health.status): \(.kind)/\(.name): \(.health.message // "")")'
}

diag_lb_listeners() {
  local d=$1 arn
  arn=$(aws elbv2 describe-load-balancers --names "$(jq -r .id <<<"$d")" --profile "$(jq -r .profile <<<"$d")" \
    --region "$(jq -r .region <<<"$d")" --query 'LoadBalancers[0].LoadBalancerArn' --output text) || return 1
  aws elbv2 describe-listeners --load-balancer-arn "$arn" --profile "$(jq -r .profile <<<"$d")" --region "$(jq -r .region <<<"$d")" \
    --query 'Listeners[].{Port:Port,Protocol:Protocol,Certificate:Certificates[0].CertificateArn}' --output table
}

# A failed GitHub Actions run: its failing jobs and steps, then each failed job's log tail.
diag_run() {
  local d=$1 repo run slug job id
  repo=$(jq -r .repo <<<"$d") run=$(jq -r .run_id <<<"$d")
  slug=$(gh_slug "$repo")
  diag_section "Jobs in run $run" gh run view "$run" -R "$slug"
  while IFS=$'\t' read -r id job; do
    [ -n "$id" ] || continue
    diag_section "Log of failed job: $job (last $DIAG_MAX_LINES lines)" gh api --method GET -H "Accept: application/vnd.github.raw" "repos/$slug/actions/jobs/$id/logs"
  done < <(gh api --method GET "repos/$slug/actions/runs/$run/jobs?per_page=100" 2>/dev/null |
    jq -r '[.jobs[] | select(.conclusion | IN("failure", "timed_out", "startup_failure"))][:3][] | [.id, .name] | @tsv')
}

# cmd_diagnose TERM : find findings in the last report whose resource or message matches, and
# diagnose one. With several matches, list them so you can be more specific.
cmd_diagnose() {
  local term=${1:-} report matches n
  report="$(pmgr_cache)/last-report.json"
  [ -n "$term" ] || die "Usage: pmgr diagnose NAME   (part of a finding's resource, e.g. checkout or sg-0abc)"
  [ -f "$report" ] || die "No report yet. Run pmgr doctor or pmgr ui first."
  matches=$(jq -c --arg t "$(lower "$term")" '[.findings[] | select(.diag != null)
    | select((.id == $t) or ((.resource + " " + .message) | ascii_downcase | contains($t)))]' "$report")
  n=$(jq length <<<"$matches")
  if [ "$n" -eq 0 ]; then die "No finding with something to diagnose matches '$term'."; fi
  if [ "$n" -gt 1 ]; then
    printf 'Several findings match. Be more specific, or use an id:\n' >&2
    jq -r '.[] | "  \(.id)  \(.resource): \(.message[0:90])"' <<<"$matches" >&2
    return 2
  fi
  printf '%s\n\n' "$(jq -r '.[0] | "\(.resource): \(.message)"' <<<"$matches")"
  diagnose_finding "$(jq -c '.[0].diag' <<<"$matches")" | jq -r '"── \(.title) " + ("─" * ([60 - (.title | length), 3] | max)), "$ \(.command)", .output, ""'
}
