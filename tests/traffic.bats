#!/usr/bin/env bats
# Load balancing: TargetGroupBindings checked against the target groups they name.

load helpers

setup() {
  setup_pmgr
  config 'clusters: [{name: prod, context: "arn:aws:eks:us-east-2:111111111111:cluster/prod", aws_profile: prd}]'
}

tgb() { # NS NAME SVC PORT [SPEC_EXTRA] [GEN] [OBSERVED]
  jq -cn --arg ns "$1" --arg n "$2" --arg svc "$3" --argjson port "$4" --argjson extra "${5:-"{}"}" \
    --argjson gen "${6:-1}" --argjson obs "${7:-1}" \
    '{metadata: {namespace: $ns, name: $n, generation: $gen}, status: {observedGeneration: $obs},
      spec: ({targetType: "ip", serviceRef: {name: $svc, port: $port}} + $extra)}'
}
tg() { # NAME TYPE [ATTACHED=true]
  jq -cn --arg n "$1" --arg t "$2" --argjson lb "${3:-true}" \
    '{TargetGroupName: $n, TargetGroupArn: "arn:aws:elasticloadbalancing:us-east-2:111111111111:targetgroup/\($n)/abc",
      TargetType: $t, LoadBalancerArns: (if $lb then ["arn:aws:elasticloadbalancing:us-east-2:111111111111:loadbalancer/app/prd-public/xyz"] else [] end)}'
}
svc() { jq -cn --arg ns "$1" --arg n "$2" --argjson p "$3" '{metadata: {namespace: $ns, name: $n}, spec: {ports: [{name: "http", port: $p}]}}'; }
slice() { jq -cn --arg ns "$1" --arg n "$2" --argjson ready "${3:-true}" \
  '{metadata: {namespace: $ns, labels: {"kubernetes.io/service-name": $n}}, endpoints: [{conditions: {ready: $ready}}]}'; }
target() { jq -cn --arg s "$1" --arg r "${2:-}" --arg d "${3:-}" \
  '{Target: {Id: "10.0.1.5", Port: 8080}, TargetHealth: ({State: $s} + (if $r == "" then {} else {Reason: $r, Description: $d} end))}'; }

# assess TGBS TGS SVCS SLICES HEALTH
assess() {
  jq -cn --argjson tgbs "$1" --argjson tgs "$2" --argjson svcs "$3" --argjson slices "$4" --argjson health "${5:-"{}"}" \
    '{cluster: "prod", region: "us-east-2", profile: "prd", tgbs: {items: $tgbs}, tgs: $tgs,
      svcs: {items: $svcs}, slices: {items: $slices}, health: $health}' | jq -c -f "$PMGR_JQ/traffic.jq"
}
ARN_API="arn:aws:elasticloadbalancing:us-east-2:111111111111:targetgroup/prd-api-tg/abc"

@test "a healthy binding is quiet and becomes a row" {
  got=$(assess "[$(tgb shop api api 80 '{"targetGroupName": "prd-api-tg"}')]" "[$(tg prd-api-tg ip)]" "[$(svc shop api 80)]" "[$(slice shop api)]" \
    "{\"$ARN_API\": [$(target healthy), $(target healthy)]}")
  [ -z "$(checks <<<"$got")" ]
  [ "$(jq -c 'select(.kind == "tgb") | [.state, .healthy, .targets, .load_balancers[0], .target_group]' <<<"$got")" = '["ok",2,2,"prd-public","prd-api-tg"]' ]
}

@test "a target group name that doesn't exist suggests the close one Terraform made" {
  got=$(assess "[$(tgb shop api api 80 '{"targetGroupName": "prd-api-tgt"}')]" "[$(tg prd-api-tg ip), $(tg prd-web-tg ip)]" "[$(svc shop api 80)]" "[$(slice shop api)]")
  [ "$(checks <<<"$got")" = "tgb.target_group_missing " ]
  [[ "$(jq -r 'select(.check) | .message' <<<"$got")" == *"names target group prd-api-tgt, which doesn't exist in us-east-2. The closest one there is prd-api-tg"* ]]
  [[ "$(jq -r 'select(.check) | .fix' <<<"$got")" == *"set the binding's targetGroupName to prd-api-tg"* ]]
}

@test "detached target group, missing service, wrong port, no ready pods, type mismatch" {
  got=$(assess "[$(tgb shop a api 80 '{"targetGroupName": "tg-a"}'), $(tgb shop b nope 80 '{"targetGroupName": "tg-b"}'),
                 $(tgb shop c api 9999 '{"targetGroupName": "tg-c"}'), $(tgb shop d idle 80 '{"targetGroupName": "tg-d"}'),
                 $(tgb shop e api 80 '{"targetGroupName": "tg-e", "targetType": "instance"}')]" \
    "[$(tg tg-a ip false), $(tg tg-b ip), $(tg tg-c ip), $(tg tg-d ip), $(tg tg-e ip)]" \
    "[$(svc shop api 80), $(svc shop idle 80)]" "[$(slice shop api), $(slice shop idle false)]")
  [ "$(checks <<<"$got")" = "tgb.no_endpoints tgb.not_attached tgb.service_missing tgb.service_port_missing tgb.target_type_mismatch " ]
  [[ "$(jq -r 'select(.check == "tgb.service_port_missing") | .message' <<<"$got")" == *"port 9999 of service api, which has ports http 80"* ]]
}

@test "unhealthy targets carry AWS's reason and what usually fixes it" {
  got=$(assess "[$(tgb shop api api 80 '{"targetGroupARN": "'"$ARN_API"'"}')]" "[$(tg prd-api-tg ip)]" "[$(svc shop api 80)]" "[$(slice shop api)]" \
    "{\"$ARN_API\": [$(target unhealthy Target.Timeout 'Request timed out'), $(target unhealthy Target.Timeout 'Request timed out')]}")
  [ "$(checks <<<"$got")" = "tgb.unhealthy_targets " ]
  f=$(jq -c 'select(.check)' <<<"$got")
  [ "$(jq -r .severity <<<"$f")" = error ]   # none healthy: requests fail
  [[ "$(jq -r .message <<<"$f")" == *"0 of 2 targets healthy, so requests to it fail. 2 Target.Timeout (Request timed out)"* ]]
  [[ "$(jq -r .fix <<<"$f")" == *"security group doesn't allow the load balancer's security group"* ]]
  # Some healthy is a warning; targets still settling aren't counted against it.
  got=$(assess "[$(tgb shop api api 80 '{"targetGroupARN": "'"$ARN_API"'"}')]" "[$(tg prd-api-tg ip)]" "[$(svc shop api 80)]" "[$(slice shop api)]" \
    "{\"$ARN_API\": [$(target healthy), $(target unhealthy Target.ResponseCodeMismatch 'Health checks failed with these codes: [404]'), $(target initial Elb.InitialHealthChecking)]}")
  [ "$(jq -r 'select(.check) | .severity' <<<"$got")" = warning ]
  [[ "$(jq -r 'select(.check) | .message' <<<"$got")" == *"1 of 3 targets healthy. 1 Target.ResponseCodeMismatch"* ]]
}

@test "no registered targets, and a change the controller hasn't applied" {
  got=$(assess "[$(tgb shop api api 80 '{"targetGroupName": "prd-api-tg"}' 3 2)]" "[$(tg prd-api-tg ip)]" "[$(svc shop api 80)]" "[$(slice shop api)]" "{\"$ARN_API\": []}")
  [ "$(checks <<<"$got")" = "tgb.no_targets tgb.not_reconciled " ]
}

@test "the sweep reads bindings, services, endpoints and target groups, and flags a target group bound twice" {
  fake 0 "{\"items\": [$(tgb shop api api 80 '{"targetGroupName": "prd-api-tg"}'), $(tgb shop api2 api 80 '{"targetGroupName": "prd-api-tg"}')]}" "" \
    kubectl --context arn:aws:eks:us-east-2:111111111111:cluster/prod --request-timeout=20s get targetgroupbindings.elbv2.k8s.aws
  fake 0 "{\"items\": [$(svc shop api 80)]}" "" kubectl --context arn:aws:eks:us-east-2:111111111111:cluster/prod --request-timeout=20s get services
  fake 0 "{\"items\": [$(slice shop api)]}" "" kubectl --context arn:aws:eks:us-east-2:111111111111:cluster/prod --request-timeout=20s get endpointslices.discovery.k8s.io
  fake 0 "{\"TargetGroups\": [$(tg prd-api-tg ip)]}" "" aws elbv2 describe-target-groups
  fake 0 "{\"TargetHealthDescriptions\": [$(target healthy)]}" "" aws elbv2 describe-target-health
  printf '[{"name": "prod", "context": "arn:aws:eks:us-east-2:111111111111:cluster/prod", "aws_profile": "prd", "kubernetes": "ok"}]' >"$PMGR_TMP/clusters.json"
  got=$(traffic_sweep)
  [ "$(checks <<<"$got")" = "tgb.shared_target_group " ]
  [[ "$(jq -r 'select(.check) | .message' <<<"$got")" == *"bound 2 times (prod/shop/api, prod/shop/api2)"* ]]
  grep -q "describe-target-groups --profile prd --region us-east-2" "$FAKE_DIR/calls"
  ! grep -E $'^aws\t' "$FAKE_DIR/calls" | grep -vqE 'elbv2 describe-'
  ! grep -E $'^kubectl\t' "$FAKE_DIR/calls" | grep -vq ' get '
  [ "$(jq -r 'select(.type == "tgb") | .detail' "$PMGR_TMP/sources.jsonl")" = "2 TargetGroupBindings in us-east-2, 2 healthy" ]
}

@test "no controller CRD is a quiet source note; unreadable bindings are reported as not checked" {
  printf '[{"name": "prod", "context": "ctx", "aws_profile": "prd", "kubernetes": "ok"}]' >"$PMGR_TMP/clusters.json"
  fake 1 "" 'error: the server doesn'"'"'t have a resource type "targetgroupbindings"' kubectl --context ctx --request-timeout=20s get targetgroupbindings.elbv2.k8s.aws
  : >"$PMGR_TMP/unseen.txt"
  [ -z "$(traffic_sweep)" ]
  [[ "$(jq -r .detail "$PMGR_TMP/sources.jsonl")" == *"CRD isn't installed"* ]]
  fake 1 "" 'Error from server (Forbidden): targetgroupbindings is forbidden' kubectl --context ctx --request-timeout=20s get targetgroupbindings.elbv2.k8s.aws
  traffic_sweep >/dev/null
  [[ "$(cat "$PMGR_TMP/unseen.txt")" == "prod: TargetGroupBindings (Error from server (Forbidden)"* ]]
}

@test "Diagnose a binding: describe with events, target health, target group settings, service, endpoints, controller logs" {
  fake 0 "x" "" kubectl
  fake 0 "x" "" aws elbv2
  got=$(diagnose_finding '{"type":"tgb","cluster":"prod","ns":"shop","name":"api","profile":"prd","region":"us-east-2","tg_arn":"'"$ARN_API"'","svc":"api"}')
  [ "$(jq -r .title <<<"$got" | tr '\n' '|')" = "Binding api (with its events)|Target health|Target group settings|Service api|Endpoints of api|Load balancer controller logs (last 40 lines)|" ]
  ! grep -qE 'kubectl.*(delete|apply|patch|edit)' "$FAKE_DIR/calls"
}
