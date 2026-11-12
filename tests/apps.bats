#!/usr/bin/env bats
# Apps: workload configuration rules.

load helpers

setup() {
  setup_pmgr
  config 'clusters: [{name: prd-eks, context: ctx-prd, aws_profile: prd}]'
}

# dep NS NAME REPLICAS CONTAINER_JSON [POD_EXTRA]
dep() {
  jq -cn --arg ns "$1" --arg n "$2" --argjson r "$3" --argjson c "$4" --argjson x "${5:-"{}"}" \
    '{metadata: {namespace: $ns, name: $n}, spec: {replicas: $r, template: {metadata: {labels: {app: $n}}, spec: ({containers: [$c]} + $x)}}}'
}
GOOD='{"name": "app", "image": "registry.example.com/shop/api:1.4.2", "resources": {"limits": {"memory": "512Mi"}}, "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}}}'
SPREAD='{"securityContext": {"runAsNonRoot": true}, "topologySpreadConstraints": [{"topologyKey": "topology.kubernetes.io/zone"}]}'
PDB='{"metadata": {"namespace": "shop", "name": "api"}, "spec": {"maxUnavailable": 1, "selector": {"matchLabels": {"app": "api"}}}, "status": {"disruptionsAllowed": 1}}'

# assess DEPLOYMENTS [PDBS] [DAEMONSETS] [ENV]
assess() {
  jq -cn --argjson d "$1" --argjson p "${2:-[]}" --argjson ds "${3:-[]}" \
    '{deployments: {items: $d}, statefulsets: {items: []}, daemonsets: {items: $ds}, pdbs: {items: $p}}' |
    jq -c --arg cluster prd-eks --arg env "${4-prd}" --argjson system '["kube-system"]' --argjson prd '["prd"]' -f "$PMGR_JQ/apps.jq"
}

@test "a well set up prd deployment is quiet" {
  got=$(assess "[$(dep shop api 3 "$GOOD" "$SPREAD")]" "[$PDB]")   # must succeed, not just print nothing
  [ -z "$got" ]
}

@test "privileged, hostPath, root and :latest" {
  c='{"name": "app", "image": "shop/api:latest", "securityContext": {"privileged": true, "runAsUser": 0}, "resources": {"limits": {"memory": "1Gi"}}, "readinessProbe": {}}'
  got=$(assess "[$(dep shop api 3 "$c" '{"volumes": [{"name": "h", "hostPath": {"path": "/var/run/docker.sock"}}], "topologySpreadConstraints": [{}]}')]" "[$PDB]")
  [ "$(checks <<<"$got")" = "apps.host_path apps.latest_tag apps.may_run_as_root apps.privileged " ]
  [ "$(jq -r 'select(.check == "apps.may_run_as_root") | .severity' <<<"$got")" = warning ]   # runAsUser 0, not just unset
  [[ "$(jq -r 'select(.check == "apps.host_path") | .message' <<<"$got")" == *"/var/run/docker.sock"* ]]
  # An image with no tag at all counts too; a digest doesn't.
  [[ "$(assess "[$(dep shop a 3 "$(jq -c '.image = "nginx"' <<<"$GOOD")" "$SPREAD")]" "[$PDB]" | checks)" == *apps.latest_tag* ]]
  got=$(assess "[$(dep shop api 3 "$(jq -c '.image = "nginx@sha256:abc"' <<<"$GOOD")" "$SPREAD")]" "[$PDB]")
  [ -z "$got" ]
}

@test "in prd: one replica, no PDB, not spread, no readiness probe, no memory limit" {
  got=$(assess "[$(dep shop solo 1 '{"name": "app", "image": "x:1"}' '{"securityContext": {"runAsNonRoot": true}}'),
                 $(dep shop pair 2 "$GOOD" '{"securityContext": {"runAsNonRoot": true}}')]")
  [ "$(jq -r 'select(.check) | "\(.resource | split("/") | last)=\(.check)"' <<<"$got" | sort | tr '\n' ' ')" = \
    "pair=apps.no_pdb pair=apps.not_spread solo=apps.no_memory_limit solo=apps.no_readiness_probe solo=apps.single_replica " ]
  # Outside prd, only the general rules apply.
  [ "$(assess "[$(dep shop solo 1 '{"name": "app", "image": "x:1"}' '{"securityContext": {"runAsNonRoot": true}}')]" "[]" "[]" dev | checks)" = "apps.no_memory_limit apps.no_readiness_probe " ]
}

@test "a PDB that allows no evictions with every pod healthy blocks drains; system namespaces are skipped" {
  stuck='{"metadata": {"namespace": "shop", "name": "db"}, "spec": {"minAvailable": 3}, "status": {"disruptionsAllowed": 0, "currentHealthy": 3, "desiredHealthy": 3, "expectedPods": 3}}'
  got=$(assess "[]" "[$stuck]")
  [ "$(checks <<<"$got")" = "apps.pdb_blocks_drain " ]
  [[ "$(jq -r 'select(.check) | .message' <<<"$got")" == *"(minAvailable 3, 3 pods), so node drains and upgrades hang on it"* ]]
  got=$(assess "[$(dep kube-system coredns 1 '{"name": "c", "image": "c:latest", "securityContext": {"privileged": true}}')]")
  [ -z "$got" ]
}

@test "the sweep reads with kubectl get only, and says what it couldn't read" {
  printf '[{"name": "prd-eks", "context": "ctx-prd", "aws_profile": "prd", "kubernetes": "ok"}]' >"$PMGR_TMP/clusters.json"
  fake 0 "{\"items\": [$(dep shop solo 1 "$GOOD" "$SPREAD")]}" "" kubectl --context ctx-prd --request-timeout=20s get deployments
  fake 0 '{"items": []}' "" kubectl --context ctx-prd --request-timeout=20s get statefulsets
  fake 0 '{"items": []}' "" kubectl --context ctx-prd --request-timeout=20s get daemonsets
  fake 1 "" "Error from server (Forbidden): poddisruptionbudgets.policy is forbidden" kubectl --context ctx-prd --request-timeout=20s get poddisruptionbudgets.policy
  : >"$PMGR_TMP/unseen.txt"
  got=$(apps_sweep)
  [ "$(checks <<<"$got")" = "apps.single_replica " ]   # prd from the cluster's name
  [[ "$(cat "$PMGR_TMP/unseen.txt")" == "prd-eks: pdbs for app checks (Error from server (Forbidden)"* ]]
  ! grep -E $'^kubectl\t' "$FAKE_DIR/calls" | grep -vq ' get '
}
