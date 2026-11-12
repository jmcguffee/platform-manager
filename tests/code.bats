#!/usr/bin/env bats
# Where to fix it: findings linked to the line in a local clone that defines the resource.

load helpers

setup() {
  setup_pmgr
  INFRA="$BATS_TEST_TMPDIR/clones/platform-infra" APPS="$BATS_TEST_TMPDIR/clones/platform-apps"
  mkdir -p "$INFRA/modules/db" "$INFRA/.terraform/modules" "$APPS/apps/api/overlays/prd"
  git -C "$INFRA" init -q && git -C "$APPS" init -q
  cat >"$INFRA/modules/db/main.tf" <<'EOF'
resource "aws_db_instance" "orders" {
  identifier = "orders-prd"
  multi_az   = false
}
resource "aws_lb_target_group" "api" {
  name = "prd-api-tg"
}
EOF
  printf 'identifier = "orders-prd"\n' >"$INFRA/.terraform/modules/cached.tf"   # never searched
  cat >"$APPS/apps/api/overlays/prd/deployment.yaml" <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
EOF
  config "clusters: []
github:
  org: my-org
  repos:
    - {name: platform-infra, kind: terraform, path: $INFRA}
    - {name: platform-apps, kind: gitops, path: $APPS}"
}

report() { jq -cn --argjson f "$1" '{findings: $f}'; }

@test "a Terraform resource and a Kustomize workload are linked to their lines" {
  got=$(code_locate "$(report '[
    {"id": "f1", "check": "data.rds_single_az", "resource": "acct/us-east-2/rds/orders-prd", "diag": {"type": "rds", "id": "orders-prd"}},
    {"id": "f2", "check": "apps.single_replica", "resource": "prd/shop/Deployment/api", "diag": {"type": "workload", "name": "api"}},
    {"id": "f3", "check": "compute.imdsv1", "resource": "acct/us-east-2/ec2/x", "diag": {"type": "ec2", "id": "i-0abc"}}]')")
  [ "$(jq -c '.findings[0].where' <<<"$got")" = '[{"repo":"platform-infra","path":"modules/db/main.tf","line":2,"url":"https://github.com/my-org/platform-infra/blob/main/modules/db/main.tf#L2"}]' ]
  [ "$(jq -r '.findings[1].where[0] | "\(.repo)/\(.path):\(.line)"' <<<"$got")" = "platform-apps/apps/api/overlays/prd/deployment.yaml:4" ]
  [ "$(jq -r '.findings[2] | has("where")' <<<"$got")" = false ]   # instance IDs aren't in code
}

@test "a missing target group points at the one Terraform made" {
  got=$(code_locate "$(report '[{"id": "f1", "check": "tgb.target_group_missing", "resource": "prd/shop/tgb/api",
    "evidence": {"wanted": "prd-api-tgt", "closest": "prd-api-tg"}, "diag": {"type": "tgb", "name": "api"}}]')")
  [ "$(jq -r '[.findings[0].where[] | "\(.repo)/\(.path):\(.line)"] | join(" ")' <<<"$got")" = \
    "platform-apps/apps/api/overlays/prd/deployment.yaml:4 platform-infra/modules/db/main.tf:6" ]
}

@test "clones are found in the usual places when no path is set; nothing configured means nothing changes" {
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME/src" && mv "$INFRA" "$HOME/src/"
  config 'clusters: []
github: {org: my-org, repos: [{name: platform-infra, kind: terraform}]}'
  [ "$(code_repo_path platform-infra)" = "$HOME/src/platform-infra" ]
  got=$(code_locate "$(report '[{"id": "f1", "resource": "r", "diag": {"type": "rds", "id": "orders-prd"}}]')")
  [ "$(jq -r '.findings[0].where[0].path' <<<"$got")" = modules/db/main.tf ]
  config 'clusters: []'
  r=$(report '[{"id": "f1", "resource": "r", "diag": {"type": "rds", "id": "orders-prd"}}]')
  [ "$(code_locate "$r")" = "$r" ]
}

@test "the terminal report prints where to fix it" {
  r=$(jq -cn '{findings: [{id: "f1", check: "x", severity: "error", area: "data", resource: "acct/r", message: "m", fix: "f", link: "",
    where: [{repo: "platform-infra", path: "modules/db/main.tf", line: 2, url: "u"}]}], clusters: [], accounts: [], unseen: [], usage_minutes: {}}')
  [[ "$(report_text "$r")" == *"code: platform-infra/modules/db/main.tf:2"* ]]
}
