#!/usr/bin/env bats
# End to end: bin/pmgr against fake aws, kubectl and gh.

load helpers

setup() {
  setup_pmgr
  PMGR="$PMGR_ROOT/bin/pmgr"
  cat >"$PMGR_CONFIG" <<'EOF'
pim: {activation_url: "https://pim.example/activate"}
clusters:
  - {name: staging, context: ctx-staging, aws_profile: stg}
  - {name: prod, context: ctx-prod, aws_profile: prd, pim_group: AWS-Prod}
github:
  org: acme
  repos:
    - {name: platform-infra, kind: terraform}
EOF
  local gh=acme/platform-infra
  fake 0 "$(identity)" "" aws sts get-caller-identity --profile stg
  fake 255 "" "An error occurred (ForbiddenException) when calling the GetRoleCredentials operation: No access" \
    aws sts get-caller-identity --profile prd
  fake 1 "" "" aws configure
  fake 0 $'yes\n' "" kubectl --context ctx-staging --request-timeout=8s
  fake 0 '{"items":[{"metadata":{"name":"api"},"spec":{},"status":{"health":{"status":"Degraded"}}}]}' "" \
    kubectl --context ctx-staging --request-timeout=15s
  fake 0 "ctx-prod" "" kubectl config current-context
  fake 0 "switched" "" kubectl config use-context
  fake 0 "{}" "" gh api --method GET orgs/acme
  fake 0 '{"default_branch":"main"}' "" gh api --method GET "repos/$gh"
  fake 0 "$(jq -cn '{workflow_runs: [
      {id: 1000, name: "Apply", path: ".github/workflows/apply.yml", head_branch: "main", status: "completed",
       conclusion: "success", created_at: "2026-11-01T10:00:00Z", run_started_at: "2026-11-01T10:00:05Z", updated_at: "2026-11-01T10:05:00Z"},
      {id: 1001, name: "Apply", path: ".github/workflows/apply.yml", head_branch: "main", status: "completed",
       conclusion: "failure", created_at: "2026-11-01T11:00:00Z", run_started_at: "2026-11-01T11:00:05Z", updated_at: "2026-11-01T11:05:00Z",
       html_url: "https://github.com/acme/platform-infra/actions/runs/1001"}]}')" "" \
    gh api --method GET "repos/$gh/actions/runs?"
  fake 0 '{"jobs":[{"id":7,"name":"apply","conclusion":"failure","steps":[{"name":"Apply","conclusion":"failure"}]}]}' "" \
    gh api --method GET "repos/$gh/actions/runs/1001/jobs"
  fake 0 $'Error: Error acquiring the state lock\n##[error]Process completed with exit code 1.\n' "" \
    gh api --method GET -H "Accept: application/vnd.github.raw" "repos/$gh/actions/jobs/7/logs"
  fake 0 '[{"type":"file","name":"apply.yml","path":".github/workflows/apply.yml"}]' "" \
    gh api --method GET "repos/$gh/contents/.github/workflows"
  fake 0 $'on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: terraform apply\n' "" \
    gh api --method GET -H "Accept: application/vnd.github.raw" "repos/$gh/contents/.github/workflows/apply.yml"
}

@test "doctor sees the whole platform" {
  run "$PMGR" doctor --format json --out "$BATS_TEST_TMPDIR/report.json"
  [ "$status" -eq 1 ]
  r="$BATS_TEST_TMPDIR/report.json"
  got=$(jq -c '.findings[]' "$r" | checks)
  for c in auth.no_access argo.degraded pipeline.broken workflow.no_plan_on_pr workflow.no_concurrency; do
    [[ "$got" == *"$c "* ]] || { echo "missing $c in: $got"; return 1; }
  done
  [ "$(jq -r '.findings[] | select(.check == "auth.no_access") | .link' "$r")" = "https://pim.example/activate" ]
  [[ "$(jq -r '.findings[] | select(.check == "auth.no_access") | .fix' "$r")" == *AWS-Prod* ]]
  [[ "$(jq -r '.findings[] | select(.check == "pipeline.broken") | .fix' "$r")" == *force-unlock* ]]
  [ "$(jq -r '.unseen | index("prod: Argo CD (no cluster access)") != null' "$r")" = true ]
}

@test "markdown report" {
  run "$PMGR" doctor --format md
  [[ "${lines[0]}" == "# Platform report"* ]]
  [[ "$output" == *"## Pipelines"* ]]
  [[ "$output" == *"| * | prod |"* ]]
}

@test "use refuses a cluster without access, and switches a healthy one" {
  run "$PMGR" use prod
  [ "$status" -eq 1 ]
  [[ "$output" == *pim.example* ]]
  ! grep -q "config use-context" "$FAKE_DIR/calls"
  run "$PMGR" use staging
  [ "$status" -eq 0 ]
  grep -q "config use-context ctx-staging" "$FAKE_DIR/calls"
}

@test "env prints exports that are safe to eval" {
  run "$PMGR" env prod
  [ "$output" = "export AWS_PROFILE=prd" ]
}

@test "a GitHub org blocked by SAML SSO is explained" {
  fake 1 "" "Resource protected by organization SAML enforcement. You must grant your OAuth token access." \
    gh api --method GET orgs/acme
  run "$PMGR" pipelines --format json
  [ "$(jq -r '.findings[0].check' <<<"$output")" = github.saml ]
  [ "$(jq -r '.findings[0].link' <<<"$output")" = "https://github.com/orgs/acme/sso" ]
}

@test "the dashboard embeds the report, and data can't close its script tag" {
  fake 0 '{"items":[{"metadata":{"name":"</script><img src=x>"},"spec":{},"status":{"health":{"status":"Degraded"}}}]}' "" \
    kubectl --context ctx-staging --request-timeout=15s
  run "$PMGR" ui --no-open
  html="$XDG_CACHE_HOME/platform-manager/dashboard.html"
  [ -f "$html" ]
  [ "$(stat -f %Lp "$html" 2>/dev/null || stat -c %a "$html")" = 600 ]
  grep -q 'id="pmgr-data"' "$html"
  grep -q '<style>' "$html"
  ! grep -q '</script><img' "$html"
  grep -q '<\\/script><img' "$html"
}

@test "init reads EKS contexts from kubeconfig and writes a private config" {
  rm -f "$PMGR_CONFIG"
  fake 0 "$(jq -cn '{contexts: [
      {name: "arn:aws:eks:us-east-1:111:cluster/prod", context: {user: "u1"}},
      {name: "demo", context: {user: "u3"}},
      {name: "kind-local", context: {user: "u2"}}],
    users: [
      {name: "u1", user: {exec: {command: "aws", args: ["--region","us-east-1","eks","get-token","--cluster-name","prod","--profile","prd"]}}},
      {name: "u3", user: {exec: {command: "aws", args: ["--region","us-east-2","eks","get-token","--cluster-name","demo"], env: [{name: "AWS_PROFILE", value: "dev"}]}}},
      {name: "u2", user: {}}]}')" "" kubectl config view
  run "$PMGR" init --from-kubeconfig
  [ "$status" -eq 0 ]
  [ "$(stat -f %Lp "$PMGR_CONFIG" 2>/dev/null || stat -c %a "$PMGR_CONFIG")" = 600 ]
  got=$(yq -o=json '.clusters' "$PMGR_CONFIG")
  [ "$(jq -c '.[0]' <<<"$got")" = '{"name":"prod","context":"arn:aws:eks:us-east-1:111:cluster/prod","aws_profile":"prd","region":"us-east-1"}' ]
  [ "$(jq -c '.[1]' <<<"$got")" = '{"name":"demo","context":"demo","aws_profile":"dev","region":"us-east-2","eks_cluster":"demo"}' ]
  [ "$(jq length <<<"$got")" = 2 ]
}
