#!/usr/bin/env bats
# Workflow gap rules and Argo CD Application health.

load helpers

setup() {
  setup_pmgr
  config 'clusters: []'
  WF="$BATS_TEST_TMPDIR/wf"
  mkdir -p "$WF"
}

RISKY='name: Deploy
on:
  pull_request:
jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: actions/setup-node@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
      - run: echo "${{ github.event.pull_request.title }}"
      - run: terraform apply -auto-approve
        continue-on-error: true
'

CAREFUL='name: Plan
on: [pull_request]
permissions:
  contents: read
  id-token: write
concurrency: plan-${{ github.ref }}
jobs:
  plan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd # v3
      - run: terraform fmt -check && terraform validate
      - run: terraform plan
'

@test "a risky workflow trips every rule" {
  printf '%s' "$RISKY" >"$WF/deploy.yml"
  got=$(workflows_assess_file infra deploy.yml "$WF/deploy.yml" | checks)
  [ "$got" = "workflow.apply_on_pr workflow.continue_on_error workflow.no_cache workflow.no_concurrency workflow.no_timeout workflow.permissions workflow.script_injection workflow.static_aws_keys workflow.unpinned " ]
}

@test "a careful workflow is clean" {
  printf '%s' "$CAREFUL" >"$WF/plan.yml"
  [ -z "$(workflows_assess_file infra plan.yml "$WF/plan.yml")" ]
}

@test "broken YAML is reported, not skipped" {
  printf 'on: [push\njobs: {' >"$WF/bad.yml"
  [ "$(workflows_assess_file infra bad.yml "$WF/bad.yml" | jq -r .check)" = workflow.unparseable ]
}

@test "a Terraform repo without plan on pull requests" {
  printf '%s' "${CAREFUL/on: \[pull_request\]/on: [push]}" >"$WF/plan.yml"
  got=$(workflows_assess_repo infra terraform "$WF" | checks)
  [[ "$got" == *workflow.no_pr_checks* && "$got" == *workflow.no_plan_on_pr* && "$got" == *workflow.no_tf_validate* ]]
}

@test "a Terraform repo with plan on pull requests has no repo gaps" {
  printf '%s' "$CAREFUL" >"$WF/plan.yml"
  [ -z "$(workflows_assess_repo infra terraform "$WF")" ]
}

@test "a reusable workflow might hold the check, so the gap stays quiet" {
  printf 'on: pull_request\npermissions: {}\njobs:\n  ci:\n    uses: acme/ci/.github/workflows/tf.yml@main\n' >"$WF/c.yml"
  [[ "$(workflows_assess_repo infra terraform "$WF" | checks)" != *no_plan_on_pr* ]]
}

@test "a GitOps repo that never renders manifests" {
  printf '%s' "$CAREFUL" >"$WF/plan.yml"
  [[ "$(workflows_assess_repo apps gitops "$WF" | checks)" == *workflow.no_manifest_check* ]]
}

@test "a repo with no workflows says so" {
  [ "$(workflows_assess_repo bare app "$WF" | jq -r .check)" = workflow.none ]
}

app() { # name sync health automated(yes|no) [op-json] [extra-status-json]
  jq -cn --arg n "$1" --arg sync "$2" --arg health "$3" --arg auto "$4" --argjson op "${5:-"{}"}" \
    --argjson extra "${6:-"{}"}" '{metadata: {name: $n, namespace: "argocd"},
      spec: {syncPolicy: (if $auto == "yes" then {automated: {}} else {} end)},
      status: ({sync: {status: $sync, revision: "abcdef123456"}, health: {status: $health},
                operationState: $op} + $extra)}'
}

@test "Argo CD: failed, degraded, drifting, waiting, stuck and unrenderable apps" {
  PMGR_NOW=$(jq -n '"2026-11-11T12:00:00Z" | fromdateiso8601')
  export PMGR_NOW
  {
    app ok Synced Healthy yes
    app broken Synced Healthy yes '{"phase":"Failed","message":"one or more objects failed to apply"}'
    app sick Synced Degraded yes '{}' '{"resources":[{"kind":"Deployment","name":"api","health":{"status":"Degraded","message":"progress deadline exceeded"}}]}'
    app drifting OutOfSync Healthy yes
    app waiting OutOfSync Healthy no
    app stuck Synced Healthy yes '{"phase":"Running","startedAt":"2026-11-11T11:00:00Z"}'
    app norender Synced Healthy yes '{}' '{"conditions":[{"type":"ComparisonError","message":"kustomize build failed"}]}'
  } | jq -s '{items: .}' >"$BATS_TEST_TMPDIR/apps.json"
  got=$(argo_assess prod "$BATS_TEST_TMPDIR/apps.json" | jq -s 'map({key: (.resource | split("/") | last), value: .}) | from_entries')
  [ "$(jq 'has("ok")' <<<"$got")" = false ]
  [ "$(jq -r .broken.check <<<"$got")" = argo.sync_failed ]
  [[ "$(jq -r .sick.message <<<"$got")" == *"Deployment/api (progress deadline exceeded)"* ]]
  # `automated: {}` is auto-sync with defaults: drifting under auto-sync is a warning, manual is info.
  [ "$(jq -r .drifting.severity <<<"$got")" = warning ]
  [ "$(jq -r .waiting.severity <<<"$got")" = info ]
  [ "$(jq -r .stuck.check <<<"$got")" = argo.stuck ]
  [ "$(jq -r .norender.check <<<"$got")" = argo.condition ]
}
