# shellcheck shell=bash
# Cluster access: is each cluster reachable with your session, and does it still exist?

safe_key() { printf '%s' "$1" | tr -c 'A-Za-z0-9_-' '_'; }

# k8s_classify TEXT : why kubectl failed.
k8s_classify() {
  local t
  t=$(lower "$1")
  case $t in
    *"context was not found"* | *"context \""*"does not exist"*) echo no_context ;;
    *unauthorized* | *"must be logged in"* | *"getting credentials"* | *"exec plugin"*) echo unauthorized ;;
    *forbidden*) echo forbidden ;;
    *"unable to connect"* | *"i/o timeout"* | *"dial tcp"* | *"no such host"* | *"deadline exceeded"* | \
      *"connection refused"*) echo unreachable ;;
    *) echo unknown ;;
  esac
}

# k8s_check CONTEXT PROFILE : prints "STATE<tab>DETAIL".
k8s_check() {
  local ctx=$1 profile=$2 key code answer
  key="k8s-$(safe_key "$ctx")"
  # AWS_PROFILE points the kubeconfig's aws exec plugin at this cluster's profile.
  code=0
  capture "$key" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=8s auth can-i get namespaces || code=$?
  answer=$(lower "$(out "$key" | tr -d '[:space:]')")
  if [ "$code" -eq 127 ]; then
    printf 'unknown\tkubectl is not on PATH\n'
  elif [ "$code" -eq 0 ] && [ "$answer" = "yes" ]; then
    printf 'ok\t\n'
  elif [ "$answer" = "no" ] && [ -z "$(err "$key" | tr -d '[:space:]')" ]; then
    printf 'limited\tAuthenticated, but not allowed to list namespaces\n'
  else
    printf '%s\t%s\n' "$(k8s_classify "$(err "$key") $(out "$key")")" "$(first_line "$(err "$key")$(out "$key")")"
  fi
}

# eks_target CLUSTER_JSON : prints "NAME<tab>REGION" for EKS API calls, or nothing.
eks_target() {
  jq -r '
    (.eks_cluster // "") as $name | (.region // "") as $region | .context as $ctx
    | if ($ctx | startswith("arn:aws:eks:")) and ($ctx | contains(":cluster/"))
      then [($name | if . == "" then ($ctx | split("/") | last) else . end),
            ($region | if . == "" then ($ctx | split(":")[3]) else . end)]
      else [$name, $region] end
    | if .[0] != "" and .[1] != "" then join("\t") else empty end' <<<"$1"
}

# eks_state CLUSTER_JSON : for an unreachable cluster, ask EKS whether it still exists.
# Prints "gone|not_active<tab>DETAIL", or nothing when it's ACTIVE or unknown.
eks_state() {
  local target name region profile key status
  target=$(eks_target "$1")
  [ -n "$target" ] || return 0
  name=${target%%$'\t'*} region=${target#*$'\t'}
  profile=$(jq -r '.aws_profile' <<<"$1")
  key="eks-$(safe_key "$name-$region")"
  if capture "$key" aws eks describe-cluster --name "$name" --region "$region" --profile "$profile" \
    --query cluster.status --output text --cli-connect-timeout 5 --cli-read-timeout 15; then
    status=$(out "$key" | tr -d '[:space:]')
    [ -n "$status" ] && [ "$status" != "ACTIVE" ] && printf "not_active\tEKS cluster '%s' is %s\n" "$name" "$status"
  elif err "$key" | grep -qi resourcenotfoundexception; then
    printf "gone\tEKS cluster '%s' doesn't exist in %s\n" "$name" "$region"
  fi
  return 0
}

current_context() {
  capture current-context kubectl config current-context && out current-context | tr -d '\n'
}

# cluster_findings STATUS_JSON : findings for one cluster's combined status.
cluster_findings() {
  local status=$1 name pim_group
  name=$(jq -r '.name' <<<"$status")
  pim_group=$(jq -r '.pim_group // ""' <<<"$status")
  auth_findings "$name" "$pim_group" "$(jq -c '.auth' <<<"$status")"

  # The exec plugin often includes the AWS error, which says more than "Unauthorized".
  local k8s detail aws_state
  k8s=$(jq -r '.kubernetes' <<<"$status")
  detail=$(jq -r '.detail' <<<"$status")
  if [ "$k8s" = unauthorized ]; then
    aws_state=$(auth_classify "$detail")
    if [ "$aws_state" = expired ] || [ "$aws_state" = no_access ]; then
      auth_findings "$name" "$pim_group" "$(jq -c --arg s "$aws_state" --arg d "$detail" \
        '.auth + {state: $s, detail: $d}' <<<"$status")"
      return 0
    fi
  fi

  jq -c --arg pim "$(pim_url)" '
    . as $c | {area: "cluster", resource: .name, evidence: {context: .context}, link: ""} as $base
    | if .kubernetes == "gone" then $base + {check: "cluster.gone", severity: "warning",
        message: "\(.detail). The kubeconfig context is stale.",
        fix: "Remove it with `kubectl config delete-context \(.context)` and drop '"'"'\(.name)'"'"' from your config."}
      elif .kubernetes == "not_active" then $base + {check: "cluster.not_active", severity: "warning",
        message: .detail, fix: "Wait for the operation to finish, or check the cluster'"'"'s health in the EKS console."}
      elif .kubernetes == "unreachable" then $base + {check: "cluster.unreachable", severity: "error",
        message: "Can'"'"'t reach the \(.name) API server: \(.detail)",
        fix: "If the endpoint is private, connect to VPN. Otherwise check the cluster'"'"'s public access CIDRs."}
      elif .kubernetes == "unauthorized" then $base + {check: "cluster.unauthorized", severity: "error",
        message: "\(.name) rejected your credentials: \(.detail)",
        fix: "Your role (\(if .auth.arn == "" then .aws_profile else .auth.arn end)) may be missing an EKS access entry, or the kubeconfig exec uses a different profile. Re-run `aws eks update-kubeconfig --name <cluster> --profile \(.aws_profile)`."}
      elif .kubernetes == "forbidden" then $base + {check: "cluster.forbidden", severity: "error",
        message: "\(.name) authenticated you but denied access: \(.detail)",
        fix: "Check the EKS access entry and access policy for your role."}
      elif .kubernetes == "limited" then $base + {check: "cluster.limited", severity: "warning",
        message: "\(.name): \(.detail)", link: $pim,
        fix: (if $pim == "" then "Expected for read-only roles." else "Expected for read-only roles. For admin work, activate the admin PIM group." end)}
      elif .kubernetes == "no_context" then $base + {check: "cluster.no_context", severity: "error",
        message: "kubeconfig has no context '"'"'\(.context)'"'"'",
        fix: "Run `aws eks update-kubeconfig --name <cluster> --profile \(.aws_profile) --alias \(.context)`."}
      elif .kubernetes == "unknown" then $base + {check: "cluster.unknown", severity: "error",
        message: "Cluster check for \(.name) failed: \(.detail)",
        fix: "Run `kubectl --context \(.context) auth can-i get namespaces` to see the full error."}
      else empty end' <<<"$status"
}

# access_sweep [CLUSTER_NAME...] : checks clusters (all, or just these) and, when unfiltered, the
# account-only profiles. Writes $PMGR_TMP/clusters.json and accounts.json; prints findings as JSON lines.
access_sweep() {
  local filter="" c profile role key i n
  [ $# -gt 0 ] && filter=$(printf '%s\n' "$@" | jq -R . | jq -cs .)
  mkdir -p "$PMGR_TMP/auth" "$PMGR_TMP/k8s"

  local clusters accounts
  clusters=$(jq -c --argjson only "${filter:-null}" \
    '[.clusters // [] | .[] | select($only == null or (.name as $n | $only | index($n)))]' <<<"$PMGR_CONFIG_JSON")
  if [ -z "$filter" ]; then
    accounts=$(jq -c '([.clusters // [] | .[].aws_profile]) as $covered
      | [.aws.profiles // [] | .[] | select(. as $p | $covered | index($p) | not)]
      | map({name: ., aws_profile: ., expected_role: "", pim_group: ""})' <<<"$PMGR_CONFIG_JSON")
  else
    accounts='[]'
  fi

  # 1. One AWS check per distinct (profile, expected role), in parallel.
  while IFS=$'\t' read -r profile role; do
    [ -n "$profile" ] || continue
    key=$(safe_key "$profile|$role")
    auth_check "$profile" "$role" >"$PMGR_TMP/auth/$key.json" &
  done < <(jq -r '.[] | [.aws_profile, (.expected_role // "")] | @tsv' <<<"$clusters $accounts" | sort -u)
  wait

  # 2. Kubernetes checks, only where the AWS session works (otherwise they'd repeat the same cause).
  n=$(jq 'length' <<<"$clusters")
  i=0
  while [ "$i" -lt "$n" ]; do
    c=$(jq -c ".[$i]" <<<"$clusters")
    key=$(safe_key "$(jq -r '[.aws_profile, (.expected_role // "")] | join("|")' <<<"$c")")
    case $(jq -r '.state' "$PMGR_TMP/auth/$key.json") in
      ok | expiring) k8s_check "$(jq -r .context <<<"$c")" "$(jq -r .aws_profile <<<"$c")" >"$PMGR_TMP/k8s/$i.tsv" & ;;
      *) printf 'skipped\t\n' >"$PMGR_TMP/k8s/$i.tsv" ;;
    esac
    i=$((i + 1))
  done
  wait

  # 3. "No such host" for a deleted cluster looks just like a VPN problem. Ask EKS which it is.
  i=0
  while [ "$i" -lt "$n" ]; do
    if [ "$(cut -f1 "$PMGR_TMP/k8s/$i.tsv")" = unreachable ]; then
      (
        verdict=$(eks_state "$(jq -c ".[$i]" <<<"$clusters")")
        [ -n "$verdict" ] && printf '%s\n' "$verdict" >"$PMGR_TMP/k8s/$i.tsv"
      ) &
    fi
    i=$((i + 1))
  done
  wait

  local active statuses="" state detail
  active=$(current_context)
  i=0
  while [ "$i" -lt "$n" ]; do
    c=$(jq -c ".[$i]" <<<"$clusters")
    key=$(safe_key "$(jq -r '[.aws_profile, (.expected_role // "")] | join("|")' <<<"$c")")
    IFS=$'\t' read -r state detail <"$PMGR_TMP/k8s/$i.tsv"
    statuses="$statuses$(jq -c --slurpfile auth "$PMGR_TMP/auth/$key.json" --arg k8s "$state" \
      --arg detail "${detail:-}" --arg active "$active" \
      '. + {auth: $auth[0], kubernetes: $k8s, detail: $detail, current: (.context == $active)}' <<<"$c")
"
    i=$((i + 1))
  done
  printf '%s' "$statuses" | jq -cs . >"$PMGR_TMP/clusters.json"

  local acct_statuses=""
  n=$(jq 'length' <<<"$accounts")
  i=0
  while [ "$i" -lt "$n" ]; do
    c=$(jq -c ".[$i]" <<<"$accounts")
    key=$(safe_key "$(jq -r '.aws_profile' <<<"$c")|")
    acct_statuses="$acct_statuses$(jq -c --slurpfile auth "$PMGR_TMP/auth/$key.json" '. + {auth: $auth[0]}' <<<"$c")
"
    i=$((i + 1))
  done
  printf '%s' "$acct_statuses" | jq -cs . >"$PMGR_TMP/accounts.json"

  # Findings.
  jq -c '.[]' "$PMGR_TMP/clusters.json" | while IFS= read -r c; do cluster_findings "$c"; done
  jq -c '.[]' "$PMGR_TMP/accounts.json" | while IFS= read -r c; do
    auth_findings "$(jq -r .name <<<"$c")" "" "$(jq -c .auth <<<"$c")"
  done
}
