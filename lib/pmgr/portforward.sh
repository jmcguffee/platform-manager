# shellcheck shell=bash
# Port-forwards to Argo CD, one per cluster, on a stable local port.
#
# `pmgr pf argo prod` runs `kubectl port-forward svc/argocd-server` for that cluster's context and
# AWS profile, remembers it, and opens Argo in your browser. Nothing in the cluster changes: it's a
# local tunnel through the API server (so a private endpoint still needs VPN).

pf_dir() { printf '%s' "${XDG_CACHE_HOME:-$HOME/.cache}/platform-manager/pf"; }

# A cluster's stable local port: argocd_port from config, else 8080 + its position in the config.
pf_port() {
  jq -r --arg n "$1" '(.clusters // []) as $c | ([$c | to_entries[] | select(.value.name == $n)] | first) as $e
    | if $e == null then empty else ($e.value.argocd_port // (8080 + $e.key)) end' <<<"$PMGR_CONFIG_JSON"
}

pf_alive() { # NAME : 0 if its port-forward process is still running
  local f
  f="$(pf_dir)/$1.json"
  [ -f "$f" ] && kill -0 "$(jq -r .pid "$f")" 2>/dev/null
}

# pf_start CLUSTER_NAME : start (or reuse) the Argo CD port-forward; prints {name, url, pid, reused}.
pf_start() {
  local name=$1 c ctx profile ns svc port remote scheme key dir log pid i
  c=$(diag_cluster "$name")
  [ -n "$c" ] || { printf '{"error": "No cluster named %s in your config."}\n' "$name"; return 1; }
  dir=$(pf_dir)
  mkdir -p "$dir" && chmod 700 "$dir"
  if pf_alive "$name"; then
    jq -c '. + {reused: true}' "$dir/$name.json"
    return 0
  fi
  ctx=$(jq -r .context <<<"$c") profile=$(jq -r .aws_profile <<<"$c")
  ns=$(jq -r '.argocd_namespace // "argocd"' <<<"$c") svc=$(jq -r '.argocd_service // "argocd-server"' <<<"$c")
  port=$(pf_port "$name")
  key="pf-$(safe_key "$name")"

  # Use the service's https port if it has one (443), else http (80, for server.insecure).
  if ! capture "$key-svc" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=15s get svc "$svc" -n "$ns" -o json; then
    jq -cn --arg e "$(first_line "$(err "$key-svc")")" --arg svc "$svc" --arg ns "$ns" --arg name "$name" \
      '{error: "Can'"'"'t read service \($svc) in \($ns) on \($name): \($e)"}'
    return 1
  fi
  # Only TCP ports can be forwarded. Prefer one named https (or 443), then http (or 80), then any TCP port.
  read -r remote scheme < <(out "$key-svc" | jq -r '
    [.spec.ports[] | select((.protocol // "TCP") == "TCP") | {p: .port, name: (.name // "")}] as $ports
    | ([$ports[] | select(.name == "https" or .p == 443)] | first) as $s
    | ([$ports[] | select(.name == "http" or .p == 80)] | first) as $h
    | if $s then "\($s.p) https" elif $h then "\($h.p) http" elif ($ports | length) > 0 then "\($ports[0].p) http" else "" end')
  [ -n "$remote" ] || { jq -cn --arg svc "$svc" '{error: "Service \($svc) has no TCP port to forward."}'; return 1; }

  if port_open "$port"; then
    jq -cn --arg port "$port" --arg name "$name" \
      '{error: "Local port \($port) for \($name) is already in use by something else. Set argocd_port for this cluster in your config."}'
    return 1
  fi
  log="$dir/$name.log"
  # nohup + setsid-like detach: the tunnel outlives this command (stop it with pmgr pf stop).
  AWS_PROFILE="$profile" nohup kubectl --context "$ctx" -n "$ns" port-forward "svc/$svc" "$port:$remote" \
    --address 127.0.0.1 >"$log" 2>&1 </dev/null 3>&- &
  pid=$!
  i=0
  while ! port_open "$port" && [ "$i" -lt 40 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.25; i=$((i + 1)); done
  if ! port_open "$port"; then
    kill "$pid" 2>/dev/null
    jq -cn --arg e "$(tail -n 3 "$log" | tr '\n' ' ')" --arg name "$name" '{error: "The port-forward for \($name) didn'"'"'t start: \($e)"}'
    return 1
  fi
  jq -cn --arg name "$name" --arg url "$scheme://localhost:$port" --argjson pid "$pid" --arg ctx "$ctx" --arg svc "$svc" \
    --arg ns "$ns" --argjson port "$port" \
    '{name: $name, url: $url, pid: $pid, port: $port, context: $ctx, target: "\($ns)/svc/\($svc)", started_at: (now | todateiso8601), reused: false}' \
    | tee "$dir/$name.json"
}

pf_stop() { # NAME
  local f pid
  f="$(pf_dir)/$1.json"
  [ -f "$f" ] || return 0
  pid=$(jq -r .pid "$f")
  # Only stop it if that pid is still our kubectl port-forward.
  if ps -p "$pid" -o command= 2>/dev/null | grep -q "port-forward"; then kill "$pid" 2>/dev/null; fi
  rm -f "$f"
}

pf_list() { # JSON array of known port-forwards with alive true/false
  local f out="[]" name
  for f in "$(pf_dir)"/*.json; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .json)
    out=$(jq -c --slurpfile p "$f" --argjson alive "$(pf_alive "$name" && echo true || echo false)" '. + [$p[0] + {alive: $alive}]' <<<"$out")
  done
  printf '%s' "$out"
}

cmd_pf() {
  local sub=${1:-list}
  [ $# -gt 0 ] && shift
  case $sub in
    list | "")
      local list
      list=$(pf_list)
      if [ "$(jq length <<<"$list")" -eq 0 ]; then printf 'No port-forwards. Start one with: pmgr pf argo CLUSTER\n'; return 0; fi
      jq -r '.[] | "\(if .alive then "running" else "stopped" end)\t\(.name)\t\(.url)\t\(.target)"' <<<"$list" | column -t -s $'\t'
      jq -e 'any(.[]; .alive | not)' <<<"$list" >/dev/null &&
        printf '\nStopped ones usually mean the SSO session expired. Run pmgr pf argo NAME to start it again.\n'
      return 0
      ;;
    argo)
      local names=() n result code=0 no_open=0
      for n in "$@"; do
        case $n in
          --all) while IFS= read -r c; do names+=("$c"); done < <(cfg '.clusters // [] | .[].name') ;;
          --no-open) no_open=1 ;;
          *) names+=("$n") ;;
        esac
      done
      [ "${#names[@]}" -gt 0 ] || die "Usage: pmgr pf argo CLUSTER... | --all"
      for n in "${names[@]}"; do
        result=$(pf_start "$n") || code=1
        if jq -e '.error' <<<"$result" >/dev/null 2>&1; then
          printf '%s: %s\n' "$n" "$(jq -r .error <<<"$result")" >&2
        else
          printf '%s: Argo CD at %s%s\n' "$n" "$(jq -r .url <<<"$result")" "$(jq -r 'if .reused then " (already running)" else "" end' <<<"$result")"
          [ "$no_open" -eq 1 ] || open_url "$(jq -r .url <<<"$result")"
        fi
      done
      [ "$code" -eq 0 ] || printf '\nIf it says forbidden, your role needs pods/portforward in the Argo CD namespace.\n' >&2
      return "$code"
      ;;
    stop)
      if [ "${1:-all}" = all ]; then
        for f in "$(pf_dir)"/*.json; do [ -f "$f" ] && pf_stop "$(basename "$f" .json)"; done
        printf 'Stopped all port-forwards.\n'
      else
        for n in "$@"; do pf_stop "$n" && printf 'Stopped %s.\n' "$n"; done
      fi
      ;;
    *) die "Usage: pmgr pf [list] | pmgr pf argo CLUSTER... | --all | pmgr pf stop [CLUSTER... | all]" ;;
  esac
}
