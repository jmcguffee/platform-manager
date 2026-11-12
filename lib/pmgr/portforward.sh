# shellcheck shell=bash
# Port-forwards to Argo CD, one per cluster, and its login from AWS Secrets Manager.
#
# `pmgr pf argo prod` runs `kubectl port-forward svc/argocd-server` for that cluster's context and
# AWS profile, remembers it, and opens Argo in your browser. Nothing in the cluster changes: it's a
# local tunnel through the API server (so a private endpoint still needs VPN).
#
# Ports: argocd_port is fixed. Otherwise the port it used last time, else 8080 + the cluster's
# position, and if that one is taken, a free port the OS picks.
#
# Login: argocd_secret names a Secrets Manager secret (plain text, or JSON with a password key).
# The password goes to the clipboard and nowhere else: not stdout, the report, the logs or the browser.

pf_dir() { printf '%s' "$(pmgr_cache)/pf"; }

# A cluster's stable local port: argocd_port from config, else 8080 + its position in the config.
pf_port() {
  jq -r --arg n "$1" '(.clusters // []) as $c | ([$c | to_entries[] | select(.value.name == $n)] | first) as $e
    | if $e == null then empty else ($e.value.argocd_port // (8080 + $e.key)) end' <<<"$PMGR_CONFIG_JSON"
}

# Each environment gets its own host name, like dev.localhost. Browsers keep cookies per host, not
# per port, so on plain localhost every Argo CD would share one login cookie and signing in to a
# second environment would sign you out of the first. *.localhost always means this machine.
pf_host() {
  local label
  label=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed -E 's/-+/-/g; s/^-//; s/-$//' | cut -c1-63)
  if [ -n "$label" ]; then printf '%s.localhost' "$label"; else printf 'localhost'; fi
}

pf_fixed_port() { # NAME : argocd_port if the config sets one
  jq -r --arg n "$1" '[.clusters // [] | .[] | select(.name == $n)] | first | .argocd_port // empty' <<<"$PMGR_CONFIG_JSON"
}

pf_free_port() { # a port nothing is listening on, picked by the OS
  perl -MIO::Socket::INET -e '$s = IO::Socket::INET->new(Listen => 1, LocalAddr => "127.0.0.1", LocalPort => 0) or exit 1; print $s->sockport'
}

# The port a cluster's tunnel will use if started now: fixed, else last used, else 8080 + position.
pf_planned_port() {
  local fixed last
  fixed=$(pf_fixed_port "$1")
  [ -z "$fixed" ] || { printf '%s' "$fixed"; return; }
  last=$(tr -cd 0-9 2>/dev/null <"$(pf_dir)/$1.port")
  if [ -n "$last" ]; then printf '%s' "$last"; else pf_port "$1"; fi
}

# pf_probe PORT [PREFERRED_SCHEME] : send a real request through the tunnel and print the scheme
# Argo CD answered on (https or http), or nothing. kubectl opens the local port before it has
# reached the pod, so an open port alone proves nothing: this is what makes the browser work.
pf_probe() {
  local port=$1 first=${2:-https} scheme code
  for scheme in "$first" $([ "$first" = https ] && echo http || echo https); do
    code=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time "${PF_PROBE_SECONDS:-8}" "$scheme://127.0.0.1:$port/" 2>/dev/null)
    case $code in 000 | "") ;; *) printf '%s' "$scheme"; return 0 ;; esac
  done
  return 1
}

# pf_why LOGFILE NS : kubectl's port-forward errors, in plain words.
pf_why() {
  local log
  log=$(grep -iE 'error|forbidden|refused|unable|lost connection|timeout' "$1" 2>/dev/null | tail -n 3 | tr '\n' ' ')
  case $log in
    *forbidden*) printf 'Your role can'"'"'t port-forward in %s (it needs create on pods/portforward). kubectl said: %s' "$2" "$log" ;;
    *"connection refused"*) printf 'The Argo CD pod refused the connection on that port, so the service port may point at the wrong container port. kubectl said: %s' "$log" ;;
    *"not running"* | *"no endpoints"* | *"does not have any active Endpoint"*) printf 'Argo CD has no running pod behind the service. kubectl said: %s' "$log" ;;
    "") printf 'kubectl reported no error, so either that service port isn'"'"'t Argo CD'"'"'s web port (check argocd_service and argocd_namespace), or the request never reached the cluster (VPN, or the session expired).' ;;
    *) printf 'kubectl said: %s' "$log" ;;
  esac
}

pf_alive() { # NAME : 0 if its port-forward process is still running
  local f
  f="$(pf_dir)/$1.json"
  [ -f "$f" ] && kill -0 "$(jq -r .pid "$f")" 2>/dev/null
}

# pf_start CLUSTER_NAME : start (or reuse) the Argo CD port-forward; prints {name, url, pid, reused}.
pf_start() {
  local name=$1 c ctx profile ns svc port remote scheme key dir log pid i sel PF_FOUND_NOTE=""
  c=$(diag_cluster "$name")
  [ -n "$c" ] || { printf '{"error": "No cluster named %s in your config."}\n' "$name"; return 1; }
  dir=$(pf_dir)
  mkdir -p "$dir" && chmod 700 "$dir"
  if pf_alive "$name"; then
    # Still answering? Then reuse it. A tunnel whose pod went away is restarted instead.
    if pf_probe "$(jq -r .port "$dir/$name.json")" "$(jq -r '.url | split(":")[0]' "$dir/$name.json")" >/dev/null; then
      jq -c '. + {reused: true}' "$dir/$name.json"
      return 0
    fi
    pf_stop "$name"
  fi
  ctx=$(jq -r .context <<<"$c") profile=$(jq -r .aws_profile <<<"$c")
  ns=$(jq -r '.argocd_namespace // "argocd"' <<<"$c") svc=$(jq -r '.argocd_service // "argocd-server"' <<<"$c")
  key="pf-$(safe_key "$name")"

  # Use the service's https port if it has one (443), else http (80, for server.insecure).
  if ! capture "$key-svc" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=15s get svc "$svc" -n "$ns" -o json; then
    if ! err "$key-svc" | grep -qiE 'NotFound|not found'; then
      jq -cn --arg e "$(first_line "$(err "$key-svc")")" --arg svc "$svc" --arg ns "$ns" --arg name "$name" \
        '{error: "Can'"'"'t read service \($svc) in \($ns) on \($name): \($e)"}'
      return 1
    fi
    # Not where the config says: find it by Argo CD's own labels. The Helm chart names it
    # <release>-argocd-server, often in an argo-cd namespace.
    local found=""
    for sel in app.kubernetes.io/name=argocd-server "app.kubernetes.io/component=server,app.kubernetes.io/part-of=argocd"; do
      if capture "$key-find" env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=15s get svc -A -l "$sel" -o json &&
        [ "$(jq '.items | length' "$PMGR_TMP/$key-find.out")" -gt 0 ]; then
        found=$(jq -c '.items' "$PMGR_TMP/$key-find.out")
        break
      fi
    done
    if [ -z "$found" ]; then
      jq -cn --arg svc "$svc" --arg ns "$ns" --arg name "$name" \
        '{error: "No Argo CD on \($name): there'"'"'s no service \($svc) in \($ns), and no service labeled app.kubernetes.io/name=argocd-server in any namespace. If one Argo CD manages every environment, open it from the cluster it runs on (and set argocd_namespace and argocd_service there if they differ)."}'
      return 1
    fi
    ns=$(jq -r '.[0].metadata.namespace' <<<"$found") svc=$(jq -r '.[0].metadata.name' <<<"$found")
    jq '.[0]' <<<"$found" >"$PMGR_TMP/$key-svc.out"
    PF_FOUND_NOTE="Found Argo CD at $ns/svc/$svc; set argocd_namespace: $ns and argocd_service: $svc for this cluster to skip the search.$([ "$(jq length <<<"$found")" -gt 1 ] && printf ' (There are %s Argo CD servers; set those to pick another.)' "$(jq length <<<"$found")")"
  fi
  # Served under a path (server.rootpath, e.g. /argocd)? Then the link needs it.
  local rootpath
  rootpath=$(env AWS_PROFILE="$profile" kubectl --context "$ctx" --request-timeout=10s get configmap argocd-cmd-params-cm -n "$ns" \
    -o 'jsonpath={.data.server\.rootpath}' 2>/dev/null | tr -cd 'A-Za-z0-9/_.-')
  rootpath=${rootpath#/}; rootpath=${rootpath%/}
  # Only TCP ports can be forwarded. Prefer one named https (or 443), then http (or 80), then any TCP port.
  read -r remote scheme < <(out "$key-svc" | jq -r '
    [.spec.ports[] | select((.protocol // "TCP") == "TCP") | {p: .port, name: (.name // "")}] as $ports
    | ([$ports[] | select(.name == "https" or .p == 443)] | first) as $s
    | ([$ports[] | select(.name == "http" or .p == 80)] | first) as $h
    | if $s then "\($s.p) https" elif $h then "\($h.p) http" elif ($ports | length) > 0 then "\($ports[0].p) http" else "" end')
  [ -n "$remote" ] || { jq -cn --arg svc "$svc" '{error: "Service \($svc) has no TCP port to forward."}'; return 1; }

  port=$(pf_planned_port "$name")
  if port_open "$port"; then
    if [ -n "$(pf_fixed_port "$name")" ]; then
      jq -cn --arg port "$port" --arg name "$name" \
        '{error: "Local port \($port) (argocd_port for \($name)) is already in use by something else. Free it, or remove argocd_port so pmgr picks an open one."}'
      return 1
    fi
    port=$(pf_free_port) || { printf '{"error": "Couldn'"'"'t find a free local port."}\n'; return 1; }
  fi
  log="$dir/$name.log"
  # nohup: the tunnel outlives this command (stop it with pmgr pf stop). --address localhost binds
  # 127.0.0.1 and ::1 only, since browsers may try either for dev.localhost.
  AWS_PROFILE="$profile" nohup kubectl --context "$ctx" -n "$ns" port-forward "svc/$svc" "$port:$remote" \
    --address localhost >"$log" 2>&1 </dev/null 3>&- &
  pid=$!
  i=0
  while ! port_open "$port" && [ "$i" -lt 40 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.25; i=$((i + 1)); done
  if ! port_open "$port"; then
    kill "$pid" 2>/dev/null
    jq -cn --arg e "$(pf_why "$log" "$ns")" --arg name "$name" '{error: "The tunnel to \($name) didn'"'"'t start. \($e)"}'
    return 1
  fi
  # Ask Argo CD itself, through the tunnel, and use whichever scheme it answers on: with
  # server.insecure it speaks plain http even behind a port named https.
  local answered
  if ! answered=$(pf_probe "$port" "$scheme"); then
    jq -cn --arg e "$(pf_why "$log" "$ns")" --arg name "$name" --arg port "$port" \
      '{error: "The tunnel to \($name) opened on port \($port), but Argo CD didn'"'"'t answer through it over https or http. \($e)"}'
    kill "$pid" 2>/dev/null
    return 1
  fi
  scheme=$answered
  jq -cn --arg name "$name" --arg url "$scheme://$(pf_host "$name"):$port/${rootpath:+$rootpath/}" --argjson pid "$pid" --arg ctx "$ctx" --arg svc "$svc" \
    --arg ns "$ns" --argjson port "$port" --arg note "${PF_FOUND_NOTE:-}" \
    --arg alt "$scheme://127.0.0.1:$port/${rootpath:+$rootpath/}" \
    '{name: $name, url: $url, alt_url: $alt, pid: $pid, port: $port, context: $ctx, target: "\($ns)/svc/\($svc)", started_at: (now | todateiso8601), reused: false}
     + (if $note != "" then {note: $note} else {} end)' \
    | tee "$dir/$name.json"
  printf '%s\n' "$port" >"$dir/$name.port"
}

# pf_status : every configured cluster's tunnel: running or not, its port (or the one it will use),
# and whether a login secret is configured. The dashboard's Environments table reads this.
pf_status() {
  local out="[]" name state alive
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    state='{}'
    alive=false
    if pf_alive "$name"; then alive=true; state=$(cat "$(pf_dir)/$name.json"); fi
    out=$(jq -c --arg n "$name" --argjson s "$state" --argjson alive "$alive" --arg planned "$(pf_planned_port "$name")" \
      --argjson c "$(diag_cluster "$name")" \
      --arg host "$(pf_host "$name")" \
      '. + [{name: $n, alive: $alive, url: ($s.url // null), alt_url: ($s.alt_url // null), host: $host, port: ($s.port // ($planned | tonumber)),
             fixed: ($c.argocd_port != null), login: (($c.argocd_secret // "") != ""),
             username: ($c.argocd_username // null)}]' <<<"$out")
  done < <(cfg '.clusters // [] | .[].name')
  printf '%s\n' "$out"
}

# pf_check NAME : where a tunnel breaks, as Diagnose sections: the process and its log, a request
# through it, RBAC, the service and its pods, and what the browser does with NAME.localhost.
pf_check() {
  local name=$1 c f ns svc port host
  c=$(diag_cluster "$name")
  [ -n "$c" ] || { jq -cn --arg n "$name" '{title: "Tunnel", command: "", output: "No cluster named \($n) in your config.", ok: false}'; return 0; }
  ns=$(jq -r '.argocd_namespace // "argocd"' <<<"$c") svc=$(jq -r '.argocd_service // "argocd-server"' <<<"$c")
  f="$(pf_dir)/$name.json"
  port=$(pf_planned_port "$name") host=$(pf_host "$name")
  if pf_alive "$name"; then
    port=$(jq -r .port "$f")
    diag_section "Tunnel process" ps -o pid,etime,command -p "$(jq -r .pid "$f")"
    local scheme
    for scheme in https http; do
      diag_section "Argo CD over $scheme, through the tunnel" curl -skI --noproxy '*' --max-time 8 "$scheme://127.0.0.1:$port/"
    done
  else
    jq -cn '{title: "Tunnel process", command: "", output: "Not running. Create tunnel starts it.", ok: false}'
  fi
  [ -f "$(pf_dir)/$name.log" ] && diag_section "kubectl port-forward log" tail -n 25 "$(pf_dir)/$name.log"
  diag_section "Can you port-forward in $ns?" diag_k8s "$c" auth can-i create pods/portforward -n "$ns"
  diag_section "Service $svc and its endpoints" diag_k8s "$c" get "svc/$svc" "endpoints/$svc" -n "$ns" -o wide
  diag_section "Argo CD server pods" diag_k8s "$c" get pods -n "$ns" -l "app.kubernetes.io/name=$svc" -o wide
  diag_section "What $host resolves to on this Mac" dscacheutil -q host -a name "$host"
  diag_section "Proxy settings (a browser may send $host to a proxy, which can't reach your Mac)" scutil --proxy
}

# ---------- login ----------

# clip_copy : copy stdin to the clipboard (PMGR_CLIPBOARD overrides the command, for tests).
clip_copy() {
  if [ -n "${PMGR_CLIPBOARD:-}" ]; then "$PMGR_CLIPBOARD"
  elif command -v pbcopy >/dev/null 2>&1; then pbcopy
  elif command -v wl-copy >/dev/null 2>&1; then wl-copy
  elif command -v xclip >/dev/null 2>&1; then xclip -selection clipboard
  else return 1
  fi
}

PF_CLIP_SECONDS=60

# pf_login NAME : copy the cluster's Argo CD password to the clipboard. Prints {name, username,
# copied, clears_in} or {error}; the password itself is never printed.
pf_login() {
  local name=$1 c sid key profile region raw pw user errf
  c=$(diag_cluster "$name")
  [ -n "$c" ] || { jq -cn --arg n "$name" '{error: "No cluster named \($n) in your config."}'; return 1; }
  sid=$(jq -r '.argocd_secret // ""' <<<"$c")
  [ -n "$sid" ] || { jq -cn --arg n "$name" '{error: "No argocd_secret for \($n). Add the Secrets Manager secret name under that cluster in your config."}'; return 1; }
  key=$(jq -r '.argocd_secret_key // "password"' <<<"$c")
  profile=$(jq -r '.argocd_secret_profile // .aws_profile' <<<"$c")
  # An ARN carries its own region (arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME); a name uses the cluster's.
  case $sid in
    arn:aws*:secretsmanager:*) region=$(printf '%s' "$sid" | cut -d: -f4) ;;
    *) region=$(jq -r '.region // ""' <<<"$c") ;;
  esac
  errf="$PMGR_TMP/pf-login.err"
  # The value stays in this function's memory and goes out through pipes only (printf is a builtin,
  # so it never shows up in a process listing).
  if ! raw=$(AWS_PROFILE="$profile" aws secretsmanager get-secret-value --secret-id "$sid" ${region:+--region "$region"} \
      --query SecretString --output text 2>"$errf"); then
    jq -cn --arg e "$(first_line "$(cat "$errf")")" --arg sid "$sid" --arg p "$profile" \
      '{error: "Can'"'"'t read secret \($sid) with profile \($p): \($e)"}'
    return 1
  fi
  # JSON secrets: take the configured key (password by default). Anything else is the password itself.
  if pw=$(printf '%s' "$raw" | jq -er --arg k "$key" 'if type == "object" then .[$k] // empty | tostring else error end' 2>/dev/null); then
    user=$(jq -r '.argocd_username // empty' <<<"$c")
    [ -n "$user" ] || user=$(printf '%s' "$raw" | jq -r '.username // "admin"')
  elif printf '%s' "$raw" | jq -e 'type == "object"' >/dev/null 2>&1; then
    jq -cn --arg sid "$sid" --arg k "$key" '{error: "Secret \($sid) is JSON but has no \($k) key. Set argocd_secret_key to the key that holds the password."}'
    return 1
  else
    pw=$raw
    user=$(jq -r '.argocd_username // "admin"' <<<"$c")
  fi
  [ -n "$pw" ] || { jq -cn --arg sid "$sid" '{error: "Secret \($sid) is empty."}'; return 1; }
  if ! printf '%s' "$pw" | clip_copy; then
    printf '{"error": "No clipboard command found (pbcopy, wl-copy or xclip)."}\n'
    return 1
  fi
  # Clear it after a minute, unless something else has been copied since.
  if [ -z "${PMGR_CLIPBOARD:-}" ] && command -v pbpaste >/dev/null 2>&1; then
    local sum
    sum=$(printf '%s' "$pw" | shasum -a 256)
    ( sleep "$PF_CLIP_SECONDS"; [ "$(pbpaste | shasum -a 256)" = "$sum" ] && printf '' | pbcopy ) \
      </dev/null >/dev/null 2>&1 3>&- &
  fi
  jq -cn --arg n "$name" --arg u "$user" --argjson s "$PF_CLIP_SECONDS" \
    '{name: $n, username: $u, copied: true, clears_in: $s}'
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
          jq -r '.note // empty | "  \(.)"' <<<"$result"
          if [ -n "$(jq -r '.argocd_secret // empty' <<<"$(diag_cluster "$n")")" ]; then pf_login_say "$n"; fi
          [ "$no_open" -eq 1 ] || open_url "$(jq -r .url <<<"$result")"
        fi
      done
      [ "$code" -eq 0 ] || printf '\nCheck shows where it breaks: pmgr pf check CLUSTER (or the Check button in pmgr ui).\n' >&2
      return "$code"
      ;;
    check)
      [ $# -gt 0 ] || die "Usage: pmgr pf check CLUSTER"
      pf_check "$1" | jq -r '"── \(.title) " + ("─" * ([60 - (.title | length), 3] | max)), (if .command != "" then "$ \(.command)" else empty end), .output, ""'
      ;;
    login)
      [ $# -gt 0 ] || die "Usage: pmgr pf login CLUSTER"
      pf_login_say "$1"
      ;;
    status) pf_status | jq -r '.[] | "\(if .alive then "running" else "stopped" end)\t\(.name)\t\(.host):\(.port)\(if .fixed then " (fixed)" else "" end)\t\(if .login then "login configured" else "no login secret" end)"' | column -t -s $'\t' ;;
    stop)
      if [ "${1:-all}" = all ]; then
        for f in "$(pf_dir)"/*.json; do [ -f "$f" ] && pf_stop "$(basename "$f" .json)"; done
        printf 'Stopped all port-forwards.\n'
      else
        for n in "$@"; do pf_stop "$n" && printf 'Stopped %s.\n' "$n"; done
      fi
      ;;
    *) die "Usage: pmgr pf [list | status] | pmgr pf argo CLUSTER... | --all | pmgr pf login CLUSTER | pmgr pf check CLUSTER | pmgr pf stop [CLUSTER... | all]" ;;
  esac
}

pf_login_say() { # NAME : pf_login for the terminal
  local r
  r=$(pf_login "$1") || { printf '%s: %s\n' "$1" "$(jq -r .error <<<"$r")" >&2; return 1; }
  jq -r '"\(.name): Argo CD password copied to the clipboard (user \(.username)); it clears in \(.clears_in)s."' <<<"$r"
}
