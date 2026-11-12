#!/usr/bin/env bats
# Argo CD port-forwards: stable ports, reuse, stop, clear errors, and the dashboard route.

load helpers

setup() {
  setup_pmgr
  config 'clusters:
  - {name: staging, context: ctx-staging, aws_profile: stg}
  - {name: prod, context: ctx-prod, aws_profile: prd, argocd_port: 28443}'
  # A kubectl whose port-forward really listens, so the tunnel can be checked end to end.
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  cat >"$BATS_TEST_TMPDIR/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DIR/kubectl-calls"
case " $* " in
  *" get svc "*)
    case " $* " in
      *" udp-only "*) printf '{"spec":{"ports":[{"name":"dns","port":53,"protocol":"UDP"}]}}' ;;
      *) printf '{"spec":{"ports":[{"name":"http","port":80,"protocol":"TCP"},{"name":"https","port":443,"protocol":"TCP"}]}}' ;;
    esac ;;
  *" port-forward "*)
    port=$(printf '%s\n' "$@" | grep -E '^[0-9]+:[0-9]+$' | cut -d: -f1)
    # Like Argo CD with server.insecure: plain http; a TLS hello is dropped. FAKE_PF=silent answers
    # nothing (the pod can't be reached), FAKE_PF=forbidden also logs what kubectl would say.
    [ "${FAKE_PF:-}" = forbidden ] && echo 'E1112 portforward.go:413] error upgrading connection: pods "argocd-server-abc" is forbidden: User cannot create resource "pods/portforward"' >&2
    exec perl -MIO::Socket::INET -e '$s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => $ARGV[0], Listen => 5, ReuseAddr => 1) or die;
      while (my $c = $s->accept) { sysread($c, my $b, 4096); if ($ENV{FAKE_PF} || substr($b, 0, 1) eq "\x16") { close $c; next }
        print $c "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"; close $c }' "$port" port-forward ;;
  *" auth can-i "*) echo no; exit 1 ;;
  *" get svc/"*) echo "NAME            TYPE        PORT(S)" ;;
  *" get pods "*) echo "NAME                READY   STATUS" ;;
esac
EOF
  chmod +x "$BATS_TEST_TMPDIR/bin/kubectl"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH" PF_PROBE_SECONDS=2
}

teardown() {
  cmd_pf stop all >/dev/null 2>&1 || true
}

@test "each cluster gets a stable port: argocd_port, or 8080 plus its position" {
  [ "$(pf_port staging)" = 8080 ]
  [ "$(pf_port prod)" = 28443 ]
  run pf_planned_port staging   # no saved port yet: quietly the default
  [ "$output" = 8080 ]
  [ -z "$(pf_port nope)" ]
}

@test "a tunnel uses the scheme Argo CD answers on through it, and a second start reuses it" {
  got=$(pf_start prod)
  # The service's port is named https, but this Argo CD speaks http (server.insecure): ask it.
  [ "$(jq -r '"\(.url) \(.alt_url) \(.reused) \(.target)"' <<<"$got")" = "http://prod.localhost:28443 http://127.0.0.1:28443 false argocd/svc/argocd-server" ]
  port_open 28443
  grep -q -- "--context ctx-prod -n argocd port-forward svc/argocd-server 28443:443 --address localhost" "$FAKE_DIR/kubectl-calls"
  [ "$(pf_start prod | jq -r .reused)" = true ]
  [ "$(grep -c port-forward "$FAKE_DIR/kubectl-calls")" = 1 ]
  run cmd_pf
  [[ "$output" == *"running"*"prod"*"http://prod.localhost:28443"* ]]
}

@test "stop closes the tunnel" {
  pf_start prod >/dev/null
  cmd_pf stop prod
  ! port_open 28443
  [ "$(pf_list)" = "[]" ]
}

block_port() { # PORT : hold it open until the test kills $blocker
  perl -MIO::Socket::INET -e '$s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => $ARGV[0], Listen => 5, ReuseAddr => 1) or die; sleep 30' "$1" &
  blocker=$!
  for i in 1 2 3 4 5 6 7 8 9 10; do port_open "$1" && break; sleep 0.2; done
}
unblock() { kill "$blocker"; wait "$blocker" 2>/dev/null || true; }

@test "a taken port: pick a free one, unless argocd_port fixes it" {
  block_port 8080
  got=$(pf_start staging)
  port=$(jq -r .port <<<"$got")
  [ "$port" != 8080 ] && [ "$port" -gt 1024 ]
  port_open "$port"
  unblock
  block_port 28443
  [[ "$(pf_start prod)" == *"28443 (argocd_port for prod) is already in use"* ]]
  unblock
}

@test "each environment gets its own host, so their Argo CD logins don't share a cookie" {
  [ "$(pf_host staging)" = staging.localhost ]
  [ "$(pf_host "Prod_EU 1")" = prod-eu-1.localhost ]
  [ "$(pf_host ___)" = localhost ]
  a=$(pf_start staging) b=$(pf_start prod)
  [ "$(jq -r .url <<<"$a") $(jq -r .url <<<"$b")" = "http://staging.localhost:8080 http://prod.localhost:28443" ]
  port_open 8080 && port_open 28443
}

@test "after a stop, the next start reuses the same port" {
  block_port 8080
  port=$(pf_start staging | jq -r .port)
  unblock
  cmd_pf stop staging >/dev/null
  [ "$(pf_planned_port staging)" = "$port" ]
  [ "$(pf_start staging | jq -r .port)" = "$port" ]
}

@test "status lists every environment with its port and whether a login is configured" {
  config 'clusters:
  - {name: staging, context: ctx-staging, aws_profile: stg, argocd_secret: argo/staging}
  - {name: prod, context: ctx-prod, aws_profile: prd, argocd_port: 28443}'
  pf_start prod >/dev/null
  got=$(pf_status)
  [ "$(jq -c '[.[] | [.name, .alive, .port, .fixed, .login]]' <<<"$got")" = '[["staging",false,8080,false,true],["prod",true,28443,true,false]]' ]
  [ "$(jq -r '.[1].url' <<<"$got")" = "http://prod.localhost:28443" ]
}

@test "clear errors: unknown cluster, a service with nothing to forward" {
  [[ "$(pf_start nope)" == *"No cluster named nope"* ]]
  config 'clusters: [{name: dns, context: ctx, aws_profile: p, argocd_service: udp-only, argocd_port: 28444}]'
  [[ "$(pf_start dns)" == *"has no TCP port to forward"* ]]
}

login_setup() {
  export PMGR_CLIPBOARD="$BATS_TEST_TMPDIR/bin/clip"
  printf '#!/usr/bin/env bash\ncat >"%s"\n' "$BATS_TEST_TMPDIR/clipboard" >"$PMGR_CLIPBOARD"
  chmod +x "$PMGR_CLIPBOARD"
  config 'clusters:
  - {name: staging, context: ctx-staging, aws_profile: stg, region: us-east-2, argocd_secret: argo/staging}
  - {name: prod, context: ctx-prod, aws_profile: prd, argocd_secret: argo/prod, argocd_secret_key: admin_password, argocd_secret_profile: shared}
  - {name: dev, context: ctx-dev, aws_profile: dev}'
}

@test "login: a plain-text secret goes to the clipboard, never to stdout" {
  login_setup
  fake 0 's3cret-Plain' '' aws secretsmanager get-secret-value --secret-id argo/staging --region us-east-2
  got=$(pf_login staging)
  [ "$(cat "$BATS_TEST_TMPDIR/clipboard")" = "s3cret-Plain" ]
  [ "$(jq -c '[.username, .copied]' <<<"$got")" = '["admin",true]' ]
  [[ "$got" != *s3cret* ]]
  grep -q $'aws\tstg\tsecretsmanager get-secret-value --secret-id argo/staging --region us-east-2 --query SecretString --output text' "$FAKE_DIR/calls"
}

@test "login: a JSON secret uses the configured key, its username and the secret's own profile" {
  login_setup
  fake 0 '{"username":"ops","admin_password":"js0n-Pw"}' '' aws secretsmanager get-secret-value --secret-id argo/prod
  got=$(pf_login prod)
  [ "$(cat "$BATS_TEST_TMPDIR/clipboard")" = "js0n-Pw" ]
  [ "$(jq -r .username <<<"$got")" = ops ]
  grep -q $'aws\tshared\tsecretsmanager' "$FAKE_DIR/calls"
  run cmd_pf login prod
  [[ "$output" == *"password copied to the clipboard (user ops)"* ]] && [[ "$output" != *js0n* ]]
}

@test "login errors say what to fix" {
  login_setup
  [[ "$(pf_login dev)" == *"No argocd_secret for dev"* ]]
  fake 0 '{"password_typo":"x"}' '' aws secretsmanager get-secret-value --secret-id argo/staging
  [[ "$(pf_login staging)" == *"is JSON but has no password key. Set argocd_secret_key"* ]]
  fake 254 '' 'An error occurred (AccessDeniedException) when calling the GetSecretValue operation: denied' aws secretsmanager get-secret-value --secret-id argo/prod
  [[ "$(pf_login prod)" == *"Can't read secret argo/prod with profile shared: An error occurred (AccessDeniedException)"* ]]
  [ ! -f "$BATS_TEST_TMPDIR/clipboard" ]
}

@test "the dashboard route needs the token header and accepts only a configured cluster" {
  SERVE_DIR="$BATS_TEST_TMPDIR/live"; mkdir -p "$SERVE_DIR"
  SERVE_HOST="127.0.0.1:8765"; SERVE_TOKEN="t0ken"
  export SERVE_DIR SERVE_HOST SERVE_TOKEN
  post() {
    { printf 'POST /api/portforward HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nContent-Length: %s\r\n' "${#1}"
      [ -z "${2:-}" ] || printf 'X-Pmgr-Token: %s\r\n' "$2"
      printf '\r\n%s' "$1"; } | serve_handle
  }
  [[ "$(post '{"cluster":"prod"}' | head -1)" == *403* ]]
  [ "$(post '{"cluster":"prod"}' t0ken | sed '1,/^\r$/d' | jq -r .url)" = "http://prod.localhost:28443" ]
  [[ "$(post '{"cluster":"prod; rm -rf /"}' t0ken | sed '1,/^\r$/d' | jq -r .error)" == *"No cluster named prodrm-rf"* ]]
}

@test "the dashboard's status, stop and login routes" {
  login_setup
  SERVE_DIR="$BATS_TEST_TMPDIR/live"; mkdir -p "$SERVE_DIR"
  SERVE_HOST="127.0.0.1:8765"; SERVE_TOKEN="t0ken"
  export SERVE_DIR SERVE_HOST SERVE_TOKEN
  req() { # METHOD PATH BODY
    { printf '%s %s HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nX-Pmgr-Token: t0ken\r\nContent-Length: %s\r\n\r\n%s' "$1" "$2" "${#3}" "$3"; } \
      | serve_handle | sed '1,/^\r$/d'
  }
  [ "$(req GET /api/portforward '' | jq -c '[.[].name]')" = '["staging","prod","dev"]' ]
  fake 0 'route-Pw' '' aws secretsmanager get-secret-value --secret-id argo/staging
  got=$(req POST /api/argo-login '{"cluster":"staging"}')
  [ "$(jq -r .copied <<<"$got")" = true ] && [[ "$got" != *route-Pw* ]]
  [ "$(cat "$BATS_TEST_TMPDIR/clipboard")" = "route-Pw" ]
  [ "$(req POST /api/portforward '{"cluster":"staging"}' | jq -r .port)" = 8080 ]
  [ "$(req POST /api/portforward/stop '{"cluster":"staging"}' | jq -r '.[0].alive')" = false ]
  ! port_open 8080
}

@test "a tunnel that opens but gets no answer from Argo CD is an error, not 'tunnel up'" {
  export FAKE_PF=silent
  got=$(pf_start prod) || true
  [[ "$(jq -r .error <<<"$got")" == *"opened on port 28443, but Argo CD didn't answer through it over https or http"* ]]
  ! port_open 28443   # and it isn't left running
}

@test "a role that can't port-forward is named as the cause" {
  export FAKE_PF=forbidden
  [[ "$(pf_start prod | jq -r .error)" == *"Your role can't port-forward in argocd (it needs create on pods/portforward)"* ]]
}

@test "a running tunnel whose pod stopped answering is restarted, not reused" {
  pf_start prod >/dev/null
  pid=$(jq -r .pid "$(pf_dir)/prod.json")
  kill "$pid"; sleep 0.3
  perl -MIO::Socket::INET -e '$s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => 28443, Listen => 5, ReuseAddr => 1) or die; sleep 30' port-forward &
  zombie=$!
  jq --argjson p "$zombie" '.pid = $p' "$(pf_dir)/prod.json" >"$BATS_TEST_TMPDIR/s" && mv "$BATS_TEST_TMPDIR/s" "$(pf_dir)/prod.json"
  got=$(pf_start prod)
  [ "$(jq -r .reused <<<"$got")" = false ] && [ "$(jq -r .pid <<<"$got")" != "$zombie" ]
  ! kill -0 "$zombie" 2>/dev/null
}

@test "Check shows where a tunnel breaks: process, a request through it, RBAC, service, name and proxy" {
  pf_start prod >/dev/null
  got=$(pf_check prod)
  [ "$(jq -r .title <<<"$got" | tr '\n' '|')" = "Tunnel process|Argo CD over https, through the tunnel|Argo CD over http, through the tunnel|kubectl port-forward log|Can you port-forward in argocd?|Service argocd-server and its endpoints|Argo CD server pods|What prod.localhost resolves to on this Mac|Proxy settings (a browser may send prod.localhost to a proxy, which can't reach your Mac)|" ]
  [ "$(jq -r 'select(.title | startswith("Argo CD over http,")) | .ok' <<<"$got")" = true ]
  [ "$(jq -r 'select(.title | startswith("Can you")) | "\(.ok) \(.output)"' <<<"$got")" = "false no" ]
  run cmd_pf check prod
  [[ "$output" == *"── Tunnel process"* ]]
}
