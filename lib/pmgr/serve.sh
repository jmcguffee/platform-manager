# shellcheck shell=bash
# `pmgr ui`: a tiny local server so the dashboard can sync on demand.
#
# The socket is held by a few lines of the perl that ships with macOS; each request is answered by
# serve_handle in bash. (Without perl it falls back to nc.) Security:
#   - Listens on 127.0.0.1 only.
#   - Every request needs the per-run token: in the page URL (?t=...) or the X-Pmgr-Token header.
#     A wrong token gets a 403 and no data.
#   - The Host header must be this exact address, which blocks DNS rebinding from websites.
#   - No CORS headers, so other sites can't read responses. Syncing needs a POST with the token
#     header, which a cross-site form can't send.
#   - Actions: run the checks again, diagnose a finding, and open a port-forward to Argo CD. None of them
#     write to AWS, Kubernetes or GitHub; a port-forward is a local tunnel.

serve_token() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 16
  else od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

# Is something listening? Uses bash's own /dev/tcp, so it needs neither nc nor perl.
port_open() { (: <"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1; }

# A free port from 8765 up.
serve_port() {
  local p=${1:-8765} last
  last=$((p + 20))
  while [ "$p" -le "$last" ]; do
    port_open "$p" || { printf '%s' "$p"; return 0; }
    p=$((p + 1))
  done
  return 1
}

# serve_render DIR : run every check and write DIR/dashboard.html (served mode) and DIR/state.json.
# Runs as a separate pmgr process, so a sync can't disturb the server's own state.
serve_render() {
  local dir=$1
  printf '%s' "$$" >"$dir/sync.running"
  if "$PMGR_ROOT/bin/pmgr" __render "$dir/dashboard.next.html" "$dir/report.next.json" >"$dir/sync.log" 2>&1 ||
    [ -s "$dir/report.next.json" ]; then
    mv "$dir/dashboard.next.html" "$dir/dashboard.html"
    mv "$dir/report.next.json" "$dir/report.json"
    chmod 600 "$dir/dashboard.html" "$dir/report.json"
    jq -cn --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{generated_at: $t, error: ""}' >"$dir/state.json"
  else
    jq -cn --arg e "$(tail -n 3 "$dir/sync.log" | tr '\n' ' ')" --slurpfile old "$dir/state.json" \
      '($old[0] // {}) + {error: $e}' >"$dir/state.next.json" 2>/dev/null && mv "$dir/state.next.json" "$dir/state.json"
  fi
  rm -f "$dir/sync.running"
}

serve_respond() { # STATUS CONTENT_TYPE BODY_FILE
  local len
  len=$(wc -c <"$3" | tr -d ' ')
  printf 'HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %s\r\nCache-Control: no-store\r\n' "$1" "$2" "$len"
  printf 'X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n'
  cat "$3"
}

serve_text() { # STATUS TEXT
  printf '%s\n' "$2" >"$SERVE_DIR/resp.txt"
  serve_respond "$1" "text/plain; charset=utf-8" "$SERVE_DIR/resp.txt"
}

# serve_handle : read one HTTP request on stdin, write the response on stdout.
# Returns 1 when the stream has ended (nc exited); a quiet connection just times out.
serve_handle() {
  local method path proto line host="" token_hdr="" length=0 query="" token_q="" rc=0
  IFS=' ' read -r -t 3 method path proto || rc=$?
  [ "$rc" -gt 128 ] && return 0   # timed out waiting: nothing to answer
  [ "$rc" -ne 0 ] && return 1     # end of stream
  [ -n "$method" ] || return 0
  proto=${proto%$'\r'}
  while IFS= read -r -t 3 line; do
    line=${line%$'\r'}
    [ -z "$line" ] && break
    case $(lower "${line%%:*}") in
      host) host=${line#*: } ;;
      x-pmgr-token) token_hdr=${line#*: } ;;
      content-length) length=${line#*: } ;;
    esac
  done
  # Read a small request body (Diagnose sends {"id": ...}); anything else is drained.
  local body=""
  case $length in '' | *[!0-9]*) length=0 ;; esac
  if [ "$length" -gt 0 ] && [ "$length" -lt 4096 ]; then
    body=$(dd bs=1 count="$length" 2>/dev/null)
  elif [ "$length" -gt 0 ] && [ "$length" -lt 65536 ]; then
    dd bs=1 count="$length" of=/dev/null 2>/dev/null
  fi

  case $path in *\?*) query=${path#*\?} path=${path%%\?*} ;; esac
  case "&$query&" in *"&t="*) token_q=${query#*t=} token_q=${token_q%%&*} ;; esac

  if [ "$host" != "$SERVE_HOST" ]; then
    serve_text "421 Misdirected Request" "Wrong host."
    return 0
  fi
  if [ "$token_hdr" != "$SERVE_TOKEN" ] && [ "$token_q" != "$SERVE_TOKEN" ]; then
    serve_text "403 Forbidden" "Missing or wrong token. Open the link pmgr ui printed."
    return 0
  fi

  case "$method $path" in
    "GET /" | "GET /index.html")
      serve_respond "200 OK" "text/html; charset=utf-8" "$SERVE_DIR/dashboard.html" ;;
    "GET /api/report")
      serve_respond "200 OK" "application/json" "$SERVE_DIR/report.json" ;;
    "GET /api/state")
      jq -c --argjson running "$([ -f "$SERVE_DIR/sync.running" ] && echo true || echo false)" \
        '. + {running: $running}' "$SERVE_DIR/state.json" >"$SERVE_DIR/resp.json"
      serve_respond "200 OK" "application/json" "$SERVE_DIR/resp.json" ;;
    "POST /api/diagnose")
      if [ "$token_hdr" != "$SERVE_TOKEN" ]; then
        serve_text "403 Forbidden" "Diagnose needs the token header."
      else
        # Only an id from the browser; what to inspect comes from pmgr's own report.
        local id
        id=$(jq -r '.id // ""' <<<"$body" 2>/dev/null | tr -cd 'a-z0-9')
        "$PMGR_ROOT/bin/pmgr" __diagnose "${id:-none}" >"$SERVE_DIR/diag.json" 2>/dev/null || printf '[]' >"$SERVE_DIR/diag.json"
        serve_respond "200 OK" "application/json" "$SERVE_DIR/diag.json"
      fi ;;
    "GET /api/portforward")
      "$PMGR_ROOT/bin/pmgr" __pf status >"$SERVE_DIR/pf.json" 2>/dev/null </dev/null || printf '[]' >"$SERVE_DIR/pf.json"
      serve_respond "200 OK" "application/json" "$SERVE_DIR/pf.json" ;;
    "POST /api/portforward" | "POST /api/portforward/stop" | "POST /api/portforward/check" | "POST /api/argo-login")
      if [ "$token_hdr" != "$SERVE_TOKEN" ]; then
        serve_text "403 Forbidden" "Port-forwarding needs the token header."
      else
        # Only a cluster name from the browser; pmgr refuses names that aren't in the config. The
        # login route copies the password to this machine's clipboard and answers without it.
        local cluster action=start
        case $path in */stop) action=stop ;; */check) action=check ;; */argo-login) action=login ;; esac
        cluster=$(jq -r '.cluster // ""' <<<"$body" 2>/dev/null | tr -cd 'A-Za-z0-9._-')
        "$PMGR_ROOT/bin/pmgr" __pf "$action" "${cluster:-none}" >"$SERVE_DIR/pf.json" 2>/dev/null </dev/null
        [ -s "$SERVE_DIR/pf.json" ] || printf '{"error": "pmgr didn'"'"'t answer."}' >"$SERVE_DIR/pf.json"
        serve_respond "200 OK" "application/json" "$SERVE_DIR/pf.json"
      fi ;;
    "POST /api/weekly")
      if [ "$token_hdr" != "$SERVE_TOKEN" ]; then
        serve_text "403 Forbidden" "The weekly report needs the token header."
      else
        local days
        days=$(jq -r '.days // 7' <<<"$body" 2>/dev/null | tr -cd '0-9')
        "$PMGR_ROOT/bin/pmgr" __weekly "${days:-7}" >"$SERVE_DIR/weekly.md" 2>&1 </dev/null || true
        serve_respond "200 OK" "text/markdown; charset=utf-8" "$SERVE_DIR/weekly.md"
      fi ;;
    "POST /api/sync")
      if [ "$token_hdr" != "$SERVE_TOKEN" ]; then
        serve_text "403 Forbidden" "Syncing needs the token header."
      else
        if [ ! -f "$SERVE_DIR/sync.running" ]; then
          : >"$SERVE_DIR/sync.running"   # before answering, so the page's first poll sees it
          (serve_render "$SERVE_DIR" </dev/null >/dev/null 2>&1 &)
        fi
        printf '{"started":true}' >"$SERVE_DIR/resp.json"
        serve_respond "202 Accepted" "application/json" "$SERVE_DIR/resp.json"
      fi ;;
    *) serve_text "404 Not Found" "Not found." ;;
  esac
}

# serve_ui [--no-open] [--port N] : check, serve the dashboard, and sync on request until Ctrl+C.
serve_ui() {
  local open=1 port=""
  while [ $# -gt 0 ]; do
    case $1 in
      --no-open) open=0 ;;
      --port) port=${2:?--port needs a number}; shift ;;
      *) die "Unknown option $1" ;;
    esac
    shift
  done
  SERVE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/platform-manager/live"
  mkdir -p "$SERVE_DIR" && chmod 700 "$SERVE_DIR"
  port=$(serve_port "${port:-8765}") || die "No free port from 8765 to 8785. Pass --port."
  SERVE_TOKEN=$(serve_token)
  SERVE_HOST="127.0.0.1:$port"
  export SERVE_DIR SERVE_TOKEN SERVE_HOST

  printf 'Checking your platform...\n' >&2
  rm -f "$SERVE_DIR/sync.running"
  printf '{}' >"$SERVE_DIR/state.json"
  serve_render "$SERVE_DIR"
  [ -f "$SERVE_DIR/dashboard.html" ] || die "The first check failed: $(tail -n 3 "$SERVE_DIR/sync.log")"

  local url="http://$SERVE_HOST/?t=$SERVE_TOKEN" server
  if command -v perl >/dev/null 2>&1 && perl -MIO::Socket::INET -MIPC::Open2 -e1 2>/dev/null; then
    serve_loop_perl "$port" &
  else
    serve_loop_nc "$port" &
  fi
  server=$!
  trap 'kill "$server" 2>/dev/null; exit 0' INT TERM
  # Open the browser only once the port answers.
  local i=0
  while ! port_open "$port" && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  printf 'Dashboard: %s\nOnly this machine can open it. Press Ctrl+C to stop.\n' "$url" >&2
  [ "$open" -eq 1 ] && open_url "$url"
  wait "$server"
}

# The socket loop, in the perl that ships with macOS: it keeps the listening socket open for the
# whole session, reads each request with a timeout (so an idle browser connection can't stall
# anything), and hands the raw request to `pmgr __handle`, which answers it in bash.
serve_loop_perl() {
  # exec, so the pid serve_ui tracks (and kills on Ctrl+C or TERM) is the listener itself.
  PMGR_HANDLER="$PMGR_ROOT/bin/pmgr" exec perl -MIO::Socket::INET -MIPC::Open2 -e '
    use strict; use warnings;
    my $srv = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => $ARGV[0], Listen => 32, ReuseAddr => 1)
      or die "pmgr: can'"'"'t listen on 127.0.0.1:$ARGV[0]: $!\n";
    while (1) {
      my $c = $srv->accept or next;
      my $req = "";
      eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 3;
        while (defined(my $line = <$c>)) { $req .= $line; last if $line =~ /^\r?\n$/; }
        if ($req =~ /^Content-Length:\s*(\d+)/mi && $1 > 0 && $1 < 65536) { read($c, my $body, $1); $req .= $body; }
        alarm 0;
      };
      if ($req ne "") {
        my $pid = open2(my $out, my $in, $ENV{PMGR_HANDLER}, "__handle");
        print $in $req; close $in;
        local $/; my $resp = <$out> // ""; close $out; waitpid($pid, 0);
        print $c $resp;
      }
      close $c;
    }' "$1"
}

# Fallback when perl isn't available: one nc per connection. Between connections the port is
# briefly closed, and the page retries a refused request.
serve_loop_nc() {
  local fifo="$SERVE_DIR/http.fifo"
  trap 'rm -f "$fifo"; exit 0' INT TERM
  while :; do
    rm -f "$fifo"
    mkfifo -m 600 "$fifo"
    # shellcheck disable=SC2094  # a FIFO: nc reads the response the handler writes into it
    nc -l 127.0.0.1 "$1" <"$fifo" | serve_handle >"$fifo"
  done
}
