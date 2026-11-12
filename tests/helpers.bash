# Shared setup for bats tests: fake aws/kubectl/gh on PATH, a temp config, and the libraries loaded.

setup_pmgr() {
  PMGR_ROOT="$BATS_TEST_DIRNAME/.."
  export PMGR_ROOT
  FAKE_DIR="$BATS_TEST_TMPDIR/fake"
  mkdir -p "$FAKE_DIR"
  : >"$FAKE_DIR/rules"
  : >"$FAKE_DIR/calls"
  export FAKE_DIR
  export PATH="$BATS_TEST_DIRNAME/stubs:$PATH"
  export AWS_CONFIG_FILE="$BATS_TEST_TMPDIR/aws-config"   # never read the real ~/.aws/config
  : >"$AWS_CONFIG_FILE"
  export PMGR_CONFIG="$BATS_TEST_TMPDIR/config.yaml"
  export XDG_CACHE_HOME="$BATS_TEST_TMPDIR/cache"
  unset NO_COLOR
  for lib in core auth clusters github runfailure pipelines workflows argo workloads pricing utilization oncall security diagnose report serve commands; do
    # shellcheck source=/dev/null
    . "$PMGR_ROOT/lib/pmgr/$lib.sh"
  done
  PMGR_TMP="$BATS_TEST_TMPDIR/work"
  mkdir -p "$PMGR_TMP"
  export PMGR_TMP
}

# fake CODE STDOUT STDERR CMD ARGS... : answer CMD ARGS... (an argument prefix) with this output.
# The last argument may be a string prefix, so API paths with query strings match.
fake() {
  local code=$1 stdout=$2 stderr=$3 cmd=$4 prefix
  shift 4
  prefix=$(printf '%s\037' "$@")
  [ $# -gt 0 ] && prefix=${prefix%$'\037'}
  jq -cn --arg cmd "$cmd" --arg prefix "$prefix" --argjson code "$code" --arg stdout "$stdout" \
    --arg stderr "$stderr" '{cmd: $cmd, prefix: $prefix, code: $code, stdout: $stdout, stderr: $stderr}' \
    >>"$FAKE_DIR/rules"
}

# config YAML : write the test config and load it.
config() {
  printf '%s\n' "$1" >"$PMGR_CONFIG"
  config_load
}

identity() {
  jq -cn --arg role "${1:-AWSReservedSSO_PlatformAdmin_abc}" --arg acct "${2:-111111111111}" \
    '{UserId: "X", Account: $acct, Arn: "arn:aws:sts::\($acct):assumed-role/\($role)/me@example.com"}'
}

checks() { jq -r 'select(has("check")) | .check' | sort -u | tr '\n' ' '; }
