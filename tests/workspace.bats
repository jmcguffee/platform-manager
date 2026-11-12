#!/usr/bin/env bats
# Workspaces: one per contract, each with its own config, history, tunnels and watch.

load helpers

setup() {
  setup_pmgr
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
  unset PMGR_CONFIG PMGR_WORKSPACE
  PMGR_CONFIG_DIR="$HOME/.config/platform-manager"
}

@test "no workspace means the same paths as before" {
  [ "$(config_path)" = "$HOME/.config/platform-manager/config.yaml" ]
  [ "$(pmgr_cache)" = "$XDG_CACHE_HOME/platform-manager" ]
  [ "$(history_dir)" = "$XDG_CACHE_HOME/platform-manager/history" ]
}

@test "new, use and -w: each workspace has its own config and cache" {
  run "$PMGR_ROOT/bin/pmgr" workspace new acme
  [ "$status" -eq 0 ] && [[ "$output" == *"Workspace acme is ready"* ]]
  [ -f "$HOME/.config/platform-manager/workspaces/acme.yaml" ]
  run "$PMGR_ROOT/bin/pmgr" workspace use acme
  [[ "$output" == "Using workspace acme." ]]
  [ "$(config_path)" = "$HOME/.config/platform-manager/workspaces/acme.yaml" ]
  [ "$(pmgr_cache)" = "$XDG_CACHE_HOME/platform-manager/workspaces/acme" ]
  [ "$(PMGR_WORKSPACE=default config_path)" = "$HOME/.config/platform-manager/config.yaml" ]
  run "$PMGR_ROOT/bin/pmgr" workspace list
  [[ "$output" == *"  default  "* ]] && [[ "$output" == *"* acme  "* ]]
  "$PMGR_ROOT/bin/pmgr" workspace new globex >/dev/null
  run "$PMGR_ROOT/bin/pmgr" -w globex workspace list   # -w wins over the default for one command
  [[ "$output" == *"* globex  "* ]] && [[ "$output" == *"  acme  "* ]]
  run "$PMGR_ROOT/bin/pmgr" workspace use nope
  [ "$status" -ne 0 ] && [[ "$output" == *"No workspace nope"* ]]
}

@test "history and the last report stay inside their workspace" {
  config_load() { PMGR_CONFIG_JSON='{}'; }
  PMGR_WORKSPACE=acme report_finalize '{"areas": ["posture"], "findings": [], "unseen": []}' >/dev/null
  PMGR_WORKSPACE=globex report_finalize '{"areas": ["posture"], "findings": [], "unseen": []}' >/dev/null
  [ "$(ls "$XDG_CACHE_HOME/platform-manager/workspaces/acme/history" | wc -l | tr -d ' ')" = 1 ]
  [ -f "$XDG_CACHE_HOME/platform-manager/workspaces/globex/last-report.json" ]
  [ ! -d "$XDG_CACHE_HOME/platform-manager/history" ]
}

@test "bad names are refused; each workspace gets its own LaunchAgent" {
  run "$PMGR_ROOT/bin/pmgr" workspace new "Bad Name"
  [ "$status" -ne 0 ] && [[ "$output" == *"lowercase letters, digits"* ]]
  run env PMGR_WORKSPACE='../x' "$PMGR_ROOT/bin/pmgr" status
  [ "$status" -ne 0 ] && [[ "$output" == *"Workspace names use lowercase"* ]]
  [ "$(PMGR_WORKSPACE=acme watch_label)" = "com.github.jmcguffee.platform-manager.watch.acme" ]
  PMGR_CONFIG_JSON='{}'
  [[ "$(PMGR_WORKSPACE=acme watch_plist_text 60)" == *"<key>PMGR_WORKSPACE</key><string>acme</string>"* ]]
  [[ "$(watch_plist_text 60)" != *PMGR_WORKSPACE* ]]
}
