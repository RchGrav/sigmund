#!/usr/bin/env bash
set -u

SIGMUND_BIN="${SIGMUND_BIN:-./sigmund}"
FAILS=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

new_env() {
  TEST_ROOT="$(mktemp -d)" || return 1
  export HOME="$TEST_ROOT/home"
  mkdir -p "$HOME" || return 1
  echo "boot-a" > /tmp/sigmund_test_boot_id
}

cleanup_env() {
  local store ids id
  store="$HOME/.local/state/sigmund"
  if [ -d "$store" ]; then
    ids=$(find "$store" -maxdepth 1 -type f -name '*.json' -printf '%f\n' 2>/dev/null | sed 's/\.json$//' || true)
    for id in $ids; do
      "$SIGMUND_BIN" kill "$id" >/dev/null 2>&1 || true
    done
  fi
  rm -rf "$TEST_ROOT"
  rm -f /tmp/sigmund_test_boot_id
}

run_test() {
  local desc="$1"
  shift
  new_env || { fail "$desc"; return; }
  if "$@"; then
    pass "$desc"
  else
    fail "$desc"
  fi
  cleanup_env
}

extract_id() {
  sed -n 's/^sigmund: id=\([0-9a-f][0-9a-f]*\).*/\1/p' | head -n1
}

start_sleep() {
  "$SIGMUND_BIN" sleep 300 2>&1
}

test_persistent_stale_records() {
  local out id store listout
  out=$("$SIGMUND_BIN" bash -c 'echo stale-line; sleep 0.2' 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  store="$HOME/.local/state/sigmund"
  sleep 0.4

  echo "boot-b" > /tmp/sigmund_test_boot_id

  [ -f "$store/$id.json" ] || return 1
  [ -f "$store/$id.log" ] || return 1

  listout=$("$SIGMUND_BIN" list)
  printf '%s\n' "$listout" | grep -Eq '^RUNID[[:space:]]+STATE[[:space:]]+STARTED_AT[[:space:]]+RESULT[[:space:]]+CMD$'
  printf '%s\n' "$listout" | grep -Eq "^$id[[:space:]]+stale[[:space:]]+"

  "$SIGMUND_BIN" stop "$id" >"$TEST_ROOT/stop.out" 2>"$TEST_ROOT/stop.err" && return 1
  "$SIGMUND_BIN" kill "$id" >"$TEST_ROOT/kill.out" 2>"$TEST_ROOT/kill.err" && return 1
  "$SIGMUND_BIN" killcmd "$id" >"$TEST_ROOT/killcmd.out" 2>"$TEST_ROOT/killcmd.err" && return 1
  grep -q 'stale' "$TEST_ROOT/stop.err"
  grep -q 'stale' "$TEST_ROOT/kill.err"
  grep -q 'stale' "$TEST_ROOT/killcmd.err"

  "$SIGMUND_BIN" tail "$id" >"$TEST_ROOT/tail.out" 2>&1 || return 1
  "$SIGMUND_BIN" dump "$id" >"$TEST_ROOT/dump.out" 2>&1 || return 1
  grep -q 'stale-line' "$TEST_ROOT/tail.out"
  grep -q 'stale-line' "$TEST_ROOT/dump.out"
}

test_prune_by_id() {
  local out1 out2 id1 id2 store
  out1=$("$SIGMUND_BIN" true 2>&1) || return 1
  out2=$("$SIGMUND_BIN" true 2>&1) || return 1
  id1=$(printf '%s\n' "$out1" | extract_id)
  id2=$(printf '%s\n' "$out2" | extract_id)
  [ -n "$id1" ] && [ -n "$id2" ] || return 1
  store="$HOME/.local/state/sigmund"
  sleep 0.2

  "$SIGMUND_BIN" prune "$id1" >/dev/null || return 1
  [ ! -f "$store/$id1.json" ] || return 1
  [ ! -f "$store/$id1.log" ] || return 1
  [ -f "$store/$id2.json" ] || return 1
}

test_prune_all_keeps_running() {
  local out_live out_dead live dead store
  out_live=$(start_sleep) || return 1
  out_dead=$("$SIGMUND_BIN" true 2>&1) || return 1
  live=$(printf '%s\n' "$out_live" | extract_id)
  dead=$(printf '%s\n' "$out_dead" | extract_id)
  [ -n "$live" ] && [ -n "$dead" ] || return 1
  store="$HOME/.local/state/sigmund"
  sleep 0.2

  "$SIGMUND_BIN" prune all >/dev/null || return 1
  [ -f "$store/$live.json" ] || return 1
  [ ! -f "$store/$dead.json" ] || return 1
}

test_transactional_launch_failure() {
  local before after
  before=$(pgrep -fc 'sleep 321')
  SIGMUND_TEST_FAIL_RECORD_WRITE=1 "$SIGMUND_BIN" sleep 321 >/dev/null 2>&1 && return 1
  sleep 0.2
  after=$(pgrep -fc 'sleep 321')
  [ "$after" -le "$before" ]
}

test_build_artifact_coexistence() {
  make clean >/dev/null || return 1
  make sigmund >/dev/null || return 1
  [ -f sigmund ] || return 1
  sum_static=$(sha256sum sigmund | awk '{print $1}')
  make sigmund-dynamic >/dev/null || return 1
  [ -f sigmund ] && [ -f sigmund-dynamic ] || return 1
  sum_dynamic=$(sha256sum sigmund-dynamic | awk '{print $1}')
  [ "$sum_static" != "$sum_dynamic" ]
}

set -e
run_test "persistent stale records are visible and non-signalable" test_persistent_stale_records
run_test "prune by id removes only selected run" test_prune_by_id
run_test "prune all removes prunable and keeps running" test_prune_all_keeps_running
run_test "transactional launch rollback leaves no untracked child" test_transactional_launch_failure
run_test "static and dynamic build artifacts coexist" test_build_artifact_coexistence

if [ "$FAILS" -ne 0 ]; then
  exit 1
fi
