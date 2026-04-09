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
}

extract_id() {
  sed -n 's/^sigmund: id=\([0-9a-f][0-9a-f]*\).*/\1/p' | head -n1
}

pgid_terminated() {
  local g="$1" tries
  for tries in $(seq 1 40); do
    if ! kill -0 "-$g" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

run_test() {
  local desc="$1"
  shift
  new_env || { fail "$desc"; return; }
  if "$@"; then pass "$desc"; else fail "$desc"; fi
  cleanup_env
}

test_list_format_and_lifecycle() {
  local out id
  out=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  "$SIGMUND_BIN" list >"$TEST_ROOT/list.out" || return 1
  grep -Eq '^RUNID[[:space:]]+STATE[[:space:]]+STARTED_AT[[:space:]]+RESULT[[:space:]]+CMD$' "$TEST_ROOT/list.out" || return 1
  grep -Eq "^$id[[:space:]]+running[[:space:]]+[0-9TZ:-]+[[:space:]]+-" "$TEST_ROOT/list.out" || return 1
  "$SIGMUND_BIN" stop "$id" >/dev/null || return 1
  "$SIGMUND_BIN" list | grep -Eq "^$id[[:space:]]+exited[[:space:]]+.*(signal=15|exit=\?)" || return 1
}

test_persistent_stale_records() {
  local out id store rc
  out=$("$SIGMUND_BIN" bash -c 'echo stale-line; sleep 0.2' 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  store="$HOME/.local/state/sigmund"
  sleep 0.4
  [ -f "$store/$id.json" ] && [ -f "$store/$id.log" ] || return 1

  sed -i 's/"boot_id": "[^"]*"/"boot_id": "different-boot-id"/' "$store/$id.json"
  "$SIGMUND_BIN" list | grep -Eq "^$id[[:space:]]+stale" || return 1

  set +e
  "$SIGMUND_BIN" stop "$id" >/tmp/sig-stop.out 2>/tmp/sig-stop.err
  rc=$?
  set -e
  [ "$rc" -eq 2 ] || return 1
  grep -q 'stale (belongs to a prior boot)' /tmp/sig-stop.err || return 1

  set +e
  "$SIGMUND_BIN" kill "$id" >/tmp/sig-kill.out 2>/tmp/sig-kill.err
  rc=$?
  set -e
  [ "$rc" -eq 2 ] || return 1

  set +e
  "$SIGMUND_BIN" killcmd "$id" >/tmp/sig-killcmd.out 2>/tmp/sig-killcmd.err
  rc=$?
  set -e
  [ "$rc" -eq 2 ] || return 1

  "$SIGMUND_BIN" tail "$id" >"$TEST_ROOT/tail.out" 2>&1 || return 1

  "$SIGMUND_BIN" dump "$id" >"$TEST_ROOT/dump.out" 2>&1 || return 1
  grep -q 'stale-line' "$TEST_ROOT/dump.out"
}

test_prune_by_id() {
  local out1 out2 id1 id2 store
  out1=$("$SIGMUND_BIN" bash -c 'echo one' 2>&1) || return 1
  out2=$("$SIGMUND_BIN" bash -c 'echo two' 2>&1) || return 1
  id1=$(printf '%s\n' "$out1" | extract_id)
  id2=$(printf '%s\n' "$out2" | extract_id)
  [ -n "$id1" ] && [ -n "$id2" ] || return 1
  store="$HOME/.local/state/sigmund"
  sleep 0.2

  "$SIGMUND_BIN" prune "$id1" >/dev/null || return 1
  [ ! -e "$store/$id1.json" ] && [ ! -e "$store/$id1.log" ] || return 1
  [ -e "$store/$id2.json" ] && [ -e "$store/$id2.log" ] || return 1
}

test_prune_all_keeps_running() {
  local out_run out_dead out_stale id_run id_dead id_stale store
  out_run=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  out_dead=$("$SIGMUND_BIN" bash -c 'echo dead' 2>&1) || return 1
  out_stale=$("$SIGMUND_BIN" bash -c 'echo stale' 2>&1) || return 1
  id_run=$(printf '%s\n' "$out_run" | extract_id)
  id_dead=$(printf '%s\n' "$out_dead" | extract_id)
  id_stale=$(printf '%s\n' "$out_stale" | extract_id)
  [ -n "$id_run" ] && [ -n "$id_dead" ] && [ -n "$id_stale" ] || return 1
  store="$HOME/.local/state/sigmund"
  sleep 0.3
  sed -i 's/"boot_id": "[^"]*"/"boot_id": "different-boot-id"/' "$store/$id_stale.json"

  "$SIGMUND_BIN" prune all >/dev/null || return 1

  [ -e "$store/$id_run.json" ] || return 1
  [ ! -e "$store/$id_dead.json" ] && [ ! -e "$store/$id_stale.json" ] || return 1

  "$SIGMUND_BIN" kill "$id_run" >/dev/null || return 1
}

test_transactional_write_failure() {
  local rc ids out pgid
  set +e
  out=$(SIGMUND_INJECT_WRITE_FAIL=1 "$SIGMUND_BIN" sleep 300 2>&1)
  rc=$?
  set -e
  [ "$rc" -eq 1 ] || return 1
  echo "$out" | grep -q 'failed to write record' || return 1
  ids=$(find "$HOME/.local/state/sigmund" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l)
  [ "$ids" -eq 0 ] || return 1
  pgid=$(echo "$out" | sed -n 's/.*pgid=\([0-9][0-9]*\).*/\1/p' | head -n1)
  if [ -n "$pgid" ]; then
    ! kill -0 "-$pgid" 2>/dev/null || return 1
  fi
}

test_build_artifact_coexistence() {
  make clean >/dev/null || return 1
  make sigmund >/dev/null || return 1
  [ -x ./sigmund ] || return 1
  [ ! -e ./sigmund-dynamic ] || return 1
  make sigmund-dynamic >/dev/null || return 1
  [ -x ./sigmund ] && [ -x ./sigmund-dynamic ] || return 1
}

set -e
run_test "list output format and lifecycle state" test_list_format_and_lifecycle
run_test "persistent stale records across boot change" test_persistent_stale_records
run_test "prune by run id removes only selected run" test_prune_by_id
run_test "prune all removes prunable and keeps running" test_prune_all_keeps_running
run_test "transactional launch rollback on record failure" test_transactional_write_failure
run_test "static and dynamic build artifacts coexist" test_build_artifact_coexistence

if [ "$FAILS" -ne 0 ]; then
  exit 1
fi
