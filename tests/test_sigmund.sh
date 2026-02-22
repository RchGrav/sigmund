#!/usr/bin/env bash
set -u

SIGMUND_BIN="${SIGMUND_BIN:-./sigmund}"
FAILS=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

new_env() {
  TEST_ROOT="$(mktemp -d)" || return 1
  export XDG_RUNTIME_DIR="$TEST_ROOT/runtime"
  mkdir -p "$XDG_RUNTIME_DIR" || return 1
  chmod 700 "$XDG_RUNTIME_DIR" || return 1
}

cleanup_env() {
  local store ids id
  store="$XDG_RUNTIME_DIR/sigmund"
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


pid_dead_enough() {
  local p="$1" st
  if ! kill -0 "$p" 2>/dev/null; then
    return 0
  fi
  st=$(ps -o stat= -p "$p" 2>/dev/null | tr -d ' ' | cut -c1)
  [ "$st" = "Z" ]
}

pgid_terminated() {
  local g="$1" tries stats
  for tries in $(seq 1 40); do
    if ! kill -0 "-$g" 2>/dev/null; then
      return 0
    fi
    stats=$(ps -o stat= -g "$g" 2>/dev/null | tr -d " ")
    if [ -n "$stats" ] && ! printf "%s\n" "$stats" | grep -qv "^Z"; then
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
  if "$@"; then
    pass "$desc"
  else
    fail "$desc"
  fi
  cleanup_env
}

test_lifecycle() {
  local out id lines
  out=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  printf '%s\n' "$out" | grep -Eq 'pid=[0-9]+ pgid=[0-9]+ sid=[0-9]+'
  printf '%s\n' "$out" | grep -Eq '^sigmund: log: .+/.+\\.log$'
  printf '%s\n' "$out" | grep -Eq "^sigmund: stop: sigmund stop $id$"
  "$SIGMUND_BIN" -l | grep -Eq "^$id[[:space:]].*running"
  "$SIGMUND_BIN" stop "$id" >/dev/null
  "$SIGMUND_BIN" -l | grep -Eq "^$id[[:space:]].*dead"
  "$SIGMUND_BIN" prune >/dev/null
  lines=$("$SIGMUND_BIN" -l | wc -l)
  [ "$lines" -eq 1 ]
}


test_start_output_stop_hint() {
  local out id
  out=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  printf '%s\n' "$out" | grep -Eq "^sigmund: stop: sigmund stop $id$"
}
test_kill_subcommand() {
  local out id pgid
  out=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  pgid=$(sed -n 's/.*pgid=\([0-9][0-9]*\).*/\1/p' <<<"$out" | head -n1)
  [ -n "$pgid" ] || return 1
  "$SIGMUND_BIN" kill "$id" >/dev/null || return 1
  pgid_terminated "$pgid"
}

test_group_kill_children() {
  local out id pgid children
  out=$("$SIGMUND_BIN" bash -c 'sleep 600 & sleep 601 & wait' 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  pgid=$(sed -n 's/.*pgid=\([0-9][0-9]*\).*/\1/p' <<<"$out" | head -n1)
  [ -n "$id" ] && [ -n "$pgid" ] || return 1
  sleep 0.2
  children=$(ps -eo pid=,pgid=,args= | awk -v g="$pgid" '$2==g && $1!=g && $3 ~ /^sleep$/ {print $1}')
  [ -n "$children" ] || return 1
  "$SIGMUND_BIN" stop "$id" >/dev/null || return 1
  sleep 0.2
  for p in $children; do
    pid_dead_enough "$p" || return 1
  done
  return 0
}

test_exec_failure_no_record() {
  local rc count
  set +e
  "$SIGMUND_BIN" nonexistent_binary_xyz >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 1 ] || return 1
  count=$(find "$XDG_RUNTIME_DIR/sigmund" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l)
  [ "$count" -eq 0 ]
}

test_fast_exit_record_dead() {
  local out id
  out=$("$SIGMUND_BIN" true 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  sleep 0.1
  "$SIGMUND_BIN" -l | grep -Eq "^$id[[:space:]].*dead"
}

test_corrupt_record_handling() {
  mkdir -p "$XDG_RUNTIME_DIR/sigmund" || return 1
  printf 'garbage\n' > "$XDG_RUNTIME_DIR/sigmund/badbad.json" || return 1
  "$SIGMUND_BIN" -l >"$TEST_ROOT/list.out" 2>"$TEST_ROOT/list.err" || return 1
  ! grep -q '^badbad' "$TEST_ROOT/list.out"
  ! grep -Eq '^0[[:space:]]' "$TEST_ROOT/list.out"
  grep -q 'warning: skipping corrupt record badbad.json' "$TEST_ROOT/list.err"
  "$SIGMUND_BIN" prune >/dev/null || return 1
  [ ! -e "$XDG_RUNTIME_DIR/sigmund/badbad.json" ]
}

test_invalid_pgid_record() {
  mkdir -p "$XDG_RUNTIME_DIR/sigmund" || return 1
  cat > "$XDG_RUNTIME_DIR/sigmund/abc123.json" <<'JSON'
{"version":1,"id":"abc123","pid":12345,"pgid":0,"sid":12345,"start_unix_ns":0,"argv":["x"],"cmdline_display":"x","uid":0,"gid":0,"proc_starttime_ticks":0,"exe_dev":0,"exe_ino":0}
JSON
  "$SIGMUND_BIN" -l >"$TEST_ROOT/list.out" 2>"$TEST_ROOT/list.err" || return 1
  ! grep -q '^abc123' "$TEST_ROOT/list.out"
}

test_orphan_log_cleanup() {
  mkdir -p "$XDG_RUNTIME_DIR/sigmund" || return 1
  : > "$XDG_RUNTIME_DIR/sigmund/a1b2c3.log" || return 1
  : > "$XDG_RUNTIME_DIR/sigmund/deadbe.log" || return 1
  "$SIGMUND_BIN" prune >/dev/null || return 1
  [ ! -e "$XDG_RUNTIME_DIR/sigmund/a1b2c3.log" ] && [ ! -e "$XDG_RUNTIME_DIR/sigmund/deadbe.log" ]
}

test_id_sanitization() {
  local rc
  for bad in '../../etc/passwd' 'AABBCC' 'hello!' ''; do
    set +e
    "$SIGMUND_BIN" stop "$bad" >/dev/null 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 5 ] || return 1
  done
}

test_killcmd_output() {
  local out id pgid got
  out=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  pgid=$(sed -n 's/.*pgid=\([0-9][0-9]*\).*/\1/p' <<<"$out" | head -n1)
  [ -n "$id" ] && [ -n "$pgid" ] || return 1
  got=$("$SIGMUND_BIN" killcmd "$id") || return 1
  [ "$got" = "kill -TERM -- -$pgid" ]
}

test_stop_multiple_ids() {
  local out1 out2 id1 id2 pgid1 pgid2 rc
  out1=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  out2=$("$SIGMUND_BIN" sleep 300 2>&1) || return 1
  id1=$(printf '%s\n' "$out1" | extract_id)
  id2=$(printf '%s\n' "$out2" | extract_id)
  pgid1=$(sed -n 's/.*pgid=\([0-9][0-9]*\).*/\1/p' <<<"$out1" | head -n1)
  pgid2=$(sed -n 's/.*pgid=\([0-9][0-9]*\).*/\1/p' <<<"$out2" | head -n1)
  [ -n "$id1" ] && [ -n "$id2" ] && [ -n "$pgid1" ] && [ -n "$pgid2" ] || return 1
  set +e
  "$SIGMUND_BIN" stop "$id1" "$id2" >/dev/null
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || return 1
  pgid_terminated "$pgid1" || return 1
  pgid_terminated "$pgid2"
}

test_argument_edges() {
  local rc out
  set +e
  "$SIGMUND_BIN" >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 1 ] || return 1
  set +e
  "$SIGMUND_BIN" stop >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 5 ] || return 1
  "$SIGMUND_BIN" --help >/dev/null || return 1
  out=$("$SIGMUND_BIN" --version) || return 1
  printf '%s\n' "$out" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+'
  "$SIGMUND_BIN" -- sleep 1 >/dev/null
}

test_special_chars_args() {
  local out id json
  out=$("$SIGMUND_BIN" echo "hello world" "it's" 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  json="$XDG_RUNTIME_DIR/sigmund/$id.json"
  [ -f "$json" ] || return 1
  grep -Fq '"hello world"' "$json"
  grep -Fq '"it'"'"'s"' "$json"
}

test_log_capture() {
  local out id log
  out=$("$SIGMUND_BIN" bash -c 'echo out; echo err >&2; sleep 0.1' 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  log="$XDG_RUNTIME_DIR/sigmund/$id.log"
  sleep 0.4
  [ -f "$log" ] || return 1
  grep -q 'out' "$log" && grep -q 'err' "$log"
}



test_tail_existing_id() {
  local out id tailed
  out=$("$SIGMUND_BIN" bash -c 'echo from_tail_id; sleep 0.2' 2>&1) || return 1
  id=$(printf '%s\n' "$out" | extract_id)
  [ -n "$id" ] || return 1
  tailed=$("$SIGMUND_BIN" --tail "$id" 2>&1) || return 1
  printf '%s\n' "$tailed" | grep -q 'from_tail_id'
}
test_concurrent_unique_ids() {
  local i id ids uniq
  ids=""
  for i in $(seq 1 20); do
    "$SIGMUND_BIN" sleep 60 >"$TEST_ROOT/start.$i.out" 2>"$TEST_ROOT/start.$i.err" &
  done
  wait
  for i in $(seq 1 20); do
    id=$(extract_id <"$TEST_ROOT/start.$i.out")
    [ -n "$id" ] || return 1
    ids="$ids\n$id"
  done
  uniq=$(printf '%b\n' "$ids" | sed '/^$/d' | sort -u | wc -l)
  [ "$uniq" -eq 20 ]
}

set -e
run_test "start/stop lifecycle" test_lifecycle
run_test "kill subcommand kills process group" test_kill_subcommand
run_test "start output includes stop helper" test_start_output_stop_hint
run_test "stop kills full process group (children)" test_group_kill_children
run_test "exec failure creates no record" test_exec_failure_no_record
run_test "fast exit command is recorded as dead" test_fast_exit_record_dead
run_test "corrupt record warning and prune cleanup" test_corrupt_record_handling
run_test "invalid pgid=0 record is not listed as running" test_invalid_pgid_record
run_test "orphan logs are removed by prune" test_orphan_log_cleanup
run_test "ID input sanitization rejects invalid ids" test_id_sanitization
run_test "killcmd prints group kill command" test_killcmd_output
run_test "stop supports multiple IDs in one command" test_stop_multiple_ids
run_test "argument edge cases" test_argument_edges
run_test "special characters are preserved in argv JSON" test_special_chars_args
run_test "logging captures stdout+stderr" test_log_capture
run_test "--tail <id> tails an existing run log" test_tail_existing_id
run_test "concurrent starts produce unique ids" test_concurrent_unique_ids

if [ "$FAILS" -ne 0 ]; then
  exit 1
fi
