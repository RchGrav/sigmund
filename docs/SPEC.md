## sigmund specification

### Purpose

`sigmund` is a small CLI utility that launches a command so it survives CI/runner “process-group cleanup” and then provides a durable handle to manage that run.

Many CI runners and non-interactive job systems terminate the invoking shell’s **process group** at step completion (commonly via SIGTERM to the group). A long-running process started in the same group can be terminated immediately. `sigmund` prevents this by launching the command in a **new session / new process group** and recording a run record that can later be listed and stopped safely.

Name note: in Old English and related Germanic languages, *mund* relates to “protection/guardianship,” so `sigmund` reads naturally as “signal protection.”

---

### Non-goals

* Not a supervisor (no restart loops, no monitoring)
* Not a scheduler
* Not a cgroup manager by default
* No mandatory configuration or naming ceremony; the primary interface remains `sigmund <command> …`

---

## Command-line interface

### Start

```
sigmund <command> [args...]
```

Behavior:

* Launches `<command>` in a new session and new process group.
* Creates a run record and prints a short durable `id`.

Default output (human):

```
sigmund: id=7f3c2a pid=12345 pgid=12345 sid=12345
sigmund: log: /path/to/7f3c2a.log
sigmund: stop: sigmund stop 7f3c2a
```

### Tail

    sigmund --tail <cmd> [args...]
    sigmund --tail <id>

`sigmund --tail <cmd> [args...]` launches the command identically to `sigmund <cmd>` (backgrounded, log file, new session), then tails the log file to stdout.

`sigmund --tail <id>` tails the log for an already-running tracked process.

Ctrl-C detaches from tailing — the background process keeps running.

### List

```
sigmund -l
sigmund --list
```

Lists run records and their status.

Columns (stable):

* `ID`
* `PID`
* `PGID`
* `AGE`
* `STATE` (`running`, `dead`, `stale`, `unknown`)
* `CMD` (truncated)

### Stop

```
sigmund stop <id>
```

Behavior:

* Sends SIGTERM to the run’s process group (`kill(-pgid, SIGTERM)`).
* Waits up to a fixed timeout (default 5000ms) for group exit.
* If the group still exists after timeout, sends SIGKILL (`kill(-pgid, SIGKILL)`).
* Updates the run record state.

Exit codes:

* `0` success (stopped or already dead)
* `2` stale / identity mismatch (refused)
* `3` permission denied
* `4` timeout / could not terminate group
* `5` record not found / invalid id

### Kill

```
sigmund kill <id>
```

Behavior:

* Sends SIGKILL to the run’s process group (`kill(-pgid, SIGKILL)`) after safety checks.
* Updates state if possible.

Exit codes follow `stop`.

### Prune

```
sigmund prune
```

Removes run records that are `dead`. Records in `stale` or `unknown` state are retained.

### Kill command helper

```
sigmund killcmd <id>
```

Prints a copy/paste command that targets the process group:

```
kill -TERM -- -<pgid>
```

---

## Stdio policy

* `stdin` is always redirected from `/dev/null`.
* `stdout` and `stderr` are always redirected to a per-run log file: `<storage_dir>/<id>.log`.

Start output always includes the log path and a stop command:

    sigmund: id=<id> pid=<pid> pgid=<pgid> sid=<sid>
    sigmund: log: /path/to/<id>.log
    sigmund: stop: sigmund stop <id>

---

## Storage and run records

### Storage directory

Preferred (volatile, per-login):

1. If `$XDG_RUNTIME_DIR` is set: `$XDG_RUNTIME_DIR/sigmund/`

Fallback (persistent):
2. `$XDG_STATE_HOME/sigmund/` else `~/.local/state/sigmund/`

Permissions:

* directory `0700`
* files `0600`

### Boot correlation (Linux)

If the fallback persistent directory is used, records must include Linux `boot_id` from:

* `/proc/sys/kernel/random/boot_id`

On `list/stop/kill`, if current `boot_id` differs from the record’s `boot_id`, the record is `stale` and `stop/kill` must refuse unless forced by implementation policy (no CLI flag is required by this spec; refusal is required).

### Record format

One JSON record per run: `<id>.json`

Required fields:

* `version` (int)
* `id` (string; 6–10 hex chars)
* `pid` (int) — leader PID at launch
* `pgid` (int)
* `sid` (int)
* `start_unix_ns` (int64)
* `argv` (array of strings)
* `uid` (int)
* `gid` (int)
* `log_path` (string)
* `boot_id` (string; Linux; required when not using `$XDG_RUNTIME_DIR`)

Linux identity fields (best-effort; required for “safe stop” when available):

* `proc_starttime_ticks` (uint64) — from `/proc/<pid>/stat` field 22
* `exe_dev` (uint64, optional) — from `stat("/proc/<pid>/exe")`
* `exe_ino` (uint64, optional) — from `stat("/proc/<pid>/exe")`

Record writes must be atomic:

* write temp file in same directory
* `fsync` the temp file
* `rename()` to final name
* (recommended) `fsync` the directory

### ID generation

* Random 6–10 hex chars from a cryptographic source:

  * Linux: `getrandom()` when available
  * fallback: `/dev/urandom`
* Collision check: if `<id>.json` exists, regenerate.

---

## Process creation and session isolation (C11 implementation requirements)

### Exec success handshake (required)

A pipe is used to distinguish “exec succeeded” from “exec failed” without races:

* Parent creates pipe with close-on-exec set on both ends (`pipe2(O_CLOEXEC)` where available; otherwise `fcntl(FD_CLOEXEC)` on both fds).
* Child keeps the write end open until `execvp()`:

  * If `execvp()` succeeds, the write end is closed automatically by CLOEXEC; the parent reads EOF.
  * If `execvp()` fails, the child writes `errno` to the pipe and exits.

### Start algorithm

1. Determine storage directory; ensure it exists with mode `0700`.
2. Generate `id`.
3. Compute log path as `<storage_dir>/<id>.log`.
4. Create exec-handshake pipe (CLOEXEC both ends).
5. `fork()`.
6. Child process:

   * `setsid()`; on failure, write `errno` to pipe and `_exit(127)`.
   * Open `/dev/null` and `dup2` to `STDIN_FILENO`.
   * Open log file and `dup2` it to `STDOUT_FILENO` and `STDERR_FILENO`.
   * `execvp(argv[0], argv)`.
   * On exec failure: write `errno` to pipe; `_exit(127)`.
7. Parent process:

   * Read the pipe:

     * EOF: exec succeeded.
     * errno payload: `waitpid(child_pid, ...)` to reap; return error; do not write a record.
   * Record leader identifiers without extra syscalls:

     * `pid = child_pid`
     * `pgid = pid`
     * `sid = pid`
   * Capture identity fields (Linux best-effort):

     * Read `/proc/<pid>/stat` and extract field 22 (`proc_starttime_ticks`).

       * Parsing requirement: `/proc/<pid>/stat` contains `comm` in parentheses; locate the last `)` and parse fields after it to reach field 22.
     * `stat("/proc/<pid>/exe")` to capture `(st_dev, st_ino)` when permitted.
     * If `/proc` reads return `ENOENT` (fast exit after exec), treat as non-fatal and write the record with missing identity fields set to 0.
   * Write record atomically.
   * Print start output including id/pid/pgid/sid, log path, and stop command.

---

## Stop/kill safety and semantics

### Safety requirements (hard)

Before signaling `-pgid`, `sigmund` must ensure the target corresponds to the recorded run:

1. If the record contains `boot_id`, it must match the current boot.
2. Determine whether the leader PID exists:

   * If `/proc/<pid>` exists (Linux) or `kill(pid, 0)` indicates existence (0 or `EPERM`), the leader is considered present.
   * If the leader is present and Linux identity fields are available, `proc_starttime_ticks` must match the current `/proc/<pid>/stat` field 22. If recorded `exe_dev/exe_ino` are present and readable, they must match.
   * If identity mismatch occurs, mark record `stale` and refuse to signal.
3. If the leader PID is absent:

   * If `kill(-pgid, 0)` returns `0` or `EPERM`, the group exists and may be signaled.
   * If `kill(-pgid, 0)` returns `ESRCH`, the group is gone and the run is `dead`.

### Stop behavior

* Send SIGTERM to `-pgid`.
* Poll for group disappearance using `kill(-pgid, 0)` until timeout:

  * `0` or `EPERM` means group exists
  * `ESRCH` means group gone
* Poll loop must sleep to avoid CPU spin (e.g., `nanosleep` 20–50ms per iteration).
* If timeout expires and group still exists, send SIGKILL to `-pgid`, then recheck.
* Update record state to `dead` when group is gone.

### Kill behavior

* Send SIGKILL to `-pgid` after the same safety checks.
* Optionally recheck and mark `dead` when gone.

---

## List semantics

For each record:

* If `boot_id` mismatches, state is `stale`.
* If leader PID exists and identity checks pass, state is `running`.
* If leader PID exists and identity checks fail, state is `stale`.
* If leader PID is absent:

  * `kill(-pgid,0)` is `0`/`EPERM` → `running` (leader exited, group lives)
  * `ESRCH` → `dead`
* If validation cannot be performed (non-Linux without strong evidence), state is `unknown`.

---

## Escape diagnostics (Linux, informational)

After stopping, session-based diagnostics may be emitted:

* Scan `/proc/[0-9]*/stat` for processes whose `SID` equals the recorded `sid`.
* If any have `PGID != recorded_pgid`, report them as having escaped the group within the session.
* Processes that created a new session cannot be detected without stronger containment (e.g., cgroups); diagnostics do not affect exit codes.

---

## Security and robustness

* Operations are constrained by OS permissions; only processes the user can signal are manageable.
* Storage directory is private (0700) and records are 0600.
* Exec failures are reaped (`waitpid`) to avoid zombies.
* No signals are sent to `-pgid` if safety checks fail; such records become `stale`.

---

## Build and compatibility

* Language: C11
* Requires POSIX APIs: `fork`, `execvp`, `setsid`, `kill`, `waitpid`, `open`, `dup2`, `pipe/pipe2`, `fcntl`, `stat`, `rename`, `fsync`, `nanosleep`
* Linux enhancements: `/proc` parsing, `boot_id`, optional `getrandom()` (fallback `/dev/urandom`)
