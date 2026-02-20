# sigmund

**A tiny, daemonless process supervisor and background job protector.**

`sigmund` is a lightweight launcher that protects detached processes from CI/runner process-group cleanup and gives you a durable, safe handle to manage them later. 

Many CI runners (like GitHub Actions or GitLab CI) and non-interactive job systems terminate the invoking shell’s **process group** at step completion. If you start a long-running process (like QEMU, a test database, or a web server) in the background using standard shell tools like `nohup cmd &`, it will be killed the moment the step finishes. 

`sigmund` prevents this by launching the command in a **new session / process group** and recording a small state file. This allows you to safely background tasks, capture their logs, and tear down their *entire* process tree cleanly when you are done.

*(Name note: in Old English and related Germanic languages, **mund** relates to “protection/guardianship,” so `sigmund` reads naturally as “signal protection.”)*

## Why use `sigmund`?

* **Better than `nohup &`:** Prevents orphan processes. `sigmund stop` kills the entire process group, ensuring child processes don't leak.
* **Safer than bare `kill $PID`:** Immune to PID recycling. `sigmund` verifies `/proc/<pid>/stat` start times and `/proc/<pid>/exe` inodes before sending signals, so you never accidentally kill a system service days later.
* **Lighter than `systemd-run` or `tmux`:** Zero dependencies, no background daemon, no D-Bus required. Just a single compiled C binary.

## Status
Private kickoff. Interface and behavior are stabilizing. Source of truth: `docs/SPEC.md`

## Quickstart

**Build:**
Requires a C11 compiler. Linux-first (relies on `/proc` for identity validation).
```bash
make
./sigmund --help
```

**Basic Usage:**
```bash
# Start a detached process
$ sigmund qemu-system-x86_64 -m 4096 -nographic
sigmund: id=7f3c2a pid=4012 pgid=4012 sid=4012
sigmund: log: /run/user/1000/sigmund/7f3c2a.log

# List tracked runs
$ sigmund -l
ID      PID      PGID     AGE    STATE    CMD
7f3c2a  4012     4012     12s    running  qemu-system-x86_64 -m 4096...

# Stop the run cleanly (sends SIGTERM, waits, then SIGKILL if needed)
$ sigmund stop 7f3c2a
```

*(Note: Use `sigmund -- <cmd>` if your command name overlaps with a sigmund subcommand).*

---

## Real-World Workflows

### 1. The CI/CD Pipeline (Integration Testing)
When running integration tests, you often need to spin up a server, run tests against it, and tear it down. `sigmund` handles the backgrounding, logging, and cleanup automatically.

```yaml
# Example CI Step
- name: Start Test Database
  run: |
    # Starts in a new session, immune to this step's teardown
    sigmund -- redis-server --port 6379
    sleep 2 # wait for boot

- name: Run Test Suite
  run: npm run test:integration

- name: Teardown
  if: always()
  run: |
    # Find and stop the redis server
    RUN_ID=$(sigmund -l | grep redis-server | awk '{print $1}')
    sigmund stop $RUN_ID
    sigmund prune
```

### 2. Local Development (Fire and Forget)
If you are testing a complex local architecture (e.g., a frontend watcher, a backend API, and a worker queue), you can use `sigmund` to spin them up into the background without keeping multiple terminal tabs open, and without losing track of them.

```bash
sigmund npm run dev:frontend
sigmund npm run dev:backend
sigmund celery -A myapp worker

# Later, when you want to stop working:
sigmund -l
# Stop them individually, or script a teardown of all running jobs
```

---

## Command Reference

| Command                | Description                                                                                    |
|------------------------|------------------------------------------------------------------------------------------------|
| `sigmund <cmd>`        | Starts a command in a new process group.                                                       |
| `sigmund -l`, `--list` | Lists all tracked runs, their PIDs, age, state, and command.                                   |                        
| `sigmund stop <id>`    | Gracefully stops a run. Sends `SIGTERM` to the group, waits up to 5s, then sends `SIGKILL`.    |
| `sigmund kill <id>`    | Forcefully kills a run immediately using `SIGKILL`.                                            |
| `sigmund prune`        | Cleans up the state files and logs for processes that are natively `dead`.                     |
| `sigmund killcmd <id>` | Prints the raw shell command needed to signal the process group (e.g., `kill -TERM -- -4012`). |

## Smart Stdio & Logging (KISS)

`sigmund` handles I/O dynamically based on your environment:

* `stdin` is always safely redirected from `/dev/null`.
* **Interactive (TTY):** If you run `sigmund` in a standard terminal, `stdout` and `stderr` stay on your console so you can see immediate startup errors.
* **Non-interactive (CI/Scripts):** If run in a pipeline or redirected, `sigmund` automatically routes `stdout` and `stderr` to a dedicated per-run log file stored next to the state record. The log path is printed to standard output upon successful launch.

## Architecture & Safety Guarantees

`sigmund` tracks state in `$XDG_RUNTIME_DIR/sigmund` (or `$XDG_STATE_HOME` / `~/.local/state`). All state updates use atomic file renames (`rename()` + `fsync()`) so records are never corrupted, even during power loss.

**Strict Identity Validation:**
Before sending *any* signal, `sigmund` checks:
1. Does the system `boot_id` match the one recorded? (Prevents signaling the wrong process after a reboot).
2. Does `/proc/<pid>/stat` start-time match? (Prevents signaling if the PID rolled over and was reassigned).
3. Do the executable device/inode numbers in `/proc/<pid>/exe` match? (Prevents signaling if a different binary took the PID).

If any check fails, the state evaluates as `stale` and signals are blocked.

**Edge Cases Handled:**
* If the original leader PID exits but child processes in the group remain alive, `sigmund stop` still targets the group safely.
* Very fast commands may exit before `/proc` can be read; this is treated as non-fatal and will accurately show as `dead` on the next list.
* Warns if child processes "escape" the process group (e.g., a child calls `setsid()` itself) but remain in the session.

## Roadmap (Near-Term)

* MVP completeness: start/list/stop/kill/prune/killcmd
* Harden edge cases in CI runners:
  * exec-handshake reliability
  * leader-exits-but-group-lives behavior
  * consistent state handling with `$XDG_RUNTIME_DIR`
* Optional Linux-only diagnostics:
  * session-ID scan to warn on group escapes

## License

Apache-2.0. See `LICENSE`.
