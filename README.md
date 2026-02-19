# sigmund

`sigmund` is a tiny launcher that protects detached processes from CI/runner process-group cleanup and gives a durable handle to manage what it started.

Many CI runners and non-interactive job systems terminate the invoking shell’s **process group** at step completion (often via SIGTERM to the group). If a long-running process (QEMU, a test server, a DB, etc.) is started in that same process group, it can be killed immediately. `sigmund` prevents that by launching the command in a **new session / new process group** and recording a small run record so it can be listed and stopped safely.

Name note: in Old English and related Germanic languages, *mund* relates to “protection/guardianship,” so `sigmund` reads naturally as “signal protection.”

## Status

Private kickoff. Interface and behavior are stabilizing.

Source of truth: `SPEC.md`

## Quickstart

### Build (local)
- C11
- Linux-first (uses `/proc` for identity validation)

```bash
make
./sigmund --help
```

### Usage

Start a detached process:

```bash
sigmund <command> [args...]
```

List tracked runs:

```bash
sigmund -l
```

Stop a run (TERM → wait → KILL):

```bash
sigmund stop <id>
```

Force kill:

```bash
sigmund kill <id>
```

Remove records for runs that are finished:

```bash
sigmund prune
```

Print a copy/paste kill command for the process group:

```bash
sigmund killcmd <id>
```

## Example

```bash
sigmund qemu-system-x86_64 -m 4096 ...
sigmund -l
sigmund stop 7f3c2a
```

## What it does (high level)

* Launches the child in a **new session** using `setsid()` so it does not receive “parent process-group cleanup” signals.
* Stops the run by signaling the **process group** (`kill(-pgid, SIGTERM)`), which terminates the whole tree that stayed in that group.
* Writes a small run record keyed by a short `id`, so runs can be listed and stopped later.

## Stdio behavior (KISS, no flags)

`sigmund` aims to be pleasant locally and safe in CI:

* `stdin` is always redirected from `/dev/null`.
* If both `stdout` and `stderr` are TTYs (interactive terminal), output stays on the console.
* Otherwise (non-interactive: pipes/CI/log collectors), `stdout` and `stderr` are redirected to a per-run log file next to the record.

When redirection is used, start output includes the log path.

## Safety / correctness notes

Linux identity validation is used to avoid PID reuse mistakes:

* The run record stores `/proc/<pid>/stat` starttime ticks (and best-effort executable identity).
* Before sending signals to a recorded group, `sigmund` verifies the leader PID still matches the recorded identity; mismatches are treated as **stale** and are refused.

Additional edge cases handled by design:

* If the original leader PID exits but the process group remains alive, `sigmund stop` still targets the group safely.
* Very fast commands may exit before `/proc` can be read; this is treated as non-fatal and will show as `dead` on the next list.

## Repo layout

* `docs/spec.md` — detailed specification (source of truth)
* `src/` — implementation
* `Makefile` — build

## Roadmap (near-term)

* MVP completeness: start/list/stop/kill/prune/killcmd
* Harden edge cases in CI runners:

  * exec-handshake reliability
  * leader-exits-but-group-lives behavior
  * consistent state handling with `$XDG_RUNTIME_DIR`
* Optional Linux-only diagnostics:

  * session-ID scan to warn on group escapes

## License

Apache-2.0. See `LICENSE`.
