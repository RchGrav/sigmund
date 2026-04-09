## sigmund specification

### Purpose

`sigmund` is a tiny CLI launcher (not a supervisor) that starts commands in a separate session/process-group and records durable run metadata under a persistent state directory.

### Non-goals

- No daemon runtime.
- No restart policy.
- No auto-restart after reboot.
- No scheduling layer.

## Storage model

- State dir: `~/.local/state/sigmund`.
- Records (`<runid>.json`) and output logs (`<runid>.log`) persist across reboot.
- Reboot must not auto-delete records or logs.
- `boot_id` is stored per run and used as a safety/classification boundary.
- `boot_id` mismatch marks runs as `stale`; it is not a restart mechanism.

## Run record fields

Each persistent run record contains at least:

- `id` (run id)
- `boot_id`
- `started_at`
- `start_unix_ns`
- `ended_at` (if known)
- `state`
- `exit_code` (if known)
- `term_signal` (if known)
- `launch_error` (if applicable)
- command/argv summary (`cmdline_display`, `argv`)
- `log_path`

## CLI

Start:

- `sigmund <command> [args...]`
- `sigmund --tail <command> [args...]`

Management:

- `sigmund list`
- `sigmund tail <runid>`
- `sigmund dump <runid>`
- `sigmund stop <runid>`
- `sigmund kill <runid>`
- `sigmund killcmd <runid>`
- `sigmund prune`
- `sigmund prune <runid>`
- `sigmund prune all`

## List output contract

Columns:

- `RUNID`
- `STATE` (`running`, `exited`, `stale`, `failed`)
- `STARTED_AT` (RFC3339 UTC)
- `RESULT`
  - `-` for running
  - `exit=<code>` for normal exits
  - `signal=<sig>` for signal termination
  - `launch=<reason>` for launch/setup failures with recorded failed run state
- `CMD`

## State semantics

- Every launch gets a new run id.
- A run id identifies one concrete execution only.
- `stale` means “belongs to a prior boot”, not “running”.
- `stop/kill/killcmd` must refuse stale runs.
- `tail`/`dump` may still operate on stale runs when log exists.

## Prune semantics

- Cleanup is explicit operator action.
- `prune <runid>` removes exactly one prunable run and its output.
- `prune all` (and bare `prune`) removes all prunable runs and output.
- Prunable = stale, exited, or failed.
- Running runs are never pruned.
- Matching is conservative: exact run id, with unique id-prefix resolution only.

## Startup transaction guarantee

After spawn, either:

1. run record persistence commits durably, or
2. launch is rolled back (spawned process-group killed, launcher reaped).

No unmanaged background process may be left running on record-write failure.
