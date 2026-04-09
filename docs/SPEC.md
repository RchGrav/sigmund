## sigmund specification

### Purpose

`sigmund` is a tiny launcher (not a supervisor) that starts a command in a new session/process-group and records that concrete run in persistent per-user state.

### Core guarantees

- `sigmund` is daemonless and does not restart processes.
- launched processes do **not** survive reboot.
- run records/logs **do** survive reboot.
- boot-id changes do **not** auto-delete state.
- boot-id mismatch classifies a run as `stale` (safety boundary), not a restart trigger.
- stale records remain visible until explicitly pruned.

---

## CLI

### Start

```
sigmund <command> [args...]
sigmund --tail <command> [args...]
sigmund -- <command> [args...]
```

### Manage

```
sigmund list
sigmund tail <runid>
sigmund dump <runid>
sigmund stop <runid>...
sigmund kill <runid>...
sigmund killcmd <runid>...
sigmund prune
sigmund prune <runid>
sigmund prune all
```

Notes:
- `tail` works for stale runs if the log exists.
- `dump` prints the saved output and exits (including stale runs if log exists).
- `stop`/`kill`/`killcmd` refuse stale runs.
- bare `prune` is kept for compatibility and behaves like `prune all`.

---

## `list` output

Columns:
- `RUNID`
- `STATE` (`running`, `exited`, `stale`, `failed`, `unknown`)
- `STARTED_AT` (RFC3339 UTC)
- `RESULT` (`-`, `exit=<code>`, `signal=<sig>`, `launch=<reason>`)
- `CMD`

---

## Persistence model

Storage directory: `~/.local/state/sigmund` (0700).

Per-run files:
- `<runid>.json` record
- `<runid>.log` output

Record fields include:
- `run_id`
- `boot_id`
- `started_at`
- `ended_at` (if known)
- `state`
- `exit_code` (if known)
- `term_signal` (if known)
- `launch_error` (if any)
- command summary/argv
- `log_path`

Every launch gets a new run id. A run id identifies one concrete execution only.

---

## Pruning

Prunable runs:
- `stale`
- `exited`
- `failed`

Non-prunable:
- `running`

Behavior:
- `prune <runid>` removes exactly that prunable run record + associated output.
- `prune all` removes all prunable run records + associated output.

---

## Transactional launch requirement

If record persistence fails after spawn, sigmund rolls launch back:
- sends `SIGKILL` to spawned process-group/leader,
- reaps leader,
- returns failure.

This ensures: either durable record commit succeeds, or no unmanaged launched process is left running.
