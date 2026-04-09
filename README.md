# sigmund

A tiny, daemonless launcher for background commands.

`sigmund` launches a command in a separate session/process-group, records a durable run record, and captures output to a log file under `~/.local/state/sigmund`.

## Design intent

- Small launcher, not a supervisor.
- No restart loops.
- No daemon process.
- Processes do **not** survive reboot.
- Records/logs **do** survive reboot.
- Reboot does not auto-clean state.
- `boot_id` mismatch marks a run `stale` (classification/safety boundary only).
- Stale records remain visible until explicitly pruned.

## Build

```bash
make               # builds static binary: ./sigmund
make sigmund       # same as default static build
make sigmund-dynamic  # builds dynamic binary: ./sigmund-dynamic
```

`make sigmund` and `make sigmund-dynamic` now produce distinct artifacts and can coexist.

## Usage

```bash
sigmund <cmd> [args...]
sigmund --tail <cmd> [args...]

sigmund list
sigmund tail <runid>
sigmund dump <runid>
sigmund stop <runid>
sigmund kill <runid>
sigmund killcmd <runid>
sigmund prune
sigmund prune <runid>
sigmund prune all
```

Use `sigmund -- <cmd> [args...]` when command names overlap subcommands.

## List output

`sigmund list` prints:

- `RUNID`
- `STATE` (`running`, `exited`, `stale`, `failed`)
- `STARTED_AT` (RFC3339 UTC)
- `RESULT` (`-`, `exit=<code>`, `signal=<sig>`, `launch=<reason>`)
- `CMD`

Example:

```text
RUNID      STATE    STARTED_AT              RESULT         CMD
7f3c2a91   running  2026-04-09T18:42:11Z    -              qemu-system-x86_64 -m 4096 ...
91ad0c44   exited   2026-04-09T17:03:55Z    exit=0         ollama serve
12ef88b0   stale    2026-04-08T23:11:02Z    exit=137       meshlink-sim ...
ab77dd31   failed   2026-04-09T18:39:10Z    launch=EACCES  python worker.py
```

## Stale semantics

A run is `stale` when its recorded `boot_id` differs from current boot.

- `list`: stale runs remain visible.
- `stop`, `kill`, `killcmd`: refuse stale runs with a clear error.
- `tail`, `dump`: still work for stale runs if log exists.

## Prune semantics

Prune is explicit operator cleanup.

- `sigmund prune` / `sigmund prune all`: remove all **prunable** runs and associated output.
- `sigmund prune <runid>`: remove one prunable run and associated output.
- Prunable = `stale`, `exited`, `failed`.
- Running runs are never pruned.

## Transactional startup guarantee

If state persistence fails after spawn, sigmund rolls launch back by killing the spawned process-group and reaping the launcher, so no unmanaged background process is left behind.

## License

Apache-2.0.
