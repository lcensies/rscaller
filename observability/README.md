# observability/

Loki + Promtail + Tracee stack (`docker-compose.yml`) plus shared bash
helpers (`test_lib.sh`, `test_lib_rscaller.sh`) for querying captured Tracee
events from a shell script. `TRACEE_EVENTS` (docker-compose) and the
`loki_query`/`loki_event_count`/`wait_for_event` helpers already take
arbitrary event names / search patterns — reuse them if you want an ad hoc
Grafana/Loki view of a run.

For the actual **baseline-vs-evasion comparison harness** (run a command
directly on the beacon vs. via `rsc exec`, diff the matching Tracee event
counts, optionally in a 2-pane tmux window for screenshots), use
`scripts/poc.sh` / `scripts/poc_tmux.sh` at the repo root instead — it talks
to the current `rsc exec --mount-profile` CLI directly (no Docker/Loki
needed) and has built-in `exec`/`file`/`network` scenarios:

```bash
bash scripts/poc.sh --scenario exec
bash scripts/poc.sh --scenario file
bash scripts/poc.sh --scenario network
bash scripts/poc_tmux.sh --scenario network   # 2-pane tmux: rsclient | rsbeacon
```

See `bash scripts/poc.sh --help` and the README's "Manual PoC from CLI"
section for the full flag list (`--events`, `--query`, `--baseline-cmd`,
`--compare`, `--cleanup-cmd`).

(The older `test_evasion_rscaller.sh` / `test_evasion_no_rscaller.sh`
scripts that used to live here were removed — they hardcoded `lse.sh` as
the only tool and referenced a `--rscfuse` binary flag that no longer
exists; `rscfuse` is now a library built into `rsc` itself, invoked via
`rsc exec --mount-profile`.)
