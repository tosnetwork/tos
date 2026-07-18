# tos31/tos32 Validation Runbook

This runbook defines the evidence required before calling a build a
real-value mainnet candidate.

## tos31 State-Sync Gate

Run the deterministic suite on every candidate:

```bash
bash scripts/run-tos31-state-sync-verification.sh
```

Before RC, also run the release-scale checks:

```bash
TOS_RUN_16GIB_CATCHUP=1 \
bash scripts/run-tos31-state-sync-verification.sh
```

Required evidence:

- `test-download-state-budget` passes, including the opt-in 16 GiB mmap
  catch-up when `TOS_RUN_16GIB_CATCHUP=1` is set.
- `test-celldb-streaming-import` passes.
- Artifact directory contains `driver.log`, per-step logs, git commit,
  host info, and disk-space snapshot.

## Crash / Replay Matrix

The candidate must preserve CellDb consistency across these interrupted
points:

- rollback manifest created, no CellDb batch committed
- rollback manifest synced, CellDb batch commit interrupted before return
- CellDb batch committed, root-store not yet committed
- root-store committed, GC lease release interrupted
- actor shutdown while worker parse is in progress
- actor shutdown while rollback job is draining
- retry after failed import and retry after process restart

Expected result:

- startup preserves `.celldb-rollback.*.partial` files during tempfile
  cleanup
- CellDb startup replays rollback manifests before `validate_meta()`
- replay erases only cells whose current serialized bytes still match the
  manifest value
- trailing partial manifest record is ignored only on startup replay
- runtime rollback remains strict

## tos32 Local RC Gate

Set up the 3-node local testnet, then run the RC loop:

```bash
sudo scripts/setup-testnet.sh --clean
TOS_RC_DURATION_SECONDS=86400 \
TOS_RC_RESTART_INTERVAL_SECONDS=1800 \
TOS_RC_CATCHUP_TEST=1 \
bash scripts/run-tos32-rc-validation.sh
```

For a smoke run:

```bash
TOS_RC_DURATION_SECONDS=3600 \
TOS_RC_CATCHUP_TEST=1 \
bash scripts/run-tos32-rc-validation.sh
```

Required evidence:

- all three validators stay `active`
- JSON-RPC health and native chain-info methods stay responsive on ports
  `8011..8013`
- scheduled validator restarts do not halt the chain
- catch-up probe stops node 3, lets nodes 1/2 advance, restarts node 3,
  and observes node 3 reaching the target block
- collected systemd logs contain no `FATAL`, metadata validation failure,
  rollback failure, or repeated restart loop

## Metrics And Alerts

Monitor these `engine_validator_getStats` / exported stats keys during
state sync and RC:

- `celldb.streaming_import.started`
- `celldb.streaming_import.committed`
- `celldb.streaming_import.failed`
- `celldb.streaming_import.cells_committed`
- `celldb.streaming_import.actor_batches`
- `celldb.streaming_import.rollback.jobs_started`
- `celldb.streaming_import.rollback.jobs_finished`
- `celldb.streaming_import.rollback.cells_processed`
- `celldb.streaming_import.rollback.cells_erased`
- `celldb.streaming_import.startup_rollback.manifests`
- `celldb.streaming_import.startup_rollback.cells_erased`
- `celldb.streaming_import.inflight`
- `celldb.streaming_import.rollback_queue_size`
- `celldb.streaming_import.gc_pause_count`

Alert conditions:

- `streaming_import.failed` increases during a clean peer set
- `rollback.jobs_started != rollback.jobs_finished` for more than 5 minutes
- `rollback_queue_size > 0` for more than 5 minutes
- `gc_pause_count > 0` for more than 5 minutes without active root-store
  progress
- any startup rollback manifest replay fails
- any `validate_meta()` fatal after replay
- validator restart loop or block-number stall across a quorum

## Archive / Catch-Up / Restart

For RC, the local loop must include:

- one validator stopped long enough to fall behind
- remaining validators continue producing blocks
- stopped validator restarts and catches up without manual DB repair
- validator restarts happen while archive and catch-up paths are active
- logs and health CSV are kept as artifacts

## Emergency Rollback / Upgrade Plan

Before external testnet or mainnet candidate rollout:

- keep the previous validator binary and config package available on every
  host
- roll one validator first, wait for catch-up and stable block production,
  then roll the remaining validators
- if `validate_meta()` fatal, rollback failure, or restart loop appears,
  stop rollout immediately and revert the changed validator to the previous
  binary
- preserve `/data/*/log`, `build/tos31-*`, `build/tos32-*`, and any
  `.celldb-rollback.*.partial` files for incident analysis
- never delete rollback manifests manually before CellDb startup has had a
  chance to replay them

## Audit Packet

Before third-party review, provide:

- source archive from `scripts/pack-source-audit.sh`
- tos31 artifact directory from the default and 16 GiB runs
- tos32 artifact directory from the long testnet run
- commit hash and build flags
- list of known residual risks and skipped optional tests
- crash/fuzz artifacts, or an explicit statement that none were produced
