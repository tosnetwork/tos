# Experimental external admission work profile

The node accepts one explicit startup option:

```
--ext-message-work-profile CONFIG_ROOT,CAPACITY,REFILL_UNITS,INTERVAL_NS,ATTEMPT_UNITS,MAX_BYTES,MAX_DEPTH
```

`CONFIG_ROOT` is the lowercase 64-digit hash of the complete authenticated
configuration dictionary (not a block hash or ConfigParam 48 hash). The remaining
fields are canonical unsigned decimal integers. Capacity, refill, interval,
attempt charge and input bounds must be positive; a single attempt must fit the
capacity. Byte/depth bounds are uint32; work values and interval are uint64.
Duplicate options, extra fields, noncanonical integers and overflow are rejected.

There is no calibrated production default. The option is absent by default.
Choose work units, interval and burst only from measurements covering the full
attempt cost for every supported destination, including special accounts,
precompiled execution, parsing and lookup. The small numbers in unit tests are
synthetic accounting fixtures, not deployment recommendations.

A configured pool charges the shared work budget immediately before checker
dispatch, after waiting for an inflight slot. All origins use that charge. Failure,
completion and cancellation do not refund work; byte/inflight occupancy still
releases. The checker executes a rejected contract once, without a diagnostic
replay. Consensus block validation does not consult this local budget.

Stopping the pool explicitly fails all queued admission promises during actor
teardown. Waiting coroutines retain the actor, so deferring promise cleanup until
destruction would create a reference cycle and retain their input bytes. Queue
errors propagate before dispatch and consume no work tokens. Dropping an external
`StartedTask` handle detaches its work; it is not a request to cancel execution.

The exact configuration pin deliberately refuses unrecognized configurations.
It also changes on unrelated configuration updates such as validator rotations.
The internal options API can explicitly rebind a reviewed configuration without
resetting tokens or the refill clock. Capacity, rate, attempt cost and input-bound
changes require restart. Unrelated options updates cannot disable an already
installed work budget. The startup flag is not a live file watcher.

Release gates remain: supported-profile update policy, measured hardware
calibration, ordinary failed external transactions reporting zero charged gas,
queued configuration changes/cancellation, real network origin coverage, mixed
attack/recovery fairness, and the actual version-18/default-credit transaction
corpus. This option alone does not resolve V5R2 release admission.

## Reproduction and verification scope

The `External admission work boundaries` workflow builds the real engine on
Linux x86-64 and AArch64. Its checks map to these boundaries:

| Boundary | Check |
| --- | --- |
| Token accounting, refill, overflow and initial gas quote | `test-ext-message-admission-budget` |
| Pool dispatch, configuration matching, rejected VM call count, live options and queued shutdown | `test-ext-message-pool` |
| Profile parsing and options validation | `test-validator-options` |
| Engine option registration and duplicate-option rejection | `scripts/check-ext-message-work-cli.py` |
| Test sensitivity to setter, parsed-profile and hash-format guards | `scripts/check-ext-message-options-controls.py` |

For a native checkout, build the three test targets and `validator-engine`, then
run the CLI probe with `--engine BUILD/validator-engine/validator-engine` and an
external `--output-dir`. Run the options control script separately for
`--boundary setter`, `parser-validation` and `parser-canonical`, supplying
`--build-dir BUILD` and a separate output directory for each. The control script
temporarily edits the guarded source, rebuilds, requires the intended failure,
and restores/retests it. Do not run it alongside another build or source editor.

The CLI probe supplies `--help` after the profile arguments and checks diagnostics
as well as exit status: the engine intentionally exits with status 2 for help.
It does not start a node. Its success establishes parser wiring, not runtime
installation, network-origin coverage, calibration or release readiness.
