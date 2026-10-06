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
| Manager broadcast/query and serialized liteserver submissions sharing one work budget | `test-ext-message-manager` |
| Profile parsing and options validation | `test-validator-options` |
| Engine option registration and duplicate-option rejection | `scripts/check-ext-message-work-cli.py` |
| Test sensitivity to setter, parsed-profile and hash-format guards | `scripts/check-ext-message-options-controls.py` |

For a native checkout, build the four test targets and `validator-engine`, then
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

The manager test retains the production submission handlers, liteserver parser
and cache, and shared pool. It substitutes startup with a frozen state and local
options, without databases or network listeners. Three malformed submissions
through different handlers consume a synthetic three-unit budget; subsequent
submissions through each handler, with null and rotating source identities,
observe the shared exhausted budget. `--manager-entrypoints` on the pool control
runner deletes shared charging and requires that test to fail. This does not
establish HTTP/ADNL transport coverage, actual signature rejection cost or mixed
network-load fairness.

The pool suite also executes a funded, non-special masterchain account from a
synthetic variant of the frozen fixture: only optional ConfigParam 31 is removed;
account code, balances and gas-price parameters remain unchanged. The
[recorded rejection](ordinary-work-20261006.json) reports `steps=13, gas_used=0`, while the VM start/finish counters each
equal one and the attempt consumes work. A targeted charge-deletion control
must fail this test. Basechain 20,000-credit calibration and full release genesis
acceptance remain separate gates.

## Explicit genesis candidate

A wrapper may define both `v5r2-network-tag` (the chosen public 256-bit AUTH
namespace) and `v5r2-admission-candidate` before including
`crypto/smartcont/gen-zerostate.fif`. This generates version 18 and basechain
ConfigParam 21 credit 20,000. Masterchain ConfigParam 20 stays at credit 10,000;
all other gas-price fields are unchanged. Omitting the candidate flag retains
the existing version-16 default or version-17 AUTH-only profile. The candidate
requires the namespace before any wallet key generation.

The [genesis evidence](admission-genesis-20261006.json) reads actual generated
BOCs and includes version/credit mutations and an early-namespace-guard deletion.
The separate localnet generator requires `v5r2_admission_candidate=True`, version
18, the deployment fee schedule and an explicit AUTH namespace. Its generated
ConfigParam 20/21 cells match the canonical candidate byte-for-byte; incompatible
profiles fail before key generation. The localnet credit and validation bypass
controls are recorded in [localnet evidence](localnet-admission-20261006.json).

This is a configuration candidate for further acceptance work. Rust defaults,
opcode version boundaries, full default-credit
transaction parity, calibrated node rates and public-network activation remain
pending; generating a BOC does not establish these gates.
