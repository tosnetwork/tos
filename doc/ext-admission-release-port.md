# External admission release alignment

This ports the external-message pool/checker subsystem through the upstream
implementation's official v2026.10 release. The upstream release is
`857b8a57a178e6ae0fe7fa86e7d81c5233de8560`; the target base is
`5bfe936ab3e144c2c055471262e14f1d604eab18`. The previous subsystem import,
`b6f8db9a44cf639ff135acd721ec65725ea0e15a`, ended at upstream
`908a5903b138eb8c8c7f01563a97f51b6c31f1df`.

The improvements were present upstream and absent from the target, except that
its early serialized-size check was already present. This follows the upstream
implementation rather than introducing a new admission strategy. The upstream
release notes describe improved external-message processing and node metrics.
The inventory reviewed 89 commits touching the subsystem, shared configuration
files and related metrics/tests. Twelve scoped ports were agreed; unrelated
shared-file changes and the already-present size check were explicitly excluded.

## Source commits

Dates below are author dates, not integration dates. The four priority commits
were authored on 2026-08-27, integrated into the upstream test branch on
2026-10-06 and included in the 2026-10-19 release.

| Upstream commit | Scoped change |
| --- | --- |
| `1c5dc25d39edb5b09952e9466253982be8fed7a8` | Pool and synchronization snapshots |
| `8b5fa7d50078e7265868afe498edfd3f69f99960` | Typed admission outcomes, removal and external-collation observations |
| `d2abbc20454b23c3f671be13ca4dc3b11cc19a5c` | Precise reprioritization and failure-stage accounting |
| `72cc56a36d3e99dff4680a1ce8aad7581c94cf92` | Ordered expiry, backlog stock and expiry tests |
| `6644911665b7438f47304b82092eb6ba6d49ff29` | Applied-only inclusion latency |
| `18a83c182a54e58b51df7b8be3311a51a5f7516f` | Compute-only admission validation |
| `051b3b0f64e6baa7c6fb9112d764006c3528cbbd` | Configurable pool and draining checker lifecycle |
| `753af2881b4ac07c944fb73cd90aa2e38313df19` | Local submission priority |
| `c82c301d4131295dab29fe86eeb80446306c4b8f` | Priority-ordered waiters |
| `9b6328bc3d0e741de8085e466adbddee3ea04368` | Designated priority checkers |
| `0f18b86cd5e097c748a67d68a59f1721bd9e1d9b` | Normalized removal of collator-refused messages |
| `a1f082eb487290f4c89ebe30f08b10475f5dcdd8` | Refuse option updates before engine startup |

Upstream `d85e3bec03694082def3ef8e3575f09058262239` contributes no new
admission hunk: the target already checks serialized size before queueing and
rechecks limits after waiting. Leader-window deduplication
`468092512ebd2d4f1a61d207016ac3b345fc5017` is ported for the part the normalized
removal of `0f18b86c` depends on: the leader-window set of processed external
messages (see C7). Its metrics and unrelated candidate-type cleanups are not. Broad block-production phase timing,
transport, consensus and whole-exporter migrations are also outside scope.

## Defaults and configuration

Upstream `validator/validator.h:141–151` defaults to 24 regular checkers, zero
priority checkers, 50,000 maximum waiters, 30 messages/address per 10 seconds,
`max_mempool_messages = 999999` per priority bucket and local submission priority
zero. The inherited insertion check uses `>` and therefore permits one additional
entry before refusing the next insertion.
Eight slots/checker gives the existing 192-inflight default. These defaults are
retained. Priority-capacity tests explicitly configure a reserved checker and
positive local priority; deployment policy is a separate decision.

The native console accepts `set-ext-message-pool-options-json <filename>`.
Validated settings are persisted in `extraconfig.ext_message_pool_config` and
propagated to the manager/pool. Authorization and engine startup are checked
before mutation. Shrinking or replacing checkers drains old generations; their
completions cannot decrement a new generation's counters.

The retired `-m` / `--mempool-num` CLI option and Docker role aliases are removed,
including the old option-construction API and its explicit test callers. The
upstream deprecated no-op is deliberately omitted under the pre-launch rule.
Current supplied operation units do not pass this flag. Historical bundles and
hash-pinned evidence are retained unchanged; site-specific upgrade inputs must
use the supported configuration path.

### Configuration fields

A negative field selects its release default, conventionally `-1`. Each update
constructs a replacement options object; negative fields do not retain a
previous non-default setting. The native schema uses signed 32-bit integers
except for the time window, which is a double in seconds.

| Field | Purpose and accepted nonnegative range |
| --- | --- |
| `max_mempool_messages` | Per-priority stored-message threshold, 0 through the schema integer maximum; the inherited insertion comparison is `>` |
| `num_regular_checkers` | Regular checker actors, 0–128 |
| `num_priority_checkers` | Reserved checker actors for positive-priority requests, 0–128 |
| `max_admission_waiters` | Absolute queued-request cap, 0 through the schema integer maximum; the effective cap may be lower |
| `max_ext_msg_per_addr` | Successful checks/address in the configured window, 1 through the schema integer maximum |
| `max_ext_msg_per_addr_time_window` | Per-address counter window, strictly positive seconds |
| `local_ls_message_priority` | Local-query queue priority, 0 through the schema integer maximum; positive values may use reserved checkers |

Zero regular checkers refuses regular requests; priority requests can use either
lane when one exists. Eight checks may be inflight per checker. Pool options are
local admission policy and do not alter consensus or full transaction execution.

## Conflict ledger

- **C1 — Checker execution:** the upstream typed outcome and lifecycle wrappers
  surround the target hardened parser, custom-workchain registry checks and
  configuration-pinned execution cache. Failed admission executes once; no
  logging retry or second execution configuration is restored. The single
  configuration is fully initialized before publication.
- **C2 — Admission ownership:** source-peer arguments, source rate limits, byte
  reservations across suspension/error paths, post-wait limit refresh and the
  pinned masterchain snapshot remain. The opt-in work budget is charged before
  dispatch and is not refunded on failure. Its implementation headers and
  off-by-default policy are unchanged. The lane selected before these checks is
  released on a pre-dispatch refusal without recording a completed VM check.
- **C3 — Metrics boundary:** upstream pool/outcome/stock/inclusion models and
  fixed label domains are adapted to the existing bounded collector interface.
  Snapshot collection does not mutate the pool or scan stored messages. Fixed
  histogram buckets match upstream. The pool and manager declare bounded
  collection reservations; existing deadline/resident-budget enforcement stays
  in place. No second exporter, generic metrics framework or actor timing stack
  is imported. Related external-collation outcomes use the same attribution
  formulas and fixed chain/result/outcome domains; unrelated phase timing is
  omitted. Target timestamps compare their numeric values where the upstream
  helper used an unavailable comparison overload.
- **C4 — Expiry:** one expiry-ordered structure replaces periodic scans. Existing
  cleanup entry points operate on this structure across every workchain. Target
  removal of empty per-address index buckets is retained. Normalized indexes,
  ordered links, stored-stock counts and applied-only latency observations are
  updated together.
- **C5 — Configuration:** pool configuration ownership is merged with existing
  PQ primary/scheduled key configuration, out-port handling and startup checks.
  The native schema, console, options object and persisted JSON agree. Retired
  CLI callers are removed rather than accommodated with a shim.
- **C6 — Lifecycle:** prioritized FIFO queues, low-priority tail eviction and
  generation-safe checker replacement follow upstream. Target stop-time queue
  draining and explicit cancellation errors remain. Displacement without an
  explicit error message uses the upstream queue-capacity refusal; other target
  cancellations propagate without dispatching stale work.
- **C7 — Collator removal:** normalized rejection removal is ported through all
  manager variants. The delay/postpone API and retired entry helpers are deleted.
  The release's fixed postponed-state metric label remains zero for these new
  entries; it does not reintroduce postponement. Refusals are reported by
  normalized hash and the pool removes every entry under that hash, so the
  collator skips, unreported, a second message whose normalized hash it has
  already taken in the same leader window, by this collation or by the one for
  an earlier slot of the window. The pool keeps an included message until its
  block is applied, so without the skip the next slot would take it again, fail
  it on replay protection, and its refusal would remove it before its block is
  final. As in `468092512`, the block producer passes the set through
  `CollateParams` and takes back the set of each candidate it uses
  (`GeneratedCandidate`); callers that collate outside a leader window keep the
  `BlockCandidate` form of `run_collate_query` and start from an empty set. As
  upstream, the backpressure skip now precedes message validation.
- **Collation retry statistics** follow `8b5fa7d5`. The release later replaced
  that external-only retry report with a full failed-attempt report
  (`932b7c89`), which is not ported; the counters here are local statistics only.
- **Persisted pool options** are unpacked at engine startup with `ensure()`, as
  upstream does: a hand-edited out-of-range value in
  `extraconfig.ext_message_pool_config` stops the engine at startup. Change these
  options through the console command, which validates them.

Namespace/schema renaming is mechanical. Source commits with unrelated node
changes contribute only their agreed subsystem hunks and dependencies. The
existing exporter, full-node startup checks, PQ custody and transaction
execution paths are preserved.

## Admission versus transaction execution

Only `ExtMessageQ::run_message_on_account`, used for admission validation, stops
at compute. `Collator::impl_create_ordinary_transaction`, validator execution
and transaction phase implementations keep their full execution semantics.
A generated probe sets an invalid action before ACCEPT. The regression requires
admission to succeed, then the unchanged full transaction path to accept compute
and reject the action with result 34. Admission success is not execution success.

The priority regression holds eight real regular checks in shard-state lookup,
queues another regular request and uses the production manager local-query
handler for a masterchain message. It requires that priority request to complete
while the regular checks remain held and queued. A routing mutation removes
priority and must fail that readiness assertion.

## Reproduction

Use the repository builder image `tos-builder-local:24`, Release mode, LLVM 21,
x86-64-v2, the allocator and linker settings used by production builds, and
bounded build parallelism. Build the native engine, console, external-message
pool/manager/ingress/budget tests, expiry tests and generated-checker fixture.

```sh
cmake --build build --parallel 4 --target validator-engine validator-engine-console \
  test-ext-message-pool test-ext-message-expiry test-ext-message-manager \
  test-ext-message-generated-checker test-ext-message-ingress test-ext-message-admission-budget
ctest --test-dir build --output-on-failure -R 'ext-message'
ctest --test-dir build --output-on-failure -L source-guard
python3 scripts/check-ext-message-generated.py --build-dir build \
  --output-dir /tmp/admission-release-fixture --controls
python3 scripts/static-analysis.py --build-dir build --base-build-dir /base/build --jobs 4
```

Mutation runs must restore source, rebuild and rerun green. Keep runtime keys,
fixtures, build output and raw receipts outside tracked files. No public host,
service, key or network configuration is changed by this port. Checker priority
alone does not change the HTTP connection limit or earlier liteserver gate.

## Local verification index

Implementation revision: `9302b1a6a1b18c6865aecad7de106997911bed33` on base
`5bfe936ab3e144c2c055471262e14f1d604eab18`. This receipt adds documentation
only. The PR description and operator-held report record the final head's
verification, static-analysis outcome and linked operator-documentation PR.

| Boundary | Command / oracle | Result |
| --- | --- | --- |
| Production build | Release engine, console and external-message targets in the pinned builder below | exit 0 |
| Native tests | `ctest --test-dir build --output-on-failure -R 'ext-message|test-validator-options|test-state-download-recovery'` | 8/8 targets passed, including 9 generated cases; exit 0 |
| Source guards | `ctest --test-dir build --output-on-failure -L source-guard` | 58/58 passed; exit 0 |
| New dispatch/configuration controls | Generated runner `--controls`, at `21ab4130f3b37bc1a4c7aa87d0bcce73ba1d92f2` | 17 variants / 22 intended assertion failures, each exit 1; restored suites exit 0 |
| Existing admission controls | Pool, manager-entrypoint and stop-on-accept runners | red assertions observed; every restored suite exits 0 |
| Retired option | Native `--mempool-num=1` and `-m1` | both exit 2, option unrecognized before startup |
| CLI profile | `check-ext-message-work-cli.py` | exit 0 |

Builder image ID:
`sha256:ce6ff9ea45fdac532b53a883538782a6a050c1fc14407e3110713ba16c5d5e95`.
LLVM 21.1.8, x86-64-v2, Release, production allocator/linker settings.
The local host is a Xeon Platinum 8455C server; native runs used a four-CPU,
eight-GiB container cap. The claim is deterministic lane isolation: 8 regular
checks held, 1 regular waiter queued, and 1 priority admission completed;
disabling routing fails the completion assertion. These are not CPU calibration
or live-listener availability measurements.

Raw public fixture/log receipts are retained in the test lead's artifact store,
`${TOS_TESTNET_DEPLOY}/ext-admission-port/evidence`, accessible to the designated
reviewer, through review and at least 2026-11-20. The manifest includes per-file
SHA-256 and byte size; its SHA-256 is
`36b97a69e5bbc1d67bf665f372771fef4a75da9bc6c458bb436e0f3a6963f61d`.
No runtime private-key files, build tree or bulk logs are committed.
