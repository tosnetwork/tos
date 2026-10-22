# A-class port review, 2026-10-22

## Scope and verdict

Reviewed source: `08018e3b361d26ed42a44bd60ee448d209b08c4b`, based on
`a5e256b623c8cda741cb40cc7336396f9ee1ce3d`. The comparison source is
`857b8a57a178e6ae0fe7fa86e7d81c5233de8560`. The review followed the
[external review brief](https://github.com/tosnetwork/memo/blob/main/upstream-sync/v2026.10-a-class/EXTERNAL-REVIEW-BRIEF.md)
and the twelve item descriptions linked from it.

The intended deployment is a fresh epoch-5 genesis with global version 16.
The absence of a version gate is intentional. This change is not approved
for the epoch-4 network. Cryptography and post-quantum protocol changes are
outside this port's scope.

The original reviewed source required changes: one conditional P1 and three
P2 defects were reproduced and corrected. Acceptance of the corrected source
is limited to the documented genesis and default collator options, and remains conditional on
the relevant x86-64, arm64 and ASan CI checks. Local tests are not deployment
or full-network acceptance.

Verdict: **CHANGES REQUESTED** on the original source; **ACCEPT with follow-ups**
for the corrections, within the scope and CI conditions above.

Code corrections: `6ce166ed6` (external credit), `fddbcbc2e` (compression),
and `c93b956aa` (transit admission and misleading LT argument).

## Findings and corrections

### P1: a foreign transit import can exceed the outbound queue cap

Original location: `validator/impl/collator.cpp:4220`, reaching the increment
at line 4030. With a valid old queue of 18000 entries, a foreign transit
import appends an entry and produces a candidate rejected by the newly added
validator cap. A nearly full queue with pending dispatch entries can reach
the same failure, because those entries already have reserved destinations.

The corresponding comparison-source path has the same omission. The concrete
routing example uses a future five-bit shard topology: source prefix `00`,
destination `f8`, relay `f0`. The current genesis limits the basechain to two
split bits and does not create this same-workchain multi-hop path. This is a
wrong-candidate defect for a supported future configuration, not evidence of
a demonstrated stall on the current genesis.

The correction checks capacity including dispatch reservations before updating
the processed-message frontier. A postponed transit message remains at the
merger head. Final deliveries, own-queue requeues and already-processed
messages remain admissible. The change adds no persistent container or actor.

Tests: `TransitAdmissionReservesDispatchSlots` and
`MultiHopRoutingNeedsTransitCapacity` use the production admission helper and
real routing function. Replacing the helper with `false` fails both tests;
ignoring dispatch reservations also fails. These are not a full Collator and
ValidateQuery candidate replay.

### P2: external precompiled gas credit was truncated in Rust

Original location: `tosctl/src/executor/src/transaction_executor.rs:484`.
With a listed precompiled fallback, positive declared usage, gas limit
`2^32`, and code that never executes ACCEPT, casting remaining credit to
`u32` makes it zero. Rust then treats the external transaction as accepted;
the native executor rejects it. This requires a configuration different from
the current gas-limit defaults.

The correction retains the complete VM credit. Regression tests cover
`2^32-1`, `2^32`, and `2^32+1`, with and without ACCEPT. Native tests also cover
the `dont_run_precompiled` switch. The cross-executor harness compares actual
transaction outcome, gas and final balance. This narrowing defect is absent
from the comparison C++ source.

### P2: balance elision changed noncanonical payload bits

Original location: `tosctl/src/block/src/boc_compression.rs:583`.
A parent balance encoded with a leading zero changes from 100 to 110;
two references to the same child each change from 0 to 5. The corrected
per-edge sum now enables elision. Reconstructing a minimal Coins encoding
changes the parent bits and breaks the MerkleUpdate hash.

The correction refuses elision for nonminimal Coins encodings, preserving the
original payload. The fixture passes with the pre-port balance aggregation,
fails on the original port, and passes after the guard. The native extractor
already refuses this encoding. This is an optimizer correction, not a change
to the general Coins decoder.

### P2: Rust elided updates outside the native decoder's supported location

Original location: `tosctl/src/block/src/boc_compression.rs:1628`.
The same duplicate-edge pattern in a standalone MerkleUpdate newly triggers
elision after this port. Rust could round-trip its own output, but the native
decoder rejects it with `depth-balance node must be reconstructed under
MerkleUpdate`. The pre-port encoding decodes successfully.

The correction limits encoder elision to the update identified by the root's
third reference, matching the native encoder. No decoder was broadened.
Tests cover normal block shape, a standalone update, and an update in the
wrong root-reference position. A native probe confirmed pre-port success,
original-port failure, corrected standalone success and corrected block
success. No production Rust compressor caller was found outside the public
API and tests, so deployment impact is not established.

### Documentation/test correction: LT is not an aggregate transaction bound

The genesis comment and test previously inferred at most 5000 first outputs
from an LT limit of 10000. Different accounts can share the same transaction
LT, so this inference was invalid. The test now checks the actual serialized
queue limits, and no longer presents that comparison as a capacity proof.
No genesis parameter or production validation rule was weakened.

A native zero-gas bounce probe constructed distinct-account transactions at
the same start/end LT. Its byte estimate crossed the basechain external
check line after 2905 transactions, while their maximum end LT stayed 1002.
This demonstrates why byte accounting matters, but is not an exhaustive
bound over every transaction shape. Source/estimator review found no current
genesis/default-options counterexample; the limits below still apply.

## Other review coverage

- Config43: C++ and Rust parsers, JSON forms, fixtures, and leading-field
  contract readers were checked. Native/Rust vectors and highload contract
  execution cover both old records and the new limits.
- Canonical dictionary labels: opted-in scan checks match the encoder's
  length and tie rules; the flag is disabled by default. No new TVM caller
  was found enabling it.
- Message LT: new, dispatched and transit production paths were compared
  against the exact validation rule. Start-LT alignment and split/merge
  expiry were checked against the collator's construction rules.
- Certificate sender gate: issuer/import transport identities use the same
  previous/current/next sets; key-block rebuild and refcount add/delete/
  rotation paths were traced. Set size follows the configured validator
  epochs (at the reviewed configuration, up to three sets of 21 transport
  identities); local subscriptions follow configured local roles, not message
  traffic or uptime. No new unbounded traffic-keyed state was identified.
- Converted fatal-error sites: bool and integer return paths, macro evaluation,
  promise completion and cleanup were inspected. The cleanup token queue is
  bounded at 500; no new container was added by these corrections. This is a
  source/resource-lifecycle review, not a long-duration RSS measurement.
- Getter serialization, concurrent lazy-cell failure handling, query routing
  and proof headers were compared with the intended changes and exercised by
  their targeted native tests.

## Verification

The native Release build was on macOS arm64 with QUIC disabled, using the
local SDK and existing OpenSSL libraries. Relevant node/collator/liteserver
objects and test targets were built. This does not reproduce the complete
Linux builder or the full `all all-tests` command.

| Boundary | Observed result |
| --- | --- |
| Focused native CTest group | 7/7 entries passed, including queue/rule tests, sender gate, routing, proof headers, emulator, Config43 |
| Native emulator | 126 cases passed |
| Database compression | 13 cases passed |
| Lazy concurrent error propagation | 1 case passed, with 500 concurrent iterations |
| Dictionary and cell-depth checks | 5 and 1 cases passed |
| TRY-bool error propagation | 1 case passed |
| Getter context | 2/2 CTest entries passed |
| Canonical genesis serialization | 1 passed, 52 deselected; actual limits remain 18000/12000 |
| Rust executor | 60 passed, 6 ignored |
| Rust compression | 64 passed |
| Rust Config43 vectors | 1 passed |
| Rust block JSON | 46 passed |
| Native/Rust external-precompile parity | 12 cases matched, including the 32-bit credit boundary |
| Highload contract policy | 15 baseline/restored tests passed; all 8 guard mutations detected |
| JSON schemas | 136 vectors passed; all 8 mutation controls detected |
| Recorded regression database | Recorded outputs matched the regenerated tests |
| Formatting | Rust formatting, changed C++ formatting, changed Python checks and whitespace checks passed |

No count in this table should be added into a claim of an independent full
repository test run: several suites overlap. In particular, this review did
not independently reproduce the PR author's complete 440-test claim.

## Remaining limits and required follow-ups

1. The queue fix prevents invalid imports but does not establish liveness for
   every future topology. Native routing admits a five-bit example in which
   shard `A(00000)` routes toward `D(11111)` through `C(11110)`, while C routes
   toward `B(00001)` through A. Full shared outbound queues can then depend on
   each other for a transit slot. This is a routing/admission model with a
   native routing probe, not a full actor replay. Saturation recovery must be
   validated before enabling deeper splits or additional routed workchains.
2. There is still no mutated-candidate end-to-end Collator/ValidateQuery
   harness. The direct queue/routing tests cannot establish frontier/proof
   behavior independently of the source review. Add this integration coverage.
3. Certificate engine wiring was source-reviewed, while the gate helper has
   local native test coverage. No engine-level key-block/identity-rotation
   integration test was run here. Full node build CI and a multi-epoch test
   remain relevant before production acceptance.
4. Epoch-4 replay is manual-only by the existing project decision; a passing
   local check does not replace a new epoch-5 corpus. The two-build static
   analyzer was not run. Skipped/manual checks are not successful checks.
5. Future changes to genesis/config limits or local deferral options require
   re-evaluating queue burst bounds. In particular, disabling optional deferral,
   whitelisting senders, or increasing the local dispatch threshold invalidates
   the default-options capacity argument. These configurations have not been
   accepted by this review. LT is a maximum frontier across accounts, not a sum
   of every account's transaction LTs.

The accompanying compact receipt contains bounded failure excerpts and raw
log digests. Raw logs are local temporary artifacts with no guaranteed
retention; they are not independently accessible proof. The committed tests,
commands and excerpts are the durable reproduction material.

## Reproduction commands

Use the repository's pinned compiler/dependency environment and a configured
native build directory (`review-build` in this run). Cargo commands below run
from `tosctl/src`:

```sh
cargo test -p tos_executor --offline
cargo test -p chain_block boc_compression --offline
cargo test -p chain_block parses_exactly_what_cpp_parses --offline
cargo test -p chain_block_json --offline
cargo build --offline --locked -p tos_executor --example pq-tx-parity
```

Run the following from the repository root (set `EMULATOR_PATH` to the native
emulator library and supply the actual parity-driver path):

```sh
review-build/test-out-msg-queue-limits
review-build/test-validate-query-rules
review-build/test-db --filter BocCompression
review-build/test-db --filter BocLazyConcurrentLoadErrors
python3 test/executor-parity/precompiled_external.py --driver PATH_TO_DRIVER --output RESULTS_DIR
TOS_CREATE_STATE_BINARY=review-build/crypto/create-state scripts/check-regression-db.sh . review-build
```

For sensitivity controls, restore each mutation before proceeding:

- Queue: return false from `out_msg_queue_postpone_transit`; separately pass
  zero instead of pending dispatch count to its capacity predicate. Rebuild
  and run the queue suite; both mutations must fail.
- Credit: append `as u32` to the credit read; run
  `cargo test -p tos_executor tests_precompiled_external --offline`.
- Noncanonical Coins: remove the new first-byte/minimality check; run
  `cargo test -p chain_block noncanonical_balance_encoding_is_not_elided --offline`.
- Update scope: remove `&& is_main_mu`; run
  `cargo test -p chain_block only_the_block_root_merkle_update_is_elided --offline`.

The receipt's `native_decoder_fixtures` are small synthetic compressed BOCs.
Base64-decode each entry and pass it to `vm::boc_decompress(data, 20 << 20)`;
the expected status is in `native_decoder_result`. The before-port controls
remove only the A7(b) repeated-edge early-return addition, rather than building
the entire earlier repository. All mutations were restored before green runs.
