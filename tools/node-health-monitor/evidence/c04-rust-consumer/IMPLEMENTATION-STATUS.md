# C04 Rust consumer status (development, not acceptance)

Baseline is accepted C03 `2060cc1a1c7a36fe7214789a254cc36017c9f3a0`.
Interface authority is memo/main `dd07098f2c07f0edc2f503fac93b8184ba69af96`,
`C04-V2-INTERFACE-RULING-20260929.md`. The earlier
`SHARED-WIRE-REVIEW.md` is historical pre-freeze review, not authority.

The current local Rust implementation keeps native-core-v1 intact and adds
explicit native-core-v2 DTO/version parsing. Consensus action/replay/capability/
context maps are finite and validated; duplicate raw JSON keys, noncanonical or
overflow u64, unknown fields, invalid order/tuples, scope/network/epoch/hash/
body mismatch, unsupported-as-enabled and incomplete-as-complete are refused.
The typed cache, edge snapshot and evidence collector can preserve v2 without
converting null/unavailable values to zero. Manager native polling preserves
the existing PQ fact, but **does not activate C04 rule facts** until real
production pairs and scoped inventory/runtime gates are reviewed.

`consensus-v2.synthetic.json` is an all-zero **synthetic shape fixture** derived
from Starbridge's canonical draft plus the supervisor's frozen changes. It is
not a production observation. Starbridge's native candidate is now separately
committed at `e89ca322253e1c7a7acb87d16d63f974e462158e`, with 48 indexed
isolated publisher pairs and source/action/persistence/metric manifests. The
consumer candidate has **not** merged that tree; the supervisor still must
review a single exact integrated commit. Native lifecycle and production
performance gates remain subject to their own evidence, not these DTO tests.

The final-candidate consumer closure receipt is
`raw/closure-final-native-restored/receipt.json` (SHA-256
`193f97d4e91512ff6c5ccfd18b6cecd70221e9069141352cec4f7bd12ae395d4`).
It binds 21 current consumer source/schema/test files, all 96 native pair
files plus the native pair index, and the isolated native test binary. Four
raw restored checks each exited 0: fmt, Clippy, full locked contract suite and
explicit cross-language producer pairs. The suite has 21 closed schemas, six
actual handler successes, a real doctor 11-gate refusal, 132 active tests and
one deliberately ignored pair gate; the separate pair command ran that gate
1/1 and validated all 48 indexed native pairs, including actual HTTP route,
collector, canonical hash, exact body/EOF and schema. The hashes of those
four logs and the source-bound native manifests are in
`consumer-evidence-index.json`.

The first closure run is retained in `raw/closure-final-native/`: fmt, Clippy
and contracts exited 0, but the pair test exited 101 because this branch's
new closure wrapper passed a relative route-output directory to a Cargo test
running from a different cwd. After canonicalizing that output directory,
the new restored closure directory completed naturally. That retained red is
a test harness path error, not a producer contract failure.

Preliminary actual-C++ cross-language check: supervisor generated three
`success-{1,2,3}.json/.prom` pairs with the current isolated
`test-health-actions` producer at
`/home/tomi/nhm-supervision/c04-native-pair-gvTGZV`. This is production-code
publisher output under synthetic actors, **not business-node data or a final
source-bound fixture**. The explicit ignored Rust test
`native_v2_producer_pair::actual_cpp_publisher_pairs_and_negatives` passed on
all three original pairs and changed-body/EOF/generation/replay/u64/scope/order/
quality negatives. The final pair also passed `NativeCache → r4_snapshot →
EdgeSnapshot::validate → collector::decode_records`; its emitted actual-pair
edge snapshot passed the edge-snapshot Draft 2020-12 schema. All three JSONs
passed the source-envelope schema with the project uint64 format checker.
The explicit test now also reads that pair through the actual authenticated
`/v1/edge/snapshot` router and decodes the returned bytes in the collector.
Its first route assertion compared entire independently sampled snapshots and
failed on legitimately increasing `source_age_ms`; the corrected assertion
compares stable generation/content hash, monotonic age and validates both
snapshots. The corrected route and cross-language test passed. This test-only
red remains part of development lineage, not a producer mismatch.
Original file digests:

| generation | JSON SHA-256 | OpenMetrics SHA-256 |
|---|---|---|
| 1 | `270cf72c8042e8524256f01698e37b434190ed513128d815709a34656ffbafac` | `52dcdcec720fe3818d84f22bfc8dfbbca47a97891a12d78ead72d90bd5962fdb` |
| 2 | `f3bf0554d9583b385b054e64c8d7c6bbdad43bf86323ee9ab114d613ff4d9dd5` | `7d96edc5cf9d6162d02f5e50998e2ecb73fd273d14fa031c4e873b781e519f9c` |
| 3 | `5c48e07f60e3657951dce585558acf67f51551a7d75ab7ff960dd62a744bec14` | `82b6555025a87598d761b228b781539a01a4ac8b181647bc9ab95004567e6734` |

The repeatable explicit cross-language entrypoint is
`scripts/run-c04-cross-language.sh PAIR_DIR OUTPUT_DIR`. It ran on these
preliminary producer bytes with natural exit 0: Rust ignored gate 1/1 and
independent Python source/edge Draft 2020-12 schema, canonical content hash,
exact OpenMetrics body/EOF and changed-property negatives. The current schema
SHA-256 is `d6302be8fd52c0e650561b48a05fb1622fdbc2307b0d01c0c34994dbebccc86c`;
the synthetic fixture SHA-256 is
`60ca85d5e8e61e94daf57aadfe9a0aa0937763c8ada4e802e50c8219bfcf1b68`.
This preliminary result is historical; the 48-pair final-candidate rerun and
source-bound receipt are recorded above.
The entrypoint now validates every `.prom/.json` pair in its input directory,
including replay/failure/post-terminal cases, while retaining the
three successive `success-1..3` samples as a distinct cache/age test. Pair
hashes are printed and checked against the native index.

The first cross-language test execution failed because its own assertion
expected an impossible replay key to fail DTO deserialization; the bounded
map intentionally rejects that key during semantic validation instead.
After correcting only the test stage, the run exited 0. Preserve that failure
as test revision lineage; it did not identify an accepted malformed pair.
The later addition of actual pairs through `r4_snapshot`/collector first had
a Rust test borrow-check failure (moving a borrowed record); cloning only the
test-owned record fixed it. The expanded test then exited 0. Neither test
revision changed production consumer logic.

Observed tests so far (commands were run in this isolated tree, no business
services):

- `cargo test --locked -p tos-health-core --test native_v2_contract`: 9/9
  after adding unapproved-scope and post-terminal incomplete controls.
- `cargo test --locked -p tos-health-services --test native_typed`:
  9/9 on the current v2/legacy union per supervisor independent run; local
  targeted v2 route and epoch-switch tests also passed.
- `scripts/run-contract-tests.sh` after its initial Python indentation red:
  natural exit 0 on restored current source; 21 closed schemas, six actual HTTP
  handler successes, production doctor 11-gate refusal and 132 active workspace
  tests passed. One final producer-pair test is deliberately ignored in the
  default suite and run explicitly through the cross-language entrypoint.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` and
  `cargo fmt --all -- --check` passed at final consumer/native-fixture freeze;
  exact command, exit and log hashes are in the restored closure receipt.

The v2 consumer separately refuses a claim of complete instrumentation when
producer drops, relay drops, parse errors or a shed reason are present, even
if PQ and consensus components themselves say complete. A targeted quality
test and the restored mutation check this implication. V2 global incomplete
currently keeps the prior PQ rule input unknown even if its PQ component is
complete; C04 must not silently treat a partial whole source as green. Keep
production v1/default behavior until a scoped component-quality rule contract
is approved and tested.

The first contract-entry run failed at an `IndentationError` introduced by
this branch. That error was fixed and a subsequent complete run exited 0;
do not erase that failure from review lineage. No C04 acceptance or deployment
is claimed by these isolated checks.

The four `tests/c04-consumer-mutations.py` changed-property mutants each had
baseline exit 0 and compiled target-assertion exit 101. Raw paired logs are in
`raw/mutations/`. The runner restored both source files; restored SHA-256 are
`consensus_v2.rs` `7da9136807b56400e4908f16d0658002c9cbe277eb764fed33d0808bc2f05228`
and `native.rs` `3bbf9b73f6bcd5fa1776d7f780088b83eaf560a5982ecdca6a048633e23c50ef`
**at that mutation run**. A later 256 KiB parser-admission check changed
`native.rs`; its affected quality mutation was rerun after adding explicit
dropped/parse/shed quality controls. Raw baseline and compiled assertion-red
logs are in `raw/mutations-after-quality/`, with restored `native.rs` SHA-256
`a080f982f1cdb8d47091790acc9d91ac63d3056d44da2cb921472cc775a6d1aa`.
The other three historical `consensus_v2.rs` mutants retain their original
source binding; none of the mutation results alone is production acceptance.
An independent test overlapping the temporary masterchain mutant saw its
expected 8/9 red. It is mutation-window evidence, not a restored regression;
the restored local test reran 9/9 green. Future independent checks should not
run during mutation windows.
