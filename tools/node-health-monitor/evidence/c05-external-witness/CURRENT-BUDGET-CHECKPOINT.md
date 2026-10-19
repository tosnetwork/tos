# C05 dev-only current-view budget checkpoint — not acceptance

Successor to `ad669381912754d92389787fb6a1ebeb7d8a1db2`. This is a
source-stable checkpoint, not a C05 READY review or a production memory gate.
All inputs are synthetic or isolated loopback mTLS. Historical archive ACK
does not qualify a current source, and no witness fact reaches the live rule
engine. Business services remain stopped.

The volatile M current-view limit is 1,048,576 bytes. Admission first reserves
400,384 bytes for one current writer's bounded request/decoded/serialized
objects, two body-lifetime read responses, one read serializer, bounded row
objects and allocator headroom. Actual capacities of durable current tracks,
current view rows/strings and map keys are charged before a candidate view is
retained. A per-entry projection is checked **before** durable current review,
and actual retained charge is checked afterward; failed admission drops the
matching volatile track/view while retaining the historical archive ACK.
History-only/missing-current-stamp input does not mutate the current-order
index and invalidates only a matching O/source epoch view. A same-generation
replay after that loss is unknown, not renewed. The cap is for this volatile
current subsystem, **not** SQLite, all historical archive requests, ingress
TLS buffers or total process heap. It is a development upper-bound inventory,
not a production 1%/3% overhead measurement.

The 32-row decoded-source test uses 64-byte target IDs, 128-byte source and
observer epochs, and fractional UTC. It measured actual durable track plus
CurrentView ownership at 34,983 bytes against the 46,336-byte preflight
projection. Arithmetic exact-cap/overflow controls and a bounded serializer
control accompany that actual-object comparison. Two timed-out queued reads
retain both permits until the writer queue is dropped; the older route test
retains permits through undrained response bodies. These do not claim that a
remote requester has consumed TLS bytes.

The real O-cache → O mTLS ingress → collector → M mTLS ingress → archive/current
test now also sends wrong token, boot ID, time namespace, future start and body
digest through M ingress. Every delivery retains its historical ACK; current
qualification is unavailable or unknown. The test spaces deliveries at the
unchanged 1/s ingress rate; a first draft that sent them too fast got HTTP
429 and is retained in the transcript lineage, not counted as a product red.
Direct M-router negatives separately cover the same metadata boundaries.

| Command, cwd `tools/node-health-monitor` | Raw log SHA-256 | Natural exit |
|---|---|---|
| `CARGO_BUILD_JOBS=2 cargo test -p tos-health-services --lib --test ingress --test witness_archive --locked` | `raw/current-budget-restored-tests.log` `21b070dfe8b11958423097a0c60fa6dc6906e1d6b644f40a937bcb4253e35479` | 0; lib 9, ingress 7, archive 9 |
| `cargo fmt --all --check && CARGO_BUILD_JOBS=2 cargo clippy -p tos-health-services --all-targets --locked -- -D warnings` | `raw/current-budget-restored-fmt-clippy.log` `f41aea617d1941ac85a7cd9826bbca7ff7e12c8f7bbe36c6da9f5b3bc2fdc898` | 0 |
| `.contract-venv/bin/python scripts/check-contracts.py` | `raw/current-budget-restored-contracts.log` `042ef2920d96db1626e2fb104c7bc9ac0bd15ffde43e8a2400bc04d1e5e466bc` | 0; 24 closed schemas |
| `CARGO_BUILD_JOBS=2 scripts/run-contract-tests.sh` | `raw/current-budget-full-entry.log` `e7a6de98d63100a1388bf2ac693c754f5e7c1434840d36abe1edf95cf085a0ea` | 0; production doctor refused 11 unverified gates; one C04 native-pair test ignored without indexed external pair |

Earlier successful intermediate logs `raw/current-budget-tests.log`,
`raw/current-budget-fmt-clippy.log` and `raw/current-budget-contracts.log`
precede the final source change and are historical only. The initial
constant-assert Clippy red and burst-rate HTTP 429 red were corrected before
the restored logs above; neither is counted as an intended mutation kill.

| Changed source/test relative to `tools/node-health-monitor` | SHA-256 |
|---|---|
| `crates/health-services/src/manager.rs` | `5dd0e4b0a9c330196e1c15324e9a5a802a8214b3453f0d4ebd4ba8c2cc6166da` |
| `crates/health-services/src/durable.rs` | `2deaa25ecbdb9b254f41540b921da34d249289889c935570789a23ee58e696c0` |
| `crates/health-services/tests/ingress.rs` | `c18260dcde3f9f2b229d8f3aa2fc6b4273bfb8487605a80592b9f876158b0a4b` |
| `crates/health-services/tests/witness_archive.rs` | `fec15941a07baf848d757032ccf4c926e8a6545cf977b1d5730b16fb905cadd5` |

## Post-checkpoint changed-property sensitivity

The isolated detached worktree `$HOME/tos-node-health-c05-mutation`
started at exact `8699a3e554dcacdd0fd0194de4c823b1b34c6e20`; the main
implementation tree was not mutated. `current-age-mutant.patch` SHA-256
`324a63723c6123c55cc0dbb9fd93a6e30b0f358ac72a6d61313471f55334098f`
removed only the volatile-track forget after a matching history-only
delivery. Mutant `manager.rs` SHA-256 was
`94ed0716f07fba7fd91419e60ed2ce9c40cdde188cdcf04944012c37bd0d046b`;
restored SHA-256 is
`5dd0e4b0a9c330196e1c15324e9a5a802a8214b3453f0d4ebd4ba8c2cc6166da`.
The same locked targeted command ran in both worktrees:
`CARGO_BUILD_JOBS=2 cargo test -p tos-health-services --test witness_archive synthetic_valid_clock_current_route_qualifies_context_without_proof --locked -- --nocapture`.
Baseline `raw/current-age-baseline.log` SHA-256
`a95aaba35f16b1d5fd9107b70fd3b0067341a75ed277ccd90e13c8a933d9c039`
exited 0; compiled mutant `raw/current-age-mutant.log` SHA-256
`cb44af1c0db4e77f7308ea4ae35ab08baaaa64c34948c563d5e732efefe7d4e9`
exited 101 at the intended assertion (`qualified` versus `unknown`),
not at compilation; restored isolated-source run
`raw/current-age-restored.log` SHA-256
`cb3d3f9fed2a3d6064404540cfa1ace92df0e620fee214e33252d1a433691965`
exited 0. The detached mutation worktree is clean afterward.

Remaining C05 review work: final source/contract inventory and exact evidence
index, then supervisor review. Production witness adapter, deterministic
verified-finality proof, cost gate, and `observer_disagreement` rule input
remain unsupported/pending.
