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
| `CARGO_BUILD_JOBS=2 cargo test -p tos-health-services --lib --test ingress --test witness_archive --locked` | `raw/current-budget-restored-tests.log` `9bc4c1503057689474155d6262a69e03ff2fceadd1135cfbd33e17a716e32809` | 0; lib 9, ingress 7, archive 9 |
| `cargo fmt --all --check && CARGO_BUILD_JOBS=2 cargo clippy -p tos-health-services --all-targets --locked -- -D warnings` | `raw/current-budget-restored-fmt-clippy.log` `6e4244edfeaa158fab42185a0abe9717ee5b9d3536bcc4c6936f4368c577d5d3` | 0 |
| `.contract-venv/bin/python scripts/check-contracts.py` | `raw/current-budget-restored-contracts.log` `042ef2920d96db1626e2fb104c7bc9ac0bd15ffde43e8a2400bc04d1e5e466bc` | 0; 24 closed schemas |
| `CARGO_BUILD_JOBS=2 scripts/run-contract-tests.sh` | `raw/current-budget-full-entry.log` `3b14870df78b71153329c84fef878de4b05fcb2106c64390a285cc00777f81dc` | 0; production doctor refused 11 unverified gates; one C04 native-pair test ignored without indexed external pair |

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

Remaining C05 review work: bind a final source/log index after this checkpoint,
complete changed-property compiled mutation evidence for the current gate,
reconcile manifest/source capability labels, and run the final affected
workspace/contract entrypoint. Production witness adapter, deterministic
verified-finality proof, cost gate, and `observer_disagreement` rule input
remain unsupported/pending.
