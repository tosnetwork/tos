# C05 dev-only transit/current checkpoint — NOT C05 acceptance

Base HEAD `f9fa4e4512c9a171586bdf3e1c58560cb90ea987`; this receipt describes
the successor WIP tree before its checkpoint commit. The synthetic source,
clock-quality fixture, test CA and test mTLS identities are **not production
fixtures or source/proof capability**. No business node was started. The
historical archive remains separate from current qualification and no witness
rule is enabled. Production witness adapter/cost/proof/receiver and C05 final
memory gate remain open.

Implemented here: optional trusted-same-host Linux BOOTTIME witness with boot
ID and time-namespace binding; separate current token; fixed alias/role mTLS
ingress routes; six bounded current-only headers; actual collector O GET and M
POST; M current ordering/read with body-lifetime two-reader leases; closed
read DTO with original row context, relative age, reported-versus-local
dimensions, and explicit production_usable=false. A missing/invalid current
stamp does not revoke a valid historical archive ACK. Current view is volatile
on restart. A duplicate's incoming validated body, not the archive's original
ACK body, supplies conservative current age.

| Exact command (from `tools/node-health-monitor`) | Raw log SHA-256 | Exit/result |
|---|---|---|
| `CARGO_BUILD_JOBS=2 cargo test -p tos-health-services --test ingress --test witness_archive --lib --locked` | `raw/transit-checkpoint-tests.log` `a19a6d11e9c2512246446ee71d9f750b1bc1ee9cb7556f9fa162d0d3246a50a8` | natural 0; lib 4, ingress 7, archive 8 |
| `cargo fmt --all --check && CARGO_BUILD_JOBS=2 cargo clippy -p tos-health-services --all-targets --locked -- -D warnings` | `raw/transit-checkpoint-fmt-clippy.log` `30ebad090907d90f4c5cc68254ee0f77e6250319960b018e24c7914857b3f052` | natural 0 |
| `.contract-venv/bin/python scripts/check-contracts.py` plus two `check-witness-current.py` actual bodies | `raw/transit-checkpoint-contracts.log` `6516a69832d362e932d6686a188145a8f380a24b61fc0e9976f413c819770f64` | natural 0; 24 closed schemas |
| `NHM_CURRENT_ACTUAL_JSON=... NHM_CURRENT_QUALIFIED_JSON=... CARGO_BUILD_JOBS=2 cargo test -p tos-health-services --test witness_archive --locked -- --nocapture` | `raw/transit-checkpoint-actual-outputs.log` `8f69f7741c1b2eedfb430cb6c291dc48ab0f4edefe63d623c7294e7674d8a67a` | natural 0; 8 tests, emitted actual route outputs |
| `.contract-venv/bin/python scripts/check-witness-current.py` for both final actual outputs | `raw/transit-checkpoint-actual-schema.log` `660118d1ec2a6f7787a440f1651a95cb267cdb5f9e21c4546e1664a04b1985ae` | natural 0; structural, semantic and nullable negatives |

Actual Unknown/stale output `raw/current-actual-handler.json`
SHA-256 `278bed4195cb2eae576d1f38d459b47af8069e95bd804d515a939ffabc136973`;
synthetic-valid-clock qualified-context output `raw/current-qualified-handler.json`
SHA-256 `8fb65466cedf0eb6c1960276ee9a8b7413556417fcfe6d39f8a9fc0d3b3b22b2`.
The qualified response still has verified_finality=false, local_action=unknown
and production_usable=false. `observer_disagreement` remains pending_C05.

Changed source/contract SHA-256 at this checkpoint:

| File | SHA-256 |
|---|---|
| `crates/health-services/src/transit.rs` | `b944a3a5f7fac233439211354ceb8d0de9fc8f4e7400f336a1a23deb8bc7d09c` |
| `crates/health-services/src/collector.rs` | `3cce74bd3b80e6c6d5b6d54fdc78d9393d24213795e226602dd916b610ce0925` |
| `crates/health-services/src/ingress.rs` | `5f7f9e1f3f1ea684a79130f649728cc6dfbc42c201bb47511d94f04ffd962a22` |
| `crates/health-services/src/manager.rs` | `ef97e4fe68a2a6ca5f08a354952f0549b669fe3eded341c37c3f9751d2f81d8d` |
| `crates/health-services/src/durable.rs` | `05c19bf197b4f541bde9f20b9f06892e3c3df5643ece7c545e3aba00836a76d4` |
| `crates/health-services/src/witness.rs` | `fc0566012d7b9c1856bd1dae6f9b2a6c28d2c2042defa717b955d7dddd8ec7aa` |
| `crates/health-services/tests/ingress.rs` | `71563447e407ffb82e2f7a6876ec1ca8567f45cd04fa8f4ab265dcdeeeb62c26` |
| `crates/health-services/tests/witness_archive.rs` | `47b18c57c8ac4a9c1501d6ffe16dc31754b1a2cadecbdc105794d8ec9f058d35` |
| `contracts/witness-current.schema.json` | `1d72a1fce7d879fa7023ac57e1241f1baeace463c95f5e2b1c15ca3324f7139e` |
| `scripts/check-witness-current.py` | `ab0abe1a1d759a0b0ccf9c88ed6665e57250c63c32e7b71fe003269ca26547aa` |
| `Cargo.lock` | `50caba7c6ddbb3646f895c9f01c90296e5e78e32049df794ca18695bac03df73` |
| `contracts/dependency-lock.json` | `cd98a9b33c9568a450f426e94c0f705ee9f057570092a8bfc2c9b3ca876484e9` |

Retained red lineage: `raw/current-actual-handler.log` exited 101 because a
relative artifact path was resolved from Cargo's package cwd, not the repo
root; the absolute-path restored log exited 0. `raw/transit-clippy-first.log`
exited 101 on three style findings; the restored fmt/Clippy raw log above is
0. These are not counted as product test negatives.

Remaining before C05 review: derive/enforce the 1 MiB current subsystem
resident plus decode/serialization/queued-response scratch bound (the current
fixed `8*32768` scratch reserve is provisional); exercise actual invalid
token/hash/boot/namespace/future-stamp through TLS ingress with unchanged
archive ACK and unavailable/unknown current; preserve a bounded timeout/queued
read lease control; complete manifest/evidence index and final regression.
