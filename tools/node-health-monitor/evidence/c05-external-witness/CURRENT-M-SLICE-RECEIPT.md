# C05 current-order development slice — not current rule acceptance

Baseline commit `f252d207273f2c49c553cb16deabba9da711e693`.
All cache bodies are synthetic and served through isolated O/M routers; no
business node or approved production witness was used.

The frozen Plan now has `current_source_epoch` per endpoint. That field gates
only a separate current lane; historical Source/CacheResponse decode and
`witness_archive_v1` continue to accept otherwise valid old/other epochs.
M's current activation table is globally capped at 16 endpoint rows including
retired entries and quarantine flags. Same revision/different plan hash
(including a renamed endpoint) refuses; same activation reopening preserves
high-water/quarantine, while an explicitly new revision may activate another
epoch. No administrative service or rule adapter was added.

`EvidenceDb::review_witness_current` validates the exact O cache wire and
plan-bound source/immutable O metadata, rejects old generation and persists
same-generation conflict quarantine. It carries original M-relative age
floors/unknown state across duplicates. Reopening without a new qualified
delivery does not restore a fresh in-memory current view. Its positive
`Some(200)`/`Some(45000)` inputs in tests are *synthetic supplied durations*;
they are not measured collector/M transit. The actual manager archival writer
calls review with `None`, hence unknown current age and no rule fact. Historical
same-identity conflict quarantines the matching current activation in the
same SQLite transaction; an unrelated historical epoch still archives without
advancing current high-water. Valid historical ACK is never revoked by a
separate current refusal.

## Commands and raw results

| Command / scope | Raw log SHA-256 | Natural exit |
| --- | --- | --- |
| `CARGO_BUILD_JOBS=2 cargo test --locked -p tos-health-core --test witness_contract` (6/6; first Plan field) | `raw/current-plan-contract.log` `1bf1eee45636c3ab0c3d3d2220ba05135aec33b57dd35e247c73f96c912e9e49` | 0 |
| `.contract-venv/bin/python scripts/check-contracts.py` (23 closed schemas) | `raw/current-plan-schema-locked.log` `222c5f4bbb98fd219fa2a42ad9d1532619abc9225bb56299e66dc5c5c2de0e00` | 0 |
| `CARGO_BUILD_JOBS=2 cargo test --locked -p tos-health-services --test witness_archive` (6/6 after writer conflict fix) | `raw/current-writer-conflict.log` `4ce0601c4afd08a96026dd076281d9bb1e4d5cf1a5523a2db5e59c746afc4d34` | 0 |
| `CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets --locked -- -D warnings` | `raw/current-slice-clippy-restored.log` `8b09d0eec363c3122413deaa9d0d6f9b44f1f46a58c1324bcc954947b379fd94` | 0 |

Retained failed attempts: system `python3 scripts/check-contracts.py` had no
`jsonschema` (`raw/current-plan-schema.log`, exit 1, SHA-256
`f38646e5c50e1c8d30210a4a4bdbc453a2c0262ba55eb79bb217ac231b9546f0`);
first Clippy run found a new tuple type-complexity lint, then was fixed
(`raw/current-slice-clippy.log`, exit 101, SHA-256
`369c6cadf047854c55466fc762aa081f680962b52f5e688ed6f749e976ec2d42`).
`current-activation-first`, `current-review-first/second/third` and
`current-route-first` are passing intermediate-source lineage, not a frozen
final-suite claim. Independent supervisor direct-helper controls passed 2/2;
the supervisor's separate receipt is
`/home/tomi/nhm-supervision/c05-current-state/receipt.json`.

## Source hashes at this slice

| Relative source | SHA-256 |
| --- | --- |
| `contracts/witness-plan.schema.json` | `bc59268cd70e2fa73f4733b980a7353092adffc17b14bc960c54b69ef58c8acf` |
| `crates/health-core/src/witness.rs` | `f7fa3b92ca42ac08b2d2820b692b30dd56003fc3c6f6027fd47a8570dc977f79` |
| `crates/health-core/tests/witness_contract.rs` | `12447df7ffc74afbb3d63791d706caaba01eb1dbd7b0cd9a4a588cb0ddaf56a9` |
| `crates/health-services/src/collector.rs` | `de3199d6072b80daffb9af2fd34acc3084e0b50e2b62e8d3551076d04bb073bf` |
| `crates/health-services/src/durable.rs` | `0005b9bf6e055ab7870562f70eb869710af2effa2ec73aa00307a9003e6921ec` |
| `crates/health-services/src/manager.rs` | `157cb7e2bd5151239f403f4484f4d68bd4e2888f46746dedabc29ef5289f8d97` |
| `crates/health-services/src/witness.rs` | `7749d139d3a059b7ea3fb8895962e39bb814e91b9217e5d664c977e5b64e021b` |
| `crates/health-services/tests/witness_archive.rs` | `47cfae2fd5a5ec509bbbcd1c53b0e123186c4235377eccdd81cca69eb5691410` |
| `crates/health-services/tests/witness_cache.rs` | `f3be6098423f3e58b11ab9cb9647b3c437d3c2289de42141dbd935f0c313802a` |
| `crates/health-services/tests/witness_poll.rs` | `c473e7a1980dd1d7fd9c3e1323f9420640af6c51f3e402cac078a293ae687da2` |
| `scripts/check-contracts.py` | `f9910002e3c65aa7182f2e4d1283bfcb9439976a3f8ca37b632779e4d4685240` |

The service, test and current-age source hashes above are before any further
changes. This slice has no actual measured M current-view read surface, no A
consumer, no production witness source or proof verifier, and does not make
`observer_disagreement` live. It is a review milestone, not READY_FOR_REVIEW.

## Successor: pre-existing historical quarantine after reactivation

The first conflict fix covered a newly detected historical conflict. A later
review found that the pre-existing `witness_quarantined` early return could
skip current invalidation after a new plan revision explicitly reactivated the
same O/source identity. Both conflict branches now call the same matched
current-quarantine update in the historical SQLite transaction; only the
matching active plan hash, endpoint, O epoch and source epoch are affected.
The actual O cache→M route test activates a new revision after historical
quarantine, verifies current reset to 0, posts the still-quarantined history,
gets HTTP conflict and verifies current quarantine returns to 1.

Restored `CARGO_BUILD_JOBS=2 cargo test --locked -p tos-health-services --test witness_archive`
passed 6/6, exit 0: `raw/current-reactivation-suite.log` SHA-256
`359dced96d505477995d156adec20b9dacf955967ccb3c294a47bfa3786998cb`.
The single actual-route negative also passed, exit 0:
`raw/current-reactivation-conflict.log` SHA-256
`f79f88f3d10a79996281a25af6d5c51a10220f8a9484d4ec8b3a84ebf0bd153d`.
Restored workspace Clippy exited 0:
`raw/current-reactivation-clippy.log` SHA-256
`40a520b60bbd24e8330a9472b629184fbee6faae6587d0f57c79f621363168cc`.
Successor source SHA-256: `crates/health-services/src/durable.rs`
`f24cd4edc4e431ff3eb06f0f1e0587f53caa262a723a14399ea4c204e964da21`;
`crates/health-services/tests/witness_archive.rs`
`1c05c7e92309d8c5336fee1bc08f8e3335ca91d167e5216e48e4c4b5a1987d2e`.
