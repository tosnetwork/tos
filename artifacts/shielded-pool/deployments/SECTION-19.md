# Section-19 offline evidence ledger

Prepared 2026-10-19 for the [frozen V16 candidate](README.md). This is a
reviewable evidence ledger, not an activation certificate. Every row below has
local regression evidence; qualifications are explicit. Independent acceptance
of the complete ledger is **pending**. Public PRI-01..03 has not been run.

Paths below are relative to `tools/shielded-pool-circuit/` unless stated
otherwise. `crosscheck/tests/` runs production contract bytecode in the Rust
sandbox; it is not a four-validator network. Native opcode checks separately
exercise the C++ implementation. The circuit relation-removal tests are
in-process constraint mutations, not contract source mutations.

| Gate | Regression / receipt | Mutation or qualification |
| --- | --- | --- |
| 1 Poseidon pin parity | `tests/vectors.rs`, `crosscheck/tests/funcs_vs_gadget.rs`, native `test-poseidon2` | Native manifest/vector/instrumentation controls execute. Parameters and circuit source are unchanged; no new parameter ceremony. |
| 2 Activation matrix | Native `test-poseidon2`; `test-pq-mldsa44` (216 vectors); genesis `tests/runtime_profile.rs`; candidate V16 acceptance | Native V15 refusal / V16 acceptance; profile minimum changed to 17 makes the new source/profile check fail. |
| 3 Circuit negatives | `tests/circuit_negative.rs`, all circuit tests | Removal tests require invalid baseline and accepted weakened circuit. Three masking baselines and a redundant relation are reported in that source; this is qualified evidence, not a claim that each relation is independently load-bearing in the full circuit. Reviewer disposition remains required. |
| 4 Deposit inflation | Contract mutation battery `mutations-pool.py --only funding-principal` | Omitting principal funding validation is killed by the named assertion. |
| 5 Local funding | Same battery `funding-compute`; `backing_at_the_floor.rs` | Missing compute funding is killed; existing backing cannot fund a new note's principal. |
| 6 PQ substitution | `mutations-auth.py --only slot-0-signature slot-1-signature context-string` | All three mutants killed, restored green. |
| 7 One-time recovery | `crosscheck/tests/mnemonic_recovery.rs`; wallet `tests/key_hierarchy.rs` | Deterministic fixture restoration only; actual sender wallet provisioning remains before live GO. |
| 8 Phantom shape | `wire_vs_vm.rs`, `wallet_drives_a_transfer.rs`, circuit shape constraints | Fixed two-key/two-signature serialization and real/dummy validation; no claim of network-level anonymity from shape alone. |
| 9 Payload binding | `tests/circuit_negative.rs`; `wire_vs_vm.rs` | Binding relation removal admits the targeted altered payload; hashes agree with bytecode. |
| 10 IMT | `imt_vs_vm.rs`; `mutations-imt.py --only append-empty sibling-order next-index` | Three mutants killed; sequential insertion and order/update checks execute. |
| 11 Atomicity | `atomicity_beyond_a_throw.rs`, `transact_in_a_mature_pool.rs` | Compute OOG, payout-action and state-limit refusal checked; exact candidate acceptance additionally verifies committed roots/liability. Omitting that nullifier check is killed by a running mutant contract. |
| 12 Backing | `backing_at_the_floor.rs`, `withdrawal_round_trip.rs`, `storage_rent.rs` | Rent test run explicitly despite its ignored default; actual live balances still need reconciliation. |
| 13 Fee solvency | Exact payout shape and three price schedules in `publication.json`; `mutations-payout.py --only liability-no-fee fee-not-config fee-no-forward` | Three mutants killed. Live and sandbox-reference fees are 885,601 nanotos; the historical higher schedule is 5,313,600, all below immutable 20,000,000. Arbitrary future governance increases are not bounded. |
| 14 Rich bounce | `withdrawal_round_trip.rs`, `bounce_dust_boundary.rs` | Actual sandbox destination/action/bounce round trip, not just injected bounced metadata. Public-network round trip remains PRI work. |
| 15 No subsidy | `mutations-recovery.py --only handler-mints-what-left` | Minting the wrong bounced amount is killed; remaining value and recovery charge are reconciled locally. |
| 16 Bounce authenticity | `forged_bounce.rs`; `mutations-pool.py --only bounced-flag-kept`; recovery `handler-unauthenticated` | Sender-controlled bounce flag and unauthenticated handler mutations killed. |
| 17 Anchors | `anchor_traffic.rs`, `anchor_ring_cost_is_worst_when_full.rs`; `mutations-anchors.py --only preserve-version recent-root` | Overwrite and mixed append behavior checked; 24 hours is simulated chain time, not elapsed public-network observation. |
| 18 Mnemonic recovery | `mnemonic_recovery.rs`; wallet key/payload tests | Restored ordinary/recovery notes and invisible other-wallet notes; live independent recovery pending. |
| 19 Wire exactness | `wire_vs_vm.rs`, `imt_vs_vm.rs`, circuit canonical encoding tests, wallet payload refusals | Canonical bytes, lengths, fields and paths checked by existing suites; no new wire format. |
| 20 Derived ceilings | `gas_ceiling_bound.rs`, mature deposit/transact suites | `mutations-ceiling.py --only transact-ceiling-sampled transact-ceiling-padded spans-not-added`, three killed. Derived spans walk configured domains; not a sampled maximum claim. |
| 21 Proof exactness | `tests/groth16_fixture.rs`; `mutations-groth16.py --only pairing-ignored vk-x-offset`; exact final-key run | Two mutations killed; 18 inputs, 19 IC points, 1,248-byte VK. Final transcript audit reproduces the published digest. |
| 22 State manifest | Genesis production/binding tests; `public_preparation.rs`; frozen BOCs and strict manifest | Wrong network, cell digest and profile provenance explicitly refused with no output directory. The reproduction verifier checks four deterministic files against committed checksums and publication fields against the committed publication (only randomized measured gas may vary). Drift with matching freshly generated checksums is refused. |
| 23 Consistency | Frozen profile/runtime test, explicit profile review, existing memo consistency watchlist | Scanner processed real documents and found 18 repeated watchlist facts. Historical t=5/RP22/two-output/gas material is historical, not normative. Profile uses t=8/RP57/three outputs/V16. Scanner is not a proof of universal prose consistency. |
| 24 Gas caps | `mutations-pool.py --only gas-ceiling-live`; mature suite | Removing the local cap is killed even with ample principal. |
| 25 Plaintext | Wallet `tests/payload_validation.rs` | Every rejection rule has its specific refusal; dummy payload cannot become spendable balance. |
| 26 Descriptor reuse | `mnemonic_recovery.rs::two_notes_sent_to_one_descriptor_are_both_recovered_and_the_index_is_burnt` | Both notes recovered and descriptor burned; no live descriptor issued in preparation. |
| 27 Bounce dust | `bounce_dust_boundary.rs` | Measures authentication and recovery-charge boundary and actual recovered amount; not an arbitrary dust constant. |
| 28 Scalar hygiene | `tests/circuit_negative.rs`; new `public_client` refusals | Nonce and real/dummy secret nonzero constraints checked; client refuses zero before proof construction. Masking qualification in gate 3 applies. |
| 29 Denominations | `gas_ceiling_bound.rs`, payout boundary and circuit negatives | All configured values and off-list cases exercised offline; 1,000 TOS live deposit exceeds approved test budget. |
| 30 Domain separation | Wallet `two_execution_domains_share_no_key_material`, wire domain parity, anchor `exec-global-id exec-account` | Two anchor mutations killed; new client refuses another account/network, and its domain guard mutation must fail the specific refusal test. |

## Commands and receipts

From the repository root, with the compiler and bounded build environment in
[README](README.md), run:

```sh
for crate in shielded-pool-circuit shielded-pool-wallet shielded-pool-genesis; do
  cargo test --release --locked --manifest-path "tools/$crate/Cargo.toml"
done
cargo test --release --locked \
  --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml --tests
cargo test --release --locked \
  --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml --tests -- --ignored
cmake --build build --target test-poseidon2 test-pq-mldsa44 -j6
build/crypto/test-poseidon2
python3 test/pq-mldsa44/prepare_vectors.py --out pq-results
build/crypto/pq/test-pq-mldsa44 pq-results/vectors.tsv pq-results/native.tsv
ctest --test-dir build --output-on-failure --no-tests=error -L source-guard
```

The 24 selected existing source mutations ran in isolated worktrees, each
against its named test, with separate target directories and restored-green
runs. Commands use `python3 test/shielded-pool/mutations-NAME.py --only LABEL...`;
the precise eight commands and log digests are in [receipts.json](receipts.json).
A compiler failure, zero selected test, or unrelated assertion is not a kill.
The new guard reproductions are listed there separately with substitutions.
Raw logs are retained outside Git by the test lead; hashes make those receipts
identifiable without adding bulky build output to this tree.

The local circuit, wallet and genesis runs passed 48, 11 and 23 tests. The
three expensive cross-check tests skipped by default were also run explicitly
and passed, including the end-to-end ceremony, rent and mature-withdrawal cases.
Final cross-check counts and the final source-guard run are recorded in the
receipt index. Strict Clippy has existing diagnostics outside changed lines;
the changed-line filter is the review gate, not a claim that the whole legacy
crate is warning-free. No C++/FunC implementation was changed, so the native
static-analysis diff gate is not applicable to this Rust/artifact preparation.

## What this does not authorize

Independent review and owner/test-lead approval are not supplied by self-run
tests. Final-key mathematical verification does not prove destruction of
ceremony randomness. The 100 TOS endowment / 50 TOS immutable floor distinction
must be accepted explicitly. No public PRI transactions, services, relayers,
public witness/seed generation, activation or deployment are included. The
public client is an offline API awaiting caller/submission review, not a
released end-user wallet. Revalidate live prices and the network identity
before requesting the separate live GO.
