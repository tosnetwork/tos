# Offline V16 deployment candidate

This directory records preparation, not deployment approval. No funding,
deployment, signature for a public transaction, or broadcast was performed.
The owner approved a 150 TOS ceiling: sender A 130, sender B 15, and a
workchain-0 recipient 5. Any live operation still requires the test lead's GO.

## Frozen identities

The shared implementation and network activate all required features at V16.
The former V17 profile matrix is superseded for all networks, not waived for
this testnet. No circuit relation, opcode, tariff or contract code changed.
The profile also corrects its recovery-cost summary to its existing section
15.4 rule and clarifies that 19 IC points have indices 0 through 18.

| Identity | Value |
| --- | --- |
| Profile commit | `1757cef815f1bd9ae96bb4ae2394e2e70f9080c7` |
| Profile blob | `9cee8b581d157edbba5f79dfa7162913af587b62` |
| Profile SHA-256 | `a513b05b6f8655fb0d76b2d2228de67c91aeb83541e28ab5e6d998c54f9c72f9` |
| Domain-prefixed profile hash | `ad94219a2db8cb24493754ac6bdf0b9cfff4cb014ebe0d2610650e4631d19beb` |
| Code-cell hash | `5528ff26426e36b948bbd6ab3bd6615c82c98c87dd774e4fb456f3965722c466` |
| Initial data-cell hash | `50ba96d38f3e0e474737a1946973f7ba528775a246bbe9b8d02a97a0425d6b4f` |
| StateInit hash / workchain-0 account | `aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe` |
| Global id | `2` |
| Final VK SHA-256 | `49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c` |
| Final transcript digest | `03e67eb4b1cff48c9bc5952992a46d37ae0c32d6ba2f76910f785daca8704579` |

The address is `0:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe`.
Use the strict [manifest](epoch4-v16/manifest.json), not a development manifest.
The code hash reproduces the earlier runtime build; the final VK and revised
profile change initial data and address. [Ceremony publication](../../phase2-ceremony-2/README.md)
contains the independent contribution and signed verification. Destruction of
randomness and independence remain declarations, not properties proved here.

## Reproduction

Use an independently held checkout containing the profile commit and finished
ceremony. Set `TOS_ROOT` to a matching V16 compiler checkout; build `func` and
`fift` with `cmake --build build --target func fift -j6`. The run used compiler
version 0.4.6 built from runtime commit
`85c679c3454f306eb867e25b1960ae3d757bd3dd`; contract sources come from this
checkout, never from `TOS_ROOT`. Use a fresh output directory:

```sh
export FUNC_PATH="$TOS_ROOT/build/crypto/func"
export FIFT_PATH="$TOS_ROOT/build/crypto/fift"
export CARGO_TARGET_DIR="$PWD/target"
export RUSTC_WRAPPER=sccache
export CARGO_BUILD_JOBS=6 RAYON_NUM_THREADS=6
cargo run --release --locked \
  --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \
  --bin prepare_public_pool -- \
  . artifacts/phase2-ceremony-2/ceremony candidate-output \
  1757cef815f1bd9ae96bb4ae2394e2e70f9080c7 \
  9cee8b581d157edbba5f79dfa7162913af587b62 2 \
  artifacts/shielded-pool/deployments/epoch4-v16-fees.json \
  49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c \
  03e67eb4b1cff48c9bc5952992a46d37ae0c32d6ba2f76910f785daca8704579
cargo run --release --locked \
  --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \
  --bin prepare_public_pool -- --verify-frozen . candidate-output
```

The tool audits the finished transcript against the committed phase-1 slice,
checks profile Git provenance, compiles code, loads the final VK, checks the
size and fee limits, and executes a deposit and real proof-backed transfer on
that exact candidate in the sandbox. It verifies committed roots and liability,
not merely a successful compute exit. Synthetic witnesses are unfunded test
material and must never be used for public notes. Public BOCs and the strict
manifest reproduce byte-for-byte; randomized proof processing may change the
reported gas receipt without changing those identities.

The verification command reads the frozen `epoch4-v16/SHA256SUMS` and
`publication.json` from **committed HEAD** in the independently held reviewed
checkout, not from the output directory or modified working-tree files. It
checks all four deterministic files against those committed hashes and every
publication field against the committed publication, except the positive
integer `sandbox_acceptance.gas` measurement. That randomized measurement is
not a frozen identity. Generated `SHA256SUMS` is only an output inventory;
checking it against files generated in the same run does not establish
reproduction. A mismatch names the file and fails. Stop on any mismatch;
do not regenerate the frozen anchors to make a drifted build pass.

## Fee evidence and funding limits

[Snapshot](epoch4-v16-fees.json) contains exact cells for CP8/18/19/20/21/24/25/31/43
read at masterchain block 211750 from two validator forwards. Every cell and
the full block identity agreed. The zero state was compared with the held
epoch-4 configuration. This is cross-node agreement, not independent proof
verification. Raw read-only requests and responses are retained by the test
lead outside the repository. Requests were serial, at least 0.6 seconds apart
per node; only read methods were used. Revalidate identity and configuration
on two nodes immediately before any live action.

[Publication](epoch4-v16/publication.json) records all rounded nanotos quotes.
Inbound compute credits include 25% headroom: deposit 1,916,669; transact
12,583,344; recovery 2,000,003; top-up 83,335. A deposit must additionally
attach its exact principal; sender-wallet execution and message forwarding
fees are separate. There is no claim that these are complete wallet sends.
The immutable 20,000,000 nanotos withdrawal fee covers the exact payout shape
under the captured live schedule, the sandbox reference schedule and the
historical higher basechain schedule;
the historical schedule from source commit
`54206889a2767bdf3172ec45be55daffd7b5dc9d` prices that same shape at
5,313,600 nanotos. These comparisons do not bound arbitrary future governance
price increases.

The planned endowment is 100 TOS with no administrator withdrawal. The frozen
contract's immutable reserve **floor is 50 TOS**, not 100: rent and legitimate
compute can consume the operational surplus. The 100 TOS endowment is not a
promise that the balance can never fall below 100 TOS. Denominations are
1, 10, 100 and 1,000 TOS; the 150 TOS test budget cannot exercise a live
1,000 TOS deposit. All four are covered offline.

## Public proving client

The reusable offline API is
[`public_client.rs`](../../../tools/shielded-pool-circuit/crosscheck/src/public_client.rs).
It lives beside the existing canonical serializers and acceptance gate to
avoid a second proof/wire implementation. It loads only a finished audited
ceremony with the independently pinned VK and unchanged proving key; proofs
bind the exact global id and account. It refuses invalid time windows and
zero nonce/output secrets. Proof entropy uses a fallible OS-seeded 256-bit
stream with no deterministic fallback or seed override. Each returned proof
is verified and canonically encoded. `fresh_nonzero_field()` supplies uniform
intent nonces and output secrets; the wallet crate supplies domain-separated
owner and encryption keys and canonical note payloads.

This is an offline library/API submitted for review, **not an approved live
wallet interface**. It has no submission transport, private-witness files or
private-key output. Before a live run, review the caller and wallet/send
adapter, provision fresh wallet seeds on the participant's controlled machine,
keep private directories/files at 0700/0600, and never place seeds, note
secrets, witnesses or private keys in command arguments, logs, Git or evidence.
Do not reuse fixture keys, notes or deterministic test RNGs. The preparation
command creates none of the public-testnet sender wallets.

## Acceptance and remaining GO

The [section-19 ledger](SECTION-19.md) maps all 30 gates to regression and
mutation evidence, with its limitations. [Receipts](receipts.json) pin the
retained logs by digest; bulky logs remain with the test lead rather than
being copied into Git. Software test success is not independent acceptance.

Still required: independent review of this profile, client and manifest;
test-lead acceptance of the qualified ledger, fee/funding policy and reserve
semantics; fresh network/config checks; reviewed wallet provisioning and
submission; explicit live GO; then the planned public PRI-01..03 flows,
settlement, recovery and balance/fee reconciliation. No deployment or mainnet
approval is included in this candidate.
