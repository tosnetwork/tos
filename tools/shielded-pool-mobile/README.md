# Shielded wallet mobile core

A synchronous C ABI over `shielded-pool-wallet` and `shielded-pool-circuit`.
This library does not implement a second key hierarchy or note validator. It
exposes descriptor issuance, batched note recovery/reconciliation, pool state
decoding and individual history-link binding.
Planning, proving and transport must be integrated before a mobile payment is
usable. No VM, consensus or contract changes are included.

## Ownership and custody

The public header is `include/tos_shielded_mobile.h`. Pass the protocol's
32-byte TOS seed, not a mnemonic's textual bytes. The seed copy is zeroized on
return, and the existing wallet clears its instance master on drop. Free every
opaque response exactly once using this library. The serialized response and
its temporary string fields are zeroized on destruction. This is not a claim
that every intermediate value in upstream cryptographic dependencies is wiped.

Response data is borrowed until free. Copy it into protected application state
before freeing. Scan responses contain private note material and must not enter
logs, analytics or ordinary unencrypted preferences. No global keys, handles,
cache, sockets or threads are retained. The application must serialize costly
operations and support cancellation at batch boundaries.

Descriptor issuance returns the standard 2573-byte SHD1 encoding. The application
must durably reserve each index *before* issuing it, including across crashes;
this stateless core does not allocate indices. Reject exhausted index space at
the application boundary. Encoding validity does not authenticate a recipient.

## Scan request version 1

A UTF-8 JSON object with no unknown fields:

```json
{
  "version": 1,
  "execution_domain": "0000000000000000000000000000000000000000000000000000000000000007",
  "outputs": [],
  "published_nullifiers": []
}
```

Each output has `slot` (0..2), `output_data` (canonical padded standard Base64),
`output_data_hash` and `note_body` (canonical 32-byte lower-case field hex),
`recovered` (optional canonical unsigned decimal amount) and `leaf_index`
(optional canonical unsigned decimal u64). Nullifiers are canonical field hex;
duplicates are rejected. Numeric protocol fields other than the small version
and slot are strings, so a mobile JSON decoder cannot truncate them.

Limits: 2 MiB request, 512 output payloads and 8192 nullifiers per call; 1 MiB
response. The request byte limit is checked before JSON parsing, with element
limits checked before decryption. There is no retry or persistent allocation.
The maximum input byte size also bounds deserialization allocation, including
malformed arrays rejected by the element-count checks.

A response contains `version`, `batch_unspent_balance`, `next_note_key_index`,
`diagnostics_count` and recovered `notes`. Each note includes its decimal index
and amount, field-hex secret/owner/body/payload hash/nullifier, spendable/spent
flags and optional leaf index. Duplicate note bodies are counted once within a
batch. Other wallets' ciphertext is ignored, while decrypted invalid deliveries
are counted as diagnostics. Spent notes are excluded after reconciliation.

**This is a batch result, not a verified or fresh wallet balance.** Callers must
verify the pool domain, chain slots, leaf positions and complete nullifier state
against one trusted checkpoint before using it; an omitted nullifier can make a
spent note appear unspent. Merge batches by note body and reconcile against a
complete verified nullifier set. Preserve the greatest durable issued index as
well as the recovered index. A failed/incomplete scan must never replace a
known balance with zero. This ABI performs no chain authentication, storage,
networking, signing approval or transaction submission.

## Verification

```sh
cargo test --manifest-path tools/shielded-pool-mobile/Cargo.toml --locked
cargo clippy --manifest-path tools/shielded-pool-mobile/Cargo.toml --locked --all-targets -- -D warnings
```

Tests decrypt a real ML-KEM/AEAD payload produced by the existing wallet, reject
mismatched note bodies, reconcile actual nullifiers, check duplicate accounting
and unsigned index limits, exercise bounds/malformed input and cross the C ABI
ownership boundary. A targeted mutation control must prove the spent-note and
note-body tests fail when their respective checks are removed.

## Pool state cells

`tos_shielded_pool_state` accepts one generic single-root BOC, up to 2 MiB,
32768 serialized cells and depth 128. Cardinality is checked before cell-table
allocation. The existing pool codec is shared with the CLI through the
`shielded-pool-codec` crate. Production codec logic is unchanged by extraction;
its existing tests run in that crate's CI step.

The UTF-8 JSON response includes `data_hash`, commitment/nullifier roots and
indices, reserved recovery leaves, epoch, liability/reserve/fee/denominations,
profile/manifest/verifying-key hashes, verifying-key bytes in standard Base64,
and preserved anchors. Monetary quantities and indices are decimal strings;
field/hash words are lower-case 32-byte hex. `version` is 1.

This is layout decoding, **not proof verification or an assertion of a current
balance**. Bind `data_hash` to the verified account's data root, verify the
account address/code/network and deployment pins, then reconcile a complete
history replay to the decoded roots before treating it as a wallet observation.
Proofs, signing and storage remain caller responsibilities. Malformed, trailing,
multiple-root, oversized and excessively deep data is rejected. The test suite
includes valid shallow BOCs on both sides of the cell limit and an otherwise
parseable state beyond the depth limit, with assertion-failure mutation controls.

## Pool history links

`tos_shielded_history_transaction` accepts a version-1 JSON request with
`boc` (canonical standard Base64), `expected_hash`, `account_id`,
`post_state_hash` (lower-case 32-byte hash hex), `expected_lt` (u64 decimal
string) and `maximum_time` (u32 decimal string). The request has no unknown
fields and is bounded by 2 MiB. The BOC has the same cell/depth bounds as pool
state decoding. A transaction must be an ordinary level-zero cell, match the
expected hash, LT and account, have the expected post-state, and be no newer
than `maximum_time`. Its previous LT/hash must be consistent and go backwards.

The first expectations must come from the verified ShardAccount transaction
head and raw Account root/time. To walk backwards, feed each response's
`previous_hash`, `previous_lt`, `pre_state_hash` and `time` as the next request's
expectations, retaining the same account. A zero previous LT/hash terminates
history. Persist page progress privately and impose an overall transaction/time
budget; this stateless operation makes one bounded step and retains nothing.

The JSON response includes the checked hash/LT/account/time, previous hash/LT,
pre/post Account hashes and a classified `event`: deposit, transact, bounce or
no-state-change. Monetary quantities are decimal strings, fields are canonical
field hex, payloads are standard Base64. Event interpretation reuses the existing
shared contract codec; rejection never means a transaction did not execute.
This does not authenticate caller-supplied expectations, assert history
completeness, perform ledger replay or return a verified private balance.

Tests classify all nine original sandbox transactions. The sandbox leaves
previous-transaction metadata zero, so link traversal is separately tested on
explicitly linked copies with unchanged bodies/state updates. Those copies are
unit-test constructions, not claimed as published chain transactions. Negative
checks cover wrong hashes, LTs, accounts, state updates, future timestamps and
skipping a linked transaction.
