# Shielded wallet mobile core

A synchronous C ABI over `shielded-pool-wallet` and `shielded-pool-circuit`.
This library does not implement a second key hierarchy or note validator. It
currently exposes descriptor issuance and batched note recovery/reconciliation.
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
