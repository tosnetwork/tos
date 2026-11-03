# Shielded wallet mobile core

A synchronous C ABI over `shielded-pool-wallet` and `shielded-pool-circuit`.
This library does not implement a second key hierarchy or note validator. It
exposes descriptor issuance, batched note recovery/reconciliation, pool state
decoding, individual history-link binding and owned replay sessions.
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

## Provisional ledger replay (Rust core)

`replay::Replay` reuses the existing wallet ledger. Its typed `Head` and expected
`PoolState` must come from the same verified account observation; the bounce
recovery charge comes from the proven gas configuration. `push` accepts raw
transaction BOCs oldest first, starting at the account's first transaction.
It checks account, time/LT ceilings, previous hash/LT, strictly increasing LT,
non-decreasing timestamps and continuity of raw Account state hashes before
applying the existing codec's event. No provisional ledger is exposed.

`finish` consumes the replay and returns a ledger only if the final hash/LT and
raw Account root match the supplied head, and all six ledger checkpoint fields
match the expected pool state. An incomplete/reordered history, unknown state
change, failed application or checkpoint mismatch returns no ledger. The empty
history case also requires an empty head and the exact genesis checkpoint.
A failed push discards provisional state; it cannot be resumed and published.
The owner releases a cancelled replay by dropping it. There is no registry.

The whole replay is bounded by **8192 transactions and 32 MiB of cumulative
serialized BOCs**, in addition to each BOC's existing bounds. Those bounds also
limit ledger leaves, nullifiers, pending recovery records and stored ciphertext:
a transaction can add at most three leaves/two nullifiers/one pending recovery
and its admitted payloads. Requests beyond either budget fail closed with no
balance result. Mobile integration must surface that as incomplete, preserve the
previous durable observation, and must not substitute a zero balance. This is
not a claim that every future pool history fits this initial bounded replay;
incremental durable replay remains necessary.

Like the existing CLI, pricing historical recovery bounces with current prices
can disagree after a gas-price change. The final checkpoint refuses that result
rather than estimating a balance. Tests exercise deposits, two spends and a
bounce, each checkpoint field, head mismatch, missing/reordered links, failure
poisoning and both aggregate resource boundaries using valid BOCs.

The typed replay core is exposed by the session C ABI below, but is not yet
connected to App history acquisition, persisted or used for product balance
display. Previous one-link mobile device evidence remains separate.

## Replay session C ABI

Create an opaque session with `tos_shielded_replay_create` and a version-1 JSON
object containing these fields (no unknown fields):

- `global_id`: signed 32-bit JSON integer from proven config 19.
- `account_id`, `last_hash`, `account_root`: lower-case 32-byte hex. The latter
  two name the verified ShardAccount transaction head and raw Account root.
- `last_lt` / `shard_time`: canonical unsigned decimal strings, u64 / u32.
- `pool_state_boc` / `pool_data_hash`: canonical standard Base64 and lower-case
  root hash for the data extracted from that verified Account.
- `gas_boc` / `gas_hash`: config-21 BOC and its root hash from the SAME checkpoint.

Hashes are checked before decoding. Gas pricing uses the existing codec. The
execution domain uses the existing global-ID/account-ID derivation. The App
must verify the network/trust anchor, address/workchain, account code and pool
profile/manifest/VK pins, ensure all these values came from ONE authenticated
observation and check freshness. The C ABI does not establish those facts from
caller-supplied expectations. A forged expectation does not become a proof.

Input pointers live for the call only. Sessions retain decoded public history,
not input pointers, seeds or private notes. Creation returns NULL on error.
Serialize all calls on a handle, including reads and free. Feed oldest-first
raw BOCs through `tos_shielded_replay_push`, then `tos_shielded_replay_finish`.
A mutator error or contained panic invalidates the session before returning;
only `tos_shielded_replay_free` is useful afterwards. Drop cancelled sessions too.
Mutator status is 0 success, 1 error, 2 contained panic. Never retry a failed
session as if its partial ledger were usable.

Only finished sessions permit `tos_shielded_replay_info` and
`tos_shielded_replay_scan`. Info returns public checkpoint fields and
`total_outputs`; `native_liability` is the WHOLE POOL liability, not this wallet's
balance. Scan consumes a temporary 32-byte seed copy and `offset`/`count` for a
non-empty page of at most 512 outputs. It reconciles against the completed
ledger's FULL published-nullifier set. The JSON envelope contains `version`,
`output_offset`, `output_count`, `total_outputs` and `scan` (the same protected
note result as the batch API). Numeric quantities are decimal strings.

Scan every page, merge notes by body, preserve the greatest durable issued
index and recheck proof freshness before atomically publishing/persisting a
wallet observation. A page's batch balance is not a complete wallet balance.
An empty ledger has zero outputs and requires no scan call. Read-only argument
errors do not change an otherwise finished session. Free every response and
session exactly once with the same library. Scan responses contain secrets;
never log them. Their fields/buffers are zeroized on destruction as in the
existing batch API. This does not claim all upstream intermediates are wiped.

Tests use original sandbox events/linked copies for lifecycle and completion,
and explicitly synthetic ledgers/transaction-state pairs for real ML-KEM note
recovery and spent reconciliation. They do not claim native VM execution or
chain proofs for the synthetic pairs. A deliberate test-only unwind exercises
session invalidation through the actual FFI mutator boundary.

## Encrypted record primitive (Rust only)

`sealed::RecordCipher` supplies bounded XChaCha20-Poly1305 pages for subsequent
state, journal and backup storage. This is not a filesystem store or a C ABI.
Its fixed-width binding includes the network ID, canonical workchain-zero pool
account, trusted genesis root/file hashes and code/profile/manifest/verifying-key
pins. Callers authenticate these expected selections independently; successful
decryption proves neither current chain state nor a spendable balance.

A separately labelled SHAKE256 derivation produces the record key. Each seal
uses a fresh random 24-byte nonce and authenticates format, record kind and the
caller's expected sequence. The envelope is `TSP1 | version:u8 | kind:u8 |
sequence:u64be | nonce:24 | ciphertext | tag:16`. Plaintext is limited to 1 MiB
before encryption; ciphertext input is capped before decoding. Oversized,
partial, altered or different-format records are refused without modifying the
input. Held keys, cipher keys on drop, and returned plaintext are zeroized;
borrowed seed/plaintext remain the caller's responsibility. No complete erasure
claim is made for hash implementation intermediates.

The later store must provide private locked files, durable journal reservation,
atomic commit. The snapshot layer below supplies the complete page manifest/generation. Individual
valid pages alone do not prevent snapshot mixing or rollback of an entire older
state/journal pair. Pin upgrades require explicit migration with the old binding;
decryption failure must never be interpreted as permission to reset UNKNOWN.


## Complete encrypted snapshots (Rust only)

`snapshot::seal/open` wraps State or Backup records in an authenticated complete
page manifest. The manifest contains a fresh 32-byte generation, exact plaintext
size, page count, and each ordered ciphertext length and SHA3-256 digest. The
manifest is record sequence zero; pages are sequences one through the page count.
Their purpose and expected positions are authenticated by the record layer.

The container is `TSSN | version:1 | reserved:3 | manifest_length:u32be |
encrypted_manifest | encrypted_pages`. The decrypted manifest is `SM01 |
generation:32 | plaintext_length:u32be | count:u32be | (length:u32be, hash:32)*`.
Plaintext is capped at 32 MiB / 32 pages, with a separate ciphertext cap. The
manifest itself is capped before decryption. All lengths, page hashes, complete
page list and absence of trailing data are checked before allocating the output.
Only the final page may be short. Returned plaintext is Zeroizing; a seal's
borrowed plaintext remains the caller's responsibility. Sealing assembles one
ciphertext buffer plus one temporary page; opening retains the input, one
output allocation, and one temporary decrypted page. These are code bounds,
not a measured device-memory acceptance result.

A restored snapshot is unverified opaque application state. This API provides
no note schema, files, atomic replacement, journal, backup export UX, C ABI or
App integration. Callers must bound their business decoding, revalidate chain
proofs, and preserve UNKNOWN and index reservations in their durable schema.
A complete old snapshot can still be restored: generation and page membership
do not establish freshness or detect full rollback. Wrong pins require explicit
migration with the original binding; never initialize empty state on failure.
