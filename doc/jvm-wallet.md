# `java.lang.Wallet` — Canonical wc=3 Account Pattern

Status: implemented (Phase E, commit `6e9b7f48f`).  Source:
`jvm/avata/rt/java/lang/Wallet.java`.

This document describes the on-chain wallet contract that ships in the
wc=3 (Avata JVM) `rt.jar`.  Audience: wc=3 contract developers,
off-chain wallet authors, and validator/full-node operators who need
to understand the canonical wc=3 account shape.  For the surrounding
account topology see [`jvm-v2-account-topology.md`](jvm-v2-account-topology.md);
for the workchain itself see [`jvm-roadmap.md`](jvm-roadmap.md).

## 1. What it is

`java.lang.Wallet` is a single-owner Ed25519 wallet contract.  It
serves three roles:

1. The **canonical wc=3 account pattern**.  Every external party that
   wants to act as a wc=3 sender (deploy new contracts, send messages
   to existing contracts) needs a wc=3 account that authenticates
   that party's intent.  Wallet is the smallest such account — one
   public key, one nonce, signature-authenticated dispatch — and is
   admitted in `rt.jar` so it can be deployed without first having to
   ship a contract through a developer toolchain.
2. The **wc=3 bootstrap account**.  Phase F's
   `jvm-zerostate-from-alloc` Fift word pre-seeds N Wallet accounts
   at zerostate, giving the chain working wc=3 senders from block 0
   (without one, the empty-default wc=3 ShardAccounts dict has no
   sender that can emit `action_create_account`).
3. A **base class for richer wallet variants**.  Subclasses can
   extend Wallet with paymaster, multi-sig, or fee-bearing semantics
   by overriding `protected static` helpers (`dispatch`, `digest`,
   `loadNonce`) without re-implementing the `@ContractEntry` surface.

V1 is intentionally minimal: single-owner, no fee delegation, no
multi-sig, no synchronous reply channel.  See §8 for known
limitations and the design rationale.

## 2. Storage layout

All three slots are stored under
`keccak256("Wallet.<name>")`.  The slot **names** are pinned at the
source-code level
(`SLOT_OWNER_PUBKEY` / `SLOT_NONCE` / `SLOT_INIT_FLAG` are
`public static final String` constants in `Wallet.java:53-55`), so
off-chain seeders compute the exact same keccak input as the live
runtime — no risk of drift between off-chain seeders and on-chain
execution.

| Slot name | Key | Value | Written by |
|---|---|---|---|
| `Wallet.ownerPubKey` | `keccak256("Wallet.ownerPubKey")` | 32-byte Ed25519 public key | `init()` |
| `Wallet.nonce` | `keccak256("Wallet.nonce")` | `Uint256` replay counter (monotonically increasing) | `init()` writes `0`; `execute()` increments by 1 |
| `Wallet.initFlag` | `keccak256("Wallet.initFlag")` | Single byte `0x01` | `init()` |

A wallet that has not been initialized has none of these slots set;
`requireInitialized()` checks `slot(SLOT_INIT_FLAG)` and reverts with
`Wallet_NotInitialized()` if the slot is absent.

The Phase F genesis seeder
(`jvm/core/genesis-wallet.cpp:54-71`) writes the three slots
verbatim in the same shape `init()` would have produced.

## 3. `@ContractEntry` methods

Three entry points, all `public static void`.  Method IDs are the
first four bytes of `keccak256(<canonical ABI signature>)`:

| Method | ABI signature | `method_id` | JVM method spec |
|---|---|---:|---|
| `init` | `init(bytes32)` | `keccak256("init(bytes32)")[:4]` | `(Ljava/lang/Bytes32;)V` |
| `execute` | `execute(uint256,bytes,bytes)` | `keccak256("execute(uint256,bytes,bytes)")[:4]` | `(Ljava/lang/Uint256;Ljava/lang/Bytes;Ljava/lang/Bytes;)V` |
| `getNonce` | `getNonce()` | `keccak256("getNonce()")[:4]` | `()V` |

The `method_id` values are derived deterministically — off-chain
clients reproduce them by keccak-hashing the ABI signature string
and taking the first 4 bytes.  Source of truth for the genesis
seeder side is `jvm/core/genesis-wallet.cpp:77-95`.

### `init(Bytes32 ownerPubKey)`

One-time owner-key install.  Reverts:

- `Wallet_BadOwnerKey()` if `ownerPubKey` is null or `Bytes32.ZERO`.
- `Wallet_AlreadyInitialized()` if the `INIT_FLAG` slot is already set.

On success, writes all three storage slots and emits a
`WalletInitialized(bytes32)` event with the owner public key as the
indexed topic.

The host's first-activation gate
(`crypto/block/transaction.cpp` / `jvm/core/dispatch-engine.cpp`)
already requires the inbound source workchain to match wc=3 and the
source address to match the JVAC `deployer`, so `init()` does not
re-check the caller.  For a genesis-seeded wallet the deployer is
the all-zero sentinel (`kJvmGenesisDeployer`) and `init()` never
runs — the seeder writes the same storage directly.

### `execute(Uint256 nonce, Bytes payload, Bytes signature)`

Authenticated dispatch.  Reverts:

- `Wallet_NotInitialized()` if `INIT_FLAG` is absent.
- `Wallet_BadNonce(uint256,uint256)` if the supplied nonce does not
  equal the stored nonce.
- `Wallet_BadSignature()` if the Ed25519 verify fails.
- `Wallet_BadPayload()` if the payload is malformed (see §4).

On success: increments the stored nonce by 1, decodes the payload
into N outbound transfers (§4), and emits one
`System.sendMessage(dest, value, body)` per transfer.  Finally
emits a `WalletExecuted(uint256,bytes32)` event carrying the digest
as topic1 and the nonce as data.

### `getNonce()`

Read-only view.  Reverts `Wallet_NotInitialized()` if the wallet has
not been initialized.  Otherwise emits a `WalletNonce(uint256)` event
carrying the current stored nonce.  V1 has no synchronous reply
channel, so reads are surfaced as events; off-chain UIs subscribe
to the event stream.

## 4. Payload format

The `payload` argument to `execute` is a tightly-packed big-endian
byte string:

```
payload   := count:uint8 || transfer*
transfer  := destWorkchain:int32 || destAddr:bytes32
          || value:bytes32 || bodyLen:uint16 || body:bytes
```

Constraints (enforced by `dispatch` / `dispatchOne`,
`Wallet.java:182-235`):

- `count` ∈ [0, 12].  The upper bound matches the host's
  `kJvmMessageCountMax`; if the wallet emitted more the host would
  reject the action list.
- Each `bodyLen` ≤ `kJvmMessageBodyMaxBytes` (128 016 bytes);
  enforced again by `System.sendMessage` so contracts cannot exceed
  the cap by under-stating the length.
- `count = 0` is valid and produces a signed "no-op" — useful for
  bumping the nonce to invalidate a previously-signed payload
  without emitting an outbound message.
- The exact byte layout must be consumed (`offset == data.length` at
  end of dispatch); trailing bytes revert `Wallet_BadPayload()`.

`destWorkchain` is a signed 32-bit value so masterchain (-1) and
basic workchains (0..N) are both addressable.  `value` is a 32-byte
big-endian Uint256.

## 5. Digest binding (replay protection)

The signed digest is:

```
digest = keccak256(
    Context.contractAddress().accountIdBytes()  // 32B — this wallet's wc=3 addr
 || nonce.toByteArray()                         // 32B — Uint256 big-endian
 || payload.rawBytes()                          // variable — the dispatch payload
)
```

Source: `Wallet.digest(...)`, `Wallet.java:151-161`.

The wallet's own address is bound into the digest so a captured
signature cannot be replayed against a different wallet at the same
nonce.  `Context.contractAddress()` returns the wc=3 account
address pinned by the runtime for this call (Phase A), so the value
is consensus-stable across all validators.

The nonce binding gives strict per-account replay protection:
each successful `execute` increments the stored nonce, so any
captured `(nonce, payload, signature)` triple is single-use.

Subclasses that want a different digest scheme (e.g. EIP-712,
secp256k1 + ecRecover) override `protected static digest(...)`; the
nonce / payload / signature ABI surface can stay unchanged.

## 6. Subclassing

`Wallet extends Contract`, so subclasses inherit:

- `Contract.revert(String)` and `Contract.revert(String, Object[])`
  for ABI-stable error encoding.
- The base contract storage handle (`Storage.current()`).

All internal helpers are `protected static`, so a subclass can swap
one piece without re-implementing the whole entry surface.  Typical
extension points:

- **Override `dispatch(Bytes payload)`** — swap in a different
  payload encoding (typed call data, batched operations with
  metadata, fee-aware forms).
- **Override `digest(Uint256, Bytes)`** — replace the Ed25519 raw-bytes
  digest with EIP-712 / EIP-191 / EIP-2098 conventions.
- **Override `loadNonce(Storage)` / `requireInitialized()`** — extend
  the storage layout to add multi-sig threshold counters, paymaster
  state, etc.  Take care not to break the slot-name commitment that
  the genesis seeder relies on if the subclass is itself meant to be
  genesis-seeded.

A subclass with a different `class_bytes` is a different consensus
artifact — it has a new `class_hash`, lives at a different derived
address (§7), and does not interfere with V1 wallets at their own
addresses.  Multi-sig / paymaster variants live alongside V1
wallets, not in place of them.

## 7. Address derivation

The wc=3 account address is computed by
`derive_jvm_contract_address` (`jvm/core/deploy-abi.cpp:234`); the
five-input formula is:

```
address_commit     = sha256(deployer || salt || init_args_cell.hash)
manifest_root_hash = sha256-cell-hash(manifest_root)   // or zero if null
addr               = sha256("TOS-JVM-CONTRACT-v2"
                            || deployer
                            || address_commit
                            || class_hash
                            || manifest_root_hash)
```

For a Wallet:

- `class_hash` = `sha256(Wallet.class bytecode)` — pinned by
  governance at network launch.
- `deployer` for a runtime-deployed wallet is the wc=3 source
  address of the `action_create_account`; for a genesis-seeded
  wallet it is the all-zero `kJvmGenesisDeployer` sentinel.
- `salt` lets one owner hold multiple distinct wallets at distinct
  addresses; pick any 32 bytes (sha256 of a human-readable name
  works well).
- `init_args` for a runtime-deployed wallet is the `JvmArgs` cell
  containing `(Bytes32 ownerPubKey)`; for a genesis-seeded wallet
  the seeder constructs the same cell so the address matches the
  one a runtime deploy would have produced.
- `manifest_root` is the wallet's three-method manifest
  (`init` / `execute` / `getNonce`), encoded the same way the genesis
  seeder builds it (`jvm/core/genesis-wallet.cpp:73-99`).

Off-chain clients compute the address by reproducing the five-input
formula.  Phase G's Rust port
(`tosctl/.../jvm_codec/address.rs`) is the reference
implementation, mirrors the C++ formula byte-for-byte, and is
pinned by 13 unit tests under `jvm_codec::tests`.

## 8. Genesis seeding

See [`jvm-v2-account-topology.md §Genesis seeding (Phase F option)`](jvm-v2-account-topology.md#genesis-seeding-phase-f-option)
for the operator-facing flow.  In short: the Fift word
`jvm-zerostate-from-alloc` accepts a tuple of
`(owner_pubkey:32B, salt:32B, balance:int)` triples; each triple
becomes a fully-active wc=3 Wallet account whose storage is
pre-populated as if `init(ownerPubKey)` had already run.

The seeder (`jvm/core/genesis-wallet.cpp`) writes the same three
slot keys, the same manifest entries, and the same init-args cell
that a runtime deploy would have produced.  The resulting address
is identical to the address the wallet would have at if it had
been deployed at runtime with the same `(class_bytes, salt, owner)`.

## 9. Off-chain wallet flow

The on-chain side is fixed; off-chain clients construct payloads and
signatures by reproducing the consensus-side encodings.  A
`tosctl jvm-wallet` CLI subcommand family is planned but not landed;
the Phase G Rust `jvm_codec` crate is the byte-stable foundation the
CLI will build on.

Conceptual send flow:

1. **Key generation.**  Generate an Ed25519 keypair off-chain.
   Publish the 32-byte public key as the wallet's owner; choose a
   32-byte salt and an initial balance.
2. **Address derivation.**  Compute the wc=3 address using the
   five-input formula in §7 (Rust callers use
   `tosctl/.../jvm_codec/address.rs`).
3. **Account materialization.**  Either genesis-seed the wallet via
   `jvm-zerostate-from-alloc` (§8), or runtime-deploy by emitting
   `action_create_account` from an existing wc=3 sender carrying a
   StateInit built by `encode_jvm_state_init_cell` and then call
   `init(ownerPubKey)`.
4. **Sending.**  Build the payload (§4), read the current nonce
   (call `getNonce` and listen for `WalletNonce(uint256)`), compute
   the digest (§5), sign with the owner Ed25519 private key, and
   submit a `JvmCallDescriptor` targeting
   `execute(nonce, payload, signature)` to the wallet's wc=3
   address.
5. **Receipt.**  `jvm_getReceipts` surfaces the resulting
   `WalletExecuted` event and any downstream-emitted events.  Failed
   signatures or stale nonces revert the entire transaction; no
   outbound messages are sent.

## 10. Known limitations

V1 is intentionally minimal.  Explicitly deferred (see
[`jvm-rt.md` §601](jvm-rt.md)):

- **Single-owner / no multi-sig.**  A subclass can extend the storage
  layout and override `execute` to implement N-of-M.
- **No fee delegation / no paymaster.**  The wallet pays gas itself;
  a paymaster subclass is possible but out of v1 scope.
- **No synchronous reply.**  `getNonce()` returns via event because
  v1 has no synchronous read channel.
- **No access control beyond signature.**  Anyone can submit
  `execute`; only a valid signature passes the `Crypto.ed25519Verify`
  gate.  No allowlists, time-based restrictions, or per-destination
  caps — these are subclass-level concerns.
- **No upgrade path.**  `class_bytes` is pinned at deploy.  Migration
  to a richer variant means deploying a new wallet at a new address
  and moving funds with an `execute`.
