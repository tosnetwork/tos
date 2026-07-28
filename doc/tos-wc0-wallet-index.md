# TOS wc=0 In-Process Wallet Index

Status: in progress (Phase W). Goal: serve wallet "aggregate" queries (jetton list,
NFT list, account events) directly from the node, without requiring an external
wallet indexer.

## Why

A bare node can serve current account state, send messages, run get-methods,
and walk a single account's transaction chain. It cannot *enumerate* which
jettons / NFTs an account owns, nor produce a parsed event feed, because
ownership is spread across per-wallet contracts. This index adds that capability
to native wc=0 so wallets and AI agents can inspect token state without a
separate indexer dependency.

## Architecture

- **Side-channel RocksDB** at `${db_root}/wc0-index`, parallel to celldb/statedb,
  completely outside the consensus state cell tree. It never contributes to any
  state hash; each operator can prune/rebuild independently (no hardfork).
- **Single-byte key tag + payload**, BOC-serialized values, `td::RocksDb` wrapper,
  module-scope singleton with `set_/get_` accessors.
- **Writer (hook):** on block apply (`ApplyBlock::applied_set`, after the block is
  marked applied), walk `BlockExtra.account_blocks -> AccountBlock ->
  transactions -> Transaction -> in_msg/out_msgs`, detect token ops, and update the
  index. The hook runs post-apply deliberately: data stored for unfinalized
  candidate broadcasts (`set_block_data` also fires for those) must never reach
  the index. All of a block's entries are written in one atomic RocksDB write
  batch, serialized by a mutex because apply actors run concurrently. Each block
  costs two WAL syncs, not one: a crash-recovery marker is durably written
  before indexing starts (see below), and the entry batch is synced
  separately on commit — collapsing these would leave a mid-index crash with
  no durable trace. Best-effort, off the consensus path (a failed write only
  degrades RPC for that block, never blocks consensus).
- **Reader (JSON-RPC):** new methods `getAccountJettons`, `getAccountNfts`,
  `getAccountEvents` range-scan the index (`for_each_in_range`, never a full table
  walk). Responses are bounded: optional `limit` param, default 100, max 1000 —
  required because third parties can inflate any account's index (anyone can send
  notification/spam transactions at it). Registered in `dispatch_method`.
  Token entries are state-verified at write time (see below); clients still
  resolve live balances via `get_wallet_data` (`runGetMethod`).

## Key schema (`wallet-index.h`)

```
0x10 + owner(32) + jetton_master(32)  -> BOC { jetton_wallet(256), last_lt(64) }
0x11 + owner(32) + nft_item(32)       -> BOC { has_collection(1), [collection(256)], last_lt(64) }
0x12 + account(32) + ~lt_be(8)        -> tx cell                // account event feed
0x13 + nft_item(32)                   -> owner(32)              // raw, for stale-entry erase
0x1E + block_seqno_be(8)              -> indexing-incomplete marker (crash recovery)
```

Prefix-scan `0x10 + owner` lists an owner's jettons; `0x11 + owner` lists NFTs.
Event keys store the bitwise complement of lt, so the ascending `0x12 + account`
scan yields newest events first and a result limit caps the scan itself.

## State-verified token indexing

First principle: the index must contain only statements verifiable against
committed chain state. Message ops are claims anyone can fake, so they never
write to the index directly — they only *nominate candidates*:

- Jetton (TEP-74): transfer `0x0f8a7ea5` / internal_transfer `0x178d4519` /
  burn `0x595f07bc` received by W nominate W; transfer_notification
  `0x7362d09c` received by O nominates its source.
- NFT (TEP-62): transfer `0x5fcc3d14` received by N nominates N;
  ownership_assigned `0x05138d91` received by O nominates its source.

Each candidate is then verified against the **post-apply shard state** by
executing gas-bounded (1M) TVM get-methods:

- **Jetton wallet W**: `get_wallet_data` on W yields (owner, master); then
  `get_wallet_address(owner)` on the *master* must resolve back to W. The
  master is the only authority on which contract is (owner, master)'s wallet —
  a hostile contract can claim any owner/master, but cannot make a master it
  does not control acknowledge it. Verified ⇒ upsert `0x10+owner+master`.
- **NFT item N**: `get_nft_data` on N yields (init, index, collection, owner);
  for collection NFTs, `get_nft_address_by_index(index)` on the *collection*
  must resolve back to N. Standalone NFTs (collection = addr_none) are their own
  sole authority and are indexed as self-claims keyed by their own address.
  Verified ⇒ upsert `0x11+owner+nft`; the `0x13+nft -> owner` reverse entry
  lets the writer erase the previous owner's `0x11` entry, so ownership changes
  never leave stale entries. Because verification reads end-of-block state,
  multiple transfers within one block converge to the final owner.

Unverifiable claims are skipped (fail-closed): missing/uninit/frozen accounts,
masters or collections outside wc=0 (or outside this shard's state), failed or
non-conforming get-methods, contracts needing library cells. Candidates are
capped at 1024 per block (logged when hit). Every transaction also appends an
`0x12+account+~lt` event entry, unconditionally — transactions in an applied
block are facts.

What verification does *not* prevent: an attacker deploying their own master M'
whose resolver acknowledges a wallet claiming owner O. That creates a truthful
entry "(O, M')" for an unwanted token airdrop. Wallets and agent clients filter
by token reputation client-side; the `limit` param bounds the blast radius.

## What stays external (cannot be in-node)

- Fiat rates (a chain cannot produce USD prices) — a small TOS-run price service.
- NFT media (IPFS/CDN), contract-source verification, community token registry.

## Phasing

- **W1 (this commit):** `WalletIndexDb` db layer + CMake wiring + read-path
  JSON-RPC methods (`getAccountJettons`/`getAccountNfts`, empty until W2). Compiles
  and links into validator-engine; the node still builds and runs.
- **W2:** block-apply hook (the writer) + token-op parsing; populate the index.
- **W3:** `getAccountEvents`; crash-recovery incomplete markers; localnet e2e
  (deploy a jetton, transfer, query).
- **W4:** re-point agent wallet and service workflow clients to
  `getAccountJettons` / `getAccountNfts`, completing the in-node token
  inspection surface for AI actor workflows.
```
