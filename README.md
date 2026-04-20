# The Open System

**The Open System (TOS)** is a multichain Layer‑1 that runs three distinct execution domains in parallel, on a single masterchain-rooted consensus:

| Workchain | Execution model | What it's for |
|---|---|---|
| **Native (wc=0)** | **Asynchronous**, message-driven, TVM | High-throughput contracts, sharded scale, actor-style async flows |
| **EVM (wc=1)** | **Synchronous**, EVM bytecode | Solidity / Ethereum-compatible contracts, wallet-compatible DeFi |
| **Uno (wc=2)** | **PQ-native privacy**, Plonky3 STARK AIRs | Shielded payments; quantum-safe and bridgeless by architecture |

One node binary (`validator-engine`) serves all three workchains. One canonical JSON-RPC surface, one operator path (`tosctl`), one wallet flow. Users choose their execution domain per transaction; validators opt in per workchain.

---

## Why three domains?

Different workloads want different trade-offs. TOS does not try to fit them into one VM.

- **Throughput and scale** are solved by TVM's asynchronous message passing + horizontal sharding (the TON-lineage design). The native layer is where 100K+ TPS is realistic, and where contract-to-contract message fan-out is cheap.
- **Developer familiarity and the Ethereum tool stack** are solved by running a real EVM as a separate workchain. Solidity contracts deploy as-is; MetaMask, ethers.js, Remix, and Foundry talk to wc=1 through standard JSON-RPC without modification.
- **Terminal privacy and post-quantum safety** require a protocol-level commitment, not a bolt-on. Uno is a native (not bridged, not retrofitted) privacy chain built on a hash-based STARK proof system — post-quantum at ship, with no Phase 2 migration debt.

Each workchain keeps its own invariants. The masterchain provides shared consensus and global time. There is **no bridge between Uno (wc=2) and any other workchain** — this is an architectural property, not a roadmap item; see the Uno section.

---

## Native Layer (workchain 0) — Asynchronous, Sharded, TVM

The native layer is the direct lineage of the TON architecture: an actor-style, message-driven execution model that scales horizontally through dynamic sharding.

### Execution model

Every account on wc=0 is an **actor**. A contract call is an **asynchronous message** delivered to an actor's inbox; execution reads the message, mutates local state, and can emit zero or more outbound messages. There are no synchronous cross-contract calls — two contracts interact by passing messages. The TVM (TON Virtual Machine) executes contract bytecode per message, with:

- deterministic, cell-native state (every account's storage is a Merkle tree of TVM cells)
- gas metering in nano-TOS, billed from the message
- built-in currency flows (tokens attached to messages are credited on delivery)
- native multi-currency support (the masterchain tracks currency registries)

Because messages are asynchronous, a contract never blocks on another contract's response. This removes the re-entrancy and cross-contract call-stack patterns that make synchronous VMs hard to parallelize.

### Dynamic sharding

The native layer is **sharded**: wc=0 is partitioned into shardchains that split and merge on demand based on account-id load. Each shard has its own collator set and produces its own blocks; the masterchain periodically signs off on shard state roots to bind them into a global chain.

- Shard splits happen automatically when a shard's traffic crosses a threshold (the masterchain signs the split).
- Shard merges happen when traffic drops and two neighboring shards can be served together.
- Cross-shard messages are routed through the masterchain's shard-routing logic with guaranteed eventual delivery.
- Validators register for specific shards; no validator is required to process all of wc=0.

This is how the native layer reaches very high throughput: the work is distributed across shards, and adding validator capacity horizontally adds throughput capacity.

### Consensus

Block production uses **Catchain**, a BFT consensus protocol with a shared-log foundation (see `doc/catchain.pdf`). Validators participate per workchain + shard; the masterchain provides global signing and handles validator-set rotation. TOS is actively converging elements of the protocol toward a **Simplex-oriented** design (see `doc/simplex.pdf`) for cleaner proof-of-progress guarantees.

### What contract teams get

- A TVM contract compiled from FunC (or TVM-targeting languages) with deterministic, byte-stable semantics.
- Asynchronous message flows that compose naturally with other actors.
- Shard-transparent addressing (the sender doesn't need to know which shard the recipient is on).
- Predictable gas, explicit bounce semantics (failed messages are returned to the sender with their balance intact), and standard TEP-style interfaces for tokens and application surfaces.

---

## EVM Workchain (workchain 1) — Synchronous, Ethereum-Compatible

The EVM workchain is a dedicated execution domain for **synchronous, Ethereum-semantic** smart contracts. Developers deploy unmodified Solidity contracts; existing Ethereum tooling works without patches.

### What's supported

- **Full EVM bytecode** — the contract execution engine is [`evmone`](third-party/evmone), the standards-compliant EVM used in production Ethereum clients. All EVM opcodes, precompiles, and semantics are available.
- **Standard Ethereum JSON-RPC** — `eth_sendRawTransaction`, `eth_call`, `eth_getBalance`, `eth_getTransactionReceipt`, `eth_getLogs`, `eth_subscribe`, and the rest of the core namespace are served directly by `validator-engine`. MetaMask, ethers.js, web3.py, Foundry, Hardhat, and Remix connect without adapters.
- **Synchronous call semantics** — `CALL`, `DELEGATECALL`, `STATICCALL`, and nested reverts behave exactly as on Ethereum. Contracts written for Ethereum's synchronous model run without re-architecture.
- **Standard transaction format** — RLP-encoded, secp256k1-signed, with the usual nonce / gas / value / data / v+r+s structure. Accounts are 20-byte keccak-derived addresses.

### How it fits into TOS

- **wc=1 is a first-class TOS workchain**, not a sidechain. It participates in the same masterchain consensus and shares validator economics with the rest of the network.
- **Cell-native state** — EVM account state (balance, nonce, code, storage) is stored as TOS cells and committed to the state root just like native contracts. This keeps the node's storage layer uniform.
- **Single executor per shard** — EVM execution on each wc=1 shard is serialized through one executor account to preserve Ethereum's sequential semantics while still benefiting from wc=1 sharding across disjoint account sets.
- **Cross-workchain value flow** — native ↔ EVM value transfers use the TOS message model (async from the native side, synchronous-entry from the EVM side). Uno (wc=2) does not participate; see the Uno section.

### What DeFi teams get

Existing Solidity codebases (ERC-20, ERC-721, ERC-4626, AMMs, lending protocols, governance frameworks) deploy as-is. The development loop is the standard Ethereum loop: write Solidity, test with Foundry, deploy via a wallet-signed RLP transaction, verify on an explorer. No custom toolchain fork. Design docs for the workchain are in `doc/evm-workchain-*.md`.

---

## Uno Workchain (workchain 2) — PQ-Native Privacy L1

Uno is a **post-quantum-native privacy Layer-1** on TOS wc=2. Its single-sentence positioning:

> **Privacy from inception, quantum-safe from inception, bridgeless by architecture.**

Uno is not a privacy mixer added on top of a public asset. It is a distinct native currency whose entire supply is born shielded at genesis and is **never** reachable through any public-asset pathway. Every transfer on wc=2 is a shielded note-pool transaction producing a Plonky3 STARK proof; on-chain data reveals only `{tx occurred, fee, anchor, spend count, output count}`.

### What makes it PQ-native

- **Proof system: Plonky3 STARK over the Goldilocks field (p = 2⁶⁴ − 2³² + 1)** — hash-based, transparent, no trusted setup, and post-quantum at v1 ship. There is no elliptic-curve discrete-log that Shor could break inside the proof system, and no mandatory Phase 2 proof-system migration. Every Halo2 / Groth16 / Varuna-based shielded chain carries that Phase 2 debt today; Uno does not.
- **In-circuit hash: Poseidon2** — Plonky3-native, constraint-efficient over Goldilocks. Consensus-binding FRI parameters: `log_blowup=2, num_queries=128, query_pow_bits=16`.
- **Note encryption: hybrid ECDH-Ristretto255 + ML-KEM-768** — closes the harvest-now-decrypt-later window at v1. An attacker who captures today's `enc_ciphertext` and waits for a CRQC (cryptographically relevant quantum computer) cannot decrypt without breaking ML-KEM, a 2030+ horizon under the most aggressive published forecasts.
- **Spend authorization: fresh per-spend Schnorr-on-Ristretto255** — each spend samples a one-time authorization key, so no long-term spend key is ever on-chain.
- **Key hierarchy: hash-native** — `fvk = (ivk, nk, ovk, sk_mlkem)`. No in-circuit curve operations. Ownership is proved via an `ivk`-commitment hash chain, not via a Pallas-style curve relation.

### What makes it bridgeless

No Shield, no Unshield, no bridge between wc=2 and any other workchain — **in v1, v2, or any later phase**. This is a **permanent architectural invariant**, not a scope decision. Reasons:

- A bridge's entry-side gas binding (the wc=0/wc=1 account that paid to shield is observable) and exit-side recipient binding (the wc=0 address that received an unshield is observable) re-introduce the deanonymization vectors that terminal privacy is meant to close. Empirically this is how Zcash t↔z flows have been deanonymized in the research literature.
- Uno's supply is fixed at genesis (21 M UNO, 60% airdrop / 25% treasury / 15% team), monotonically non-increasing (fees are burned in UNO), and entirely contained within wc=2.
- Validator compensation for wc=2 is paid in native TOS at the masterchain level, so the chain does not require a UNO inflation path to remain economically viable.

Users who want composable public liquidity hold public assets (native TOS, EVM-side ERC-20s). Users who want real privacy hold UNO.

### Architectural constants

- **Wire format**: 1..4 spends × 1..4 outputs per Transfer. PI length: `64 + 64·S + 72·O` bytes. Proofs ~52 KB typical / ~100 KB worst case (when the real Transfer AIR lands; the current MVP AIR is larger).
- **Merkle tree**: 32 levels (≈ 4 B-leaf cap), Poseidon2 internal nodes.
- **Anchor window**: 100 blocks.
- **Address size**: ~1.26 KB (carries the recipient's ML-KEM-768 public key); shared via QR code, deep link, or wallet DM. Addresses carry a Bech32m envelope with BLAKE3 checksum — wallets and RPC MUST reject malformed envelopes.
- **Validator hardware floor**: 4 physical cores / 16 GB RAM / 500 GB SSD / 200 Mbps symmetric. Client-side proving is the only compute-heavy step; validators only verify.

Full design in [`doc/uno-workchain.md`](doc/uno-workchain.md). Implementation under [`uno/`](uno/).

---

## Architecture principles

- **The node is the root of truth.** Public APIs come from `validator-engine`, not from fragmented sidecar stacks.
- **One operator path.** `tosctl` is the canonical CLI for node operation, wallet flows, and workchain-specific tooling.
- **Standards-first.** Wallet send / estimate / track semantics, RPC conventions, trust tiers, indexing and explorer surfaces are defined as standards, not as implementation artifacts.
- **Deterministic execution everywhere.** No wall-clock, no OS RNG, no HashMap iteration in any consensus-critical path — on all three workchains.
- **Cell-native state across the board.** TVM cells, EVM account state, and Uno shielded state all commit into TOS cells. The node's storage layer does not grow a new persistence mechanism per workchain.

---

## Ecosystem surfaces

- ✅ `validator-engine` serves JSON-RPC natively (Ethereum `eth_*` namespace on wc=1, TOS `tos_*` on wc=0, `uno_*` on wc=2)
- ✅ OpenAPI surface in [`doc/openapi.yaml`](doc/openapi.yaml)
- ✅ Canonical operator workflow through `tosctl`
- ✅ Health, readiness, metrics, and machine-facing node operations
- ✅ Wallet send, estimate, and track semantics documented as standards
- ✅ Standards map covering RPC, wallet, trust, indexing, operator, and application surfaces
- ✅ **TOS Connect** — wallet-to-dApp connection flows
- ✅ **TOS DNS** — on-chain name resolution
- ✅ **TOS Sites** — decentralized site hosting with RLDP HTTP proxy support
- ✅ ADNL, DHT, RLDP, QUIC, and validator networking stack
- ✅ Trust-tier and verification model for different client types
- ✅ Transaction history and indexed-data contracts for explorers and backends
- ✅ Token and application standardization work (TEP-style surfaces)
- ✅ Catchain-based consensus foundation with ongoing Simplex-oriented convergence work

---

## Build

Build instructions — including Uno workchain prerequisites (liboqs, corrosion-rs, Rust toolchain) — are in [`BUILD.md`](BUILD.md).

## Documentation

- **EVM workchain**: [`doc/evm-workchain-topology.md`](doc/evm-workchain-topology.md), [`doc/evm-workchain-cell-native-state.md`](doc/evm-workchain-cell-native-state.md), [`doc/evm-workchain-test-plan.md`](doc/evm-workchain-test-plan.md)
- **Uno workchain**: [`doc/uno-workchain.md`](doc/uno-workchain.md) (Draft v2, 45 locked decisions)
- **Consensus**: [`doc/catchain.pdf`](doc/catchain.pdf), [`doc/simplex.pdf`](doc/simplex.pdf)
- **RPC policy**: [`doc/json-rpc-policy.md`](doc/json-rpc-policy.md)
- **Cell / block theory**: `doc/tblkch.tex`, `doc/fiftbase.tex`, `doc/func_v0.4.6.pdf`

## License

This repository is licensed under the GNU General Public License v3.0. See [`LICENSE`](LICENSE).

TOS is built on top of foundational work originally developed by Telegram (TON), EverX, Erigon, and RSquad Blockchain Lab. The Uno workchain additionally builds on Polygon's Plonky3 toolkit, NIST PQC finalists (ML-KEM-768), and the Zcash Orchard specification family. This repository continues that line of work as its own system while explicitly acknowledging those prior technical foundations.
