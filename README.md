# The Open System

**The Open System (TOS)** is a multichain Layer‑1 that defines four distinct execution domains over a single masterchain-rooted consensus. The default node binary carries Native + EVM + Uno; the JVM engine is a build-time opt-in (it needs a Java toolchain). The network **launches with the Native chain (wc=0)** and **stages in the others by governance** as they harden — no redeploy.

| Workchain | Execution model | What it's for | Launch status |
|---|---|---|---|
| **Native (wc=0)** | **Asynchronous**, message-driven, TVM | High-throughput contracts, sharded scale, actor-style async flows | **Live at genesis** |
| **EVM (wc=1)** | **Synchronous**, EVM bytecode | Solidity / Ethereum-compatible contracts, wallet-compatible DeFi | Implemented — staged activation |
| **Uno (wc=2)** | **PQ-native privacy**, Plonky3 STARK AIRs | Shielded payments; quantum-safe and bridgeless by architecture | Implemented — staged activation |
| **JVM (wc=3)** | **Deterministic Java 8 bytecode**, Avata JVM | Account-autonomous Java smart contracts | Implemented — build-time opt-in (`-DTOS_ENABLE_JVM=ON`) |

One node binary (`validator-engine`) serves the workchains: each compiled-in engine is **dormant until a workchain descriptor in `ConfigParam 12` routes traffic to it**. The Native, EVM, and Uno engines are compiled in by default; the JVM engine is gated behind `-DTOS_ENABLE_JVM=ON` at build time (off by default, since `rt.jar` needs `javac`). The canonical genesis ([`crypto/smartcont/gen-zerostate.fif`](crypto/smartcont/gen-zerostate.fif)) ships with wc=0 alone; EVM and Uno are then switched on by a `ConfigParam 12` governance update with no binary change, while wc=3 additionally requires validators to run a JVM-enabled build. (The all-in-one four-chain template lives at [`gen-zerostate-allchains.fif`](crypto/smartcont/gen-zerostate-allchains.fif) and is not launch-ready.)  One canonical JSON-RPC surface, one operator path (`tosctl`), one wallet flow. Users choose their execution domain per transaction; validators opt in per workchain.

---

## Why four domains?

Different workloads want different trade-offs. TOS does not try to fit them into one VM.

- **Throughput and scale** are solved by TVM's asynchronous message passing + horizontal sharding (the TOS native design). The native layer is where 100K+ TPS is realistic, and where contract-to-contract message fan-out is cheap.
- **Developer familiarity and the Ethereum tool stack** are solved by running a real EVM as a separate workchain. Solidity contracts deploy as-is; MetaMask, ethers.js, Remix, and Foundry talk to wc=1 through standard JSON-RPC without modification.
- **Terminal privacy and post-quantum safety** require a protocol-level commitment, not a bolt-on. Uno is a native (not bridged, not retrofitted) privacy chain built on a hash-based STARK proof system — post-quantum at ship, with no Phase 2 migration debt.
- **Deterministic, audit-friendly application logic in a mainstream language** is served by the JVM workchain: contracts are Java 8 bytecode run on a restricted, JIT-free Avata interpreter, so existing JVM tooling applies while consensus-grade determinism is preserved.

Each workchain keeps its own invariants. The masterchain provides shared consensus and global time. There is **no bridge between Uno (wc=2) and any other workchain** — this is an architectural property, not a roadmap item; see the Uno section.

---

## Native Layer (workchain 0) — Asynchronous, Sharded, TVM

The native layer is the TOS native architecture: an actor-style, message-driven execution model that scales horizontally through dynamic sharding.

### Execution model

Every account on wc=0 is an **actor**. A contract call is an **asynchronous message** delivered to an actor's inbox; execution reads the message, mutates local state, and can emit zero or more outbound messages. There are no synchronous cross-contract calls — two contracts interact by passing messages. The TVM (TOS Virtual Machine) executes contract bytecode per message, with:

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

Block production runs **Simplex** — a fast, leader-driven consensus (see `doc/simplex.pdf`) — as the **primary** path, with **Catchain** BFT (a shared-log protocol, see `doc/catchain.pdf`) retained as a conservative Byzantine fallback. The leader produces blocks continuously without waiting for full BFT voting; notarization is asynchronous. Validators participate per workchain + shard; the masterchain provides global signing and handles validator-set rotation. The active profile is selected on-chain (`ConfigParam 30` carries the Simplex config, `ConfigParam 29` the Catchain fallback).

### What contract teams get

- A TVM contract compiled from FunC (or TVM-targeting languages) with deterministic, byte-stable semantics.
- Asynchronous message flows that compose naturally with other actors.
- Shard-transparent addressing (the sender doesn't need to know which shard the recipient is on).
- Predictable gas, explicit bounce semantics (failed messages are returned to the sender with their balance intact), and standard TEP-style interfaces for tokens and application surfaces.

---

## EVM Workchain (workchain 1) — Synchronous, Ethereum-Compatible

The EVM workchain is a dedicated execution domain for **synchronous, Ethereum-semantic** smart contracts. Developers deploy unmodified Solidity contracts; existing Ethereum tooling works without patches.

> **Launch status: implemented, staged activation.** The `evmone` engine ships in the node binary and stays dormant until wc=1 is added to `ConfigParam 12`. A wc=0-only genesis omits it; governance activates wc=1 when the EVM domain is ready.

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

> **Launch status: implemented, staged activation.** The STARK verifier (Plonky3 + ML-KEM via liboqs) ships in the node binary and stays dormant until wc=2 is added to `ConfigParam 12`. "Genesis" above refers to the wc=2 chain's own genesis state, established when governance activates the workchain — a wc=0-only launch omits it.

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

- **Wire format**: 1..4 spends × 1..4 outputs per Transfer. PI length: `64 + 64·S + 72·O` bytes. The real Poseidon2 Transfer AIR is implemented; v1 proofs are ~520 KB typical (1-spend/2-output) / ~915 KB worst case (4/4) under the pinned FRI Option B parameters. The original ~52 KB / ~100 KB design target is deferred to a post-v1 `uni-stark → batch-stark` AIR rearchitecture.
- **Merkle tree**: 32 levels (≈ 4 B-leaf cap), Poseidon2 internal nodes.
- **Anchor window**: 100 blocks.
- **Address size**: ~1.26 KB (carries the recipient's ML-KEM-768 public key); shared via QR code, deep link, or wallet DM. Addresses carry a Bech32m envelope with BLAKE3 checksum — wallets and RPC MUST reject malformed envelopes.
- **Validator hardware floor**: 4 physical cores / 16 GB RAM / 500 GB SSD / 200 Mbps symmetric. Client-side proving is the only compute-heavy step; validators only verify.

Full design in [`doc/uno-workchain.md`](doc/uno-workchain.md). Implementation under [`uno/`](uno/).

---

## JVM Workchain (workchain 3) — Deterministic Java Smart Contracts

The JVM workchain runs **Java 8 bytecode smart contracts** on **Avata**, a C++ JVM that TOS forks and owns (the upstream project is retired). It targets developers who want a mainstream language and JVM tooling without giving up consensus-grade determinism.

> **Launch status: implemented, build-time opt-in + staged activation.** The engine, RPC namespace, gas model, config parameters, and operator tooling are all wired into `validator-engine`, but the JVM is the one domain that is **off by default at build time** — it builds only with `-DTOS_ENABLE_JVM=ON`, because its `rt.jar` runtime needs a Java 8 JDK (`javac`); see [`BUILD.md`](BUILD.md). A JVM-enabled binary then keeps wc=3 dormant until it is added to `ConfigParam 12`, and JVM carries two extra activation gates beyond the other domains: its runtime hash (`stdlib_hash` in ConfigParam 85) and its genesis wallet/deployer set must be pinned first. See [`doc/jvm/jvm-mainnet-activation.md`](doc/jvm/jvm-mainnet-activation.md).

### Execution model

- **Account-autonomous topology.** Every Java contract is its own real wc=3 account with a 256-bit deterministic address — there is no singleton executor and no shared class store. A contract's address is derived at deploy time from a nested-sha256 commitment over the deployer, salt, init args, class hash, and method-manifest root, so the deployed code and method set are bound into the address.
- **Restricted, deterministic profile.** Interpreter-only (no JIT/AOT), deterministic SoftFloat floating point, no `invokedynamic`, no mutable static fields (only `static final` constants), and no host I/O, threads, wall-clock, or OS entropy. This is what keeps replay byte-identical across validators and platforms (verified identical on x86_64 and Apple Silicon).
- **Constrained persistence.** Only explicit `java.lang.Persistent*` containers (`Storage`, `Mapping`, `PersistentMap`, `PersistentList`) survive a call; the transaction heap is discarded at the boundary. Persisted state commits into TOS cells like every other workchain — the contract's `storage_root` is the only mutable field of its state cell.

### Runtime and consensus binding

- **`rt.jar` / `api.jar`** provide the contract standard library (`java.lang.*` plus TOS-specific `Context`, `Storage`, `Event`, `ABI`, `Crypto`, `ContractCall` APIs).
- **`stdlib_hash`** binds the exact runtime bytes into consensus via ConfigParam 85. Validators reject any inbound call whose `stdlib_hash` does not match the network's pinned value, so the runtime is reproducible by construction (a CI job verifies byte-identical rebuilds of `rt.jar`).

### Interfaces and limits

- **RPC namespace** served directly by `validator-engine`: `jvm_deployContract`, `jvm_callContract`, `jvm_getContractState`, `jvm_getReceipts`.
- **Operator tooling** via `tosctl` JVM wallet subcommands (key/address generation, state queries; deploy/execute flows depend on genesis seeding).
- **DoS-hardened resource limits**: `max_gas_per_tx = 1M`, `max_heap = 4 MiB`, `max_class_bytes = 64 KiB`, `max_storage_cells = 65536`, `max_outbound_actions = 12`, bounded RPC receipt scans.

Design and operations are documented under [`doc/jvm/`](doc/jvm/): [`jvm-v2-account-topology.md`](doc/jvm/jvm-v2-account-topology.md), [`jvm-rt.md`](doc/jvm/jvm-rt.md), [`jvm-rt-reproducibility.md`](doc/jvm/jvm-rt-reproducibility.md), [`jvm-mainnet-activation.md`](doc/jvm/jvm-mainnet-activation.md), [`jvm-validator-ops.md`](doc/jvm/jvm-validator-ops.md), [`jvm-profile.md`](doc/jvm/jvm-profile.md), [`jvm-wallet.md`](doc/jvm/jvm-wallet.md), and [`jvm-dos-hardening.md`](doc/jvm/jvm-dos-hardening.md). Implementation under [`jvm/`](jvm/).

---

## Architecture principles

- **The node is the root of truth.** Public APIs come from `validator-engine`, not from fragmented sidecar stacks.
- **One operator path.** `tosctl` is the canonical CLI for node operation, wallet flows, and workchain-specific tooling.
- **Standards-first.** Wallet send / estimate / track semantics, RPC conventions, trust tiers, indexing and explorer surfaces are defined as standards, not as implementation artifacts.
- **Deterministic execution everywhere.** No wall-clock, no OS RNG, no HashMap iteration in any consensus-critical path — on all four workchains.
- **Cell-native state across the board.** TVM cells, EVM account state, Uno shielded state, and JVM contract state all commit into TOS cells. The node's storage layer does not grow a new persistence mechanism per workchain.

---

## Ecosystem surfaces

- ✅ `validator-engine` serves JSON-RPC natively (Ethereum `eth_*` namespace on wc=1, TOS `tos_*` on wc=0, `uno_*` on wc=2, `jvm_*` on wc=3)
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
- ✅ Simplex fast leader-driven consensus (primary) with Catchain BFT fallback

---

## Build

Build instructions — including Uno workchain prerequisites (liboqs, corrosion-rs, Rust toolchain) and JVM workchain prerequisites (openjdk-8 for the `rt.jar` runtime) — are in [`BUILD.md`](BUILD.md).

## License

This repository is licensed under the GNU General Public License v3.0. See [`LICENSE`](LICENSE). Third-party components, modifications, and foundational acknowledgments are catalogued in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
