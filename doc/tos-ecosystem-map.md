# Legacy Ecosystem Tools & Libraries Distribution Map

## TOS Consolidation View

Version 1.0 | Generated from ~/tos monorepo analysis | 2026-04

---

## Layer 6: Wallets & DApps

### Legacy Ecosystem (Fragmented)

| Project | Status |
|---------|--------|
| legacy web SDK | Independent repo, npm publish, version out of sync with node |
| legacy mobile wallet | Closed-source, independent dev, depends on hosted API service |
| connect protocol | Independent repo, independent versioning, each wallet implements differently |

### TOS (Consolidated)

- ✅ Compatible with existing wallets — no SDK modification needed
- ✅ Method names aligned with legacy web/API conventions, clients only need to change URL
- ✅ New `account.capability` API provides standardized capability discovery

---

## Layer 5: SDKs & Client Libraries

### Legacy Ecosystem (Fragmented)

| Library | Language | Issues |
|---------|----------|--------|
| legacy API SDK | JS/TS | Independent repo, depends on hosted API service, version fragmentation |
| Python SDK | Python | Independent repo, different maintainer, inconsistent API style |
| Go SDK | Go | Independent repo, custom serialization, self-managed compatibility |
| Kotlin SDK | Kotlin/JVM | Independent repo, update lag |

### TOS (Consolidated)

| Library | Language | Approach | Status |
|---------|----------|----------|--------|
| toscenter-rs | Rust | Vendored into monorepo, supply chain controlled, version synced with node | ✅ |
| pytosiq_core | Python | Vendored into monorepo, no external dependency, unified test coverage | ✅ |
| chain-rpc-client | Rust | Native Rust RPC client, used internally by tosctl, JSON output support | ✅ |

---

## Layer 4: Operations Tooling

### Legacy Ecosystem (Fragmented)

| Tool | Issues |
|------|--------|
| legacy ops controller (Python) | Independent repo/install, Python scripts patchwork, depends on system Python, no unified config, no daemon mode |
| Staking/Election scripts | Scattered across repos, manual validator ops, each implements own key management, no alerting, inconsistent docs |
| Monitoring & Keys | Prometheus self-configured, keys stored as raw files on disk, no Vault integration, no Telegram alerts |

### TOS (Consolidated)

**tosctl** — Rust CLI, single binary, 90 subcommands:

| Module | Capability | Status |
|--------|------------|--------|
| node-control | Node management (start/stop/status/logs/config) | ✅ |
| elections | Staking/elections/nomination pools (SingleNominator/NominatorPool/Liquid) | ✅ |
| contracts | Contract deployment and interaction wrappers | ✅ |
| secrets-vault | Key management (file + HashiCorp Vault backend) | ✅ |
| daemon | Daemon process + Telegram/Webhook alerting | ✅ |
| JSON output | 15 commands support --json, consumable by CI/CD | ✅ |

---

## Layer 3: API Layer (Query & Submit)

### Legacy Ecosystem (Fragmented — 3+ independent paths)

| API Server | Issues |
|------------|--------|
| HTTP API service (Python) | Independent repo/process, requires Python runtime, needs liteserver connection, hosted API service, version out of sync, extra ops burden |
| commercial API | Closed-source SaaS, richer features but paid, vendor lock-in risk, not self-hostable, different API style |
| HTTP API C++ service (3rd party) | Third-party C++ impl, independent compile/deploy, needs liteserver, extra process, maintained independently |

### TOS (Consolidated — embedded in validator-engine)

**JSON-RPC Server** — 35 methods, embedded, zero external dependencies:

| Domain | Methods | Status |
|--------|---------|--------|
| accounts | 6 methods (getAddressInfo/Wallet/Balance/State/TokenData) | ✅ |
| blocks | 8 methods (getMasterchainInfo/lookupBlock/shards/signatures) | ✅ |
| transactions | 5 methods (getTransactions/tryLocate*/BlockTxExt) | ✅ |
| send | 5 methods (sendBoc/ReturnHash/NoError/sendQuery/estimateFee) | ✅ |
| runmethod + config + utils | 11 methods | ✅ |
| Infrastructure | REST GET + POST + OpenAPI 3.1 + Prometheus + API Key + Response cache | ✅ |

---

## Layer 2: Node / Validator

### Legacy Ecosystem

| Component | Issues |
|-----------|--------|
| validator-engine (C++) | Independent compile, no embedded API, must run external API process |
| lite-client + console | Command-line query tool + control console, limited automation support |

### TOS (Consolidated)

| Component | Approach | Status |
|-----------|----------|--------|
| validator-engine (C++, embedded JSON-RPC) | Consensus (Catchain BFT) + block execution + Liteserver + embedded JSON-RPC — single process, no external API needed | ✅ |
| blockchain-explorer | HTTP block explorer | ✅ |
| lite-client + console | Query tool + console, tosctl replaces most use cases | ✅ |

---

## Layer 1: Protocol & VM & Smart Contracts

### Legacy Ecosystem (C++ only)

| Component | Issues |
|-----------|--------|
| TVM (C++) | Only C++ implementation |
| block (C++) | Only C++ implementation |
| crypto (C++) | Only C++ implementation |
| FunC compiler (C++) | Only C++ implementation |
| emulator (C++ FFI) | Transaction emulation requires C++ library call, WASM available but poor performance, mobile/browser integration difficult, no pure Rust/Go/Python alternative |

### TOS (Dual-stack: C++ + Rust)

**C++ Stack (native):**

| Module | Purpose | Status |
|--------|---------|--------|
| crypto/ | Cryptographic primitives | ✅ |
| vm/ | TVM virtual machine | ✅ |
| block/ | Block format | ✅ |
| emulator/ | Transaction emulation | ✅ |
| tolk/ | New compiler | ✅ |
| catchain/ | Consensus protocol | ✅ |

**Rust Stack (86K lines ported, inside tosctl):**

| Module | Purpose | Status |
|--------|---------|--------|
| vm/ | TVM interpreter | ✅ |
| executor/ | Transaction executor | ✅ |
| assembler/ | TVM assembler | ✅ |
| emulator/ | Rust emulator | ✅ |
| block/ | Block parsing | ✅ |
| sandbox/ | Local chain simulator | ✅ |

---

## Layer 0: Network Transport

### Legacy Ecosystem

- ADNL + RLDP + DHT — C++ only, no standalone library for other languages

### TOS (Consolidated)

- ✅ ADNL (C++ + Rust dual implementation) + RLDP/RLDP2 + DHT + QUIC + FEC
- ✅ Rust ADNL enables tosctl to perform P2P communication independently

---

## Summary: Key Differences

| Dimension | Legacy Ecosystem | TOS Consolidated | Status |
|-----------|---------------|------------------|--------|
| API Layer | 3+ independent projects (hosted API / commercial API / C++) | Embedded in validator-engine, single process | ✅ |
| Ops Tooling | legacy Python ops controller + scattered scripts | tosctl (Rust, 90 commands, single binary) | ✅ |
| SDKs | Each language in independent repo, versions diverge | Vendored (toscenter-rs/pytosiq), supply chain controlled | ✅ |
| Virtual Machine | C++ only | C++ + Rust dual-stack (86K lines) | ✅ |
| Permission Model | None (wallets guess) | account.capability + role separation (planned) | 🔧 In progress |
| Repo Structure | 10+ independent repos | 1 monorepo | ✅ |
| Deploy Complexity | Node + API + ops tools deployed separately | validator-engine single process + tosctl | ✅ |
