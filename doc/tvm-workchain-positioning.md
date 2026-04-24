# TVM Workchain — Strategic Positioning

A first-principles analysis of why TOS maintains a TVM workchain alongside
the EVM workchain, and what that means for FunC investment.

---

## TL;DR

TOS runs two workchains side by side: **EVM** (Solidity, Chain ID
`0x544F53`) and **TVM** (FunC, workchain 0 and -1). With the EVM
workchain already offering the full Ethereum developer experience —
MetaMask, Hardhat, Foundry, ethers.js, OpenZeppelin — any investment
in rebuilding the same application libraries in FunC duplicates what
users can already get by deploying Solidity on the other workchain.

The strategic conclusion: **TVM workchain enters maintenance mode**.
It stays stable, stays available, and retains the six differentiated
capabilities that only it can offer (account abstraction,
asynchronous messaging, sharding, cell storage, system contracts,
cross-workchain bridges) as **latent invitation**, not active
framework-building.

**Positioning:**

- **EVM workchain** — the default target for standard DeFi, NFTs,
  DAOs, bridges, and any application that an OpenZeppelin import
  can solve. Ethereum tooling works unchanged.
- **TVM workchain** — the systems layer, with infrastructure
  (wallet / elector / DNS contracts, `stdlib.fc`, `func`/`fift`
  compilers, TVM node) kept stable. Six latent differentiators
  (see §2) wait for builders who actively need them. No proactive
  framework / library construction.
- **FunC** — stable legacy language. No upgrade planned. No new
  stdlib families. Security + fixes only.

---

## 1. The Dual-Workchain Landscape

| Dimension | EVM workchain (wc=1) | TVM workchain (wc=0, -1) |
|---|---|---|
| Source language | Solidity (EVM Shanghai) | FunC (compiled via `func` → Fift → TVM bytecode) |
| Chain ID | `5525331` (`0x544F53`) | Masterchain = -1, Basechain = 0 |
| Developer tooling | MetaMask, Hardhat, Foundry, Remix, ethers.js | Hand-rolled FunC + Fift scripts |
| Standard contract libraries | `@openzeppelin/contracts@latest` | Custom per-project today |
| Execution model | Synchronous calls, reentrancy-aware | Asynchronous messages, bounce-aware |
| Account model | EOA vs contract account distinction | Every account is a contract |
| Storage model | 32-byte slots, addressed by keccak | Cell trees, content-addressed |
| Sharding | Not native | Native, automatic on basechain |
| State rent | Pay-once gas for storage | Storage rent over lifetime |

EVM workchain is production-ready for any developer who already knows
Ethereum. A new user who wants ERC-20, ERC-721, an AMM, a multisig, or
a governor contract can deploy the relevant OpenZeppelin contract on
the EVM workchain today with zero additional tooling on our side.

This raises a fair question: **what is the TVM workchain for?**

---

## 2. First-Principles: Why Keep TVM Workchain At All?

If the TVM workchain only replicates EVM's capabilities with a
different VM and a harder language (FunC), it is redundant. The
honest answer is that TVM has specific capabilities EVM does not,
and its value is concentrated in applications that lean on those
capabilities.

### 2.1 Account is a contract (native account abstraction)

On EVM, an external account (EOA) is a keypair and a contract account
is separate bytecode. Wallets are EOAs. Smart wallets ride on top via
ERC-4337, which is a protocol-layer workaround.

On TVM, **every address is a contract**. Wallets, tokens, exchanges —
all the same primitive. This enables, natively and without any
external infrastructure:

- Social recovery wallets
- Session keys and sub-key delegation
- Fee delegation (gasless UX — a third party pays the gas)
- Meta-transactions
- Multisig as a first-class wallet, not a workaround
- Per-user subscription contracts

Anything that would require ERC-4337 bundlers, paymasters, and
entry-point contracts on Ethereum is ambient on TVM.

### 2.2 Asynchronous message passing

EVM calls are synchronous: contract A calls B; B's state changes
complete before A's code continues. This introduces reentrancy as a
persistent attack surface.

TVM messages are asynchronous: contract A sends a message; the next
transaction (possibly on another shard, possibly after a delay)
delivers it to B. Reentrancy in the EVM sense doesn't exist. Instead,
new patterns become expressible:

- Saga workflows (multi-step, rollback on failure)
- Scheduled / recurring messages
- Long-running governance (propose → voting window → auto-execute)
- Request-response with bounce (error-path routing)
- Time-delayed callbacks

### 2.3 Native sharding

EVM L1 is serial. TVM basechain automatically shards: high-volume
dApps can effectively occupy their own shard, with masterchain
coordinating cross-shard references.

Applications that benefit:

- Order-book exchanges, game state, social-graph platforms where
  shardable user state is the norm.
- Systems that would hit EVM's single-chain throughput ceiling.

### 2.4 Cell-based storage

EVM storage is 32-byte slots indexed by `keccak(slot_id)`. TVM
storage is a tree of cells (up to 1023 bits of data + 4 child refs
per cell), content-addressed.

Implications:

- Identical sub-trees are deduplicated automatically (Merkle DAG).
- Cross-shard proofs are cheap — a cell hash is all you need.
- Efficient for NFT images, archive data, inscriptions.
- Per-field storage rent maps naturally to lifetime state costs.

### 2.5 System contracts

EVM L1 keeps consensus, validator selection, and configuration in
the client binary. TVM does it in smart contracts: elector,
config-params, masterchain governance. These contracts MUST be
written in FunC — it's the only way to author them.

### 2.6 Cross-workchain bridges

A TOS-unique capability is having both VMs in the same L1 with
cross-workchain messaging. An asset bridge between TVM and EVM
workchains lives inside the protocol, not as a third-party bridge.
This is structurally simpler, trust-minimized, and a competitive
differentiator for TOS over chains with only one VM.

---

## 3. The Strategic Mistake: Rebuilding OpenZeppelin in FunC

Earlier we discussed building a FunC-native OpenZeppelin equivalent:
Jetton (ERC-20 analogue), NFT, Vault (ERC-4626 analogue), AMM,
Staking, Governor, Multisig. Every item on that list already exists
for Solidity, battle-tested, audited, and would deploy on the EVM
workchain unchanged.

By investing in the FunC equivalents, we would:

1. Spend months delivering what the EVM workchain already offers.
2. Compete with our own EVM workchain for developer mind-share.
3. Present new developers with a harder-to-learn version of the
   same functionality.
4. Ship unaudited clones of code that has taken years to audit on
   the Ethereum side.

A commercial user wanting a token does not care which workchain it
runs on. They will go where it's easier. If both options work, the
familiar one wins. That's the EVM workchain.

The honest reading: **any marginal FunC-application-library work
subtracts from the clarity of TOS's value proposition**.

---

## 4. TVM Workchain Enters Maintenance Mode

Given that EVM workchain owns general-purpose contract territory, a
natural next question is: "what proactive work should we do on the
TVM side?"

The honest first-principles answer: **nothing**.

The differentiated capabilities listed in §2 (account abstraction,
async messaging, sharding, cell storage, system contracts, cross-
workchain bridges) are real, but none of them have a present-day user
driving the need for framework-level tooling. Proactively building
"wallet frameworks", "bridge primitives", "async workflow libraries",
or "sharding-aware templates" would create tools for hypothetical
users who may never materialise — a classic builder's-syndrome
anti-pattern.

Instead, TVM workchain enters maintenance mode:

### 4.1 What maintenance mode means

**Keep running:**
- TVM node code — security patches, performance tuning, crash fixes
- Existing system contracts (elector, config-params, DNS, wallet
  variants) — bug fixes, required policy changes
- `stdlib.fc` — security patches only, no feature additions
- Existing `crypto/smartcont/` contracts — dependency bumps,
  regression fixes
- `func` + `fift` compiler binaries — minimal maintenance; they
  are stable legacy tools

**Do not build:**
- FunC equivalents of OpenZeppelin contracts (Jetton / NFT / Vault
  / AMM / Governor / Multisig-as-app-contract) — these exist on the
  EVM workchain.
- `mapping` type syntax sugar or other FunC language extensions —
  the language is adequate for its narrow remaining mission;
  compiler energy is better spent elsewhere (or not spent at all).
- `stdlib.fc` DeFi wrapper families (`std_typed_dict.fc`, etc.) —
  speculative ergonomic sugar, no pain point driving the demand.
- Wallet framework / session-key libraries / social-recovery
  primitives — existing wallet contracts (wallet-v3/v4/v5,
  highload-wallet, session-wallet, restricted-wallet) cover the
  realistic use cases. Wallet projects fork them as needed.
- Cross-workchain bridge infrastructure — premature until a
  concrete TVM-native application has assets worth bridging out.
  Chicken-and-egg: bridge value follows application value, not
  vice versa.
- Async workflow library (saga / timeout / callback templates) —
  hypothetical users only.
- Sharding-aware templates — TOS traffic is nowhere near the
  thresholds where basechain auto-sharding activates in practice.
- FunC language upgrade (v0.5.0 / v0.6.0) — already retired; the
  archived `func-v0.5.0` branch and its documents are gone.
- Rewriting `func` or `fift` in Rust — TOS Rust's precedent (they
  rewrote node/TVM/emulator in Rust but left FunC and Fift alone)
  stands as the right judgement. These are stable legacy C++
  binaries that can sit untouched for years.

### 4.2 Reactive work is welcome

Maintenance mode is not "frozen." When a concrete, named need
surfaces — a specific project asking for X, a security issue
requiring Y, a policy change requiring a system-contract
amendment — that work is appropriate.

The default stance shifts from "what should we proactively build?"
to "what actual request is on the table?" Absent such a request,
TVM-side effort is zero.

### 4.3 The six capabilities remain the differentiation story

§2's list of six things TVM can do that EVM cannot is still the
narrative reason TOS carries two workchains. The shift is that
those capabilities become **latent differentiators** rather than
active construction projects — available to anyone who wants to
build a TVM-native application, but not prematurely packaged into
frameworks by us.

If and when a team decides to build (for example) a novel
account-abstraction wallet or a cross-workchain bridge, the TVM
primitives will be there to support them. The stdlib and existing
system contracts are the raw material; no pre-built "framework"
is needed beyond what already ships.

---

## 5. `tosctl` Positioning

`tosctl` stays the operator + generic SDK tool. Its scope:

- Validator operations (nodes, wallets, pools, elections, voting)
- Key management + vault integration
- Generic contract operations: `deploy contract`, `account
  run-method`, `account send-boc`
- TVM assembler + emulator + executor crates (already shipped)

`tosctl` does NOT grow application-specific subcommands such as
`tosctl jetton`, `tosctl nft`, `tosctl bridge`, `tosctl amm`, etc.

- DeFi-style applications live on the EVM workchain; users interact
  with them via Hardhat / Foundry / ethers.js.
- Hypothetical TVM-native applications (bridges, specialised
  wallets, async workflows) do not yet exist and should not be
  pre-empted by CLI surface area.

The principle is the same as for FunC: avoid building tooling for
users who are not yet present. When a concrete TVM-native project
lands and needs operational tooling, adding a targeted subcommand
at that point is reactive and appropriate.

---

## 6. Developer Messaging

A clear story for anyone landing on TOS documentation:

> **Want to build a standard DeFi app, token, NFT collection, DAO,
> or anything your EVM experience covers?**
> Deploy to the EVM workchain. Use Solidity, Hardhat, MetaMask,
> OpenZeppelin. Everything works exactly as it does on Ethereum.
>
> **Want to build a TVM-native application that leans on one of
> the six differentiators — native account abstraction,
> asynchronous messages, sharding, cell storage, system contracts,
> cross-workchain bridges?**
> The TVM workchain is there, with its base infrastructure
> (`crypto/smartcont/`, `stdlib.fc`, TVM node, `func`/`fift`
> compilers). Existing wallet / elector / DNS contracts are
> useful starting points. Expect to build on raw primitives; we
> do not ship a TVM application framework.

The dual-workchain architecture becomes a **benefit**: it gives
developers a choice based on what they're actually building, not a
confusion about which to pick. It also sets expectations
correctly: the EVM side is a fully-stocked developer experience;
the TVM side is a systems-level environment where unique
capabilities are raw material for builders who want them.

---

## 7. Anticipated Questions

### "So will TVM workchain have no ERC-20?"

Correct. Developers wanting an ERC-20 deploy on the EVM workchain.
If someone builds an account-abstracted holder pattern on TVM — where
each holder's wallet natively tracks the token balance without a
separate token-wallet sub-contract — that would lean on TVM's unique
capabilities, but nobody is building it, and we are not going to
pre-build the framework either.

### "Won't everyone just use the EVM workchain then?"

Most users will, and that is the right outcome. The TVM workchain
exists for the rare application whose value depends on one of the
six differentiators. Until such an application shows up, it's fine
for the TVM side to look quiet from the outside.

### "Then why have a TVM workchain at all?"

Six latent capabilities EVM cannot match natively: account
abstraction, asynchronous messaging, sharding, cell storage, system
contracts, cross-workchain bridges. These capabilities are properties
of the VM and the protocol layer — they exist whether or not we
build frameworks around them.

An earlier draft of this document argued we SHOULD actively
invest in turning those capabilities into frameworks. A harder
first-principles pass corrected that: building frameworks for
hypothetical users is the wrong move. The capabilities stand as
**invitation**, not as construction backlog. When someone decides
to exploit one of them, the primitives in `crypto/smartcont/` +
`stdlib.fc` + the TVM itself are there.

### "Does this mean FunC development stops?"

Effectively yes, for new feature work. FunC stays in maintenance
mode: security patches, required fixes, nothing else. The archived
v0.5.0 upgrade is gone; no v0.6.0 is planned. `func` and `fift`
binaries stay as they are — stable, boring, functional.

### "What about existing FunC contracts in `crypto/smartcont/`?"

They stay. They're the base system: wallets (v3 / v4 / highload /
restricted / session), elector, config-params, DNS. They're the
protocol layer, not application examples. They'll see reactive
updates when specific bugs or policy changes require them, and
nothing else.

### "What if a team comes to us wanting to build a TVM-native dApp?"

Welcome. Point them at `crypto/smartcont/` as reference, `stdlib.fc`
as the primitive set, and `tosctl deploy contract` + `account
run-method` + `account send-boc` as the generic deployment /
interaction path. If specific tooling gaps surface during their
build, that's a reactive trigger to fill that specific gap —
narrower and more useful than any framework we would have invented
up front.

---

## 8. Decision Record

This document records the strategic position. Three concrete
decisions follow from it:

1. **Do not ship a FunC OpenZeppelin equivalent.** No
   `crypto/smartcont/tos-oz/`. No `std_typed_dict.fc` for
   DeFi-style mappings. No FunC Jetton / NFT / Vault / AMM.
   Point users at the EVM workchain for those.

2. **Do not extend FunC the language.** The archived
   `func-v0.5.0` work stays archived. No v0.6.0. No `mapping`
   keyword. No `func` → BOC direct-emit project. No Rust
   reimplementation of `func` or `fift`. These are stable legacy
   tools.

3. **TVM workchain is in maintenance mode.** No proactive
   framework / stdlib / library construction. Security patches,
   required bug fixes, and policy-driven system-contract changes
   only. New work is strictly reactive to concrete, named requests
   from specific projects.

The EVM workchain continues on its own track (see
`doc/evm-workchain-*.md` series) and absorbs general-purpose
smart-contract development. This document is about what the TVM
side does with its existence — which, for now, is stay stable,
stay available, and wait for applications whose need for its
unique capabilities is strong enough to drive specific requests.
