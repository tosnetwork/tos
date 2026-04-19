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

The strategic conclusion: **TVM workchain should specialise in what
EVM cannot do**, not compete with it on standard smart-contract
territory.

**Positioning:**

- **EVM workchain** — the default target for standard DeFi, NFTs,
  DAOs, bridges, and any application that an OpenZeppelin import
  can solve. Ethereum tooling works unchanged.
- **TVM workchain** — the differentiated layer for native account
  abstraction, asynchronous message workflows, sharded applications,
  cell-optimised storage, system contracts, and cross-workchain
  infrastructure.
- **FunC** — the TVM systems language, kept minimal and oriented
  toward what only TVM can express. Not an application-layer library
  platform.

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

## 4. Where FunC Investment Should Go

With the recognition that EVM workchain owns general-purpose
smart-contract territory, FunC's job becomes to make TVM workchain's
unique capabilities first-class.

### P0 — Highest leverage

**P0-1: Wallet Framework**

The single biggest win for TOS users. Account abstraction is ambient
on TVM; a good stdlib surfaces it.

```
crypto/smartcont/tvm-native/wallet/
├── WalletBase.fc          — account-abstraction primitive
├── SessionKey.fc          — time-bounded subkeys
├── SocialRecovery.fc      — N-of-M guardian recovery
├── FeeDelegation.fc       — sponsored transactions / gasless UX
├── SubscriptionWallet.fc  — scheduled recurring payments
└── MultisigWallet.fc      — multi-owner wallet (not external contract)
```

These aren't "nice to have" — they're what dApp wallets need to
offer modern UX. EVM can't easily do them; TVM can naturally.

**P0-2: Cross-workchain bridge**

The killer protocol-level feature only TOS can offer: TVM ↔ EVM
inside one L1.

```
crypto/smartcont/tvm-native/bridge/
├── TVMAssetLock.fc        — TVM-side asset lock / unlock
├── MessagePassing.fc      — cross-workchain message envelope
├── ProofVerifier.fc       — masterchain proof verification
└── (Solidity side)        — EVM gateway contract (in evm/)
```

Done right, users transfer value between workchains in one UX flow.
No external bridge. No third-party custody.

**P0-3: System contracts**

Elector, config-params, masterchain governance. Existing system
contracts are in FunC; this is where FunC's seriousness matters most.
Future work on validator economics, slashing, governance evolution
lives here.

### P1 — Differentiated application primitives

**P1-1: Async workflow library**

Patterns that only make sense on TVM:

- Saga with rollback
- Message timeout + bounce routing
- Deadline + callback scheduling
- Two-phase commit across contracts

**P1-2: Sharding-aware frameworks**

- Per-user shard allocation patterns
- Cross-shard state synchronisation utilities
- Shardable order book / game state templates

### What FunC investment should NOT fund

- FunC equivalents of OpenZeppelin contracts (Jetton / NFT / Vault /
  AMM / Governor / Multisig-as-app-contract / etc.) — these exist
  on EVM workchain.
- `mapping` type syntax sugar — ergonomic improvement, zero new
  capability; `stdlib.fc` dict primitives already express every
  TVM storage pattern.
- FunC language upgrade (v0.5.0 / v0.6.0) — the language is adequate
  for its new systems-level mission; compiler energy is better
  spent elsewhere.
- `crypto/smartcont/tos-oz/` or similar "OpenZeppelin clone"
  directory — we will not ship this.

---

## 5. `tosctl` Positioning

`tosctl` stays the operator + SDK tool. Its scope:

- Validator operations (nodes, wallets, pools, elections, voting)
- Key management + vault integration
- Generic contract operations: `deploy contract`, `account
  run-method`, `account send-boc`
- TVM assembler + emulator + executor (already shipped)
- Bridge operations (new, tied to P0-2)
- Wallet-framework interactions (new, tied to P0-1)

It should NOT grow application-specific subcommands like `tosctl
jetton` or `tosctl nft`. Users writing DeFi apps against the EVM
workchain use Hardhat / Foundry / ethers.js. `tosctl` is for
TVM-native operations and cross-workchain glue.

---

## 6. Developer Messaging

A clear story for anyone landing on TOS documentation:

> **Want to build a standard DeFi app, token, NFT collection, DAO,
> or anything your EVM experience covers?**
> Deploy to the EVM workchain. Use Solidity, Hardhat, MetaMask,
> OpenZeppelin. Everything works exactly as it does on Ethereum.
>
> **Want to exploit TOS's unique capabilities — native account
> abstraction, sharded applications, asynchronous workflows, or
> cross-workchain bridges?**
> Build on the TVM workchain with FunC. Use our wallet framework,
> async-workflow primitives, and bridge infrastructure.
>
> **Want to move assets or messages between the two workchains?**
> Use the native cross-workchain bridge. No third-party custody.

The dual-workchain architecture becomes a **benefit**: it gives
developers a choice based on what they're actually building, not a
confusion about which to pick.

---

## 7. Anticipated Questions

### "So will TVM workchain have no ERC-20?"

Correct. Developers wanting an ERC-20 deploy on the EVM workchain.
On TVM, the equivalent might be an account-abstracted holder pattern
— where each holder's wallet natively tracks the token balance
without a separate token-wallet sub-contract. This leans on what
TVM can uniquely do.

### "Won't everyone just use the EVM workchain then?"

Yes, for standard applications they should. That's the right outcome.
The TVM workchain is for applications whose value comes from what
only it can do. This is healthy specialisation, not a loss.

### "Then why have a TVM workchain at all?"

Account abstraction, asynchronous messaging, sharding, cell storage,
system contracts, and cross-workchain bridges are the six reasons.
If we don't invest in making those capabilities first-class, TVM
workchain is indeed redundant. This document argues we SHOULD invest
in those, not in generic application libraries.

### "Does this mean FunC development stops?"

No. It redirects. FunC work moves from "build application libraries"
to "make TVM-unique capabilities accessible". The stdlib stays
minimal and systems-oriented. Compiler work is deferred unless a
differentiated use case surfaces a specific gap.

### "What about existing FunC contracts in `crypto/smartcont/`?"

They stay. They're the base system: wallets, elector, DNS, etc.
They're valuable precisely because they use TVM's unique properties.
They're not examples of application development — they're the
protocol layer.

---

## 8. Decision Record

This document records the strategic position. Three concrete
decisions follow from it:

1. **Do not ship a FunC OpenZeppelin equivalent.** No
   `crypto/smartcont/tos-oz/`. No `std_typed_dict.fc` for
   DeFi-style mappings. No FunC Jetton / NFT / Vault / AMM.
   Point users at the EVM workchain for those.

2. **Do not extend FunC the language.** The archived
   `func-v0.5.0` work stays archived. No Phase 7 AST project. No
   `mapping` keyword. FunC is a systems language; its current
   feature set is adequate.

3. **Invest in TVM-native differentiators.** Sprint priorities go
   to: wallet framework (P0-1), cross-workchain bridge (P0-2),
   system contracts (P0-3). Async-workflow and sharding-aware
   libraries (P1) follow.

The EVM workchain continues on its own track (see
`doc/evm-workchain-*.md` series). This document is about what the
TVM side does with its existence.
