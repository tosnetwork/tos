# TOS FunC/Fift Contract Standard Library — Design

Version: v3 (Draft)
Status: Design proposal. Not an implementation manifest.
Supersedes: v1 (OpenZeppelin-shaped taxonomy), v2 (DeFi-first, 8 axes, scenarios).

## 1. Purpose

This document defines, from first principles, the standard library TOS should provide for FunC / Fift / Tolk contract authors. The library is **DeFi-first and comprehensive**: its taxonomy, priorities, and roadmap are shaped by the full surface area of protocols a developer will actually ship on TVM — tokens, AMMs, lending, governance, stablecoins, perps, liquid staking, NFT-Fi, bridges, account abstraction — not by the curated subset OpenZeppelin provides for EVM.

The document answers five questions:

1. **What is actually hard** about writing a DeFi contract on TVM, once you step outside toy examples.
2. **What already exists** in the TON/TOS ecosystem we should build on, align with, or supersede.
3. **Which library surfaces** must exist so the hard things stop being hard.
4. **How each primitive is specified** — a 7-field contract (storage, ops, invariants, failures, composition, gas, rent) that turns a library into audit-reviewable shared code.
5. **In what order** to deliver, driven by scenarios: Jetton → AMM → Lending → Governance → Stablecoin / Perps / Liquid Staking → Bridge / AA → NFT-Fi / Prediction / Insurance.

This document complements:

- [tos-tep-token-standards.md](tos-tep-token-standards.md) — canonical TOS-TEP-74 / TOS-TEP-62 interfaces.
- [actor-v3.md](actor-v3.md), [smc-guidelines.md](smc-guidelines.md) — execution model and TON-inherited authoring guidelines.
- [tos-standards-map.md](tos-standards-map.md) — stability tiers applied to primitives below.
- [tos-account-permission-model.md](tos-account-permission-model.md) — permissions consumed by Trust-axis mixins.
- [uno-workchain.md](uno-workchain.md) — shielded workchain that derives its own stdlib family from the axis structure here.

## 2. First Principles — What Makes TVM-Side DeFi Different

OpenZeppelin canonicalises EVM mistakes. TVM developers make a **different set** of mistakes because the runtime is different. The library must be derived from these differences.

### 2.1 There is no synchronous call

EVM: `tokenB.transferFrom(...)` blocks, returns, reverts atomically. This is what makes `ReentrancyGuard` both necessary and sufficient and why composability in EVM is free.

TVM: every cross-contract interaction is a message. There is no return value; a reply arrives later as a separate message, possibly after unrelated messages mutate this contract's state.

Consequences:
- The canonical failure is not reentrancy but the **async race (carousel attack)**.
- **Atomicity is no longer free.** A multi-contract op is a tree of messages; either the protocol engineers atomicity explicitly (saga, 2PC, intent + escrow), or it does not have it.

### 2.2 Sharding and code-is-address

Contract address = `hash(code, initial_data)`. Per-user state is split across per-user contracts (Jetton wallet). Cross-shard messages are the default.

Consequence: **deterministic factory** and **master-worker** are primitive operations, not design patterns.

### 2.3 Fees are the contract author's responsibility

Every outgoing message pays gas, forward fee, possibly rent. Insufficient attached value → chain stalls. Excess must be explicitly returned. A swap across 3–5 hops must attach value covering worst-case plus round-trip refund.

### 2.4 Contracts pay to exist

Storage rent. Long-lived vesting wallets, paused contracts, treasury contracts — all burn rent. A frozen contract is a compromised contract.

### 2.5 Bounce is the error channel

Failed messages return with `bounced=true` and ≤256 bits of original payload. Without a bounce handler the contract silently leaks funds or state.

### 2.6 External messages have no sender

Messages from off-chain wallets carry no `sender`. Authentication is a signature the contract itself verifies, plus a replay nonce. `Ownable` in OZ presumes `msg.sender`; TVM breaks that presumption at every dApp boundary.

### 2.7 Upgrade is cheap and native

`set_code` is a TVM opcode. Proxy patterns (UUPS/Transparent/Beacon) are irrelevant. What matters: versioned code registry, safe migration, rollback window, and migrations that cannot touch in-transit value.

### 2.8 Cells, not slots; TL-B, not bytes

Storage is a DAG of cells (≤1023 bits + ≤4 refs), serialised through TL-B. Ad-hoc slice parsing is the top production bug source. **TL-B codec generation is not a convenience — it is a safety boundary.**

### 2.9 Value in transit exists

A message carrying 100 TON leaves sender, crosses network, arrives at receiver over some blocks. During that window the value is **in neither account**. Any ledger that does not explicitly account for in-transit value will miscompute solvency.

### 2.10 Intent-based DeFi is native, not bolted on

EVM intent frameworks (CowSwap, UniswapX) live off-chain because EVM's synchronous model fights them. TVM's async model *is* the intent protocol: users sign intents, solvers compete to fulfill, chain validates results. The library treats intent / solver as a **first-class axis**, not an extension.

### 2.11 Storage rent changes lifecycle invariants

In EVM a contract lives forever until `selfdestruct`. In TVM a contract can freeze (miss rent), thaw (pay back rent), or destroy. The library must make lifecycle states a first-class property of every mixin, and emergency shutdown must drain rent before abandoning state.

### 2.12 Deterministic, content-addressed messages

Because addresses are hashes of code + data and messages carry content hashes, **content-addressed replay protection** is native. Cross-chain bridges, intent deduplication, and idempotent operations all exploit this; the library must codify it.

## 3. The Contract Author's Problem

What a DeFi contract author actually faces today without a stdlib.

| Milestone | Scenario | Typical pain (without stdlib) |
|-----------|----------|-------------------------------|
| **Day 1** | Publish a Jetton | ~400 lines hand-rolled FunC; 7 audit-known mistake shapes repeated in forks; excess-fee math wrong in ~30% of forks |
| **Week 1** | Ship an AMM | `mul_div` signed-overflow; no carousel guard; reply-handler byte-offset parsing; TWAP skipped; sandwich attacks day-two |
| **Month 1** | Launch lending | Health factor hand-rolled; liquidation auction bespoke; oracle staleness missed; keeper bot one-off; in-transit accounting absent → insolvency under load |
| **Quarter 1** | Governance + treasury | Proposal queue, timelock, vote snapshot, circuit breaker all reinvented; upgrade path without migration tests |
| **H1** | Stablecoin (CDP / algorithmic / pegged) | Peg controller hand-rolled; stability reserve ad-hoc; liquidation cascades untested; oracle manipulation defences inconsistent |
| **H1** | Perps / derivatives | Funding rate, mark price, PnL accounting, insurance fund — every protocol bespoke; no shared audit vocabulary |
| **H1** | Liquid staking | Operator registry bespoke; reward splitter per-protocol; exit queue patterns diverge across forks |
| **Year 1** | Bridge / AA / advanced | Light-client verifier custom; wrap/unwrap reinvented; smart wallet recovery bespoke; every bridge exploited once |
| **Y1+** | NFT-Fi, prediction, insurance | No shared primitives at all; each protocol writes its own auction, fractionalisation, oracle resolver |

The stdlib's purpose: move each row from "hand-rolled per protocol" to "audit-reviewed shared code," with **one vocabulary** auditors and contributors share across the ecosystem.

## 4. Ecosystem Survey and Relationship

The library is not born on a blank slate. Responsibly positioning requires naming what exists.

| Existing effort | What it provides | Our relationship |
|-----------------|------------------|------------------|
| `ton-core` / `@ton/core`, `@ton/ton` SDK | Off-chain cell/slice builders, address helpers, wallet impls | Keep for off-chain; on-chain stdlib does not replace this |
| TON community Jetton / NFT reference implementations | Reference contracts for TEP-74 / TEP-62 | Import as seed; harden, audit, add extensions as stdlib mixins |
| Tolk (TON's typed successor to FunC) | Newer, typed, safer language; still evolving | Stdlib must be **Tolk-ready**: primitives expose Tolk type signatures; FunC and Tolk mixins share TL-B schemas and op codes |
| TonKeeper / Blueprint / Sandbox | Deployment, testing, debugging | Stdlib ships Blueprint-native project templates; Sandbox is the reference test host |
| OpenZeppelin Contracts (EVM) | Gold-standard reference for audit-reviewable shared code | Adopt the **spirit** (audited, composable, well-documented) but not the surface shape |
| Solmate / Solady | Gas-optimised EVM primitives | Reference for gas-budget discipline |
| Curve / Balancer / Uniswap v2–v4 pool contracts | Reference invariants for AMM math | Port invariants, not code; FunC implementations are fresh |
| ERC-4626, ERC-2612, ERC-721, ERC-1155, EIP-712 | EVM standards whose **semantics** translate | Reimplemented over TVM primitives; wire protocol is TL-B, not ABI |
| `uno-workchain` (wc=2, shielded) | Shielded note-pool workchain | Derives its own stdlib family sharing axis structure |

**Positioning statement.** TOS stdlib is the first on-chain FunC library designed around DeFi composability and audit-reviewability, building on TON community conventions, aligned with Tolk as it matures, informed by OpenZeppelin / Solmate / Uniswap / Curve / Balancer, and published under a permissive dual license (see §15).

## 5. The Nine Axes

v3 adds **Axis 0** (foundational primitives and codecs) beneath the eight value-flow axes from v2. Axis 0 is what every other axis depends on; it was implicit in v2 and is made explicit here.

```
             ┌─────────────────────────────────────────────────────┐
             │  Axis 0: Primitives & Codecs (foundation)           │
             └──────────────────▲──────────────────────────────────┘
                                │ used by all
   ┌────────────┬───────────────┼───────────────┬────────────┐
   │            │               │               │            │
   ▼            ▼               ▼               ▼            ▼
Value      Price &         Coordination    Time        Trust
Accounting  Invariants      (async atom)                & Provenance
   │            │               │               │            │
   └────────────┴───────┬───────┴───────┬───────┴────────────┘
                        │               │
                        ▼               ▼
                   Composition       Lifecycle
                        │               │
                        └───────┬───────┘
                                ▼
                         Observability
```

Coordination is the hub; Axis 0 is the floor.

### 5.0 Axis 0 — Primitives & Codecs

**What it covers.** The common substrate every other axis presumes. Recovered from v1's Tier 4, made explicit in v3 because every production bug eventually traces back here.

**Primitives.**

| Primitive | Role |
|-----------|------|
| `Cell.Dict.Typed<K,V>` | Wrapper over raw dict with typed keys/values, bounded-iter, range-split |
| `Cell.Bag<T>` | Unordered multiset with O(log n) add/remove/contains |
| `Cell.Set<T>` | Unordered set; dedup on insert |
| `Cell.Stack<T>` / `Cell.Queue<T>` | Ordered containers; bounded-size variants for rent budgeting |
| `Slice.Reader` | Trap on over-read; never silently truncates |
| `Builder.Checked` | Trap on over-write of cell bit/ref budget |
| `TLB.Codec<T>` | Encode / decode / verify; generated from schema by `tlbc` |
| `TLB.Schema.Version` | Wire-compatible schema evolution with required `v` tag |
| `Address.Parse` / `.Format` / `.ValidateWorkchain` | stdaddr encoding, bounce flag, workchain-whitelist enforcement |
| `Error.Registry` | Reserved ranges: 0–999 TVM, 1000–1999 stdlib core, 2000–2999 tokens, 3000–3999 DeFi, 4000–4999 governance, 5000–5999 lifecycle, 6000–6999 observability, 9000+ user-defined |
| `Version.SemVer` | Monotonic version comparison; required on every mixin |
| `BitPack` | Layout helpers aware of 1023-bit cell boundary; flags over-boundary packing at compile time |
| `String.Utf8` | Minimal encode / decode / length; TVM is not a string machine |
| `Math.Int256` | Canonical signed / unsigned 256-bit ops |
| `Math.SafeCast` / `.Signed` | Overflow-trap narrowing and signed helpers |
| `Math.Fixed.Q64_96` / `.Q128_128` / `.UD60x18` | Fixed-point layouts with checked `mul_div`, `sqrt`, `log`, `exp`; bit-exact across builds |
| `Math.Rounding.{TowardZero, AwayFromZero, FavorProtocol, HalfEven}` | Explicit rounding policy; no default — caller must choose |

**Invariants.**
1. Slice over-read and builder over-write trap, never truncate silently.
2. Every public surface has a TL-B schema; raw slice code inside mixins is a lint violation.
3. Rounding direction is explicit at every fractional op; no implicit truncation.
4. Error codes never overlap across mixins; registry machine-checked.

### 5.1 Value Accounting

**What it covers.** Balances, shares, interest, rent, in-transit value, wrap/unwrap, rewards, governance share, CDP, perps, liquid staking, bonds. Any time a number represents money.

**Sub-axis A — Core assets.**

| Primitive | Role |
|-----------|------|
| `Jetton.Master` / `Jetton.Wallet` | TEP-74 reference + Mintable / Burnable / Pausable / Permit / Capped / FlashMint mixins |
| `NFT.Collection` / `.Item` / `.SBT` | TEP-62 reference with TEP-66 Royalty and LazyMint |
| `MultiToken` | ERC-1155 analogue: shared metadata, per-id wallets |
| `ShareVault` | ERC-4626 analogue; async deposit/withdraw via request-ticket NFT |
| `ShareVault.FirstDepositGuard` | Seeds minimum liquidity to defeat donation / share-inflation attacks |
| `ShareVault.PrecisionBuffer` | Reserves dust shares against rounding attacks |
| `ValueLedger` | Per-asset: `spot`, `in_transit_out`, `in_transit_in`, `available`, `reserves` |
| `InTransitAccountant` | Hooks into `ReplyRouter`; moves value between spot and in-transit on send / reply / bounce |
| `RentManager` | Computes current rent; exposes `top_up`; emits low-rent events |
| `WrapUnwrap.TOMI` | wTOMI (native → Jetton); canonical for AMM quoting |
| `Stream` | Continuous accrual per block; used by vesting, salary, subscription |

**Sub-axis B — Interest and rewards.**

| Primitive | Role |
|-----------|------|
| `InterestModel.Linear` / `.Compound` / `.JumpRate` / `.Kink` | Canonical accrual curves |
| `RewardPerShare` | Standard `(accRewardPerShare, lastUpdate)` accumulator; defeats precision-loss bug class |
| `AccumulatedReward` | Per-user debt tracking; pairs with `RewardPerShare` |
| `EmissionSchedule.Halving` / `.Linear` / `.Exponential` | Token emission curves with canonical roundoff |
| `BoostMultiplier` | ve-style boost (0.4× base .. 2.5× boosted); canonical bounds |
| `GaugeController` | Weighted allocation across multiple gauges; integrates `VoteEscrow` |
| `BribeMarket` | Third-party incentives routed to gauge voters |
| `RewardSplitter` | Multi-recipient reward distribution (Synthetix-style) |

**Sub-axis C — Governance share.**

| Primitive | Role |
|-----------|------|
| `VotesCheckpoint` | Historical balance snapshots; required for flash-loan-safe voting |
| `Delegation` | Voting-power delegation (opt-in, revocable) |
| `VoteEscrow` | Time-locked stake for boost; canonical decay curve |
| `SnapshotBallot` | Merkle-root-of-balances voting (off-chain signature, on-chain tally) |

**Sub-axis D — CDP / Stablecoin.**

| Primitive | Role |
|-----------|------|
| `CDP.Vault` | Collateralised debt position; `deposit / borrow / repay / close`; integrates `HealthFactor` |
| `CDP.StabilityReserve` | Absorbs liquidation shortfalls; fed by protocol fees |
| `Peg.Controller` | PID-style peg correction via mint/burn, funding rates, or buy-back |
| `Peg.Oracle` | Multi-oracle peg target with deviation bounds |
| `Redemption.Queue` | Ordered redemption under adversarial conditions; prevents run-on-bank |

**Sub-axis E — Perpetuals.**

| Primitive | Role |
|-----------|------|
| `FundingRate` | Canonical periodic funding computation; long/short skew |
| `MarkPrice` | Manipulation-resistant mark from TWAP + index blend |
| `PnLAccounting` | Unrealised / realised / fee separated; defeats inflation attacks |
| `InsuranceFund` | Absorbs bankrupt positions |
| `PositionMargin.Isolated` / `.Cross` | Canonical margining modes |

**Sub-axis F — Liquid staking and restaking.**

| Primitive | Role |
|-----------|------|
| `LiquidStakingShare` | Rebasing share token over staked principal + rewards |
| `OperatorRegistry` | Validator registration, bond, performance tracking, slashing |
| `ExitQueue` | Ordered unstaking under validator-exit rate-limit |
| `RestakingHooks` | Opt-in additional-slashing commitments |

**Sub-axis G — Bonds / POL / bonding curves.**

| Primitive | Role |
|-----------|------|
| `Bond.Issuer` | Discounted-token bond issuance for treasury liquidity |
| `Bond.Treasury` | Treasury-owned liquidity manager |
| `POL.Manager` | Protocol-owned LP position management |
| `BondingCurve.Continuous` | Continuous token model (buy/sell on curve); canonical Bancor-style |
| `AirdropMerkle` | Standard merkle-root drop with claim tickets |

**Axis invariants.**
1. `spot = Σ(user_balances) + in_transit_out − in_transit_in + reserves` after every message (test-harness enforced).
2. Wrap / unwrap round-trips are exact; no dust accumulation.
3. Reward accumulators never deflate; canonical precision ≥ 1e18 ratio.
4. Every share vault has either `FirstDepositGuard` or `PrecisionBuffer` declared; audit lint enforces.
5. Governance share mixins are flash-loan-safe: `VotesCheckpoint` is required for Governor reads.

### 5.2 Coordination (async atomicity)

**What it covers.** Every cross-contract operation. The library's strongest differentiator.

**Primitives.**

| Primitive | Role |
|-----------|------|
| `MessageEnvelope` | `op:uint32 / query_id:uint64 / body:TL-B`; op-range allocation per mixin |
| `ReplyRouter` | query_id → continuation table; single-shot; bounce-integrated |
| `BounceHandler` | Mandatory `recv_internal bounced=true` scaffold; declared recovery per op |
| `PendingRequestTable` | In-flight request ledger; gates new ops against unresolved ones |
| `CarouselGuard` | State-version tag on outbound; reply rejected if version advanced |
| `OptimisticLock` | Queue stale reply for re-evaluation vs rejection |
| `SagaCoordinator` | Multi-step with per-step compensation; reverse-rollback on failure |
| `Saga.Nested` | Saga-of-sagas; parent saga compensates over children |
| `TwoPhaseCommit` | Prepare → commit / abort across N cohorts; coordinator + participant mixins |
| `IntentPool` | User-signed intent lives as an actor; `claim` op for solvers |
| `SolverRegistry` | Solver bond, slashing, reputation; `fulfill` / `challenge` ops |
| `MetaIntent` | Intent-of-intents: solver may post sub-intents, recurse |
| `EscrowAtomicity` | N-of-M condition predicate; timeout refund |
| `MulticallBatch` | User-scoped ephemeral actor; serial execution; self-destruct |
| `GasForwarder` | `estimate_chain_fee(op, depth_bound, body_bits)`; `split_inbound` |
| `FeeMeter` | Runtime measurement for off-chain estimators to learn from |
| `DryRun` | Simulation-only message mode; state changes discarded; for off-chain quoting |
| `MessageHashLedger` | Content-hash dedup; idempotency key |
| `ConsistencyLevel` | Declared per op: `Eventual`, `Causal`, `StrongViaEscrow` — auditors can see which |

**Axis invariants.**
1. Every outgoing op has: declared bounce handler, OR declared `bounce=false` with justification + conformance test, OR is routed through `ReplyRouter`.
2. Saga with N steps has ≥ N compensations; lint enforces.
3. Intents are content-addressable; replay protected by `MessageHashLedger`.
4. `DryRun` cannot produce persisted state; mode flag is honored by every mixin.
5. Consistency level is declared per public op; auditors can filter by level.

### 5.3 Price & Invariants

**What it covers.** Fixed-point math, AMM invariants, oracle protocols, health factor, liquidation, auctions.

**Primitives.**

| Primitive | Role |
|-----------|------|
| `AMM.XYK` | Constant-product reference |
| `AMM.StableSwap` | Curve-style for pegged assets |
| `AMM.Concentrated` | Uniswap-v3-style tick math |
| `AMM.Weighted` | Balancer-style n-asset weighted pool |
| `AMM.ComposableStable` | Stable pool composing with yield-bearing tokens |
| `AMM.Hooks` | Uniswap-v4-style hook interface for pool extensions |
| `Oracle.Push` | Signer posts; staleness threshold; multi-signer aggregation |
| `Oracle.Pull` | Consumer requests; reply-routed; TTL-cached |
| `Oracle.Dual` | Two independent oracles cross-checked; reject if drift > ε |
| `TWAP.Snapshot` | Rolling `(block, cumulative_price)`; manipulation-cost model documented |
| `VolatilityEstimator` | Realised-volatility window; input to margin / funding |
| `OracleManipulationCost` | Static calculator: attacker capital × block-count × slippage |
| `HealthFactor` | Canonical `HF = Σ(collateral × ltv × price) / Σ(debt × price)` |
| `LiquidationAuction.Dutch` | Decaying price; keeper-driven |
| `LiquidationAuction.English` | Ascending bid for large positions |
| `LiquidationAuction.Batch` | Frequent-batch clearing; MEV-resistant |
| `BadDebtAbsorber` | Socialised loss via `ShareVault` or `InsuranceFund` |
| `GradualDutchAuction` | Time-streaming launch auction (for token sales) |
| `BondingCurve.Continuous` | See §5.1-G |
| `PredictionMarket.LMSR` | Logarithmic market-scoring-rule maker |

**Axis invariants.**
1. Fixed-point ops are bit-exact, deterministic across builds; conformance test vectors ship.
2. AMM invariants (`x·y ≥ k`, Curve invariant, weighted geometric mean) asserted after every state change; violation traps with reserved error.
3. Oracle staleness is a hard precondition, not a warning.
4. Manipulation-cost model documented per oracle; consumers declare minimum cost they require.

### 5.4 Time

**What it covers.** Scheduling, keepers, expiry, rent heartbeat. TVM does not schedule itself; every recurring action needs an external trigger.

**Primitives.**

| Primitive | Role |
|-----------|------|
| `Timelock` | Proposed op → delay → executable; cancel in window |
| `Scheduler` | Future-dated op list; keeper-picked |
| `KeeperRegistry` | Registration, bond, reward, slashing; `trigger(schedule_id)` |
| `Cron` | Recurring schedules per-block / per-hour / per-day |
| `RentHeartbeat` | Self-scheduling rent top-up for long-lived contracts |
| `ExpiryGuard` | Rejects messages after `valid_until`; standard in `ExternalMessageGuard` |
| `BlockTimeOracle` | Message-local `now()`; ages data across reply-latency |
| `Deadline.Relative` / `.Absolute` | Canonical deadline encoding |

**Axis invariants.** No stdlib mixin relies on "this will run automatically"; every recurring action is keeper-triggered or fails loudly when overdue.

### 5.5 Trust & Provenance

**What it covers.** Signatures, sender, bounce, cross-contract auth, interface discovery, compliance, initialization safety.

**Primitives.**

| Primitive | Role |
|-----------|------|
| `ExternalMessageGuard` | sig + `valid_until` + seqno + chain_id binding |
| `OwnableActor` | Owner slot + rotate; internal-sender and external-signed variants share storage |
| `AccessControl` | RBAC role dict; `has_role / grant / revoke`; reserved role-id ranges |
| `MultiSig.v5` | Proposal queue, threshold rotation, emergency veto |
| `Signature.Ed25519` / `.ECDSA` / `.BLS` | Canonical verifiers; library-fixed domain separation |
| `SignatureMalleabilityGuard` | ECDSA low-s enforcement |
| `StructuredMessage` | EIP-712 equivalent over cell hashing; domain `(chain_id, wc_id, addr, version)` |
| `SupportsOp` | Mandatory get-method `int supports_op(int op_id) -> bool` |
| `ContractProof` | Prove "message X came from contract with code hash H" |
| `ComplianceHook` | Pluggable pre-transfer check (allowlist / blocklist / jurisdiction) |
| `AccountPermission.Binding` | Integration with hierarchical permissions |
| `InitializationGuard` | Prevents re-init race and frontrunning of first message |
| `StorageSlotSafety` | Per-mixin namespace to prevent storage collision across composed mixins |

**Axis invariants.**
1. External entry points route through `ExternalMessageGuard` or fail lint.
2. `SupportsOp` is mandatory for every mixin with public ops.
3. Storage namespaces never overlap; machine-checked at build.
4. Initialisation happens exactly once; second attempt traps.

### 5.6 Composition

**What it covers.** Plugging contracts together across authors, workchains, chains. Adapters, registries, bridges, MEV protection, AA, marketplaces, randomness, insurance, prediction.

**Sub-axis A — Discovery and registry.**

| Primitive | Role |
|-----------|------|
| `InterfaceDiscovery` | Client-side probing built on `SupportsOp` |
| `ContractRegistry` | Well-known contract lookup (oracle router, bridge, token list, wTOMI); DNS-backed, governance-curated |

**Sub-axis B — Cross-chain.**

| Primitive | Role |
|-----------|------|
| `BridgeGateway` | Uniform inbound/outbound protocol |
| `LightClientVerifier.EVM` / `.Cosmos` / `.Bitcoin` | Header + Merkle proof verification |
| `InboundWrap` | External proof → mint Jetton |
| `OutboundCommit` | Burn Jetton → emit commitment |
| `CrossChainReplayGuard` | Content-hash + origin + destination dedup |
| `CrossWorkchain.Bridge` | wc=0 ↔ wc=1 (EVM) ↔ wc=2 (Uno) safe message patterns |

**Sub-axis C — MEV and execution.**

| Primitive | Role |
|-----------|------|
| `MEVProtection.CommitReveal` | Two-phase sealed actions |
| `MEVProtection.BatchAuction` | Frequent-batch clearing |
| `Paymaster` | Sponsored gas / rent on behalf of user |

**Sub-axis D — Account abstraction.**

| Primitive | Role |
|-----------|------|
| `AccountAbstraction.SessionKey` | Time- and scope-bounded auxiliary key |
| `AccountAbstraction.SocialRecovery` | N-of-M guardians rotate main key after delay |
| `AccountAbstraction.SpendingLimit` | Per-asset rolling-window cap |
| `AccountAbstraction.SessionPolicy` | Per-session allowed-op / target policy |

**Sub-axis E — Orderbook and markets.**

| Primitive | Role |
|-----------|------|
| `Orderbook.CLOB` | Central limit orderbook; async matching |
| `Orderbook.RFQ` | Request-for-quote with solver responses |
| `Marketplace.Listing` | NFT / asset listing with offers and bids |
| `Marketplace.Auction.English` / `.Dutch` | Canonical auction listing variants |
| `Royalty.Enforce` | On-chain TEP-66 royalty enforcement |

**Sub-axis F — NFT-Fi.**

| Primitive | Role |
|-----------|------|
| `NFT.FractionVault` | Fractionalise NFT into Jetton shares + buy-out |
| `NFT.Lend` | NFT-collateralised loan with auction fallback |
| `NFT.Rent` | Time-bounded NFT rental with role-based access |

**Sub-axis G — Insurance and coverage.**

| Primitive | Role |
|-----------|------|
| `CoverPool` | Pooled cover with premium streaming |
| `ClaimArbiter` | Claim resolution: oracle, multisig, or arbitration court |
| `MutualInsurance` | Member-pooled coverage with governance-driven payouts |

**Sub-axis H — Randomness and prediction.**

| Primitive | Role |
|-----------|------|
| `VRF.Adapter` | Verifiable-random-function client (chainlink-style) |
| `CommitReveal.Randomness` | Multi-party commit-reveal entropy |
| `PredictionMarket.Outcome` | Binary / categorical outcome settlement |

**Axis invariants.**
1. Every bridge primitive documents trust model (validator set / light client / ZK) in manifest; consumers see it statically.
2. Cross-chain replay requires content-hash + origin-chain-id + destination-chain-id.
3. Randomness primitives document manipulation cost in block-validator collusion terms.
4. Marketplace primitives enforce royalty unless caller has explicit waiver permission.

### 5.7 Lifecycle

**What it covers.** Deploy, upgrade, migrate, emergency stop, wind-down, multi-contract orchestration.

**Primitives.**

| Primitive | Role |
|-----------|------|
| `DeterministicFactory` | `(code, init_data) → address` predictor; `ensure_deployed` helper |
| `MasterWorker` | Generalised Jetton-master / wallet pattern; wallet-code pinning |
| `UpgradeableActor` | `set_code` wrapper: monotonic version, required migration, hash allowlist, rollback window |
| `CodeRegistry` | `(package, version) → code_hash`; governance-administered |
| `MigrationHandler` | Transform cell layouts across versions; proves schema compatibility |
| `DeploymentPlan` | Multi-contract deploy DAG with dependencies; atomic or compensating |
| `CrossVersionMigration` | Multi-contract coordinated migration across a protocol |
| `Pausable` | Freeze transfers; short-incident use only — still burns rent |
| `CircuitBreaker` | Rate-limited auto-pause on anomaly (price drift, unusual volume) |
| `GracefulShutdown` | Stop new state, drain outstanding, refund, `set_code` to keep-alive or destroy |
| `RentSponsor` | Third-party actor subsidising rent |
| `EmergencyMultisig` | Multi-sig scoped to shutdown / pause only |

**Axis invariants.**
1. Upgrades changing storage layout require a migration handler + Sandbox-replay dry-run on mainnet snapshot.
2. Migrations cannot touch in-transit value: `InTransitAccountant` state is in the frozen invariants.
3. `Pausable` is not `GracefulShutdown`; distinction in manifest and tests.
4. `DeploymentPlan` is either all-or-nothing or documents compensations per step.

### 5.8 Observability

**What it covers.** Events, logs, traces, indexer protocol, error codes, metrics.

**Primitives.**

| Primitive | Role |
|-----------|------|
| `EventEmitter` | Standard `ext_out_msg` topic layout: `(topic_hash, indexed_args, body)` |
| `IndexerFeed` | Canonical stream schema for explorers / indexers / analytics |
| `StateSnapshot` | Read-only get-methods: `(version, invariants_ok, key_metrics)` |
| `InvariantAssertion` | Manifest-declared invariants; compile to runtime asserts in debug |
| `MessageTreeTag` | Correlation id across multi-hop message tree |
| `Trace` | Debug-build `printf` sink; stripped from release |
| `MetricsFeed` | Monitor-friendly periodic state emission |

**Axis invariants.**
1. Events are part of the public surface; topic change = breaking change.
2. Error codes machine-checked against `Error.Registry`.
3. Every mixin ships a `StateSnapshot` view for uniform monitor health-checks.

## 6. Primitive Contract Template

Every primitive in this library is specified by seven fields. The table rows above state only the "Role"; the full contract is where audit-reviewability lives. **No mixin graduates past `experimental` without all seven fields filled.**

| Field | Meaning |
|-------|---------|
| **Storage** | TL-B schema of persistent state; versioned |
| **Ops** | Table of `(op_id, body schema, reply schema, bounce schema, required value)` |
| **Invariants** | Statements that are true before and after every op; mapped to runtime asserts + property tests |
| **Failures** | Table of `(error_code, condition, recovery expectation)` |
| **Composition** | Required companion mixins; incompatible mixins; storage namespace claim |
| **Gas budget** | Worst-case TVM-gas per op |
| **Rent budget** | Persistent cells + refs; rent/day estimate |

See **Appendix A** for five exemplar contracts filled in (`RewardPerShare`, `CarouselGuard`, `SagaCoordinator`, `HealthFactor`, `IntentPool`). The L.1 scoping document fills the contracts for all GA-target L.1 primitives.

## 7. Primitive Dependency Graph (abridged)

The full DAG is maintained in `doc/tos-stdlib-dependencies.md` (to be created). Excerpt:

```
Axis 0 (Cell / Slice / Builder / TLB / Math / Error)
  └── Coordination: MessageEnvelope
        ├── ReplyRouter ◄── BounceHandler
        │       └── CarouselGuard ─┐
        │       └── PendingRequestTable
        │       └── SagaCoordinator ◄── Saga.Nested
        │       └── TwoPhaseCommit
        │       └── IntentPool ◄── SolverRegistry ◄── KeeperRegistry
        │                          ▲
        │                          └── MetaIntent
        │       └── MulticallBatch
        ├── GasForwarder ◄── FeeMeter
        └── MessageHashLedger ◄── CrossChainReplayGuard

Trust: ExternalMessageGuard ◄── Signature.Ed25519, StructuredMessage, ExpiryGuard
           ▲
           └── InitializationGuard, StorageSlotSafety

Value: ValueLedger ◄── InTransitAccountant (needs ReplyRouter)
         ├── Jetton.Master/.Wallet (needs DeterministicFactory + MasterWorker)
         ├── ShareVault (needs InterestModel, FirstDepositGuard, PrecisionBuffer)
         ├── RewardPerShare ◄── AccumulatedReward ◄── BoostMultiplier
         └── VotesCheckpoint ◄── Delegation ◄── VoteEscrow

Price: Math.Fixed ──► AMM.XYK / StableSwap / Concentrated / Weighted
         ├── Oracle.Push/Pull/Dual ──► TWAP.Snapshot ──► MarkPrice
         ├── HealthFactor (needs Oracle + ValueLedger)
         └── LiquidationAuction.* (needs HealthFactor + KeeperRegistry)

Lifecycle: UpgradeableActor ──► CodeRegistry + MigrationHandler
              └── DeploymentPlan ──► CrossVersionMigration
Composition: BridgeGateway ──► LightClientVerifier + CrossChainReplayGuard
              └── AccountAbstraction.* ──► Paymaster
Observability: EventEmitter, InvariantAssertion, StateSnapshot (all depend only on Axis 0)
```

Graph properties:
- **Axis 0 and `MessageEnvelope` are the two roots**; everything else transitively depends on them.
- **`SolverRegistry` and `KeeperRegistry`** share the bond-slashing machinery; both should ship together or neither GA.
- **`IntentPool` cannot GA before `SolverRegistry`** — this constrains Year-1 scenario timing.
- **`ShareVault.FirstDepositGuard` / `PrecisionBuffer`** are not optional adjuncts; they are required dependencies of `ShareVault`.

## 8. DeFi Attack Surface Catalogue

Canonical map from attack class → primitive that defends. Every audit of a stdlib-using protocol walks this checklist.

| Attack class | Defence primitive | Axis |
|--------------|-------------------|------|
| Reentrancy (EVM) | N/A — TVM is async; reentrancy is not the bug | — |
| Carousel / async race | `CarouselGuard`, `OptimisticLock` | Coordination |
| Bounce-induced fund loss | `BounceHandler`, `InTransitAccountant` | Coordination + Value |
| Stalled message chain (fee exhaustion) | `GasForwarder`, `FeeMeter` | Coordination |
| Rent-exhaustion freeze | `RentManager`, `RentSponsor`, `RentHeartbeat` | Value + Time |
| Replay (same chain) | `ExternalMessageGuard` seqno + `valid_until` | Trust |
| Replay (cross chain) | `CrossChainReplayGuard` (content + origin + dest) | Composition |
| Sandwich attack | `MEVProtection.BatchAuction` | Composition |
| Oracle manipulation (spot) | `Oracle.Dual`, `TWAP.Snapshot`, `OracleManipulationCost` | Price |
| Oracle staleness | `Oracle.*` staleness precondition | Price |
| Flash-loan voting | `VotesCheckpoint` (historical balance) | Value |
| Governance hostile takeover | `Timelock` + `EmergencyMultisig` | Time + Lifecycle |
| Share-inflation / donation attack | `ShareVault.FirstDepositGuard`, `PrecisionBuffer` | Value |
| Precision / rounding direction | `Math.Rounding.FavorProtocol` | Axis 0 |
| Reward-accumulator precision drift | `RewardPerShare` canonical impl | Value |
| Initialization race | `InitializationGuard` | Trust |
| Storage collision between mixins | `StorageSlotSafety` namespaces | Trust |
| Signature malleability | `SignatureMalleabilityGuard` | Trust |
| Upgrade-authority capture | `CodeRegistry` + governance + `UpgradeableActor.rollback_window` | Lifecycle |
| Migration data loss | `MigrationHandler` dry-run + invariant preservation | Lifecycle |
| JIT liquidity / LP griefing | `AMM.Concentrated` tick rules + hook filtering | Price + Composition |
| Liquidation front-running | `LiquidationAuction.Batch` | Price |
| Bridge validator collusion | `LightClientVerifier` + dual-validator proofs | Composition |
| VRF bias / tampering | `VRF.Adapter` proof verification + commit-reveal fallback | Composition |
| Fee-switch misdirection | `PaymentSplitter` + `Timelock` on routing changes | Value + Time |
| Stablecoin bank run | `Redemption.Queue`, `Peg.Controller` | Value |
| Perp funding manipulation | `MarkPrice` (TWAP + index blend), `InsuranceFund` | Value + Price |

## 9. Scenario-Driven Roadmap

Delivery organises around scenarios. Primitives GA when the first scenario that needs them is scheduled; overlap is permitted but phases gate each other on GA evidence.

### 9.1 Day 1 — Publish a Jetton

**GA primitives.**
- Axis 0: Cell.Dict.Typed, Slice.Reader, Builder.Checked, TLB.Codec, Address.Parse, Error.Registry, Math.Rounding
- Value: Jetton.Master/Wallet, ValueLedger, RentManager
- Coordination: MessageEnvelope, ReplyRouter, BounceHandler, GasForwarder
- Trust: ExternalMessageGuard, OwnableActor, SupportsOp, InitializationGuard
- Lifecycle: DeterministicFactory, MasterWorker, Pausable
- Observability: EventEmitter, ErrorCodeRegistry, StateSnapshot

**Experimental.** Mintable / Burnable / Permit / Capped, ComplianceHook.

**Exit.** Copy reference project → edit metadata → deploy mainnet → audit checklist passes. Same day.

### 9.2 Week 1 — Ship an AMM

Add: ShareVault + FirstDepositGuard + PrecisionBuffer; WrapUnwrap.TOMI; PendingRequestTable; CarouselGuard; Math.Fixed.Q64_96; AMM.XYK; TWAP.Snapshot; ExpiryGuard; InvariantAssertion.

**Optional.** AMM.StableSwap / Concentrated / Weighted; MEVProtection.CommitReveal; Oracle.Dual.

**Exit.** Reference AMM passes attack suite (sandwich, flash-loan price manipulation, JIT liquidity, carousel, donation).

### 9.3 Month 1 — Launch lending

Add: InterestModel.JumpRate, InTransitAccountant, Stream; SagaCoordinator, EscrowAtomicity; HealthFactor, LiquidationAuction.Dutch, BadDebtAbsorber, Oracle.Pull, Oracle.Dual; Scheduler, KeeperRegistry, Cron; ComplianceHook; CircuitBreaker.

**Optional.** IntentPool + SolverRegistry; LiquidationAuction.Batch.

**Exit.** Reference isolated-market lending + keeper reference + liquidation bot template, all audited.

### 9.4 Quarter 1 — Governance + treasury

Add: MultiSig.v5, AccessControl, AccountPermission.Binding; TwoPhaseCommit; Timelock; UpgradeableActor, CodeRegistry, MigrationHandler, EmergencyMultisig, GracefulShutdown; ContractRegistry; VotesCheckpoint, Delegation, SnapshotBallot.

**Optional.** Governor; PaymentSplitter; VestingWallet; VoteEscrow; GaugeController.

**Exit.** Governance-and-treasury kit with audited upgrade pathway, rollback window, emergency-pause multisig, gauge-weighted emissions.

### 9.5 H1 — Stablecoin

Add: CDP.Vault, CDP.StabilityReserve, Peg.Controller, Peg.Oracle, Redemption.Queue; VolatilityEstimator; OracleManipulationCost; AMM.StableSwap; EmissionSchedule.*.

**Exit.** Reference CDP-style stablecoin + peg stability test harness + bank-run simulation.

### 9.6 H1 — Perpetuals (alternative H1 track)

Add: FundingRate, MarkPrice, PnLAccounting, InsuranceFund, PositionMargin.Isolated/Cross; VolatilityEstimator; Orderbook.CLOB or AMM.Concentrated with perp extension.

**Exit.** Reference perp market + funding-rate oracle + liquidation cascade test.

### 9.7 H1 — Liquid staking (alternative H1 track)

Add: LiquidStakingShare, OperatorRegistry, ExitQueue, RestakingHooks; RewardSplitter.

**Exit.** Reference liquid-staking token + validator-exit simulation + slashing handler.

### 9.8 Year 1 — Bridge / AA / Advanced

Add: BridgeGateway, LightClientVerifier.{EVM,Cosmos,Bitcoin}, InboundWrap, OutboundCommit, CrossChainReplayGuard; AccountAbstraction.*; Paymaster; IntentPool + SolverRegistry + MetaIntent + MulticallBatch; CrossWorkchain.Bridge.

**Exit.** Reference bridge to major EVM chain + reference AA wallet + reference intent protocol, all with public audits.

### 9.9 Y1+ — NFT-Fi / Prediction / Insurance

Add: NFT.FractionVault, NFT.Lend, NFT.Rent; Marketplace.Listing + Auction variants + Royalty.Enforce; CoverPool, ClaimArbiter, MutualInsurance; PredictionMarket.Outcome + LMSR; VRF.Adapter, CommitReveal.Randomness; Bond.Issuer, Bond.Treasury, POL.Manager, BondingCurve.

**Exit.** Reference NFT marketplace, prediction market, cover pool — all audited, with bridge + AA already in production.

### 9.10 Phase mapping

Scenarios 9.1 – 9.4 collapse to delivery phases **L.1 – L.4**; 9.5 – 9.7 are parallel H1 tracks **L.5a / b / c**; 9.8 is **L.6**; 9.9 is **L.7**. Each phase delivers: reference FunC + Tolk source, TL-B schemas, Fift deployment template, Blueprint project skeleton, JS SDK bindings, documentation page, conformance test suite, attack suite, audit report.

## 10. DeFi Cookbook

**Notation.** Examples below are written in **typed pseudo-code** for readability (close to how a future typed FunC dialect or Tolk would spell it). **FunC transcriptions for every example live in Appendix B.** Pseudo-code and FunC compile to identical op codes, TL-B schemas, and error codes (see Principle 9 in §11).

### 10.1 Minimal Jetton transfer

```text
use stdlib.value_accounting.jetton_wallet;
use stdlib.coordination.dispatch;

contract JettonWallet uses JettonWalletState {
  on internal message {
    dispatch(
      on Transfer(body)         -> on_transfer(body),
      on Burn(body)             -> on_burn(body),
      on InternalTransfer(body) -> on_internal_transfer(body)
    )
  }

  on bounced message {
    BounceHandler::route(
      on Transfer(body) -> refund(body.amount, body.sender)
    )
  }
}
```

### 10.2 Swap against an AMM with carousel guard + invariant assertion

```text
fn on_swap(notify: JettonWallet.Notify, body: SwapArgs) {
  let (amount_out, next_k) = AMM.XYK.quote_and_next_k(
      body.amount_in, state.reserve_in, state.reserve_out);
  require(amount_out >= body.min_out, ErrorCodes.SLIPPAGE);

  let router = CarouselGuard.begin(state.version);
  JettonWallet.transfer(state.out_wallet, amount_out, notify.recipient,
      fees: GasForwarder.for_reply(depth: 2, reply_body_bits: 512));
  ReplyRouter.expect(router, on_swap_confirmed);

  InvariantAssertion.check(AMM.XYK.k(state) >= state.k);
  state.k = next_k;
}
```

### 10.3 Intent-based swap (TVM superpower)

```text
// User side (off-chain)
let intent = SwapIntent {
  from: my_wallet, give: 100 USDT,
  want_at_least: 99 USDC,
  valid_until: now() + 300, nonce: n
};
let sig = sign(my_secret, StructuredMessage.hash(intent));
IntentPool.submit(intent, sig);

// Solver side (on-chain)
fn on_claim(claim: IntentPool.Claim) {
  let intent = claim.intent;
  require(StructuredMessage.verify(intent, claim.user_sig, intent.from),
      ErrorCodes.SIGNATURE);
  require(now() <= intent.valid_until, ErrorCodes.EXPIRED);
  SolverRegistry.bond_lock(claim.solver, intent.want_at_least);
  // ... solver sources liquidity however; settlement releases bond
}
```

### 10.4 Reward distribution with canonical precision (MasterChef equivalent)

```text
contract StakingPool uses StakingPoolState, RewardPerShare {
  on Stake(amount) {
    let user = state.users.get(sender);
    RewardPerShare.update(state, now());
    let pending = RewardPerShare.pending(user);
    if pending > 0 { RewardsToken.transfer(sender, pending); }
    user.shares += amount;
    user.debt = RewardPerShare.debt(user.shares, state.acc);
    state.users.put(sender, user);
  }
  // on Unstake / Claim symmetric
}
```

`RewardPerShare` handles the `accRewardPerShare * 1e18 / total_shares` precision pattern that half of EVM fork contracts get wrong.

### 10.5 CDP open + liquidation

```text
fn on_open_cdp(collateral_amount, debt_amount) {
  let hf = HealthFactor.compute(collateral_amount, debt_amount,
      Oracle.Dual.read(oracle1, oracle2));
  require(hf >= MIN_HF, ErrorCodes.UNHEALTHY);
  CDP.Vault.open(sender, collateral_amount, debt_amount);
  Stablecoin.mint(sender, debt_amount);
}

// Liquidator triggers
fn on_liquidate(cdp_id) {
  let cdp = CDP.Vault.get(cdp_id);
  let hf = HealthFactor.compute(cdp.collateral, cdp.debt,
      Oracle.Dual.read(oracle1, oracle2));
  require(hf < LIQUIDATION_THRESHOLD, ErrorCodes.STILL_HEALTHY);
  LiquidationAuction.Dutch.start(cdp.collateral, cdp.debt);
}
```

Each example demonstrates multi-axis composition: Value + Coordination + Price + Trust + Observability all present.

## 11. Cross-Cutting Design Principles

These are PR-review constraints. Violations block merge.

1. **DeFi-first taxonomy.** Axes reflect what contracts do with value; names use developer vocabulary.
2. **Safe by default; opt into risk.** No bounce handler → no compile. `bounce=false` requires comment and test.
3. **Composable mixins, not inheritance.** FunC / Tolk have no OO; composition is `#include` + non-overlapping op / role / error-code / storage namespaces, machine-checked.
4. **TL-B first.** Every public op has a schema; raw-slice code in mixins is a lint violation.
5. **Explicit money paths.** Outgoing value / forward fee / excess-refund flow through one macro call; hidden `send_raw_message` discouraged.
6. **Explicit async boundaries.** Any code that sends and expects a reply routes via `ReplyRouter`. "I'll handle it in another recv_internal" is banned.
7. **Invariants as code.** Manifest invariants compile to runtime asserts (debug) and property tests (CI).
8. **Upgrade lane declared.** Every mixin declares class: layout-stable, migration-required, or upgrade-forbidden.
9. **FunC / Tolk parity.** FunC and Tolk mixins compile to identical ops, schemas, error codes. No wrappers, no glue. Any future typed dialect adopted by the project must join the same parity contract.
10. **Reference impl + conformance suite + cookbook + attack suite.** Every primitive ships all four.
11. **Primitive contracts are the source of truth.** The 7-field template (§6) is required; description without contract is not a primitive.
12. **Ecosystem-positive by default.** MIT / Apache-2 dual license; public RFC for extensions; audit evidence published with each release (see §14).

## 12. Testing and Audit Obligations

- **Property-based tests per mixin.** Standard invariants: balance conservation, no orphan reply-router, saga completeness, rent safety, AMM k monotonicity, reward precision bounds.
- **Message-tree fuzzer.** Random schedules of bounces, drops, permitted reorderings.
- **Attack suite per scenario.** Reference contracts must pass canonical adversary contracts (sandwich, flash-loan manipulator, oracle manipulator, JIT LP, saga-interruption, donation, precision-drift, initialization-race, carousel, replay, governance-flash-loan).
- **Gas + rent simulator.** Per release, per reference contract.
- **Deterministic replay.** Sandbox runs reproducible bit-for-bit from seed.
- **Mainnet fork replay.** Sandbox consumes a snapshot of mainnet state and replays proposed migration; required before any layout-changing upgrade.
- **Formal verification hooks.** TL-B schemas emit Coq / Isabelle skeletons; critical invariants (fund conservation, rent safety, carousel rejection) are proof-target-able.
- **Audit playbook.** Per-axis checklist auditors apply uniformly.
- **Static analysis.** Lints: missing bounce handler, raw `send_raw_message`, unregistered error code, overlapping op / role / storage range, out-of-bound slice, missing `SupportsOp`, undeclared consistency level, unguarded share vault.

Tooling lives in `tools/tos-stdlib/`. A mixin without full evidence stays `experimental`.

## 13. Cross-Workchain Semantics

| Axis | wc=0 (TOS) | wc=1 (EVM) | wc=2 (Uno shielded) |
|------|------------|------------|---------------------|
| 0 Primitives & Codecs | Native | Solidity lib port | Shielded-aware variants |
| Value Accounting | Native | Bridged as ERC-20/721 on wc=1 | Shielded equivalents from Orchard |
| Coordination | Native | Not applicable (EVM synchronous) | With shielded carrier |
| Price & Invariants | Native | Solidity lib via wc=1 | Shielded-AMM requires separate design |
| Time | Native | Adapted to wc=1 block model | Native |
| Trust & Provenance | Native | ECDSA / EIP-712 | Shielded-key variants |
| Composition | Native | Complementary | View-key support |
| Lifecycle | Native | Proxy pattern | Native |
| Observability | Native | EVM log semantics; topic-mapped | Selective disclosure |

Shielded stdlib family derives per [uno-workchain.md](uno-workchain.md) in phase L.5+.

## 14. Ecosystem and Governance

- **License.** MIT OR Apache-2.0 dual (contributor chooses). No GPL code in stdlib.
- **RFC process.** New primitives enter as `experimental` via RFC: motivation, design, alternatives, security, open questions. Graduation to `beta` requires: reference impl, conformance suite, attack suite, cookbook entry. Graduation to `GA` (Level 1 under [tos-standards-map.md](tos-standards-map.md)) requires: external audit, 90-day mainnet soak, no critical issues.
- **Audit funding.** Three-tier pool: foundation-paid for core (Axis 0, Coordination), grant-paid for ecosystem extensions, user-paid for niche variants. Audit reports public.
- **Governance.** Stdlib repository governed by a technical steering committee (5 members, quarterly rotation) with public RFC decisions. Emergency security fixes may bypass RFC with retroactive review.
- **Naming rules.** `tos-stdlib-*` reserved; forks must not use this namespace.
- **Compatibility matrix.** Each release states compatibility with: FunC compiler version, Tolk version, Blueprint version, TON core protocol version.

## 15. Relation to Existing TOS Efforts

- **[tos-tep-token-standards.md](tos-tep-token-standards.md)** — canonical wire protocol; stdlib provides audited reference implementations and composable extensions.
- **[tos-account-permission-model.md](tos-account-permission-model.md)** — Trust axis consumes directly via `AccountPermission.Binding`.
- **[actor-v3.md](actor-v3.md)** — execution model.
- **[smc-guidelines.md](smc-guidelines.md)** — TON-inherited authoring guidelines; stdlib must not contradict.
- **[tos-standards-map.md](tos-standards-map.md)** — Axis 0 + L.1 primitives promote to Level 1; extensions start at Level 2.
- **[tos-evm-workchain-feasibility.md](tos-evm-workchain-feasibility.md)** — EVM workchain ships Solidity path; this stdlib is the TVM-side complement.
- **[uno-workchain.md](uno-workchain.md)** — shielded workchain derives its own stdlib family.
- **[tooling-consolidation-design.md](tooling-consolidation-design.md)** — test-CLI (Foundry-for-TVM) tracked there, not here.

## 16. Open Questions

Resolve before L.1 GA unless noted.

1. **Package layout.** Single repo `tos-stdlib/` with per-axis subdirs, or per-axis repos? Current lean: single repo, atomic cross-axis changes > independent versioning.
2. **Versioning.** Per-mixin SemVer inside whole-library release train; `experimental` mixins until conformance + audit lands.
3. **TL-B codec generator.** Extend upstream `tlbc` for typed FunC / Tolk / TypeScript emit; do not fork.
4. **Audit funding allocation.** Three-tier (see §14) — ratio to be set by foundation + DAO.
5. **Foundry-for-TVM.** Wrap Blueprint / Sandbox or collaborate upstream; tracked separately.
6. **Intent settlement venue.** `IntentPool` on-chain (slow, trustless) vs off-chain batch (fast, needs slashing). Lean: ship on-chain first, enable batch in L.6 once `SolverRegistry` audited.
7. **Rent-sponsor economics.** Protocol fee split / grant pool / user opt-in. Decide before L.3.
8. **Cross-chain trust registry governance.** `ContractRegistry` bridges must not become single-admin; governance model borrowed from `CodeRegistry`.
9. **Tolk migration timing.** Deliver stdlib in FunC first with Tolk interop, or Tolk-native from L.1? Current lean: FunC reference in L.1; Tolk mirror in L.2; both GA together from L.2 onward.
10. **Formal verification scope.** Which invariants are proof-targets (fund conservation, carousel rejection, rent safety) vs property-test-only? Decide before L.3.
11. **Insurance fund capitalisation.** Protocol-owned, token-backed, or premium-only? Decide before L.5.
12. **Orderbook residency.** On-chain CLOB vs solver-matched off-chain with on-chain settlement. Decide before L.6.

---

## Appendix A — Exemplar Primitive Contracts

Five primitives filled in per the §6 template to establish the rigour bar.

### A.1 `RewardPerShare`

**Storage (TL-B).**
```
reward_per_share_state$_
  acc_reward_per_share: uint256   // scaled by 1e18
  last_update_time: uint32
  reward_rate: uint128            // rewards/sec
  total_shares: uint256
  = RewardPerShareState;
```

**Ops.**
| op_id | name | body | reply | bounce | required value |
|-------|------|------|-------|--------|----------------|
| 0x3000 | `update` | `now: uint32` | — | — | 0 |
| 0x3001 | `pending` (get-method) | `user_shares, user_debt` | `amount: uint256` | N/A | N/A |

**Invariants.**
- `acc_reward_per_share` monotonic non-decreasing.
- For all users, `pending(u) ≥ 0`.
- Rounding: `Math.Rounding.FavorProtocol` on division (leaves ≤ 1 wei dust per update).
- If `total_shares == 0`, `update` is a no-op (not a div-zero).

**Failures.**
| code | condition | recovery |
|------|-----------|----------|
| 3100 `STALE_UPDATE` | `now < last_update_time` | Skip update |
| 3101 `OVERFLOW` | `acc * reward > 2^256` | Trap — protocol has exceeded design limits |

**Composition.**
- Requires: `Axis 0.Math.Fixed` (UD60x18 or equivalent), `ValueLedger`.
- Compatible with: `BoostMultiplier`, `GaugeController`, `EmissionSchedule.*`.
- Storage namespace: `reward_per_share/`.

**Gas.** ~2.5k TVM gas per `update`; ~1k per `pending`.

**Rent.** 2 cells persistent; ~0.1 TON/year at current rent rates.

### A.2 `CarouselGuard`

**Storage.**
```
carousel_state$_
  version: uint64   // monotonic state-version tag
  = CarouselState;
```

**Ops.** Used via library macros `begin(state_ref) -> tag`, `expect_reply(tag, handler)`, `check_reply(tag) -> ok|stale`.

**Invariants.**
- `version` monotonic strictly increasing on any user-visible state mutation.
- Reply with `tag < current_version` rejected (stale).
- No persistent per-request storage — composes with `ReplyRouter` for continuation memory.

**Failures.** `3200 CAROUSEL_STALE` — reply rejected.

**Composition.** Requires `ReplyRouter`. Incompatible with nothing; additive.

**Gas.** ~200 TVM gas per begin / check.

**Rent.** 1 cell persistent per contract; negligible.

### A.3 `SagaCoordinator`

**Storage.**
```
saga_state$_
  saga_id: uint64
  step: uint16             // current step index
  total_steps: uint16
  compensations: ^Cell     // list of (step_id, target_addr, compensation_op, body_cell)
  status: uint2            // 0=running, 1=committed, 2=compensating, 3=aborted
  origin: MsgAddress
  = SagaState;
```

**Ops.**
| op_id | name | body | reply | bounce | value |
|-------|------|------|-------|--------|-------|
| 0x2100 | `start` | `total_steps: uint16, origin: MsgAddress` | saga_id | — | fees |
| 0x2101 | `step_ok` | `step: uint16, compensation: (addr, op, body)` | — | — | 0 |
| 0x2102 | `step_fail` | `step: uint16, reason: uint32` | — | — | 0 |
| 0x2103 | `compensate` | `from_step: uint16` | — | handler runs compensation | fees × (from_step+1) |

**Invariants.**
- For any saga with N steps, there are ≥ N compensations registered by commit; lint enforces.
- `step_fail` at step k triggers compensation for steps `k-1, k-2, ..., 0` in reverse.
- `status` transitions are strictly `running → (committed | compensating) → (done | aborted)`; no backward transitions.
- Saga in `compensating` cannot accept new `step_ok`.

**Failures.**
| code | condition | recovery |
|------|-----------|----------|
| 2200 `SAGA_MISSING_COMPENSATION` | commit attempted without all compensations | lint-caught; runtime trap if bypassed |
| 2201 `SAGA_DOUBLE_FAIL` | `step_fail` in non-running state | Ignore |
| 2202 `SAGA_COMPENSATION_BOUNCED` | compensation step itself bounced | Manual intervention via `EmergencyMultisig` |

**Composition.** Requires `ReplyRouter`, `BounceHandler`, `GasForwarder`. Compatible with `Saga.Nested`.

**Gas.** ~5k per step_ok; compensation chain scales linearly.

**Rent.** Saga state freed on terminal status transition; `RentSponsor` can be attached for long-running sagas.

### A.4 `HealthFactor`

**Storage.** Stateless — computed from inputs.

**Ops.** Get-method `health_factor(collaterals: list, debts: list, prices: list, ltvs: list) -> UD60x18`.

**Invariants.**
- `HF = Σ(collateral_i × ltv_i × price_i) / Σ(debt_i × price_i)`.
- `HF` returned in `Math.Fixed.UD60x18`.
- All prices must come from an oracle with manifest-declared manipulation cost ≥ consumer threshold.
- Empty debt → `HF = infinity` (encoded as max UD60x18).
- Division by zero never traps — infinity encoding is the contract.

**Failures.**
| code | condition | recovery |
|------|-----------|----------|
| 3301 `PRICE_STALE` | any price older than oracle staleness threshold | Caller refuses decision |
| 3302 `PRICE_INSUFFICIENT_MANIPULATION_COST` | oracle manipulation cost < threshold | Caller refuses decision |

**Composition.** Requires `Oracle.*`, `Math.Fixed.UD60x18`. Compatible with all liquidation auctions.

**Gas.** ~3k + n × 500 for n collateral/debt entries.

**Rent.** N/A (stateless).

### A.5 `IntentPool`

**Storage.**
```
intent_pool_state$_
  intents: ^(HashmapE 256 IntentEntry)  // content_hash -> entry
  open_count: uint32
  = IntentPoolState;

intent_entry$_
  intent: ^IntentCell
  user_sig: bits512
  user: MsgAddress
  submitted_at: uint32
  claimed_by: (Maybe MsgAddress)
  = IntentEntry;
```

**Ops.**
| op_id | name | body | reply | bounce | value |
|-------|------|------|-------|--------|-------|
| 0x2300 | `submit` | `intent, sig` | `content_hash` | refund submitter | submitter pays fees |
| 0x2301 | `claim` | `content_hash` | `intent_body` | release claim | solver pays fees + bond lock |
| 0x2302 | `fulfill` | `content_hash, proof` | — | solver slashed | settlement |
| 0x2303 | `cancel` | `content_hash, user_sig_cancel` | — | — | small fee |
| 0x2304 | `expire` | `content_hash` | — | — | 0 |

**Invariants.**
- `content_hash = StructuredMessage.hash(intent)`.
- An intent can be claimed by exactly one solver; second claim fails.
- Expired intents (`now > valid_until`) cannot be claimed.
- Cancelled intents cannot be claimed.
- Every claim locks solver bond ≥ `intent.want_at_least`; unlock on fulfillment, slash on timeout.
- `MessageHashLedger` prevents re-submission of identical intent within the expiry window.

**Failures.**
| code | condition | recovery |
|------|-----------|----------|
| 2400 `INTENT_SIGNATURE` | `user_sig` invalid | Reject submission |
| 2401 `INTENT_EXPIRED` | `now > valid_until` at claim | Reject claim |
| 2402 `INTENT_ALREADY_CLAIMED` | claim on already-claimed | Reject |
| 2403 `INTENT_INSUFFICIENT_BOND` | solver bond < threshold | Reject claim |
| 2404 `INTENT_FULFILL_UNVERIFIED` | proof invalid at fulfill | Slash solver |

**Composition.** Requires `SolverRegistry`, `StructuredMessage`, `MessageHashLedger`, `ReplyRouter`, `BounceHandler`. Compatible with `MetaIntent`, `Paymaster`.

**Gas.** ~4k submit; ~3k claim; ~5k fulfill.

**Rent.** Per-intent cells freed on fulfill / expire / cancel.

---

## Appendix B — FunC Transcription of Cookbook Examples

*(Skeleton — detailed FunC spelling lives in `doc/tos-stdlib-cookbook/`. This appendix demonstrates that every §10 pseudo-code example has a direct FunC analogue at the op-code level.)*

```func
;; 10.1 Jetton wallet — FunC transcription skeleton
#include "stdlib/value_accounting/jetton_wallet.fc"
#include "stdlib/coordination/dispatch.fc"

() recv_internal(cell in_msg_full, slice in_msg_body) impure {
    DISPATCH_BEGIN(in_msg_full, in_msg_body)
        DISPATCH_OP(op::jetton_transfer,          on_transfer)
        DISPATCH_OP(op::jetton_burn,              on_burn)
        DISPATCH_OP(op::jetton_internal_transfer, on_internal_transfer)
    DISPATCH_END()
}

() recv_bounced(cell in_msg_full, slice in_msg_body) impure {
    BOUNCE_ROUTE_BEGIN(in_msg_body)
        BOUNCE_HANDLE(op::jetton_transfer, refund_transfer)
    BOUNCE_ROUTE_END()
}
```

Identical `op_id` values, identical TL-B body schemas. `DISPATCH_BEGIN` / `BOUNCE_ROUTE_BEGIN` expand to envelope-parse + bounce-aware `recv_internal` scaffolding. A developer may hand-write `recv_internal` directly, but must still emit the same op codes and pass the same lints.

---

**End of design.** Next documents:
- `tos-stdlib-L1-scope.md` — exact file list, TL-B schemas, conformance / attack tests, audit envelope for L.1.
- `tos-stdlib-dependencies.md` — full primitive DAG, machine-checkable.
- `tos-stdlib-cookbook/` — FunC + Tolk full walkthroughs per scenario.
- `tos-stdlib-attack-suite.md` — canonical adversarial scenarios.
- `tos-stdlib-rfc-process.md` — contribution and graduation workflow.
- `tos-stdlib-ecosystem-survey.md` — detailed position vs ton-core / Tolk / OZ / Uniswap / Curve / Balancer.
