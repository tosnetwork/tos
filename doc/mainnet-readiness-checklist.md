# TOS Mainnet Readiness Checklist

> **Honest assessment as of 2026-05-15** (HEAD `58a2b7292`, post-Phase-EE).
> This document is the canonical answer to "can we go to mainnet?".
> Each item is marked ✅ done, ⚠️ partial, or ❌ blocked.  Items
> marked ❌ are NOT engineering gaps — they require operational
> resources, time, or external parties that this repo cannot
> conjure.

---

## 1. Engineering correctness

### 1.1 wc=0 (base TOS)

| Item | Status | Evidence |
|---|---|---|
| TOS-native state model | ✅ | Long-standing; same as TON-derived base |
| Validator quorum (128-bit) | ✅ | `validator-set.cpp` cap landed; `audit_tos3_2026_04_26` verified |
| Catchain consensus | ✅ | Production-tested in pre-TOS lineage |
| Independent fresh audit | ❌ | No post-tos18 audit has covered the base chain |

### 1.2 wc=1 (EVM)

| Item | Status | Evidence |
|---|---|---|
| Critical 9.2 trie-cache divergence | ✅ | Closed by `25f130fa2` (MPT removed entirely) |
| High 8.1 free-blockspace DoS | ✅ | `EvmTxDisposition::InvalidPreValidation` at `evm/core/compute-phase.cpp:518` |
| Medium 6.6 decoder canonical check | ✅ | `evm/core/cell-codec.cpp:384` + commitment cross-check at line 390 |
| 18 high-severity RPC/admission caps | ✅ | Codex iterative audit (see `audit_tos3_2026_04_26_iterative.md`) |
| Independent fresh audit (post-MPT-removal) | ❌ | The 0426 audit predates the architectural change |

### 1.3 wc=2 (UNO — privacy payments)

| Item | Status | Evidence |
|---|---|---|
| MineUno Phase 3b soundness | ✅ | `df7d3d01a` — soundness-complete per `mine_uno_phase3b_complete.md` |
| Carry-proxy (32 carry cells) | ✅ | `mine_uno_carry_proxy.md` documents the soundness requirement |
| `UNO_DEVNET_ALLOW_ENV_TARGET` gated | ✅ | Per 0426 audit `audit_tos3_2026_04_26.md` |
| Independent fresh audit | ❌ | Same status as base chain — no recent dedicated audit |

### 1.4 wc=3 (JVM — this audit arc's primary focus)

| Item | Status | Evidence |
|---|---|---|
| rt.jar contracts admitted (Wallet, Deployer, full stdlib) | ✅ | Phases A–E |
| System.sendMessage + System.createAccount primitives | ✅ | Phase H |
| Genesis seeding (wallets + deployers) | ✅ | Phase F + I |
| Address-binding gate (5-input domain-tagged hash) | ✅ | Phase J/N parity vectors |
| Deploy + call lifecycle | ✅ | Phase Q end-to-end test |
| Multi-validator replica convergence | ✅ | Phase R |
| Rust↔C++ codec parity (17 reference vectors) | ✅ | Phases J/K/L/M/N |
| Stdlib_hash algorithm alignment | ✅ | Phase DD (critical bug fix) + Phase EE direct parity test |
| tosctl jw CLI end-to-end | ✅ | Phases P/S |
| Genesis ceremony rehearsal | ✅ | Phase X |
| rt.jar reproducible build + CI gate | ✅ | Phases V/W/Z/AA |
| Validator runbook | ⚠️ | Phase T draft; some TBDs remain (metric names, db paths) |
| DoS hardening inventory | ✅ | Phase U |
| Independent external audit | ❌ | Self-audit only; no third-party review |

### 1.5 Cross-workchain

| Item | Status | Evidence |
|---|---|---|
| `action_create_account` policy gates | ✅ | wc=3 admits via Phase Q TLB tests; wc=1 uses standard policy |
| Cross-workchain message routing | ⚠️ | Code exists; not stressed at multi-validator scale |

---

## 2. Operational readiness

### 2.1 Testnet

| Item | Status | Path forward |
|---|---|---|
| Internal devnet (single-validator) | ⚠️ | Exists for development; not load-tested |
| Public testnet (multi-validator) | ❌ | **MUST RUN ≥4 weeks before mainnet decision.**  Without this the latent bugs that first-principles audit can't predict (catchain edge cases, network partition recovery, real-world misbehavior) cannot surface. |
| Testnet bring-up rehearsal | ✅ | `scripts/jvm-testnet-genesis-rehearsal.sh` produces canonical ShardState BOC |
| Testnet validator set committed | ❌ | Operational decision; not in repo |

### 2.2 Validator operations

| Item | Status | Evidence |
|---|---|---|
| Hardware spec documented | ✅ | `doc/jvm-validator-ops.md` §2 |
| Software prerequisites pinned | ✅ | `doc/jvm-rt-reproducibility.md` + Phase Z Dockerfile |
| rt.jar canonical hash committed | ✅ | `ae4ff3b7...e5ade765` (Phase DD) verified at HEAD `58a2b7292` |
| Monitoring metrics defined | ⚠️ | Names placeholder in runbook; instrumentation pending |
| Disaster recovery runbook | ⚠️ | Draft in `jvm-validator-ops.md §8`; some TBDs |
| Multi-validator stress test on real hardware | ❌ | Only Phase R unit-level convergence; no production-grade load test |

### 2.3 Security

| Item | Status | Path forward |
|---|---|---|
| Internal first-principles audit | ✅ | 35+ phases (rounds 1–168 + Phase O–EE arc); found Phase DD's critical bug |
| External audit (Trail of Bits / ConsenSys / Halborn class) | ❌ | **Required before mainnet.**  4–8 week engagement; budget per workchain |
| Bug bounty program | ❌ | Operational decision; needs funding + disclosure policy |
| Penetration test on staging validator | ❌ | Needs running infrastructure |
| Responsible disclosure policy published | ❌ | Operational |

### 2.4 Network parameters

| Item | Status | Path forward |
|---|---|---|
| ConfigParam 85 canonical values | ✅ | `JvmConfig::default_activation()` defaults; stdlib_hash via Phase DD canonical algorithm |
| Initial validator set | ❌ | Governance decision |
| Initial staking economics | ❌ | Business decision |
| Token distribution genesis | ❌ | Business decision |
| Inflation / fee burn parameters | ❌ | Business decision |

### 2.5 Ecosystem

| Item | Status | Path forward |
|---|---|---|
| Block explorer (any) | ❌ | Out of scope; separate system |
| Indexer for events | ⚠️ | Event signature registry exists (Phase BB); indexer service not built |
| Mobile / desktop wallet | ❌ | Out of scope; separate product |
| Browser extension (MetaMask-class) | ❌ | Out of scope |
| Developer documentation portal | ⚠️ | `doc/jvm-*.md` exist but no unified dev portal |
| Reference contract examples | ⚠️ | `jvm/avata/test/` has standalone tests but no curated example library |

---

## 3. The honest gap

**Engineering correctness**: substantially complete.  The wc=3 JVM
work is the most rigorously audited of the four workchains; the
EVM workchain has had its known critical issues closed.  No known
open Critical/High consensus bugs.

**Operational readiness**: the largest remaining gap.  No serious
chain has gone to mainnet without:

  * **≥4 weeks of public-testnet operation** under adversarial
    conditions — every chain that skipped this has had a bad time.
  * **External security audit** by a third party with no skin in
    the game.  Internal audits cannot replace this; the auditor's
    incentive structure matters.
  * **Multi-validator stress test on production-grade hardware**
    showing the chain can sustain target TPS through real network
    conditions (partitions, slow peers, byzantine actors).

These three items are **not** engineering gaps.  No amount of
first-principles auditing from this terminal can close them.

**Economic + ecosystem**: separate concerns from this checklist.
They block mainnet utility but not mainnet correctness.

---

## 4. Recommended path forward

### Phase 1 — Closed testnet (4–6 weeks)

1. Stand up 5–10 validators on real hardware (cloud or self-
   hosted), running the post-Phase-EE binary.
2. Generate a canonical zerostate via
   `scripts/jvm-testnet-genesis-rehearsal.sh` with real launch
   keypairs.
3. Open to a small set of invited developers; ask them to
   actively try to break things.
4. Maintain a public bug log.  Every bug found here is one that
   would have hit mainnet.
5. Fix discovered issues; track via Phase-numbered commits as the
   audit arc has done.

### Phase 2 — Public testnet (4–8 weeks)

1. Open to the public.  Announce a faucet, sample contracts.
2. Run an external security audit in parallel.  4–8 week
   engagement.
3. Bug bounty program: $10K–$50K tier for critical findings,
   smaller tiers for less severe.
4. Run a multi-validator stress test once a week, document
   results.

### Phase 3 — Pre-mainnet (2–4 weeks)

1. Address all findings from the external audit (or have explicit
   "accepted risk" sign-off for any deferred items).
2. Either re-audit or have the original auditor sign off on the
   fixes.
3. Finalize ConfigParam values (gas prices, validator set, token
   distribution).
4. Run a final dry-run genesis ceremony — execute the same
   sequence the real mainnet launch will, but to a throwaway
   chain.

### Phase 4 — Mainnet launch

1. Genesis ceremony.
2. Validator activation.
3. Standby for hotfix on day-1 issues.

---

## 5. Bottom line

**Is the engineering complete?** Substantially yes.  No known
critical bugs; cross-implementation parity locked; reproducible
builds; comprehensive doc set.

**Is TOS ready for mainnet today?** No — and it would be a category
mistake to ship.  The remaining blockers (testnet operation,
external audit, validator infrastructure) are operational, not
engineering, but they are **not optional**.

**How long until mainnet is realistic?** 10–16 weeks of disciplined
execution of §4, assuming no major findings in external audit.
The conservative answer is "3–4 months from when Phase 1 starts."

The path is clear, the engineering is mature, and the remaining
work is well-defined.  The only mistake left to avoid is shipping
mainnet without doing the operational legwork that no amount of
code review can substitute for.
