# TOS Pre-Mainnet Security Audit — Native Core (wc=0)

**Date:** 2026-06-01
**Scope:** The Native (wc=0) workchain + masterchain (wc=-1) and all shared
core subsystems: consensus (Simplex + Catchain/validator-session), block
validation/collation, state/Merkle/cell layer, P2P network stack, genesis
economics & elections, and the crypto/key/signature layer.
**Out of scope (by request):** the three auxiliary workchains — EVM (wc=1),
Uno (wc=2), JVM (wc=3). These are activated by `ConfigParam 12` governance,
not by the binary, and are deliberately excluded from a native-only launch.
**Method:** One systematic round across 8 dimensions (parallel finder agents),
followed by adversarial verification of every surfaced High/Critical finding.
**Codebase:** HEAD at audit time, `/home/tomi/tos`.

---

## 1. Executive summary

The native core is a **faithful, hardened port of TON**. The state machine
(per-tx re-execution + hash compare, value conservation, ValueFlow
reconciliation, Merkle-update verification), the cell/BoC/Merkle layer, the
catchain + validator-session BFT fallback, and the crypto/signature layer
were all found to be sound, with TON's known cycle/overflow/abort hardening
present and correct.

**No TOS-introduced, confirmed Critical/High *runtime* vulnerability was
found.** The two findings initially rated High were both **downgraded under
adversarial verification** (see §4) — a good outcome that avoided risky,
unnecessary edits to the consensus and collation paths.

The genuinely actionable items are **not classic code exploits** but
**release-discipline and economic-parameter decisions** that the project
owner must make before mainnet:

| ID | Dimension | Title | Severity | Status |
|----|-----------|-------|----------|--------|
| **F1** | Genesis | Canonical `gen-zerostate.fif` still builds EVM/Uno/JVM + PoW givers | **Critical (release-process)** | Mitigated (banner) — owner decision pending |
| **F2** | Economics | Stake-limit set permits cheap 1/3 liveness veto | **High (economic)** | Owner decision pending |
| **F3** | Economics | Full 5M pre-mine + minter under one single-sig key | **High (custody)** | Owner decision pending |
| H-1 | Network | Overlay broadcast rate-limiters inert by default | Medium | Latent (upstream-inherited); hardening optional |
| S-2 | Simplex | Network equivocation not detected/slashed (`wants()` pre-filter) | Medium | Accountability gap, not a safety break |
| M-1a | Collator | lite-server `sendMessage` drops ADNL src → skips per-peer throttle | Medium | Confined (gas-credit bounds wc=0 cost) |
| M-1b | Network | FEC broadcast decode state can grow ~1 GB per in-flight broadcast | Medium | Bounded by H-1 fix / symbol-size floor |
| F4 | Economics | `min_validators` raised 3→4 across all templates+docs (BFT f=1 floor) | Medium | Fixed |
| S-1 | Simplex | Vote broadcast before durable persistence | Low (was High) | Downgraded — see §4.1 |
| C-1 | Collator | "Unbounded TVM DoS" from failing ext-messages | Refuted (was High) | Not a bug — see §4.2 |
| L-* | Various | Defense-in-depth items (see §6) | Low/Info | Selected fixes applied |

**Bottom line for mainnet:** the native chain has no known exploitable
consensus/state hole, but it must **not** be launched from the default
`gen-zerostate.fif` (F1), and the **stake economics (F2) and pre-mine custody
(F3) are launch-blocking *policy* decisions**, not code bugs. Independent
external review and ≥4 weeks of multi-validator public testnet remain
prerequisites (unchanged from the readiness checklist).

---

## 2. Scope & method

Eight dimensions were each audited by a dedicated agent reading the actual
source (grep + read, not pattern-matching):

1. **Simplex consensus** (`validator/consensus/simplex/`) — primary, novel.
2. **Block validation** (`validator/impl/validate-query.cpp`).
3. **Collation / mempool / ext-message admission** (`validator/impl/`).
4. **State / Merkle / cell / BoC** (`crypto/vm/`, `tdactor`, boc).
5. **Catchain + validator-session** BFT fallback.
6. **P2P network** (`adnl/ overlay/ dht/ rldp/ rldp2/ quic/`).
7. **Genesis / economics / elections** (`gen-zerostate*.fif`, elector, mc-config).
8. **Keys / signatures / crypto** (`keys/`, `crypto/Ed25519`, sig call-sites).

Every High/Critical was then handed to a **skeptical verifier agent** tasked
to *refute* it (default: not-a-bug unless the code proves otherwise). Two of
two original Highs were refuted/downgraded.

---

## 3. Confirmed launch-blocking items (owner decisions)

### F1 — Critical (release-process): canonical mainnet template ships unaudited chains

`crypto/smartcont/gen-zerostate.fif` — the file whose name marks it as *the*
mainnet template — still registers wc=1 (EVM), wc=2 (Uno), wc=3 (JVM) and
still `include`s `etos-pow-givers.fif` (10 PoW givers, each pre-funded 10M
eTOS). The native-only decision was only applied to `zerostate.py` (tostester)
and the separate `gen-zerostate-wc0-only.fif`; the canonical `.fif` and
`gen-zerostate-test.fif` were left as four-chain templates.

The wc=2/wc=3 states are explicitly `TODO`/empty and flagged *not launch
ready* in their own comments. Launching from this template would ship the
three excluded, unaudited workchains plus a PoW-giver eTOS mint — directly
contradicting the "5M fully pre-mined, no givers" model.

This is not a runtime exploit; it is a **release trap**. The fix is to make
the safe path the default. A `LAUNCH-SAFETY` banner has been added to the two
four-chain templates pointing operators at `gen-zerostate-wc0-only.fif`.
**Owner decision needed:** make `gen-zerostate-wc0-only.fif` the canonical
mainnet template (rename / retire the four-chain templates to a clearly
post-launch name), so the default name cannot be misused.

### F2 — High (economic): stake limits permit a cheap 1/3 liveness veto

Current `ConfigParam 17` / 16: `min_stake=10K, max_stake=100K,
min_total_stake=10K, max_stake_factor=10.0`, `min_validators=4,
max_validators=40`, against a **5M** total supply. With a small early
validator set, a party controlling >1/3 of *weight* can block the ≥2/3
quorum (halt/censor). `min_total_stake=10K` (one single min-stake) lets an
election finalize a tiny-total-stake set where a marginal party dominates.

This is an **economic parameterization choice**, not a code defect — the
overflow/zero-weight guards (`tos/quorum.h`, `mc-config.cpp:701`) are sound.
**Suggested hardening:** raise `min_total_stake` to ≥ N×`min_stake` for the
target validator count, lower `max_stake_factor` (e.g. 3) to flatten weight
concentration, and raise `min_validators` (e.g. 7) so a 1/3 veto requires
more independent parties. Final values are the owner's call.

### F3 — High (custody): single key controls 100% of supply and the minter

`gen-zerostate.fif` pre-mines the entire 5M TOS to one v3 single-sig wallet
*and* sets that same address as `ConfigParam 2` (the minter recipient for any
`config.to_mint` extra-currency delta; base TOS supply is **not** inflatable —
`collator.cpp:2342` excludes base grams — verified). One Ed25519 key
(`main-wallet.pk`) is therefore a total single-point-of-failure for the entire
economy. The two hard-coded extra-currencies `to_mint` (#-17, #239) appear to
be copied TON test values.

**Suggested hardening:** move the pre-mine to a multisig/threshold custody
contract; decouple the minter address from the pre-mine wallet; set
`config.to_mint!` empty unless -17/239 are intentional TOS assets. This is a
custody/ops decision, not a code bug.

---

## 4. Adversarial verification of the original High findings

### 4.1 S-1 (was High → Low): "vote broadcast before durable persistence"

**Claim:** a validator broadcasts its Simplex vote before the RocksDB write is
durable; on crash-recovery it could sign a *conflicting* vote → slashable
self-equivocation/fork.

**Verdict: premise true, conclusion refuted.** The broadcast (`OutgoingProtocolMessage`)
is indeed published concurrently with, not after, the DB write. But
self-equivocation is prevented regardless:
- The write-side guard is **deterministic**: each slot notarizes the single
  pending candidate (`consensus.cpp:171,257,296`) — there is no source of a
  *different* value to sign on re-vote.
- Recovery **replays persisted votes** (`db.cpp:116-204` → `consensus.cpp:46-79`).
- A self-conflict hard-crashes via `LOG_CHECK("We produced conflicting votes!")`
  (`pool.cpp:694`) — crash-stop, not silent fork.

**Residual (Low):** RocksDB writes use `WriteOptions{sync=false}`, so a
*power-loss* (not clean crash) can lose a vote record. Consequence is liveness
(re-derive + re-vote), not safety. Optional hardening: `sync=true` on the vote
write and `co_await` persistence before broadcast (cost: one fsync of latency
per vote).

### 4.2 C-1 (was High → refuted): "unbounded TVM DoS from failing ext-messages"

**Claim:** failing external messages run a *full* TVM execution uncounted →
unbounded CPU DoS.

**Verdict: refuted.** The premise "failing message runs a full TVM" is false.
An external message carries **zero balance**, so `gas_limit` collapses to 0 and
the VM runs only on a small fixed `gas_credit` (~10k), aborting when credit is
exhausted (`transaction.cpp:1605-1609`, `vm.h:77`). A failing message never
reaches ACCEPT, so it cannot raise its own limit to `gas_max`
(`transaction.cpp:1604`). `stop_on_accept_message` halts even accepting
messages at ACCEPT (`external-message.cpp:169`). The genuinely expensive Uno
STARK-verify path **does** have layered per-peer + per-kind rate limiters
consumed before any verify work (`ext-message-pool.cpp:622-636`). This is the
standard TON gas-credit admission defense, present and active.

**Residual (Medium, M-1a):** the lite-server `liteServer_sendMessage` path
drops the ADNL `src`, so the per-peer Uno bucket is skipped for direct
lite-client connections (`manager.cpp:813-832`). Confined: global Uno buckets
still apply, and wc=0 TVM cost is gas-credit-bounded regardless of attribution.

---

## 5. Verified-sound subsystems (no TOS-introduced issue)

- **Block validation** (`validate-query.cpp`): all *disabled* checks
  (split/merge prepare/install, IHR import/discard, deferred-when-disabled)
  are **fail-closed** (`reject_query`) — safe to keep disabled. Core state
  transition (re-execute + hash compare, value conservation, ValueFlow) intact.
- **State / Merkle / cell / BoC**: faithful hardened TON port; the ported
  `ton/1b05d621` cycle-guards (visited-set dedup in MerkleProof/MerkleUpdate)
  are present and correct; BoC topological constraint prevents cycles;
  state-forgery resistant.
- **Catchain + validator-session**: faithful TON port. Every approve/vote/
  precommit/commit verifies the signer's signature over `(root_hash,file_hash)`;
  duplicate/double-vote rejected; weight accounting uses
  `checked_add_validator_weight` (zero-weight + overflow guarded); DAG block
  validation (incarnation/height/src/linkage/deps) intact.
- **Crypto / keys / signatures**: faithful TON port with verification intact.
  Ed25519 verify returns OK only on success; ADNL handshake verifies the
  signature before deriving identity (no MITM gap); consensus signatures are
  domain-separated via `consensus_dataToSign{session_id, data}` (no
  cross-session replay); Simplex certificate verification bounds-checks
  indices, rejects duplicate signers, overflow-guards weight, and verifies
  **every** signature individually. No private keys logged; randomness via
  `td::Random::secure_bytes` / OpenSSL.

### Note on the quorum threshold (Catchain TOS-1, Info — by design)

`tos/quorum.h` deliberately uses `≥ ceil(2N/3)` (the standard Tendermint /
HotStuff / PBFT BFT-2/3 convention) rather than TON's strict `> floor(2N/3)`.
The file documents this (lines 42-55): the two differ only when N is divisible
by 3, and the `f < N/3` safety claim holds equally for the `≥` form. For very
small equal-weight sets (N=3) this tolerates f=0 only — i.e. N=3 provides no
Byzantine fault tolerance regardless. **Operational note, not a bug:** launch
with N ≥ 4 (preferably ≥ 7, per F2) so the set actually tolerates a fault.

---

## 6. Lower-severity items

- **H-1 (Medium, network):** `OverlayOptions::{unauth,auth}_broadcast_{,size_}rate_limit_`
  default to `{}` (`duration=0` → `RateLimiterWindow::check` returns `true`),
  so the broadcast flood limiter is inert. **This is inherited verbatim from
  upstream ton-c** (which also never sets these), so it is a latent
  upstream weakness, not a TOS regression. Public overlays (shard/fast-sync,
  which accept unauthorized broadcasts) thus have no per-source broadcast
  cap; signature-check + FEC-decode CPU and re-broadcast amplification are
  attacker-driven. *Hardening (optional, needs testnet tuning to avoid
  starving legitimate consensus broadcasts):* set conservative non-zero
  defaults (e.g. unauth 30 msgs / 4 MB per 60 s; auth far higher).
- **M-1b (Medium, network):** FEC broadcast `received_parts_`/`parts_` bounded
  only by `seqno < symbols_count*2+4` with `symbol_size` min = 1, so a single
  16 MB broadcast can hold ~32M parts (~hundreds of MB–GB) before 60 s GC.
  *Fix:* enforce a `symbol_size` floor (TON uses 768) in `FecType::create`.
- **S-2 (Medium, Simplex):** network equivocation is never detected because
  `Pool::wants()` (`pool.cpp:418`) pre-filters before `add_vote`, so a
  Byzantine peer can equivocate via bare votes without being slashed.
  Accountability gap; does not break safety/liveness of honest quorum.
- **F4 (Medium → Fixed):** `min_validators` was inconsistent (3 in the `.fif`
  templates, 4 in `zerostate.py`) and the production floor of 3 gave zero BFT
  fault tolerance. Raised to **4** uniformly across all genesis templates,
  `zerostate.py`, and the bootstrap doc; the local testnet was expanded from 3
  to 4 nodes (`setup-testnet.sh`, `testnet-ctl.sh`, `Validator-Local.md`) to
  stay self-consistent. 4 is the smallest set tolerating 1 fault; ≥7 is
  recommended for mainnet (see F2).
- **L — `debug_checks_` dead code** (`validate-query.cpp:1799-1802`): neighbor
  `OutMsgQueueInfo` structural validation is unreachable (flag never set true).
  Downstream redundant validation covers consensus; defense-in-depth only.
- **L — QUIC global new-connection limiter** (`quic-server.h:60-61`):
  `period=1e-5 s` makes the global cap a no-op; per-IP cap (10/0.2s) holds.
- **L — Uno ext-msg limiter is process-global static** (cross-shard shared).
- **L — `MerkleProofCombineFast::merge` CHECK-abort** (`MerkleProof.cpp:215`)
  on peer-supplied proofs — convert to `td::Status::Error` to avoid
  process-abort DoS.
- **L — placeholder genesis validator** (`gen-zerostate.fif:306-309`): the
  `keys-from-file=false` default appoints a hard-coded public key. Mainnet
  must use `load-keys-from-file` with a real `validator-keys.pub`.
- **L — `move_as_ok()` aborts** in `validator/consensus/types.cpp:28` and
  `keys/keys.cpp:118-126` — not attacker-reachable (trusted inputs); propagate
  errors for robustness.

---

## 7. Pre-mainnet checklist (unchanged prerequisites)

1. ☐ **F1**: switch the canonical mainnet zerostate to native-only.
2. ☐ **F2**: finalize stake economics (min_total_stake, max_stake_factor,
   min_validators) for the 5M supply.
3. ☐ **F3**: move the 5M pre-mine to multisig/threshold custody; decouple minter.
4. ☐ Independent external security review (this internal audit is not a substitute).
5. ☐ ≥ 4 weeks public multi-validator testnet with adversarial load.
6. ☐ Launch with N ≥ 7 independent validators (per F2 / TOS-1).
7. ☐ Optional hardening: H-1 limiter defaults, M-1b symbol-size floor,
   S-1 sync vote write, M-1a lite-server attribution.

---

*This is an internal pre-mainnet audit of the native (wc=0) core. It does not
cover the EVM/Uno/JVM auxiliary workchains and is not a substitute for an
independent third-party review.*
