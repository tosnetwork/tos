# UNO v1 Testnet Burn-In Plan

> **Scope.** Strategic plan for the 60-day public testnet burn-in
> that gates UNO v1 mainnet. Post-pivot v1 architecture: per-Tx
> Plonky3 direct proofs, `BLOCK_TX_CAP = 4`, no block-level
> aggregation (`doc/uno-aggregation-design.md` §-1; commits
> `0116de520`, `42fdb46a7`, `b2d601a09`, 2026-04-21).
>
> The **operator bring-up runbook** lives in
> `doc/uno-testnet-runbook.md` ("how do I stand up a node").
> This document is the companion plan ("what does the 60 days
> need to prove, and how do we know we passed").

---

## 1. Objectives

UNO v1 mainnet activation is gated by a single 60-day public testnet
run on `workchain_id = 2` (testnet variant). The testnet exists to
answer one question: **is the v1 per-Tx-direct build deterministic,
operationally boring, and decentralization-achievable on commodity
hardware for 60 consecutive days?** The run follows the existing TOS
pre-mainnet pattern for wc=0 / wc=1: opt-in validator set, same
binary as mainnet, separate network id, published genesis and
day-60 sign-off gate. It is the V1-4 phase in
`doc/uno-aggregation-design.md` §4.1 and the final step before the
wc=2 mainnet fork block.

Non-goals: benchmarking aggregation (v2 research); multi-asset flows
(v2); bridges (never, `uno-workchain.md` §1.5); > 4 TPS throughput
(intentional v1 ceiling, §1.4 #7).

---

## 2. Success criteria (quantitative gates)

Gates below are measured on a **7-day rolling window** and must
hold continuously for the final 30 days of the 60-day run (§7).
Gates marked "TBD measured" have no baseline yet — week-1/2 of
burn-in sets the number, which then freezes for the remaining 45
days.

| # | Dimension                         | Target                            | Floor (acceptable)               | Status  |
|---|-----------------------------------|-----------------------------------|----------------------------------|---------|
| 1 | Sustained TPS per wc=2 shard      | 4 TPS                             | ≥ 3.5 TPS                        | pinned  |
| 2 | Block finality (Simplex 2-round)  | < 1 s p50                         | < 1.2 s p95                      | pinned  |
| 3 | Per-Tx verify time, single core   | ~100 ms (4/4 shape, ~26 ms 1/2)   | p99 < 500 ms                     | pinned from §2.1 Option B measurement |
| 4 | Per-block verify time (4 × Tx)    | ~400 ms (parallel across 4 cores) | p99 < 1 s                        | pinned  |
| 5 | Per-block bandwidth               | 2 MB typical, 3.7 MB worst 4/4    | ≤ 4 MB                           | pinned from §-1 v1 architecture |
| 6 | Validator uptime                  | ≥ 95 % across ≥ 20 validators     | ≥ 90 % across ≥ 15 validators    | pinned  |
| 7 | Proof verify correctness          | 100 % accept on honest Tx         | error budget ≤ 1 / 10 000        | pinned  |
| 8 | Cross-validator state-root drift  | 0 divergences                     | **P0 halt on first occurrence**  | pinned (§12 P.5 determinism) |
| 9 | Wallet cold-sync time (genesis → tip) | ≤ 30 s at testnet cadence     | ≤ 60 s                           | TBD measured (week-1 baseline) |
| 10 | Compact-filter false-positive rate | empirical ≤ 2⁻¹⁶ over 1 M outputs | ≤ 2⁻¹⁴                         | TBD measured (§4.7 scenario) |
| 11 | Compact-filter false-negative rate | 0 (wallet always sees own notes) | **must be 0**                    | pinned |
| 12 | Nullifier lookup latency (10 M set) | ≤ 1 ms cache-warm, ≤ 10 ms cold | p99 ≤ 20 ms cold                 | pinned from §1.4 #5 |
| 13 | Consensus forks                   | 0 in 60 days                      | **P0 halt on first occurrence**  | pinned  |
| 14 | Proof-related hotfixes            | 0                                 | 0 critical, ≤ 2 non-critical     | pinned  |
| 15 | Validator hardware floor          | 4-core / 16 GB / consumer fiber   | see §3                           | pinned from §1.4a |
| 16 | Mempool memory ceiling under DoS  | ≤ 512 MB steady                   | ≤ 1 GB peak                      | TBD measured (§4.9 scenario) |
| 17 | Wallet scan throughput            | ≥ 1000 notes/s trial-decrypt      | ≥ 500 notes/s                    | TBD measured |

Gates #1, #2, #5, #6, #13 are the decentralization / throughput
numbers UNO's Zcash/Penumbra-class positioning depends on. Gates
#3, #4, #7, #8 are the proof-system correctness floor — any failure
is a mainnet blocker. Gates #9, #10, #17 are UX gates — failure
triggers re-scope, not abort.

---

## 3. Validator set composition

**Target**: 20–40 independently-operated validators. Below 15, the
decentralization signal is too weak to justify mainnet; above 40,
coordination overhead outweighs marginal diversity gain.

**Composition targets**:

- **Geographic**: ≥ 5 countries; no single country > 40 % voting weight.
- **Jurisdictional**: ≥ 3 legal jurisdictions.
- **Hosting**: ≥ 25 % home/residential-fiber operators (not only
  datacenter/VPS). This is the load-bearing decentralization signal
  given §1.4a's "4-core commodity achievable" framing. Missing this
  minimum fails gate #15 and delays mainnet.
- **Software**: all validators run the same pinned `uno` commit at
  genesis; per-validator divergence is an incident.

**Opt-in**: matches the existing wc=0/wc=1 pattern — wc=2 capability
advertised on masterchain via the standard validator-config
extension (`uno-workchain.md` §1.4a). No additional registration flow.

**Upgrade schedule**: two pre-announced windows at day 20 and day 40.
Hotfixes outside these windows require P0 justification (§6).
In-window upgrades target 48 h rolling restart; each operator runs
`test-uno-restart-survival` (§12 P.4) on the upgrade locally before
it reaches the shared testnet. Validators that fail local
restart-survival MUST NOT roll to the testnet.

---

## 4. Test scenarios

Each scenario is a numbered experiment with a definition,
success/failure condition, and the gate(s) it exercises. Scenarios
run sequentially in the day-22 through day-49 scenario window
(see §8 Timeline), with at least 48 h between any two adversarial
scenarios to allow for observation.

### 4.1 Normal load
Sustain 4 TPS (`BLOCK_TX_CAP = 4` × 1 s cadence) for 24 h. Wallet
fleet of 3 test-operator identities sends at ~1.3 TPS each on
random destinations. **Pass**: gates #1–#8 hold.

### 4.2 Burst load
10–15 Tx bursts every 5 min for 1 h; excess queues in mempool.
**Pass**: mempool drains inside 4 s of each burst end; no
admission rejects under `BLOCK_TX_CAP`. A 15-Tx burst takes ≥ 4
blocks to drain by design. Exercises #2, #5, #16.

### 4.3 Adversarial Tx — deterministic reject
Inject each malformed case from `uno-workchain.md` §4.3 verify
order: malformed proof, bad Schnorr sig, stale anchor, reused
nullifier (same-tx / same-block / cross-block), bad Ristretto
point, bad version, wrong chain id, insufficient fee. Each reject
must land under the correct
`uno_transfers_rejected_total{reason=...}` label
(`uno/rpc/metrics.h`). **Pass**: byte-identical reject reason
across all validators, at the same pipeline point; no admits, no
panics. Exercises #7, #8, #14.

### 4.4 Worst-case shape stress
4 Tx/block of 4-spend/4-output for 1 h. Per-Tx proof ~915 KB
(§2.1 Option B 4/4), block payload ~3.7 MB. **Pass**: gates #1,
#2, #4, #5 hold; no validator drops out. Exercises #4, #5, #6.

### 4.5 Wallet key rotation
A test-operator wallet reissues its BIP-39 seed mid-run and
migrates its `ivk`. Scan keeps receiving on the old
`ivk_commitment` until outstanding notes clear, then on the new.
**Pass**: no missed notes, no double-claim, balance reconciles.
Exercises #11, #17.

### 4.6 Validator churn
At day 30, reboot ⅓ of active validators on a rolling 10-min
interval. **Pass**: rebooted validators reach tip within 3 min;
gates #8 and #13 hold. Exercises #6, #8, #13.

### 4.7 Compact-filter correctness
Scan a synthetic 1 M-output history where the wallet owns
~10 000 notes. **Pass**: scan returns exactly 10 000 (gate #11);
empirical false-positive rate ≤ 2⁻¹⁶ (gate #10). Exercises #10,
#11, #17.

### 4.8 ML-KEM-768 hybrid-KEM load
20 simulated receiving wallets trial-decrypt the full testnet-day
graph in parallel (hybrid ECDH-Ristretto255 + ML-KEM-768 decap).
Watch `uno_verify_transfer_seconds` histogram for timing channels
and any regression vs `uno/test/reference/hybrid_kem_kat.py`.
**Pass**: all 20 wallets reconcile; no new timing channel
emerges. Exercises #7, #17.

### 4.9 Mempool DoS
Flood one validator's RPC with 10 000 fuzzed malformed Transfers
over 10 min (seeded from `test-uno-codec-fuzz`). **Pass**:
validator memory ≤ 1 GB (gate #16), no panic, reject counters
increment under correct reasons, valid traffic unaffected.
Exercises #14, #16.

---

## 5. Monitoring / observability

Metrics already live in `uno/rpc/metrics.{h,cpp}` behind the
`uno_getMetrics` RPC (K-uno-metrics, Prometheus 0.0.4 text). Signals
below exist today unless marked **proposed**; no new instrumentation
gates testnet start.

**Counters (already shipping)**:
- `uno_transfers_admitted_total`
- `uno_transfers_rejected_total{reason="<enum>"}` — 16 reason labels
  pinned in `metrics.h::RejectReason`
- `uno_blocks_produced_total`
- `uno_blocks_state_root_divergences_total` (external-harness fed)
- `uno_nullifier_lru_hits_total` / `uno_nullifier_lru_misses_total`

**Gauges (already shipping)**:
- `uno_anchor_window_size`
- `uno_commitment_tree_next_position`
- `uno_nullifier_set_size`
- `uno_mempool_size`

**Histograms (already shipping)**:
- `uno_verify_transfer_seconds{phase="admission"|"compute"}`
- `uno_apply_transfer_seconds`
- `uno_block_filter_gcs_bytes`

**Proposed additions for V1-4** — non-consensus, C++-side only:
- `uno_block_tx_count` (histogram, 0..4 buckets) → gate #1
- `uno_validator_peer_count` (gauge) → gate #6
- `uno_compact_filter_false_positives_total` (counter, off-chain
  scan harness bumps during §4.7) → gate #10
- `uno_mempool_bytes` (gauge) → gate #16
- `uno_wallet_cold_sync_seconds` (histogram, reported by test-wallet
  fleet on connect) → gate #9

All metrics are scraped into a central Grafana dashboard reviewed
daily by the 5-operator quorum. Dashboard URL pinned at genesis
announcement; alert routing follows the existing wc=0 / wc=1
on-call rotation.

---

## 6. Incident response

**Severity taxonomy**:
- **P0** — consensus break, state-root drift (gate #8), fork (#13),
  accept-on-malformed (#7). Immediate wc=2 halt; wc=0 / wc=1 continue.
- **P1** — validator crash / OOM but consensus holds. Isolate
  affected operator, preserve artefacts, run
  `test-uno-restart-survival` on snapshot.
- **P2** — UX / throughput gate (#9, #17) trips. No halt; root-cause
  inside next upgrade window.

**P0 halt procedure** (reuses the TOS shardchain rollback established
for wc=1 pre-mainnet):
1. Operator quorum (≥ 3 of 5 seed operators) votes to halt.
2. Halt executed via `ConfigParam` update on masterchain setting
   wc=2 paused.
3. State snapshot frozen; `test-uno-restart-survival`,
   `test-uno-determinism`, `test-uno-state-transition-golden` are
   replayed by all operators.
4. Root cause identified, hotfix lands on `uno` with §12 green.
5. Testnet resumes from the last pre-divergence block. The 60-day
   clock resets if the halt exceeds 24 h or if any §2 pinned gate
   needs re-baselining.

**Hotfix deployment**: non-consensus-binding hotfixes (metrics,
logging, wallet-side) roll async inside upgrade windows (day 20,
day 40). Consensus-binding hotfixes require a coordinated restart;
validators unreachable within 2 h of the restart-window close are
dropped and lose signing weight until they re-sync.

**Key-compromise**: if a validator's BIP-39 seed leaks, the operator
is dropped via the standard masterchain validator-rotation path.
No UNO funds are at risk — validators do not custody UNO; only the
wc=2 signing key (derived from the masterchain validator key, which
has its own rotation) is compromised. Testnet genesis is a separate
file from `zerostate-genesis-notes.json` by design; no mainnet key
material is on testnet.

**Proof-system bug**: if the Plonky3 verifier rejects a valid proof
(or accepts an invalid one), wc=2 halts. wc=0 / wc=1 stay fully
operational — UNO shielded state is isolated by §1.5 bridgelessness.
A wc=2-only outage cannot take TOS down.

---

## 7. Exit criteria → mainnet

Mainnet is authorized when ALL hold:

1. All §2 gates #1–#17 meet target or floor continuously for ≥ 30
   days on the 7-day rolling window.
2. All §4 scenarios executed with pass-status.
3. No unaddressed P0 or P1 incidents open.
4. External crypto audit (`doc/uno-audit-scope.md`, to be superseded
   by `doc/uno-v1-audit-scope.md` after the v1-scope recut) complete
   and all critical / high remediations merged.
5. Validator hardware profile (#15) reproducibly met by ≥ 5
   independent operators on commodity hardware (≥ 2 residential
   fiber + ≥ 3 VPS at < 4-core-equivalent tier). Datacenter-only
   operator sets do not close this gate.
6. `uno_sendTransfer` e2e verified with ≥ **3 independent wallet
   implementations** — reference `tosctl uno send`, a second on a
   different HTTP stack, and a third-party wallet. V1-3b (daemon
   BoC parity, `c9f06da56`) must land before this gate can run.
7. `doc/uno-aggregation-design.md` §4.1 shows all V1-* phases ✅
   DONE; V1-4 flips ✅ on day-60 pass.

Any slipped criterion defers mainnet by the remediation period + a
fresh 30-day clean window. No fast-track, no partial pass.

---

## 8. Timeline

60 calendar days from testnet-genesis block (T0) to mainnet
activation decision (T0 + 60).

```
Week  Days    Phase              Activities
────  ─────   ─────              ──────────
 1    1–7     Bootstrap          Validator bring-up per doc/uno-testnet-runbook.md §5
                                 Genesis load; first 24 h synthetic traffic
                                 §2 gate #9 / #10 / #16 / #17 TBD baselines set
 2    8–14    Bootstrap cont.    All 20+ validators live; dashboard shared
                                 Scenario 4.1 (normal load 24 h) runs
 3    15–21   Normal-load burn   Continuous 4 TPS traffic; daily op review
 4    22–28   Scenario window 1  4.2 (burst), 4.3 (adversarial Tx), 4.4 (4/4 stress)
 5    29–35   Scenario window 2  4.5 (key rotation), 4.6 (churn, day-30 anchor)
 6    36–42   Scenario window 3  4.7 (filter correctness), 4.8 (ML-KEM load)
 7    43–49   Scenario window 4  4.9 (DoS); start 30-day clean window (day 30)
 8    50–56   Stability          No new scenarios; observe only; daily dashboard
 9    57–63*  Stability          Final stability window; exit-criteria drafting
10    60     Gate review        Operator quorum sign-off or defer
```

`*` Day 61–63 is contingency padding. Day 20 and day 40 are the
pre-announced upgrade windows; no scenario is scheduled inside them.

The 30-day clean rolling window starts no earlier than day 30 (end
of scenario window 2). If 4.4 / 4.9 uncover a gate violation the
clean window restarts from remediation merge + 1 day.

---

## 9. Risks + fallbacks

**TPS demand exceeds the 4 TPS ceiling** (gate #1 saturation, not
failure): success-path risk. v1 response is a second wc=2a
shardchain (`uno-workchain.md` §1.4 #7, §14 "Sharding wc=2"). Each
adds 4 TPS. Per-shard TPS > 4 requires v2 aggregation, deferred per
`uno-aggregation-design.md` §-1.

**Prover-time regression on commodity hardware** (§1.4 #4, 22 s
target on 8-core x86): flag V1-2b parameter recalibration (currently
pending per `uno-aggregation-design.md` §4.1 V1-2 PARTIAL) to re-tune
fees, admission, filter sizing. Not a mainnet-blocker unless prover
time exceeds 60 s, which would push UX across the line.

**High-severity security finding mid-run**: testnet extends by the
remediation window + a fresh 30-day clean window. No fast-track.

**ML-KEM-768 protocol revision**: FIPS 203 is stable (2024-08),
mid-run breakage is extremely low probability. Escape hatch is the
reserved `scheme_id = 0x02` path (originally scoped for ML-DSA
hybrid spend-auth, extensible to cover a KEM swap via wc=2
hardfork).

**Validator set < 15 mid-run**: gate #6 trips. Operator-side cause
(quit, hardware) → recruit replacement in 7 days or slip. Chain-side
cause (consensus pushing operators out) → P0 by a different route.

**wc=2 halts while wc=0 / wc=1 continue**: by design. §1.5
bridgelessness makes wc=2 outages orthogonal to the rest of TOS.
Mainnet preparation on wc=0 / wc=1 is independently gated.

---

## 10. Open items (as of plan publication)

Known unknowns that must land or be explicitly waived before
testnet genesis:

1. **V1-3b daemon BoC parity** — `tosctl-uno` wire encoding mismatches
   the daemon decoder for path-dependent Cell trees (commits
   `c9f06da56`, `583969266` flagged it). Must land before bring-up;
   without it wallet → validator traffic cannot round-trip. Tracked
   as V1-4 prerequisite in `uno-aggregation-design.md` §4.1.
2. **V1-2b parameter recalibration** — fees, filter sizing, bandwidth
   tables in `uno-workchain.md` §1.4a / §2.8 / §7.6 were sized
   against the pre-pivot 30 TPS target. Qualitatively correct but
   quantitatively upper-bound; should land before day-7 baselines
   freeze.
3. **V1-audit scope finalization** — `doc/uno-audit-scope.md` is
   pre-pivot. The v1-scope recut into `doc/uno-v1-audit-scope.md`
   (prompt-referenced, not yet created) should drop the aggregator-
   AIR / block-proof surface and re-add the Transfer-AIR-direct
   boundary with per-Tx-proof parity. Needed for §7 exit #4.
4. **Testnet faucet model** — free vs rate-limited vs captcha-gated.
   Testnet UNO has no value, but a faucet is required to bootstrap
   test wallets.
5. **Testnet genesis distribution file** — distinct from mainnet
   `zerostate-genesis-notes.json` (K-genesis-distribution landed the
   mainnet builder). Must not share any key material with mainnet.
6. **Dashboard and alert routing** — URL + on-call rotation mapping
   for the 20+ operator set; extends the existing wc=0/wc=1 rotation.
7. **Operator recruitment** — 20+ independent operators across 5+
   jurisdictions is an open non-technical ask. Pre-testnet call for
   90-day commitments (60 testnet + 30 mainnet stabilization).
8. **§2 gates #9, #10, #16, #17 baselines** — "TBD measured"; freeze
   at day 14 via plan amendment.

---

## 11. References

- `doc/uno-aggregation-design.md` §-1 (v1 pivot), §4.1 (V1-* phases)
- `doc/uno-workchain.md` §1.4 (success criteria), §1.4a (validator
  hardware), §2.1 (FRI Option B pin), §4.3 (verify order), §13 (P.0–P.7)
- `doc/uno-testnet-runbook.md` — operator bring-up companion
- `doc/uno-audit-scope.md` — audit scope (v1-recut pending into
  `doc/uno-v1-audit-scope.md`)
- `doc/uno-aggregation-metrics.md` — §2 gate #3/#4/#5 baselines
- `uno/rpc/metrics.{h,cpp}` — Prometheus registry for §5
- `uno/test/` — §12 test binaries invoked by §4 scenarios

**Key commits**: `0116de520` (BLOCK_TX_CAP 30→4), `42fdb46a7`
(revert A6-4a + reinstate per-Tx verify), `b2d601a09` / `4623e987a`
(v1 TPS posture doc), `c9f06da56` / `583969266` (V1-3a/b BoC parity
gap), `6698e2875` (`test-block-proof-verifier` n_transfers pin).
