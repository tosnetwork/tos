# UNO v1 Validator Operations Runbook

> **Status**: draft for v1 launch — reflects the 2026-04-21 per-Tx pivot
> recorded in [`doc/uno-aggregation-design.md`](uno-aggregation-design.md) §-1.
> The pre-mainnet testnet procedure lives in
> [`doc/uno-testnet-runbook.md`](uno-testnet-runbook.md) (60-day stability
> gate). This document is the **mainnet** operator runbook that takes over
> on day-60 cutover.
>
> Several concrete commands, flags, and endpoint names below are marked
> **TBD** — they depend on shipped binary surfaces that are landing
> incrementally. Where TBD, we cite the source file an operator should
> inspect to recover the current truth.

---

## 1. Scope and audience

This runbook addresses a **TOS validator operator** already running a
healthy TOS validator on `wc=0` (and optionally `wc=1`) who wants to
**opt into `wc=2` (UNO)**. It does not cover first-time TOS validator
setup — that lives in [`doc/Validator.md`](Validator.md) and
[`doc/Validator-Local.md`](Validator-Local.md). UNO does not add a
separate node binary: the same `validator-engine` picks up UNO once
the link dependency and config flip are in place
([`uno/core/init.cpp`](../uno/core/init.cpp) installs the `wc=2`
compute handler alongside the existing EVM handler). Expected reader
skill: Linux systems operator comfortable with `systemd`,
`journalctl`, and Prometheus/Grafana.

---

## 2. Hardware specification (v1)

### 2.1 Minimum

| Resource  | Value                                          |
|-----------|------------------------------------------------|
| CPU       | 4 physical cores (x86_64 AVX2, ARM NEON, or equivalent) |
| RAM       | 16 GB                                          |
| Storage   | 1 TB NVMe SSD (plus ~300 GB/year UNO growth)    |
| Network   | 50 Mbps sustained / 100 Mbps burst, symmetric  |

Rationale:

- **CPU** — parallel verify contract in
  [`uno/core/parallel-verify.h`](../uno/core/parallel-verify.h): one
  `Plonky3Verifier` handle per worker, ≥ 3.5× speedup at 4 workers.
  Single-thread verify lands at ~7 ms typical / ~26 ms worst-case 4/4
  under the Option B FRI pin ([`uno-workchain.md`](uno-workchain.md)
  §2.1), so 4 cores clear the 1 s block budget with ample headroom.
- **RAM** — dominated by the nullifier LRU (~100 MB at 1 M entries,
  §5.9) plus catchain/block cache shared with `wc=0`.
- **Storage** — per-Tx proofs ~520 KB typical / ~915 KB worst. At 4 TPS
  that is ~2 MB/s ≈ ~172 GB/day of wire data; pruned-mode validators
  retain only the last N blocks of proof bodies (trees, nullifier set,
  and filters are small and kept indefinitely).
- **Network** — 4 TPS × 520 KB = ~16 Mbps outbound at the typical
  1-spend/2-output mix ([`uno-aggregation-design.md`](uno-aggregation-design.md)
  §-1); 4/4 worst case triples that and stays under 50 Mbps
  sustained.

This is intentionally a **consumer-broadband** profile — the direct
corollary of the 2026-04-21 per-Tx pivot (pre-pivot 200 Mbps sustained
was sized for a 30 TPS block-aggregated shard; per-Tx @ 4 TPS cuts
that ~8×, [`uno-workchain.md`](uno-workchain.md) §1.4a).

### 2.2 Recommended

| Resource  | Value                                      |
|-----------|--------------------------------------------|
| CPU       | 8 cores                                    |
| RAM       | 32 GB                                      |
| Storage   | 2 TB NVMe                                  |
| Network   | 100 Mbps sustained / 1 Gbps burst          |

Recommended leaves room for: growing nullifier LRU beyond 1 M entries
(tunable via ConfigParam 84, §10.2), serving a public RPC endpoint,
running an indexer or wallet-gateway co-tenant, and surviving a
sustained 4/4-worst-case mix without bandwidth saturation.

### 2.3 Hardware matching against other validator roles

The 4-core / 16 GB / 50 Mbps floor is a deliberate design statement —
[`uno-workchain.md`](uno-workchain.md) §1.4a records it as a decision,
not a discovery. The chain does not assume a datacenter-only validator
set; the post-pivot bandwidth profile explicitly admits residential-fiber
home operators. This is the opposite trade from Aleo/Aztec-class chains
that push prover hardware into the validator role; UNO validators
**only verify**, never prove. If your existing `wc=0+wc=1` node runs
healthy on 4-core / 16 GB / 100 Mbps, it fits UNO with no further
investment. Datacenter-class nodes (32+ cores, 10 Gbps) see UNO as a
marginal load.

---

## 3. Opt-in process (joining wc=2)

UNO participation is a subset relationship: every UNO validator is a TOS
validator first, and TOS validators opt in to `wc=2` by flipping one
config flag. There is **no separate staking contract** and **no separate
key material** — UNO inherits both from the masterchain validator set.

### 3.1 Key material

UNO reuses the **TOS validator identity key** you already maintain. No
separate UNO signing key, no separate consensus key, no fresh BLS
ceremony. The `wc=2` compute phase runs under the same process as your
existing handlers (see `init_uno_workchain` in
[`uno/core/init.cpp`](../uno/core/init.cpp)); block signatures trace
back to the masterchain validator set via TOS's standard Simplex round.
Post-compromise key rotation is the standard TOS procedure
([`doc/Validator.md`](Validator.md)) — nothing UNO-specific.

### 3.2 Stake requirements

`wc=2` validator economics match any other TOS shardchain: rewards paid
from masterchain validator revenue in native TOS, not in UNO
([`uno-workchain.md`](uno-workchain.md) §16 decision #23). UNO fees
are paid in UNO and **burned**; the validator never collects them. No
UNO-specific stake top-up — the stake that qualifies you for
`wc=0`/`wc=1` qualifies you for `wc=2`.

### 3.3 Opt-in flag (TBD wiring)

Opt-in is a per-validator advertisement in the TOS validator config,
carried via masterchain config-param voting. The **exact flag name and
ConfigParam slot are TBD** — they land alongside the `wc=2` zerostate
rollout ([`uno-workchain.md`](uno-workchain.md) §10). Until shipped,
a validator joins `wc=2` implicitly by running a `validator-engine`
build that includes `uno_workchain` in `target_link_libraries` (§11.6).
Operators wanting `wc=0+wc=1` only must build without the
`uno_workchain` link dep.

### 3.4 Activation timeline

1. Flip the opt-in flag (or deploy the UNO-enabled build); restart
   `validator-engine`.
2. On startup, `init_uno_workchain(db_root_)` loads the commitment
   tree / nullifier set / anchor window, warms the 1 M-entry nullifier
   LRU, and registers the compute handler.
3. On the next **masterchain epoch boundary**, validator-set formation
   rotates the node into (or out of) the `wc=2` catchain subset.

---

## 4. Installation / bootstrap

### 4.1 Required TOS version

Minimum `validator-engine` version: the first release that carries the
`uno_workchain` library and the v1 zerostate (tag **TBD**,
will be published to the TOS release channel). Do **not** mix a `uno`-
enabled binary with a `uno`-disabled zerostate; `init_uno_workchain`
will either refuse to come up (if it sees a `wc=2` in ConfigParam 12
but no handler) or silently ignore `wc=2` (if it sees a handler but no
zerostate entry). Both states are operational failures.

### 4.2 Required build flags / feature flags

From `validator-engine/CMakeLists.txt` ([`uno-workchain.md`](uno-workchain.md) §11.6):

```cmake
target_link_libraries(validator-engine uno_workchain)
```

This in turn pulls in `libuno_plonky3_ffi.a` via the vendored
corrosion-rs bridge ([`third-party/corrosion/`](../third-party/corrosion/)).
Build command (per the machine-profile memory: 192 CPUs, use 2/3):

```bash
cargo build -j 128 --release --manifest-path uno/plonky3-ffi/Cargo.toml
cmake --build build -j 128 --target validator-engine
```

Sanity-check at boot: the startup log should emit, in order, something
close to this shape (verbatim strings from [`uno/core/init.cpp`](../uno/core/init.cpp)):

```
uno-workchain: initialising (workchain_id=2, db_root='<path>')
uno-workchain: nullifier LRU warm-up requested k=1048576 ...
uno-workchain: handler registered, RPC setter-DI bound (12/12: ...)
```

If the third line is missing, the RPC surface is partially wired and
wallet clients will get empty responses on several methods — treat as
a bad build, do not advertise `wc=2`.

### 4.3 Config-file diff vs wc=0 / wc=1-only operator

A `wc=0+wc=1`-only config is essentially unchanged. Minimal delta:

- (TBD) opt-in flag advertising `wc=2` participation (§3.3).
- (TBD) `uno.db_path` — dedicated directory for `UnoShardState` cell
  storage, block-filter archive, and the per-block outputs slab used by
  `uno_getOutputsAtBlock`. Default `<state_dir>/uno/`.
- Optional: `UNO_ALLOW_SERVER_SCAN=1` (env) exposes server-assisted
  `ivk` scan to wallets trusting your node with their incoming viewing
  key. **Privacy-sensitive** — leave unset on public RPC endpoints.

No separate catchain descriptor, no separate gossip port.

### 4.4 Health-check commands right after startup

Once the process is up, the fastest sanity sweep is:

```bash
# TBD CLI: substitute your tosctl / validator-console path.
# All three should answer within ~100 ms on a healthy validator.

tosctl uno chain-info                  # returns head_seqno, scheme_id, chain_id
tosctl uno get-anchor latest            # returns the current commitment-tree root
curl -s http://localhost:<rpc-port>/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"uno_getMetrics","params":[]}' \
  | jq -r '.result.metrics' | head -20
```

Expected state immediately after a clean bring-up:
- `head_seqno` = whatever the live `wc=2` chain reports; should advance
  by 1 every second after catchain sync settles.
- `anchor_window_size` gauge ≥ 1 (the genesis root is pushed at
  `init_uno_workchain` time).
- `uno_transfers_admitted_total` starts at 0 and climbs only if the
  node is receiving real mempool traffic.
- `uno_blocks_state_root_divergences_total` MUST be 0. A non-zero value
  here is a consensus-level incident — see §6.2.

---

## 5. Daily monitoring

Metrics are surfaced through the existing JSON-RPC facade as
`uno_getMetrics` (Prometheus text exposition inside a JSON envelope,
one of the surfacing decisions recorded in
[`uno/rpc/metrics.h`](../uno/rpc/metrics.h)). A Prometheus scrape on the
validator's RPC endpoint (§11) picks these up without a separate
exporter binary.

| Metric                                       | Source      | Healthy range                 | Severity |
|----------------------------------------------|-------------|-------------------------------|----------|
| `uno_verify_transfer_seconds{phase="compute"}` p99 | Prometheus | < 400 ms                | MED      |
| `uno_transfers_rejected_total{reason="bad_proof"}` rate | Prometheus | < 0.01% of admitted | HIGH if rate spikes |
| `uno_blocks_produced_total` rate             | Prometheus  | ≈ 1 / s (global block rate)   | HIGH if stalls |
| `uno_blocks_state_root_divergences_total`    | Prometheus  | 0                              | CRITICAL if ≠ 0 |
| `uno_transfers_admitted_total` per block     | Prometheus  | 0–4 (the `BLOCK_TX_CAP = 4` ceiling) | INFO |
| `uno_mempool_size` (bytes / entries)          | Prometheus  | bounded; not monotonically climbing | MED if unbounded growth |
| `uno_nullifier_lru_hits_total / (hits + misses)` | Prometheus | > 95% warm, > 70% cold | MED |
| `uno_anchor_window_size` gauge                | Prometheus  | = `ConfigParam 84.anchor_window_size` (100 at launch) | MED if not |
| `uno_commitment_tree_next_position` gauge     | Prometheus  | monotonically increasing       | MED if stuck |
| `uno_block_filter_gcs_bytes` histogram        | Prometheus  | stable; not blowing out        | LOW |
| Validator peer count (TOS-side)               | existing `validator-console` metrics | ≥ 10 | HIGH if < 5 |
| Block production latency (wall-clock, end-to-end) | logs / Grafana panel | p99 < 1 s | HIGH |
| Disk free on `uno.db_path`                    | node exporter | > 20% warn / > 10% critical | HIGH / CRIT |

A derived signal worth tracking: **proof-verify success rate** =
`1 − rejected{reason="bad_proof"} / admitted`. Expect ≥ 99.99% on a
healthy network. Sustained drop below 99% is almost always either
(a) malformed-Tx flood (harmless; admission catches them before any
state impact — the §4.3 verify chain in
[`uno-workchain.md`](uno-workchain.md) is deterministic-reject at
every step), or (b) a version mismatch against the linked Plonky3
staticlib (see §9 FAQ).

Two metrics to **not** alert on directly:
- `uno_mempool_size` growing *briefly* during a user-visible spike is
  normal; the §4.3a admission rate-limit controls the steady-state
  ceiling. Alert on the *derivative* (unbounded climb) not the level.
- Transient `uno_nullifier_lru_misses` after cold start; the LRU is
  explicitly warmed at boot but the hit rate converges in the first
  few minutes.

---

## 6. Incident playbooks

### 6.1 Proof verify rate drops below 99%

Two realistic causes:

1. **Malformed-Tx flood.** Every reject is deterministic at the §4.3
   step where it first fails (see the cascade in
   `rpc_admission_check_fn`, [`uno/core/init.cpp`](../uno/core/init.cpp)).
   If `uno_transfers_rejected_total{reason=...}` skews to `malformed` /
   `decode_error` / `bad_version`, this is spam — admission is
   O(syntax), touches no state, and the rate recovers on its own.
2. **Genuine `bad_proof` rise.** Collect last 1 h of `uno-workchain`
   logs, the `uno_getMetrics` snapshot, and the
   `uno_plonky3_abi_version()` value. If it does not match
   `kExpectedAbiVersion` in
   [`uno/crypto/plonky3-verifier.h`](../uno/crypto/plonky3-verifier.h)
   (currently `3`), you have a staticlib/header mismatch — rebuild
   clean.

Escalate to the UNO dev channel (TBD) with the diagnostic bundle if
neither applies.

### 6.2 Block production stall (wc=2 blocks stop)

First rule: **check `wc=0` before `wc=2`.** If the masterchain is down,
no shard produces blocks; the fix is upstream.

If `wc=0` is healthy but `wc=2` is stuck:
- Confirm `wc=2` catchain peer count ≥ 10 — a split catchain stalls
  quietly.
- Check `uno_blocks_state_root_divergences_total`. Non-zero = your
  validator disagrees with the rest of the set. This is a consensus
  bug: freeze the validator, preserve `db_root` + last 1 h of logs,
  file an incident.
- Otherwise restart `validator-engine`. The P.4 restart-survival
  contract ([`uno-workchain.md`](uno-workchain.md) §12) guarantees
  byte-identical post-restart state roots.

### 6.3 Wallet-sync reports stuck

User-visible symptom: wallet reports "sync N h behind head". Check:
- `uno_block_filter_gcs_bytes` histogram count should track
  `uno_blocks_produced_total`. Lagging filter production starves
  compact-filter-based wallets.
- Confirm `uno_getBlockFilter` RPC answers (e.g. `tosctl uno
  get-filter <seqno>`). If the filter archive is healthy, fault is
  wallet- or network-side.

### 6.4 Mempool OOM

Prevention: the §4.3a per-IP admission rate-limit bounds mempool
inflow. If OOM still occurs (many distinct peer IPs flooding in
parallel), the process exits and `systemd` restarts it; mempool
contents are not state, so no loss. To **recover from repeated OOM
cycles**: tighten per-IP admission limit (operator-configurable, not
consensus) or rate-limit upstream at a reverse proxy.

### 6.5 Validator disk nearly full

Primary lever: **switch to pruned mode** if running archive. Pruned
retains commitment tree, nullifier set, anchor window, block-filter
archive, and last N blocks of raw proof bodies. Archive retains every
proof body forever — at ~172 GB/day only indexers should run it. Exact
pruning command and `--retain=<blocks>` parameter are **TBD**; consult
the tool's `--help` once it ships.

### 6.6 Nullifier collision false positive

Not a bug. The nullifier LRU (§5.3) is a probabilistic accelerator,
not the consensus source of truth — on a miss the validator falls
back to the authoritative cell-dict lookup. INFO-level "cache miss
resolved positive" lines are expected and should not page. The
consensus-observable counter is
`uno_blocks_state_root_divergences_total`; LRU counters are
diagnostic only.

---

## 7. Upgrade procedures

### 7.1 Non-consensus upgrade

Patch releases that change internal representation only (e.g. log
format, metric cardinality, pruning defaults) are rolled out one
validator at a time:

1. Drain — stop accepting new wallet RPC traffic at your reverse proxy.
2. Let in-flight rounds complete.
3. `systemctl stop validator-engine`; upgrade binary; `systemctl start`.
4. Watch the bring-up log for the three-line init banner (§4.4).
5. Watch `uno_blocks_state_root_divergences_total` stay at 0 for ≥ 60 s.
6. Re-enable wallet traffic.

Move to the next validator only after the current one is visibly
healthy.

### 7.2 Consensus upgrade

Any change that affects `scheme_id`, the AIR, ConfigParam 84's
consensus-binding fields (`max_spends_per_tx`, `max_outputs_per_tx`,
`tree_depth`, `anchor_window_size`), or the verify path requires a
**network-wide coordinated activation at a specific block height**.
This is carried as a masterchain ConfigParam 11 vote
([`uno-workchain.md`](uno-workchain.md) §10, §12 governance note).

Protocol:

1. Governance proposal is announced with target activation height.
2. Operators upgrade their `validator-engine` binaries during the
   announced window (typically ≥ 7 days ahead) but leave the flag off.
3. At the activation height, the new behaviour takes effect
   atomically across the validator set. Validators not on the new
   binary deterministically-reject at the first post-activation block
   they see; they are slashed under standard TOS downtime rules if
   they remain behind.

Fee-schedule changes (§8.1 in the testnet runbook) are consensus
upgrades but not AIR-shape changes. They still follow the same
coordinated-height flow.

---

## 8. Security checklist

### 8.1 Key management

- TOS validator signing key → hardware-backed storage if possible
  (TPM 2.0, YubiHSM, TEE). Failing that, OS keyring plus an offline
  cold backup on encrypted removable media is the minimum acceptable
  posture.
- No key material in logs, metrics, or telemetry. The
  [`uno_getMetrics`](../uno/rpc/metrics.h) surface is designed so every
  label is public-safe; verify this holds for any custom dashboards.
- Rotation cadence follows TOS policy. On suspected compromise run the
  full TOS rotation procedure — UNO participation follows automatically.

### 8.2 OS and firmware hygiene

- Apply kernel and microcode updates on the same cadence as other TOS
  validators.
- UFW/nftables: inbound only TOS consensus port(s) + public RPC port
  (if exposed); outbound unrestricted; everything else denied.
- Publicly-exposed RPC must sit behind an authenticating reverse
  proxy — methods like `uno_getOutputsAtBlock` paging and
  `uno_getBlockFilter` for deep history are expensive queries.

### 8.3 Plonky3 dependency rev

UNO pins **Plonky3 commit `6374a36f`** (upstream v0.5.1), vendored to
[`third-party/plonky3-uno/`](../third-party/plonky3-uno/) per §16
decision #43. Canonical statement: the `p3-*` dependency paths in
[`uno/plonky3-ffi/Cargo.toml`](../uno/plonky3-ffi/Cargo.toml). **Do
not upgrade independently of a UNO release.** A Plonky3 rev mismatch
between the Rust staticlib and the C++ verifier header surfaces as
`kExpectedAbiVersion != uno_plonky3_abi_version()` and the validator
refuses to enter verify paths — safe failure mode, but you do not
want to discover it at 3 AM.

### 8.4 PQ hygiene

v1 closes the HNDL (harvest-now, decrypt-later) window at ship day:
every private Tx uses hybrid-KEM (Ristretto255 ECDH + ML-KEM-768) for
note encryption and Schnorr-over-Ristretto255 for spend authorization
([`uno-workchain.md`](uno-workchain.md) §6, §1.4 invariant #8). For
operators this is passive — **no action needed beyond running the
shipped binary.** Do not enable `UNO_MLKEM_STUB=1` on mainnet; that
build aborts at runtime on any `uno_sendTransfer`.

---

## 9. Troubleshooting cookbook

**Q: My validator shows `BadPlonky3Proof` for every Tx.**
A: Almost certainly a version mismatch between the Rust staticlib
and the C++ verifier header. Check the ABI-version pair
(`uno_plonky3_abi_version()` vs `kExpectedAbiVersion`, currently `3`
in [`uno/crypto/plonky3-verifier.h`](../uno/crypto/plonky3-verifier.h)).
If they differ, rebuild from a clean `build/` tree. Incremental builds
across branch switches sometimes reuse a stale
`libuno_plonky3_ffi.a`.

**Q: CPU pegs at 100% during the compute phase. Is parallel verify working?**
A: Yes, by design. The `ParallelVerifyPool`
([`uno/core/parallel-verify.h`](../uno/core/parallel-verify.h)) spins
`num_cores` workers; 100% spikes during block gossip are expected on
a 4-core node. The signal to watch is **determinism, not utilization**:
`uno_blocks_state_root_divergences_total` must remain 0. The pool
guarantees input-order-stable results.

**Q: How do I verify my validator is counted in the `wc=2` subset?**
A: Query masterchain validators for the current epoch (`tosctl` /
`validator-console`; exact command **TBD**, §3.3) and check your node
ID advertises `wc=2`. Operational cross-check: if
`uno_transfers_admitted_total` climbs at all, your compute handler
is being called — ground truth.

**Q: Nullifier LRU hit rate is 60% on a running validator. Problem?**
A: Warm-up phase (first few minutes): normal. Sustained 60% after the
first hour: LRU is undersized. Tune `nullifier_lru_capacity` upward
via ConfigParam 84 (advisory, not consensus — local change, no
coordinated activation, see §5.9).

**Q: `uno_getMetrics` returns empty.**
A: Metrics ride the JSON-RPC facade, not a separate HTTP port
([`uno/rpc/metrics.h`](../uno/rpc/metrics.h)). Confirm the RPC server
itself is up (`uno_chainInfo` should answer) before blaming metrics.

**Q: Do I need a PhD in cryptography?**
A: No. UNO's crypto is librarified inside `uno_plonky3_ffi`; the
verifier surface is one pure function. UNO adds one dashboard's worth
of signals to validator ops, not a new mental model.

**Q: Can I run UNO and wc=1 (EVM) on the same `validator-engine` process?**
A: Yes — the designed deployment shape.
[`uno/core/init.cpp`](../uno/core/init.cpp) registers the UNO compute
handler next to EVM's at startup; both share the process and RPC
server.

---

## 10. Logging and debugging

- Default log level: `INFO` for `validator-engine`. UNO-specific lines
  are tagged `uno-workchain:` (see the `LOG(...)` calls in
  [`uno/core/init.cpp`](../uno/core/init.cpp)).
- For UNO-specific issues, raise the `td::LogLevel` for the
  `uno-workchain` / `uno_workchain::` namespace to DEBUG. The exact
  CLI flag is **TBD** pending a per-module log-level surface; for now,
  rebuild with a higher compile-time default or use the existing
  `validator-engine --log-verbosity`.
- Log retention recommendation: **14 days rolling for routine
  operational logs, 90 days sealed for any file containing an
  incident marker.** The sealed archive is the input to post-incident
  audit.
- **Diagnostic bundle** — when opening an issue, collect:
  1. `validator-engine` config file (with secrets redacted).
  2. Last 1 h of `journalctl -u validator-engine` output.
  3. A single `uno_getMetrics` JSON-RPC response at time of incident.
  4. Last 100 blocks summary: `tosctl uno chain-info` + per-block
     `uno_getBlockFilter` sizes + `uno_transfers_admitted_total` delta.
  5. `uno_plonky3_abi_version()` at the time of the bundle.
  6. OS + CPU info (`uname -a`, `lscpu`, `free -h`).
  7. Git commit the binary was built from.

Do not include key material, encrypted note plaintext, or any
`UNO_ALLOW_SERVER_SCAN=1` data in the bundle. The public metric
surface is safe; everything else requires redaction review.

---

## 11. Observability integration

### 11.1 Prometheus scrape config

Add the validator's RPC endpoint to your Prometheus scrape list. The
endpoint path and authentication are site-specific; a minimal example:

```yaml
scrape_configs:
  - job_name: uno-validator
    scrape_interval: 15s
    metrics_path: /            # JSON-RPC POST, see uno_getMetrics
    params:
      method: [uno_getMetrics]
    static_configs:
      - targets: ['validator-1.example:<rpc-port>']
```

Because metrics ride the JSON-RPC server, some Prometheus versions need
a small relay (a 20-line Python or Go script that POSTs
`uno_getMetrics` and unwraps `result.metrics`). The hand-rolled
exposition inside [`uno/rpc/metrics.cpp`](../uno/rpc/metrics.cpp) is
Prometheus text format 0.0.4-compatible once unwrapped.

### 11.2 Grafana dashboard

Reference dashboard JSON location: **TBD** — will be published to the
TOS operator repository alongside the v1 release. The signal set is
what §5 already lists; an initial dashboard should have one panel per
metric plus a summary row showing (proof-verify success rate, block
production cadence, peer count, disk free).

### 11.3 Alerting thresholds

- **Page (high severity)**:
  `uno_blocks_state_root_divergences_total > 0`;
  block production stalled > 30 s;
  disk free < 10%;
  proof-verify success rate < 99% for 5 consecutive minutes.
- **Slack (medium)**:
  disk free < 20%;
  peer count < 10;
  `uno_verify_transfer_seconds{phase="compute"}` p99 > 400 ms for
  10 consecutive minutes;
  nullifier LRU hit rate < 70% for ≥ 1 h after warm-up.
- **Dashboard-only (low)**:
  `uno_block_filter_gcs_bytes` shifting distribution;
  mempool-size transients under the admission rate-limit;
  `uno_nullifier_lru_misses_total` spikes that do not affect hit rate.

---

## 12. FAQ for operators considering joining

**Q: Why add UNO `wc=2` on top of my existing `wc=0` setup?**
A: (1) Earn validator rewards from the `wc=2` catchain share of
masterchain revenue — mechanically identical to any other shard. (2)
Participate in the most PQ-forward privacy chain shipping in 2026:
UNO's stack (Plonky3 FRI over Goldilocks, Poseidon2, Schnorr-on-
Ristretto255, ML-KEM-768) is the stack Ethereum has stated it intends
to migrate to by 2030 ([`uno-aggregation-design.md`](uno-aggregation-design.md)
§-1). UNO ships it four years early.

**Q: What's the additional hardware cost?**
A: Marginal — on a typical `wc=0+wc=1` validator, UNO adds ~4 cores,
~8 GB RAM, and ~50 Mbps sustained uplink. Recommended-tier nodes
absorb it in existing headroom.

**Q: Do I need a PhD in cryptography?**
A: No. Operating the validator is ops-level work; crypto lives inside
`uno_plonky3_ffi` and surfaces as a pure function. You should know
*what* STARK-based verification implies operationally (CPU-bound
verify during compute phase, no trusted setup, no ceremony) but you
do not modify or audit the circuit.

**Q: What happens if I opt out mid-run?**
A: Stake unbonds through TOS's normal exit process — no UNO-specific
unbond lock. Local `UnoShardState` stays readable by a wc=2-disabled
build, so if you rejoin the catchain resyncs via the same
restart-survival contract that protects routine restarts.

**Q: Is there a separate UNO reward channel?**
A: No. Rewards come from masterchain validator revenue in native TOS.
UNO fees are burned ([`uno-workchain.md`](uno-workchain.md) §16
decisions #19, #23) — the validator never receives them. Deliberate,
keeps UNO supply monotonically non-increasing.

**Q: Can I run UNO without running TOS?**
A: No. UNO is a TOS workchain, not standalone. Without a masterchain
validator identity there is no consensus path into `wc=2`.

**Q: What's the v2 upgrade path?**
A: v2 is **block-level proof aggregation + WHIR/BaseFold PCS**, gated
on five trigger conditions
([`uno-aggregation-design.md`](uno-aggregation-design.md) §-1). When
it lands, the validator hardware envelope tightens back toward a
datacenter-leaning profile — v1 consumer-broadband operators may need
to upgrade uplink or opt out. Known tradeoff, not on the v1 horizon.

---

*End of runbook. Operational feedback, corrections, and incident
post-mortems that should be folded back into this document go to the
UNO dev channel (TBD).*
