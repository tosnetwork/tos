# Uno Workchain — 60-Day Testnet Operator Runbook

This runbook is the operator playbook for the P.7 **60-day, 5-validator testnet**
that gates v1 mainnet activation. It tells the five validator operators how to
bring up a `wc=2` testnet, what to monitor, how to respond to incidents, and
how the day-60 stability gate is judged and signed off.

Every reference back to the protocol spec is written as "§x.y" and resolves
against [`doc/uno-workchain.md`](uno-workchain.md). Build prerequisites are in
[`BUILD.md`](../BUILD.md).

This document is itself the **P.7 mainnet-activation artifact**: once the
60-day gate closes green, the signed-off version of this runbook plus the
testnet-green report produced at day 60 (§10 below) becomes the evidence
package that releases wc=2 from pre-mainnet to mainnet.

---

## 1. Goals of the testnet

The testnet exists to answer **one question**: is the wc=2 validator code
sufficiently deterministic, correct, and operationally boring to run native
UNO supply against it?

"Sufficiently" is pinned to the following seven metrics. All of them are
measured against a 7-day rolling window, and all of them must hold
continuously for the final 60 consecutive calendar days before mainnet is
cleared.

| # | Signal                                | Target (7-day rolling)                                    | Alarm action                                |
|---|---------------------------------------|-----------------------------------------------------------|---------------------------------------------|
| 1 | Sustained transaction throughput      | ≥ 4 TPS per wc=2 shard under synthetic load (`BLOCK_TX_CAP = 4`) | Backpressure triage, re-check admission path |
| 2 | Plonky3 verify latency, single thread | Median < 150 ms, P99 < 500 ms (relaxed §1.4 target — see §9.4 stability gate) | Profile, correlate against proof shape       |
| 3 | Cross-validator state-root agreement  | Byte-identical across all 5 validators at every block     | **Immediate halt, see §8.1**                 |
| 4 | Unexplained forks                     | 0                                                         | **Immediate halt, see §8.4**                 |
| 5 | Validator crashes / panics / OOMs     | 0 not attributable to OS/hardware                         | Preserve artifacts, open issue              |
| 6 | Determinism drift (HashMap order, wall clock, RNG, uninit) | 0 — §12 P.5 must stay green on a snapshot replay | **Immediate halt, root-cause**       |
| 7 | Restart survival                      | All 5 validators pass §12 P.4 round-trip on rolling snapshots | Block re-replay, §12 P.4 diagnostics         |

"Stable" = all seven hold for 60 consecutive calendar days. The §9 stability
gate spells out how a window resets if any of them trips.

---

## 2. Chain parameters for testnet

### 2.1 Network identifiers

| Parameter        | Value                                      | Source       |
|------------------|--------------------------------------------|--------------|
| `chain_id`       | `0x554E4F54` ("UNOT")                      | §10.4        |
| `workchain_id`   | `2`                                        | §1.0         |
| Address HRP      | `unot` (testnet)                           | §2.6 envelope |
| `network_tag`    | `0x00` (testnet)                           | §2.6 envelope |
| `version_tag`    | `0x01`                                     | §2.6 envelope |
| `scheme_id`      | `0x01` (`v1-plonky3-goldilocks`)           | §2.0         |
| Global block time | 1 s (masterchain `ConfigParam 30`)        | §1.4         |

Any address whose HRP is not exactly `unot`, or whose `network_tag` is not
`0x00`, is a consensus-of-tooling reject on this network (§2.6 address
envelope MUST).

### 2.2 ConfigParam 84 — testnet launch values

Testnet ships with the §10.2 defaults verbatim. Nothing is relaxed for
testnet; the fee DoS floor, spend/output bounds, anchor window, tree depth,
and expiry window are all the mainnet targets. The only freedom is
`nullifier_lru_capacity`, which is advisory (not consensus).

```
UnoConfig (testnet launch):
  version                = 1
  chain_id               = 0x554E4F54     // "UNOT"
  min_fee_nano           = 100_000        // 0.0001 UNO
  fee_per_byte_nano      = 10
  fee_per_spend_nano     = 50_000         // 0.00005 UNO
  fee_per_output_nano    = 50_000         // 0.00005 UNO
  max_spends_per_tx      = 4
  max_outputs_per_tx     = 4
  anchor_window_size     = 100            // ~100 s at 1 s block rate
  tree_depth             = 32             // ≈ 4 B-leaf capacity
  expiry_window_blocks   = 64             // ~64 s forward window
  nullifier_lru_capacity = 1_000_000      // ~100 MB advisory LRU
```

`chain_id`, `max_spends_per_tx`, `max_outputs_per_tx`, `tree_depth`, and
`anchor_window_size` are effectively frozen at genesis — mutating them
breaks AIR public-input shape (§10.2 governance note). The four fee fields
are mutable via `ConfigParam 11` voting **but must not be changed during the
60-day gate window**; a fee-schedule change resets the 60-day clock.

### 2.3 Genesis notes file

- **File**: `zerostate-genesis-notes.json` (§10.3).
- **Scope for testnet**: synthetic distribution list — not a rehearsal of
  the real 21 M mainnet distribution. The testnet genesis includes only the
  accounts the five validator operators and the smoke-test wallet set need
  to exercise admission / spend / scan paths.
- **Authoring**: the genesis notes file is built by
  `uno_workchain::build_zerostate()` (§10.3 zerostate build process) using
  a synthetic distribution list maintained by the release manager alongside
  this runbook.
- **Signature**: the release manager signs the SHA-256 of the published
  `zerostate-genesis-notes.json` with the release key. The signed manifest
  is published to the testnet operator distribution list (distribution
  channel: **TBD**, see §11).
- **Operator action**: each operator obtains the signed notes file,
  verifies the release-key signature, places it at
  `<state_dir>/zerostate-genesis-notes.json`, and confirms the file's
  SHA-256 matches the published value **before** starting `validator-engine`.
  The loader (K-genesis-loader) validates total supply at startup — any
  mismatch is a hard refusal to come up.

---

## 3. Validator hardware requirements

Straight from §1.4a. These are not aspirational; they are the binding
envelope that the v1 verify-cost model assumes.

| Resource          | Minimum               | Notes                                                      |
|-------------------|-----------------------|------------------------------------------------------------|
| CPU               | 4 physical cores      | No GPU, no FPGA, no proving accelerator                    |
| RAM               | 16 GB                 | Nullifier LRU accounts for ~100 MB by default              |
| Disk              | 500 GB SSD            | Local-cell cache + historical state snapshots              |
| Bandwidth         | 200 Mbps symmetric sustained, ~1 Gbps burst | Catchain consensus + block gossip                |
| Placement         | Datacenter / colo / modern residential fiber (≥ 500 Mbps symmetric) | Residential ADSL, cellular, and satellite are out of scope |
| Time sync         | NTP-synced; drift < 50 ms | Admission / expiry windows depend on wall clock **outside** the consensus path |
| OS                | Ubuntu 22.04 (matches the build-verified baseline, [`BUILD.md`](../BUILD.md) §Verified C++ Environment) | Other Linux distros are operator's risk |

Proving is **not** a validator workload (§1.4a). The 22 s-on-a-2020-laptop
client-side proving target is a wallet concern, not a validator concern;
operators do not need additional CPU headroom for proving.

---

## 4. Build prerequisites

All prerequisites live in [`BUILD.md`](../BUILD.md). The Uno-specific
dependencies over and above the base C++/Rust build are summarized here so
an operator can verify their tree is the right one. Authoritative details
are in [`BUILD.md`](../BUILD.md) §"Uno Workchain (wc=2) — Additional
Prerequisites".

| Dependency     | Purpose                                                 | Source                                        | Action        |
|----------------|---------------------------------------------------------|-----------------------------------------------|---------------|
| libsodium      | Ristretto255 / ChaCha20-Poly1305 / BLAKE2b (§2.5, §2.7) | `third-party/sodium/` (bundled)               | none          |
| liboqs         | ML-KEM-768 (§2.7)                                       | external, pinned (`uno/crypto/LIBOQS_VERSION.md`) | **manual install** |
| avatar BLAKE3  | transcripts / cell hashing (decision #41)               | `third-party/avatar-crypto/` (vendored)       | none          |
| corrosion-rs   | CMake ↔ Cargo bridge for `uno_plonky3_ffi`              | `third-party/corrosion/` v0.5.2 (vendored)    | none          |
| Plonky3        | STARK prover / verifier / Goldilocks / Poseidon2 (§2.1) | `third-party/plonky3-uno/` commit `6374a36f` (vendored) | none |
| Rust toolchain | `uno_plonky3_ffi` build                                 | rustup; pin from `tosctl/src/rust-toolchain.toml` (`1.91.1`) | rustup install |

If `liboqs` cannot be found at configure time, CMake emits
`-- uno_workchain: liboqs not found — ML-KEM-768 built with UNO_MLKEM_STUB=1
(runtime abort)`. That build MUST NOT be used on the testnet; the runtime
will abort on every `uno_sendTransfer` (see [`BUILD.md`](../BUILD.md)
§"Installing liboqs").

---

## 5. Bring-up checklist — per operator

Five operators × one checklist each. Run through the steps in order; do not
skip forward. Step 7 (state-root quorum) is the go/no-go gate for the
network — if any operator's step-7 hash disagrees, **nobody advances to
step 8**.

### Step 1 — Clone the `uno` branch at the pinned commit

```bash
git clone https://github.com/<org>/tos.git       # repository URL: TBD (§11)
cd tos
git checkout uno
git checkout <GENESIS_COMMIT_HASH>               # commit hash: TBD (§11)
```

The `GENESIS_COMMIT_HASH` is published by the release manager alongside the
signed `zerostate-genesis-notes.json`. Operators verify the commit matches
the published hash before continuing. Running off an arbitrary `uno` tip is
not acceptable — the testnet's 60-day window is tied to a specific
buildable commit.

### Step 2 — Install prerequisites

Follow [`BUILD.md`](../BUILD.md) top-to-bottom:

1. Linux base toolchain and `clang-21` ([`BUILD.md`](../BUILD.md) §Linux
   Prerequisites).
2. Rust via `rustup` ([`BUILD.md`](../BUILD.md) §"Installing the Rust
   toolchain").
3. `liboqs` at the pinned commit from `uno/crypto/LIBOQS_VERSION.md`
   ([`BUILD.md`](../BUILD.md) §"Installing liboqs"). Path A (`/usr/local`,
   sudo) is preferred for single-purpose validator hosts; Path B
   (`$HOME/.local`) is the multi-user fallback.

### Step 3 — Compile `validator-engine` and `tosctl`

C++ build:

```bash
cd /path/to/tos
rm -rf build-clang21 && mkdir build-clang21 && cd build-clang21
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21
# Or, for Path-B liboqs:
# CMAKE_PREFIX_PATH="$HOME/.local" cmake .. -G Ninja ...
ninja validator-engine
```

Confirm the Uno wiring lines are present in the configure output per
[`BUILD.md`](../BUILD.md) §"C++ Configure":

```
-- uno_workchain: found liboqs at /.../liboqs.a
-- uno_workchain: Corrosion found — linking libuno_plonky3_ffi.a into uno_workchain
-- uno_workchain: using vendored avatar BLAKE3 at /.../third-party/avatar-crypto
```

Rust tooling:

```bash
cd /path/to/tos/tosctl/src
cargo build --workspace --release -p tosctl
cd /path/to/tos/tosctl/uno
cargo build --release
```

### Step 4 — Obtain and place the genesis notes file

```bash
# Verify the release-manager signature of zerostate-genesis-notes.json
# (signing key distribution + verification command: TBD, see §11)
sha256sum zerostate-genesis-notes.json          # must match published value
mkdir -p /var/lib/tos-uno/testnet
cp zerostate-genesis-notes.json /var/lib/tos-uno/testnet/
```

The genesis loader is the K-genesis-loader path in §10.3 — it refuses to
come up if the total supply invariant fails.

### Step 5 — Generate the validator keypair and register with the masterchain

Validator-set formation on wc=2 is a subset of the existing TOS validator
set — operators opt in to wc=2 by advertising the capability (§1.4a "what
this means socially"). The concrete registration command surface re-uses
the existing masterchain validator registration path (see
[`doc/Validator-Local.md`](Validator-Local.md) §systemd Services for the
base pattern).

**Command: TBD** (§11). The registration transaction is a standard
masterchain op; the wc=2-opt-in flag is the only Uno-specific addition.
Operators follow the release-manager-provided recipe at testnet bring-up.

Once registered, the operator's validator public key appears in the
`ConfigParam 34` validator set alongside the other four.

### Step 6 — Start `validator-engine` and `tosctl uno scan` as systemd services

The validator itself is launched via the existing systemd pattern
documented at [`doc/Validator-Local.md`](Validator-Local.md) §systemd
Services (`tos-validator@<N>.service`). The Uno-specific additions are:

- the wc=2 activation flag on the `validator-engine` command line (flag
  surface: **TBD**, see §11 — the current `uno` branch does not yet expose
  `validator-engine --uno`, so the placeholder stays explicit);
- a companion `tos-uno-scan@<N>.service` running `tosctl uno scan` against
  the local RPC endpoint for the smoke-test wallet (§7).

Both services are expected to come up and stay up. `Restart=always` is
acceptable for `tosctl uno scan`; `validator-engine` should be
`Restart=on-failure` so a deterministic crash becomes visible instead of
being silently masked by a restart loop.

### Step 7 — Confirm the initial state-root quorum

After all five validators complete steps 1–6, each operator runs:

```bash
tosctl uno chain-info --rpc http://127.0.0.1:<rpc_port>
# Expected fields: { chain_id: 0x554E4F54, workchain_id: 2,
#                    head_seqno: 0, anchor_window_size: 100, ... }
```

The release manager publishes the **expected zerostate commitment-tree
root** (the `get_uno_getAnchor()` value at `head_seqno = 0`) computed by
the reference zerostate builder. Expected root hash: **TBD** (§11).

All five operators post their measured `uno_getAnchor()` zerostate root
back to the distribution channel. Byte-identical hashes across all five =
go for step 8. Any disagreement = halt and root-cause before proceeding; a
disagreement at step 7 means the five operators did not all start from the
same zerostate, and the 60-day gate cannot begin.

### Step 8 — Open the monitoring dashboard

Metrics endpoints: **TBD** (§11). The `uno_workchain` code path exposes the
signals in §6; the dashboard / alerting infrastructure (scraper, time-series
store, alert rules) is not yet set up in the repo and will be nominated at
testnet bring-up time.

Until the dashboard is set up, operators fall back to direct RPC polling of
`uno_chainInfo()`, `uno_getAnchor()`, and the validator-engine stderr log.

---

## 6. Tx-generation smoke test

Once all five validators report green at step 7, the release manager runs a
continuous synthetic-load smoke test against one of them. Two smoke-test
wallets (A and B) are pre-funded in the genesis notes file.

```bash
# Wallet A → Wallet B, 1-spend / 2-output typical shape
tosctl uno send \
  --from <wallet_A_fvk.json> \
  --to   <wallet_B_address> \
  --amount 1000000 \
  --rpc  http://<validator_rpc>
```

Expected behaviour:

- `uno_sendTransfer` returns a tx hash.
- The tx is included **within 5 blocks** (≤ ~5 s at 1 s block time) under
  light load; under sustained synthetic 4 TPS load, within 10 blocks.
- `tosctl uno scan` on wallet B sees the incoming note within one block
  after inclusion (§5.8 wallet sync budget).
- `tosctl uno balance` on wallet B increments by the exact sent amount
  (fees are paid by wallet A's change output shape, §4.3 step 4 balance
  constraint).

If inclusion exceeds 10 blocks under load, the smoke test fails and the
incident is triaged under §8.

---

## 7. Monitoring and alerts

Every signal listed here maps to a file in `uno/core/` or `uno/rpc/`. The
names of the metrics endpoints, the scrape targets, and the alerting
infrastructure are **TBD** (§11).

### 7.1 State-root drift (P0 alert — any drift fires immediately)

- **What**: any cross-validator disagreement on the post-block
  `commitment_tree_root` or `nullifier_set_root` at the same `block_seqno`.
- **Why this is P0**: this is the single most serious failure mode. A
  state-root divergence means two of the five validators applied the same
  tx stream and produced different states — which is, by definition, a
  determinism-invariant breach (§12 P.5). The 60-day gate resets on any
  occurrence (§9).
- **Signal**: each operator posts the post-block state root into a cross-
  validator reconciliation channel (polling `uno_getAnchor()` at every new
  seqno); the dashboard alerts on any per-seqno hash mismatch.
- **Action**: §8.1 state-root drift incident playbook.

### 7.2 Block production cadence

- **What**: time between consecutive block commits on the head validator.
- **Target**: 1 s ± 250 ms (p95 over a 5-minute window). Sustained cadence
  outside this band indicates either consensus trouble (catchain rounds
  over budget) or compute-phase overrun (§5.9 budget breakdown).
- **Signal**: monotonic `head_seqno` from `uno_chainInfo()` sampled at 500
  ms from each validator; timestamp delta derived client-side.
- **Action**: correlate with §7.4 verify-time trend; if verify is in-band,
  look at consensus / propagation (catchain, QUIC flood control).

### 7.3 Nullifier LRU hit rate + cold-dict traversal rate

- **What**: ratio of nullifier-set lookups answered by the in-memory LRU
  (§5.3) vs. ratio that fall through to the on-cell dictionary.
- **Why**: a collapsing hit rate (e.g. < 90 %) signals either LRU capacity
  misconfiguration or an adversarial access pattern that defeats the LRU.
  Cold-dict traversal can blow the 1 s block budget under sustained load
  (§5.3 implementation requirement M2).
- **Signal**: counters exposed by `uno/core/nullifier-set.cpp` (endpoint
  **TBD**).
- **Action**: tune `nullifier_lru_capacity` (advisory, non-consensus); file
  issue if a pattern persists.

### 7.4 Plonky3 verify time (P50 / P99)

- **What**: per-tx Plonky3 verify latency measured inside
  `ParallelVerifyPool` (§13 P.3).
- **Targets during the stability window**:
  - Median **< 150 ms** single-thread
  - P99 **< 500 ms** single-thread

  These are the relaxed testnet targets. §1.4's single-thread 20 ms target
  depends on the §13 P.2 column-collapse work landing fully; until then the
  testnet runs under the relaxed envelope. See §9.4 for the rationale.
- **Signal**: per-tx verify-latency histogram (endpoint **TBD**).
- **Action**: trend-watch. A climbing P99 without a shape-correlated
  explanation is a trigger for a §13 P.3 re-measurement.

### 7.5 Memory and disk growth

- **What**: `validator-engine` RSS and `/var/lib/tos-uno/<state_dir>` size
  growth rates.
- **Targets**:
  - RSS steady-state < 12 GB (inside the 16 GB envelope of §3)
  - Disk growth ≤ ~500 MB per 10 M spends (§5.3 on-disk scaling note)
- **Signal**: standard `process_resident_memory_bytes` + `df -h` / `du -s`
  on the state directory.
- **Action**: RSS > 14 GB for > 10 min = OOM risk; file incident per §8.3.

---

## 8. Incident response playbook

Each class of incident has the same three phases: **halt** (stop the
damage), **preserve** (capture artifacts), **report** (file a trackable
issue with enough evidence to root-cause). The 60-day window enters the
reset logic in §9 based on the incident classification.

### 8.1 State-root drift across validators

1. **Halt** the diverging validator(s) immediately
   (`systemctl stop tos-validator@<N>`). Do not restart.
2. **Preserve**: copy the entire state directory, the
   `validator-engine` log for the last ≥ 10 minutes, and the
   diverging-block raw data to a drift-capture directory
   (`/var/lib/tos-uno/incidents/<UTC-timestamp>-drift/`).
3. **Report**: file an issue including
   - `block_seqno` at which the roots diverged,
   - the last-agreed `commitment_tree_root` and `nullifier_set_root`
     (from `uno_getAnchor()` at `block_seqno - 1`),
   - each diverging validator's post-block roots,
   - a serialized state-snapshot diff (what leaves / nullifiers / anchor
     entries differ) produced from the drift-capture state snapshots.
4. The 60-day window resets (§9).

### 8.2 Unverifiable proof (validator rejects a proof the prover believed valid, or vice versa)

1. Dump the offending `Transfer` in its entirety: wire bytes, decoded
   header + spend + output structures, and the serialized `zk_proof` cell.
2. Dump the public-input vector (§4.3 step 4) that the validator
   reconstructed.
3. File an issue against the `uno_plonky3_ffi` crate with both artifacts
   attached plus the exact verifier error code from
   `uno_plonky3_verify`. This class of incident is non-halting (the tx is
   already deterministically rejected) but is a reset trigger only if it
   turns out the reject was wrong (i.e. a sound proof was rejected).

### 8.3 Panic, crash, OOM

1. Preserve the core dump (`systemd-coredumpctl list` + `coredumpctl dump
   validator-engine > core.<UTC-timestamp>`).
2. Preserve the full state directory (tar + gzip).
3. Preserve the last ≥ 1 h of the validator-engine log.
4. Restart per standard systemd recovery. If the crash recurs on the same
   block seqno after a clean restart, this is a deterministic crash and
   escalates to a §9 reset.

### 8.4 Network partition / fork

wc=2 rides the standard TOS masterchain consensus (§5.0 single executor
account, §8.5 no changes to TOS block header). Network partitions follow
the upstream TOS recovery procedure documented in
[`doc/Validator-Local.md`](Validator-Local.md). Uno-specific recovery
additions:

- Once the partition heals, the five validators must re-converge on
  identical `uno_getAnchor()` values before any new txs are accepted on
  the lagging validator. The reconciliation channel from §7.1 is the
  authoritative check.
- If the partition produced two competing commitment-tree roots that both
  advanced, §8.5 (rollback / fork recovery) applies.

### 8.5 Rollback and fork recovery

The testnet may fork during the 60-day window. Forks are expected; they
are not failures so long as they are recoverable and understood.

Decision matrix:

| Situation                                                                    | Canonical chain                                      | Re-launch?       | Genesis notes version |
|------------------------------------------------------------------------------|------------------------------------------------------|------------------|-----------------------|
| 3+ of 5 validators on chain A, 0–2 on chain B                                | Chain A (masterchain consensus threshold)            | No               | unchanged             |
| 2 + 2 + 1 split, reconcilable within 100 blocks (anchor window §5.4)         | Whichever chain reaches 3-of-5 first                 | No               | unchanged             |
| Unreconcilable split; no 3-of-5 agreement within 1 h                         | **None — testnet is halted and re-launched**         | **Yes**          | **version bump**      |
| A reproducible determinism bug (e.g. HashMap order leak) is discovered       | Existing chain invalid; root-cause and fix first     | **Yes**          | unchanged unless root-cause requires new distribution |

Restart procedure:

1. Release manager calls the restart in the operator distribution channel.
2. All five validators stop (`systemctl stop tos-validator@<N>`) and
   archive their state directories and logs for post-mortem.
3. If the genesis notes file is re-issued, it is versioned as
   `zerostate-genesis-notes-v<N>.json` with a fresh release-key signature
   and a new published SHA-256.
4. The 60-day window **resets** to day 0 (§9). There is no preserving of
   history across a re-launch; the testnet gate is a contiguous 60-day
   window.

---

## 9. Stability gate — what counts as "60 days of stability"

The testnet-green gate is **60 consecutive calendar days** during which
all four of the following hold, every day:

### 9.1 Zero unexplained state-root divergences

"Unexplained" means: a divergence that, once root-caused, is traced to a
validator code path that ran at least once during the window (i.e. an
actual determinism breach inside wc=2 code). A divergence that is
traced entirely to an operator-local cause (wrong genesis notes file,
wrong commit hash, clock pathology breaking the expiry window,
corrupted disk) is a gate-pass: the network halts, the operator
re-bootstraps, and the window **does not reset** so long as the wc=2
code path itself produced identical outputs on the validators that had
clean inputs.

A root-cause that touches `uno/core/*` or `uno/plonky3-ffi/*` **does**
reset the window.

### 9.2 Zero validator crashes not attributable to OS / hardware

OS/hardware class (window does not reset): kernel OOM-killer on an
under-provisioned host, disk full, unrelated system service fault,
NIC flap, power event.

Validator class (window resets): panic inside `validator-engine`
originating in `uno/core/*` / `uno/crypto/*` / `uno/rpc/*` /
`uno/plonky3-ffi/*`, assertion failure in the same code, OOM
attributable to an RSS leak inside the Uno compute or state code.

### 9.3 Zero reproducible failures of the §12 test binaries run against a state snapshot

At least weekly (and after every incident), the release manager takes a
state snapshot from one of the validators and runs the full §12 matrix
against it on a reference machine. The 14 binaries listed in the §13
integration table must pass with zero **unintended** skips:

- `test-uno-primitive-parity`
- `test-uno-mandatory-negatives`
- `test-uno-end-to-end`
- `test-uno-parallel-verify`
- `test-uno-restart-survival`
- `test-uno-determinism`
- `test-uno-state-transition-golden` (intended opt-in skips behind
  `UNO_RUN_PROVE_FIXTURES=1` are allowed per §13)
- `test-uno-public-input-fixture`
- `test-uno-codec-shapes`
- `test-uno-transfer`
- `test-uno-filter`
- `test-uno-genesis-loader`
- `test-uno-bech32m-envelope`
- `test-uno-nullifier-warm-lru`

A reproducible failure resets the window.

### 9.4 Plonky3 verify latency under the relaxed envelope

- **Median verify < 150 ms** single-thread
- **P99 verify < 500 ms** single-thread

These are relaxed from the §1.4 target of ≤ 20 ms single-thread because
the §13 P.2 column-count collapse is in flight: the K-air-col-share +
K-air-col-step2 passes landed cumulative −92.5 % (cols 27,837 → 2,081,
proof 33 MB → 2.22 MB, verify 790 ms → 111 ms at 4/4 worst case), and
remaining shrinkage to reach the §3.4 envelope (~22× further) is
expected during the testnet window itself. The relaxed envelope lets
the testnet run productively while that work lands; it does not relax
the mainnet-activation verify target (§10).

A verify regression above the relaxed envelope, sustained over 24 h,
resets the window.

---

## 10. Day-60 decision process

On day 60, if §9.1–§9.4 all hold for the preceding 60 consecutive
calendar days, the release manager produces a **testnet-green report**
and circulates it to the five operators plus the project technical
leads. The report contains:

1. The window start and end dates and the exact commit hash the
   validators ran (pin to §5 step 1).
2. The SHA-256 of the `zerostate-genesis-notes.json` in use for the
   window (one hash — re-launches reset the window, so the 60-day
   window has exactly one genesis file).
3. Measured values for each of the §1 seven signals, weekly rolled.
4. The full incident log for the window, each incident classified per
   §9 (window-resetting or not) with a short root-cause note.
5. The full §12 matrix output from the final weekly snapshot replay.
6. A signed-off attestation from each of the five operators that their
   validator ran continuously (excepting classified §9.2 OS/hardware
   events) for the full 60 days.

Sign-off:

- The release manager signs the report on behalf of the release.
- Each of the five operators signs their own attestation.
- The project technical lead signs the go/no-go decision.

Once signed, this runbook + the testnet-green report becomes the **P.7
mainnet-activation artifact** referenced by §13 P.7. Mainnet ships
against the same commit hash, with:

- `chain_id` switched to `0x554E4F4D` ("UNOM", §10.4)
- HRP switched to `uno`, `network_tag = 0x01` (§2.6 envelope)
- a fresh `zerostate-genesis-notes.json` carrying the real 21 M
  mainnet distribution (§10.3)
- §1.4 verify targets restored to the mainnet envelope (20 ms
  single-thread); if §13 P.2 column collapse has not reached that
  envelope by day 60, mainnet activation is deferred, not forced.

A no-go decision sends the chain back to P.2/P.3/P.7 work and restarts
the 60-day window once the blocker is resolved.

---

## 11. Open placeholders — to be resolved at bring-up

The following items are deliberately marked **TBD** because the current
`uno` branch does not yet pin concrete infrastructure choices for them.
The release manager finalizes each one at the beginning of the testnet
window and publishes the values to the operator distribution channel.

| Placeholder                                                  | Resolved by                  |
|--------------------------------------------------------------|------------------------------|
| Repository clone URL (§5 step 1)                             | Release manager              |
| `GENESIS_COMMIT_HASH` on branch `uno` (§5 step 1)            | Release manager              |
| Signed `zerostate-genesis-notes.json` distribution channel (§2.3, §5 step 4) | Release manager |
| Release-key signature verification command (§5 step 4)       | Release manager              |
| Expected zerostate commitment-tree root at `head_seqno = 0` (§5 step 7) | Release manager   |
| Validator registration command on the masterchain for wc=2 opt-in (§5 step 5) | Release manager |
| `validator-engine` command-line flag surface for wc=2 activation (§5 step 6) | Release engineering |
| Metrics endpoint for nullifier-LRU counters, verify-latency histograms, block cadence (§7.3, §7.4, §7.2) | Release engineering |
| Monitoring dashboard + alert rule set (§5 step 8, §7)        | Release engineering          |
| Cross-validator reconciliation channel for state-root posting (§7.1) | Release manager      |
| Operator distribution channel for incident broadcast and restart calls (§8.5) | Release manager |

These TBDs are **not** a gap in the protocol design — they are
infrastructure decisions that sit one layer below the wc=2 protocol
and are invariant under the 60-day gate outcome. They are tracked here
so the gate cannot be declared green with any of them silently
unresolved.

---

## 12. Related documents

- [`doc/uno-workchain.md`](uno-workchain.md) — full wc=2 protocol design
  (45 locked decisions, §1–§16).
- [`BUILD.md`](../BUILD.md) — C++ / Rust build instructions, liboqs
  install paths, Uno-specific configure output.
- [`doc/Validator-Local.md`](Validator-Local.md) — base TOS validator
  systemd setup pattern; partition / recovery procedure.
- [`doc/Validator.md`](Validator.md) — base TOS validator overview.
