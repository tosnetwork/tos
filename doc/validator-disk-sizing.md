# Validator disk sizing

This note estimates how much disk a validator needs, states the retention rules
the estimate depends on, and checks each estimate against the four public-testnet
validators.

- **Release:** 4fb9ee70330e6247f2e0bc766a9ac5638b42ce58, on all four validators.
- **Network:** the epoch-6 public testnet (global id 2), about 13.4 days old.
- **Measured:** 2026-11-11 23:32 UTC.
- **Load at measurement:** the 72 h load run (about 2 transfers/s), with about 2.45 masterchain blocks/s.

## Summary

- **Retention is not a month.** It is set per node by two engine flags. A block
  is deleted `state-ttl + archive-ttl` after it was produced:

  | Configuration | Flags | A block is kept for |
  |---|---|---|
  | Public-testnet validator unit | `--state-ttl 3600 --archive-ttl 86400` | about 25 h |
  | Production template (`tos-ops production/systemd/tos-validator.service`) | `--state-ttl 86400 --archive-ttl 86400` | about 2 days |
  | Engine defaults (no flags) | 1 day + 7 days | about 8 days |

- **The node prunes by itself.** No operator action is needed for:
  - blocks;
  - old states;
  - the simplex consensus store;
  - the engine's own log files.
- **Outside the TTLs:**
  - the live state (celldb), which grows with accounts and storage, not with time;
  - persistent-state snapshots, kept by a separate tiered rule;
  - system logs;
  - any deployment tooling kept on the host.
- **At the measured load:**
  - blocks arrive at **3.6 GiB/day**;
  - the validator's data directory is **7.3 GiB**;
  - with logs, the validator's own footprint is about **11 GiB**.
- **Load drives the block term.** Size production from a real-TPS measurement.
  Until one exists, follow the upstream validator requirement (1 TB NVMe) and
  keep the database on NVMe. A rotating disk cut the local block rate about 20×
  through cell-store latency alone.

## 1. Retention rules

| Data | Rule | Source |
|---|---|---|
| Blocks in archive packages | Deleted once older than `gc_mc_time − archive-ttl`, where the GC masterchain block lags the head by about `state-ttl`. So a block lives about `state-ttl + archive-ttl`. | `validator/manager.cpp` (`Db::run_gc(..., archive_ttl)`); the engine's `--archive-ttl` help text |
| Old states | GC'd once older than `state-ttl` | `validator/manager.cpp` (`state_ttl()` check) |
| Persistent-state snapshots | Made for the first key block in each 2^17 s (36.4 h) window. A snapshot made at time `ts` is kept until `ts + (2^18 << b)` s, where `b` is the number of trailing zero bits of `ts / 2^17`. Half the snapshots are kept 3.03 days, a quarter 6.07 days, an eighth 12.1 days, and so on. They are written after a random delay of 0–6 h. | `validator/interfaces/validator-manager.h` (`is_persistent_state`, `persistent_state_ttl`); `validator/state-serializer.cpp` (`need_serialize`, the delay) |
| Snapshot GC | A snapshot is removed when its TTL has passed, or when its masterchain block handle cannot be resolved | `validator/db/archive-manager.cpp` (`got_gc_masterchain_handle`) |
| Key-block proofs | `key-proof-ttl` defaults to 10 years | `validator/validator.h` |
| Engine logs | `--log-rotate-mb 15 --log-keep-files 5` per log thread. `--session-logs` rotates at 256 MiB and keeps one `.old`. | the testnet unit; measured |
| System journal | journald default cap (10 % of the filesystem, at most 4 GiB) | host default |

**Theoretical snapshot count.** With a snapshot every 36.4 h, the number kept at
any time is about `2 + log2(network age / 36.4 h)`. Each one is a full serialized
state, so the count reaches about 10 after a year.

## 2. Estimation model

```
disk ≈ B × (state-ttl + archive-ttl)      blocks (archive packages)
     + celldb                               live state, grows with accounts/storage
     + N_snap × S_snap                      persistent snapshots (tiered TTL)
     + files + consensus + state            short-lived engine stores (bounded)
     + 6 × S_snap                           spool reserve while syncing from a snapshot
     + logs (≈2 GiB cap) + journal (≤4 GiB)
     + OS and tooling
```

Where:
- `B` is the block byte rate, which depends on load;
- `S_snap` is the serialized state size;
- the spool reserve follows the 600 % default in
  [persistent-state-spool-budget.md](persistent-state-spool-budget.md).

## 3. Theory against the four validators

All four validators run with `--state-ttl 3600 --archive-ttl 86400`. The figures
are per node; the four agree closely.

| Claim | Predicted | Measured (node-1 … node-4) | Verdict |
|---|---|---|---|
| Oldest ordinary block file | ≈ 25 h (+ GC granularity) | 25.8 h on every node | **holds** |
| Block byte rate | constant under steady load | 131–196 MiB/h in each hourly bucket, mean 154–156 MiB/h = **3.62–3.66 GiB/day** | **holds**. An earlier estimate of 4.3 GiB/day was wrong: it counted the whole `archive/` directory, which includes 0.54 GiB of snapshots that do not scale with retention. |
| Archive packages | ≈ 3.65 GiB/day × 25.8 h ≈ 3.9 GiB | 3.92–3.96 GiB | **holds** |
| Key-block data outside the window | small, kept | 24–34 MiB of key packages since genesis; 20–29 MiB of key-block entries in ordinary packages | **holds** (negligible) |
| Snapshot write delay | 0–6 h after the key block | mc 2,641,972: key block 16.5 h old, files 13.2–15.6 h old. mc 2,310,070: about 54 h old, files 47–53 h old | **holds** |
| Snapshots present now | windows 13690 (b=1, kept 6.07 d), 13689 (b=0, kept 3.03 d), 13688 (b=3, kept 24.3 d), 13684 (b=2, kept 12.1 d) | 13690 and 13689 only (mc 2,641,972: 288 MiB; mc 2,310,070: 252 MiB), identical on all four | **does not hold.** The two long-TTL snapshots are absent on all four nodes. See §5. |
| `consensus/` (simplex store) is bounded | no file older than the TTLs | 0.62 GiB on each node, 285 files, oldest 1.1 h | **holds** |
| `files/` (blocks not yet packaged) is bounded | no large file older than the TTLs | 0.76–0.78 GiB; ≤ 67 KB older than 26 h | **holds** |
| `celldb` is flat at steady state | no growth in time | 0.89–0.94 GiB. The 72 h run's 10-minute series shows 0.85–0.98 GiB over 6.8 h with no trend. | **holds**. It tracks state size: the serialized state grew 252 → 288 MiB between the two snapshots (≈ 37 h). |
| Engine logs are capped | ≈ 16 threads × 6 × 15 MiB + 2 × 256 MiB ≈ 2 GiB | 1.70–1.81 GiB, 107–110 files | **holds** |
| System journal is capped | ≤ 4 GiB | 1.5–2.8 GiB | **holds** |

**Whole-disk accounting (node-1, 98.2 GiB filesystem, 36.7 GiB used):**

| Component | Size |
|---|---|
| validator data directory | 7.3 GiB |
| engine logs | 1.8 GiB |
| journal | 1.8 GiB |
| testnet build tooling (`/var/lib/tos-build`) | 10.5 GiB |
| installed binaries and the ops copy | 0.25 GiB |
| OS and everything else | ≈ 15 GiB |

The build tooling keeps every release build: six builds of about 1.07 GiB each,
plus the sources. It is not pruned, so it grows by about 1.2 GiB per release.
It is deployment tooling, not validator data, and a production host need not
keep old builds.

## 4. Sizing at the measured load

Measured inputs:
- `B` = 3.65 GiB/day;
- celldb ≈ 0.9 GiB;
- `S_snap` ≈ 0.29 GiB, with 2 snapshots kept;
- `files + consensus + state` ≈ 1.45 GiB;
- logs ≈ 2 GiB;
- journal ≤ 4 GiB.

| Block retention | Blocks | Validator total (data + logs + journal cap) |
|---|---|---|
| 25 h (testnet) | 3.8 GiB | ≈ 13 GiB |
| 2 days (production template) | 7.3 GiB | ≈ 16 GiB |
| 8 days (engine defaults) | 29 GiB | ≈ 38 GiB |
| 30 days | 110 GiB | ≈ 119 GiB |

Add the OS and the spool reserve.

These figures are for a light load. The block term scales with block bytes:
- historical single-host measurements under transfer/privacy load recorded about
  190 GB/day of writes per validator (`tos-ops production/Hardware-and-Hosting.md`);
- that is a write rate, not retained data, but it shows that heavy load can
  multiply `B` many times over.

The live state also grows with the number of accounts, and every snapshot is a
copy of it. At mainnet scale, `celldb + N_snap × S_snap` may dominate.

## 5. Open points

1. **Missing long-TTL snapshots.**
   - The tiered rule predicts snapshots for windows 13688 and 13684, which were
     made about 90 h and 236 h ago and are still within their 24.3-day and
     12.1-day TTLs.
   - None of the four nodes has them.
   - The engine logs that would show their serialization or removal have
     already rotated.
   - A JSON-RPC `lookupBlock` no longer finds mc 2,310,070, but that snapshot is
     still on disk. So the snapshot GC does not delete a snapshot just because
     this lookup fails.
   - **Check:** mc 2,641,972 (b=1) should stay until about 2026-11-17 08:41 UTC.
     If it disappears soon after its block leaves the archive window (about
     2026-11-12 08:51 UTC), snapshots are being removed earlier than their TTL.
   - Until this is settled, size for the tiered rule's upper count, not the two
     snapshots measured.
2. **The block rate under real load** is the largest unknown. Measure archive
   bytes per day at the real-TPS test and replace `B` above.
3. **Spool reserve** applies only while a node syncs from a snapshot. Keep it
   free on every validator, because any node may need to resync.

## 6. Recommendation

- **Disk:** NVMe, starting at 1 TB per validator, following the upstream
  validator requirement. Re-derive it once the real-TPS test gives `B`.
- **Disk tier:** never put the database on a rotating disk. Disk flush latency,
  not capacity, is the tightest disk resource on the testnet VPS class.
- **Retention:** keep the production template's 2 days unless an archive service
  is required. A longer history belongs on dedicated archive nodes, not on
  validators.
- **Alerts:** alert on free space and on write rate separately.

## 7. How the measurement was taken

The measurement was read-only. It ran on each validator as root over SSH, at
`nice -n 19 ionice -c3`. For each node it collected:
- `statvfs("/")`;
- `du -sb` of every top-level entry under `/var/lib/tos/validator`, plus
  `/var/log/tos`, `/var/log/journal` and `/var/lib/tos-build`;
- for `archive/packages`, per-package bytes and file mtimes, bucketed by age in
  hours;
- for `archive/states`, each file's name, size and mtime;
- for `consensus/`, `files/`, `celldb/` and `state/`, the file count, the oldest
  mtime and the bytes older than 26 h;
- the TTL and log flags from `systemctl show -p ExecStart` of the validator unit.

Key-block times come from JSON-RPC `getBlockHeader` on the `prev_key_block_seqno`
chain.
