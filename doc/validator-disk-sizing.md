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

  Upstream TON's validator settings are `state-ttl 86400`, `archive-ttl 86400`
  (mytonctrl validator mode and the upstream docker image), the same as the
  production template. tos-ops #88 aligns the testnet validator (and the full
  node, to mytonctrl's 30-day liteserver archive). The measurements below were
  taken before that change, with the testnet's `state-ttl 3600`.

- **The node prunes by itself.** No operator action is needed for:
  - blocks;
  - old states;
  - the simplex consensus store;
  - the engine's own log files.
- **Outside the TTLs:**
  - the live state (celldb), which grows with accounts and storage, not with time;
  - persistent-state snapshots. A validator keeps only its two newest, plus any
    whose key block is still inside the block window (§1);
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
| Snapshot GC | Only a snapshot with snapshots of at least two newer masterchain seqnos after it is considered. It is then removed when its TTL has passed, **or when its masterchain block can no longer be found by seqno**. That lookup searches the ordinary archive packages only, not the key-block packages, so it fails once the block's package is pruned, `state-ttl + archive-ttl` after the block. | `validator/db/archive-manager.cpp` (`persistent_state_gc`, `got_gc_masterchain_handle`, `get_block_by_seqno`) |
| Key-block proofs | `key-proof-ttl` defaults to 10 years | `validator/validator.h` |
| Engine logs | `--log-rotate-mb 15 --log-keep-files 5` per log thread. `--session-logs` rotates at 256 MiB and keeps one `.old`. | the testnet unit; measured |
| System journal | journald default cap (10 % of the filesystem, at most 4 GiB) | host default |

**Effective snapshot count.** The tiered TTL alone would keep about
`2 + log2(network age / 36.4 h)` snapshots, about 10 after a year. The handle rule
caps that on any node whose block window is shorter than the TTLs. Such a node
keeps the two newest snapshots, plus those whose key block is younger than
`state-ttl + archive-ttl`:
- a validator with a 1–2 day window keeps 2, briefly 3;
- a node with an 8-day window keeps those made in the last 8 days that are still within their TTL;
- the tiered TTL fully applies only where the block window covers it (archive nodes).

## 2. Estimation model

```
disk ≈ B × (state-ttl + archive-ttl)      blocks (archive packages)
     + celldb                               live state, grows with accounts/storage
     + N_snap × S_snap                      persistent snapshots (2 on a validator; §1)
     + files + consensus + state            short-lived engine stores (bounded)
     + 9 × S_snap + max(1 GiB, 0.3 × S_snap) free at import (resync gate, see below)
     + logs (≈2 GiB cap) + journal (≤4 GiB)
     + OS and tooling
```

Where:
- `B` is the block byte rate, which depends on load;
- `S_snap` is the serialized state size;
- the import term is the free space that a snapshot import requires before it
  starts. Below it, `CellDbIn::import_persistent_state_streaming` refuses the
  snapshot (`validator/db/celldb.cpp`, `check_persistent_state_spool_free_space`).
  The requirement is `persistent_state_import_required_free_bytes` in
  `validator/state-download-buffer.cpp`, made of three parts:
  - the spool reservation, 600 % of the snapshot file
    ([persistent-state-spool-budget.md](persistent-state-spool-budget.md));
  - plus half of it, for the CellDb copy of the new cells;
  - plus `max(1 GiB, reservation / 20)` for the node's other writers.

  With `S_snap` the snapshot file size, that is
  `6 S + 3 S + max(1 GiB, 0.3 S) = 9 × S_snap + max(1 GiB, 0.3 × S_snap)`.
  At today's 0.29 GiB snapshot it is about 3.6 GiB. It is checked against the
  free space of the database filesystem at import time, on top of everything the
  node already holds.

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
| Snapshots present now | windows 13690 (b=1, kept 6.07 d), 13689 (b=0, kept 3.03 d), 13688 (b=3, kept 24.3 d), 13684 (b=2, kept 12.1 d) | 13690 and 13689 only (mc 2,641,972: 288 MiB; mc 2,310,070: 252 MiB), identical on all four | **does not hold for the tiered TTL alone.** The two long-TTL snapshots are absent on all four nodes. The handle rule explains it (§5): 13688's and 13684's key blocks left the 25 h window long ago, and each had two newer snapshots after it. **Holds with the handle rule:** exactly the two newest remain. |
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

Add the OS and the free space a resync needs (`9 × S_snap + max(1 GiB, 0.3 × S_snap)`,
about 3.6 GiB today).

These figures are for a light load. The block term scales with block bytes:
- historical single-host measurements under transfer/privacy load recorded about
  190 GB/day of writes per validator (`tos-ops production/Hardware-and-Hosting.md`);
- that is a write rate, not retained data, but it shows that heavy load can
  multiply `B` many times over.

The live state also grows with the number of accounts, and every snapshot is a
copy of it. At mainnet scale, `celldb + N_snap × S_snap` may dominate.

## 5. Open points

1. **Missing long-TTL snapshots: explained.**
   - **Why only two remain:**
     - `got_gc_masterchain_handle` deletes a snapshot whose masterchain block handle cannot be found by seqno, whatever its TTL.
     - `get_block_by_seqno` looks in the ordinary packages only (`get_file_desc_by_seqno(..., false)`).
     - On the testnet, a key block's ordinary package is pruned about 25.8 h after the block.
     - The only guard keeps the two newest snapshots (`persistent_state_gc`: "do not delete the most recent fully serialized state").
     - So a validator keeps exactly the two newest snapshots.
   - **Evidence:** JSON-RPC `lookupBlock` for mc 2,310,070 returns this same function's error ("seqno not in db"). Its snapshot is still on disk only because it is one of the two newest.
   - **Upstream:** the behaviour is identical. The delete-on-missing-handle path dates from upstream's 2019 database rewrite, and the two-newest guard was added upstream in 2024. TOS's version differs only by an index check (§8).
   - **Not a defect for validators:**
     - a node that syncs needs the newest snapshot, and the two newest are always kept;
     - for disk, it means snapshots do not pile up on validators.
     - Making the tiered TTL bind on a validator would mean resolving the block from the key-block packages. That would diverge from upstream and add disk for no current consumer. Keep long snapshot history on archive nodes instead.
   - **Dated check:** mc 2,641,972 (b=1) has a TTL until 2026-11-17 08:41 UTC. The handle rule predicts it is deleted shortly after the snapshot for window 13692 is written. That window opens 2026-11-14 06:30 UTC, and the snapshot follows the next key block plus up to 6 h. The tiered TTL alone would keep it for three more days.
2. **The block rate under real load** is the largest unknown. Measure archive
   bytes per day at the real-TPS test and replace `B` above.
3. **Resync headroom** applies only while a node imports a snapshot. The import
   refuses to start below `9 × S_snap + max(1 GiB, 0.3 × S_snap)` free on the
   database filesystem. Keep that much free on every validator, because any
   node may need to resync. It grows with the state, not with retention.

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

## 8. Comparison with upstream TON

Checked against upstream TON v2026.10 (`857b8a57`), function by function. The
retention rules this note depends on are the same:

| Rule | Upstream | TOS | Effect on disk |
|---|---|---|---|
| Snapshot schedule and TTL (`is_persistent_state`, `persistent_state_ttl`) | 2^17 s windows, `2^18 << b` | identical | none |
| Which key blocks get a snapshot (`need_serialize`, `have_newer_persistent_state`), random delay 0–6 h | as stated | identical. TOS adds a test-only switch to skip the delay. | none |
| Snapshot GC (`persistent_state_gc`, `got_gc_masterchain_handle`) | delete on TTL expiry or an unresolvable handle | identical | none |
| Engine TTL defaults (`validator.h`) | state 1 d, archive 7 d, key proof 10 y | identical | none |
| Block (archive package) GC candidates | packages older than `gc_ts − archive_ttl`, never the newest candidate | the same candidates (`archive_packages_by_ttl`). TOS also refuses to delete a package that a reader, an applying block or an unapplied block may still need (`archive-gc-floor.h`). | TOS can only keep more, never less |
| State GC (`try_advance_gc_masterchain_block`) | `state-ttl`, plus a hold while upstream's global-balance calculator runs (`gc_blockers_`) | `state-ttl`; TOS has no global-balance calculator, so no hold | upstream may briefly keep extra states |
| Serializer with a block the database no longer knows | escapes to the latest key block only when the handle has a timestamp | the same escape, plus one after a day without progress when the handle has no timestamp (a liveness fix) | none in normal operation |
| Engine log size | no built-in limit; the engine reopens its log on SIGHUP, so an external logrotate must cap it | built-in `--log-rotate-mb` / `--log-keep-files` | TOS logs are capped without logrotate; an upstream host needs logrotate |

So the measured behaviour, including the two-snapshot cap explained in §5, follows
logic shared with upstream (including `get_block_by_seqno`, which searches the
ordinary packages only in both); it is not a TOS-specific change.
