# Running a TOS Validator

This guide describes the operator view of the validator stack in this repository.

Validators are the verification backbone for AI actor workflows. Agent runners, service operators, and verifier processes may query validators, but validator nodes remain responsible only for protocol validation, consensus, and serving verified chain state.

## Main Components

- [validator-engine](../validator-engine)
- [validator-engine-console](../validator-engine-console)
- [lite-client](../lite-client)

## Validator vs Full Node

- a full node follows and serves chain data
- a validator additionally manages validator keys, consensus participation, and stake-related operations

## Required Artifacts

- global config
- local validator config
- validator keys
- persistent database directory
- Fift scripts directory

## Production Hardware Requirements

The following requirements apply to a normal TOS validator participating in
consensus. They assume a 64-bit Ubuntu 22.04 or 24.04 host, a validator
binary built with the production configuration, and a node that is not also
running unrelated workloads.

| Resource | Testnet / development minimum | Recommended production configuration (TON-aligned) |
|----------|-----------------------|---------------------------------------|
| CPU | 2 physical or virtual cores | 16 dedicated cores (32 threads preferred); 8 cores / 16 threads is the lower TON baseline |
| Memory | 4 GB RAM | 128 GB RAM |
| Storage | 100 GB SSD | 2 × 1.92 TB enterprise NVMe SSD; target at least 250k read IOPS and 83k write IOPS per device |
| Network | 10 Mbps symmetric bandwidth; a public IPv4 address is strongly preferred | 1 Gbps symmetric bandwidth with a fixed public IP |
| Operating system | Ubuntu 22.04 or 24.04, 64-bit | Ubuntu 22.04 or 24.04, 64-bit, on a dedicated host |

The production values are aligned with the TON-derived validator-engine,
consensus, storage, and peer-to-peer operating model used by TOS. The testnet
minimum is not a production capacity guarantee.

The testnet minimum is suitable for initial synchronization and a lightly
loaded development network. It is not a capacity guarantee for a busy
production network. Operators must leave free disk capacity for the RocksDB
database, logs, snapshots, temporary synchronization data, and future chain
growth; do not provision a disk that is already close to full.

### Production operating profile

For a production validator, use one validator process per physical host. Do
not colocate several validators on the same machine unless the deployment is
explicitly a lab or testnet. The production baseline is:

- 16 dedicated CPU cores (32 hardware threads preferred)
- 128 GB ECC RAM
- two enterprise NVMe devices, each 1.92 TB or larger
- sustained 1 Gbps symmetric connectivity and a fixed public IP
- redundant power, UPS, remote console, and hardware monitoring

The storage devices should provide predictable low-latency random I/O, not
just a high sequential benchmark. Keep separate capacity for the database,
temporary synchronization files, snapshots, and logs. Maintain at least 25%
free space on each device and replace a device before it reaches its
endurance or capacity limit.

### State retention and garbage collection

TOS validators are not archival nodes by default. Retention must be bounded so
that old state and archive data do not grow without limit. The validator
engine exposes these controls:

```text
--state-ttl <seconds>    state retention; default 86400 seconds
--archive-ttl <seconds>  archive retention; default 7 * 86400 seconds
--permanent-celldb       disable CellDB garbage collection (archival only)
```

Use the default TTLs for an ordinary validator unless a documented recovery,
compliance, or archival requirement justifies longer retention. Do not enable
`--permanent-celldb` on a consensus validator: it disables the storage
garbage-collection path and can cause unbounded disk growth.

Garbage collection requires free disk space and a healthy database. Monitor
the GC masterchain position, database size, archive size, and free space; a
validator that is behind the GC watermark must catch up before old state can
be deleted.

### CellDB and memory policy

Keep CellDB on RocksDB for production. The normal profile is:

```text
--celldb-cache-size 1073741824
```

TON-compatible builds use a 16 GiB minimum cache when the two-level index/filter
is enabled. Low-memory test nodes can override that floor explicitly, for
example:

```text
--celldb-cache-size 1073741824 --celldb-cache-min-size 536870912
```

The default remains 16 GiB; this option only lowers the minimum and does not
force the cache above `--celldb-cache-size`.

The V2 Cell reader also has an independent entry-count limit. For a low-memory
test node, use for example:

```text
--celldb-cell-cache-max-size 100000
```

The default is 1,000,000 Cell entries. Lowering this value bounds the in-memory
Cell object cache; it may increase cache misses and disk reads, but does not
change consensus correctness. To enable the additional arena, mmap, and V2
Cell-cache diagnostics temporarily, set:

```text
TOS_MEMORY_DIAGNOSTICS=1
```

When the variable is unset (the normal production setting), those diagnostic
logs are disabled.

Simplex CandidateResolver retains a bounded recent finalized-slot window. The
default is 4,096 slots. A low-memory test node can use a smaller window:

```text
TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS=1024
```

Candidates and notarization certificates outside the window are recovered
from persistent storage. Reducing the window lowers the steady-state consensus
working set but can increase database reads and writes during catch-up. Keep
the default on production validators unless a smaller value has passed
restart, partition, and offline catch-up testing for the target workload.

`--celldb-direct-io` may be evaluated only with a deliberately large CellDB
cache and a measured workload; the engine does not use direct I/O for small
cache settings. Do not enable it blindly.

Do not use `--celldb-in-memory` or `--celldb-preload-all` on a normal
validator. Those modes deliberately trade large amounts of RAM for startup
or read performance and are intended only for controlled benchmarks or
dedicated high-memory archival deployments. If memory pressure is observed,
reduce the CellDB cache, disable diagnostic session logs, and verify that GC
is advancing before applying a hard process memory limit.

The operating system may report database mappings and allocator arenas as
resident memory. Track both RSS and allocator statistics before concluding
that the database itself has leaked memory.

### Logging and observability

Production logging must be bounded. Use log rotation for validator, session,
and journald output; do not leave `-v3` and unbounded `--session-logs` enabled
indefinitely on a production host. Preserve enough logs to diagnose consensus
and networking faults, but cap retention and alert on rapid growth.

At minimum, collect the following per validator:

- finalized masterchain height and height lag against peers
- process RSS, allocator resident/allocated bytes, and swap usage
- CellDB cache size, RocksDB write stalls, compaction status, and database size
- archive/state size and GC watermark
- CPU utilization, validator thread count, disk latency, and free space
- peer/session counts, overlay traffic, and reconnect/error rates

The engine has built-in CellDB statistics and optional jemalloc statistics.
Enable the jemalloc build only for diagnostics, and use the runtime statistics
signal during an incident rather than enabling expensive profiling on every
production node.

### Resource limits and upgrades

Use systemd cgroup limits only as a safety net. A hard `MemoryMax` or strict
`CPUQuota` can interrupt block validation and cause a validator to fall behind.
Prefer alerting and controlled cache/log reductions; apply a limit only after
measuring the node's normal and peak working set.

Before an upgrade or configuration change:

1. Confirm at least two other validators are healthy and synchronized.
2. Record the current masterchain height, database size, RSS, and GC watermark.
3. Stop one validator gracefully and retain its database and logs.
4. Upgrade and restart it, then verify finalized blocks and height convergence.
5. Roll out the change to the remaining validators one at a time.

For CPU-intensive mining, collation, or other workloads running alongside
validation, use at least 8 vCPUs and increase memory and storage based on the
measured workload. A GPU is not required for ordinary validator
synchronization or consensus participation.

Monitor CPU, RSS, database size, disk free space, network transfer, and block
height continuously. If the node is expected to retain a long archive or
serve public full-node queries, provision substantially more storage than the
minimum or recommended values above.

## Starting the Validator Engine

```bash
cd build
./validator-engine/validator-engine \
  -C /data/tos/global-config.json \
  -c /data/tos/local-config.json \
  -D /data/tos/db \
  -f ./crypto/fift/lib \
  -I <public-ip>:<port> \
  --initial-sync-delay 5 \
  --quic-flood-control -1 \
  -l /data/tos/logs/validator-engine.log
```

### Required Launch Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `--initial-sync-delay` | `5` (seconds) | Delay before starting validation to allow initial state sync. Without this, ADNL handshake fails and liteserver connections time out. |
| `--quic-flood-control` | `-1` (disabled) | Disable QUIC flood control. Required for local/small networks. Without this, peer-to-peer communication may stall. |

These parameters are required for the node to accept external connections (lite-client, validator console). Omitting them causes the node to appear active but reject all ADNL handshakes.

### Optional Parameters

- `-t <N>`: worker threads (default: 7)
- `--parallel-validation`: enable account-level parallel validation
- `--collect-validator-telemetry`: export validator telemetry
- `--db-event-fifo`: publish DB events
- `--exporter-address`: bind metrics exporter
- `--session-logs <file>`: validator session statistics

## Using Validator Console

Connect with:

```bash
cd build
./validator-engine-console/validator-engine-console \
  -a <server-address> \
  -k <client-private-key> \
  -p <server-public-key>
```

Use the console for:

- key and permission management
- operational introspection
- validator maintenance actions
- governance and network management flows supported by the node

## Operating Guidelines

- rotate keys deliberately and document every change
- separate node identity, validator keys, and operator credentials
- pin logs and DB paths explicitly
- monitor sync status before attempting validator operations
- stage config or governance changes before main deployment
- keep AI agent keys, service API credentials, and validator keys in separate trust domains
- do not run unreviewed off-chain agent workers with validator keyring access

AI actor infrastructure should treat validators as chain-state providers, not as agent runtimes. Agent runners and service workers should be deployed as separate processes with their own logs, credentials, and restart policy.

## Maintenance and Graceful Shutdown

TOS does **not** auto-slash a validator that goes offline. There is no
"missed-block jail" rule, no consecutive-downtime threshold, and no
voluntary-exit signal that you have to send before stopping the process.
Operators may stop, restart, upgrade, or migrate a validator at any time
without losing stake.

This is a deliberate design choice based on complaint-driven slashing.
Concretely:

- **No automatic stake reduction for downtime.** Slashing is triggered
  only when another participant submits a `validator_complaint`
  (`crypto/block/block.tlb` — `validator_complaint#bc`) with a severity
  and a `suggested_fine`, and the complaint passes a 2/3 vote among the
  remaining validators within the post-round complaint window. The fine
  is then deducted from the offline validator's frozen stake by the
  elector contract (`crypto/smartcont/elector-code.fc::register_complaint`).
  Pure absence is, in practice, not a basis for a complaint that clears
  the vote — complaints are reserved for protocol violations such as
  double-signing or producing malformed blocks.

- **Block-level uptime is observable, but it is a soft signal.**
  `BlockExtra.block_create_stats` (see `crypto/block/block.cpp` and
  the liteserver query) records who collated and signed each block.
  This is exposed for monitoring and external accountability, but no
  on-chain code path reads it to deduct stake automatically.

- **Stake recovery is gated by the round window, not by uptime.** After
  a validator's term (`validators_elected_for`) ends, the stake stays
  frozen for `stake_held_for` so any complaint can still be filed. If
  no successful complaint lands in that window, the stake can be
  reclaimed via `recover_stake`, regardless of how many blocks the
  validator missed during the round.

### Recommended upgrade procedure

For a single validator in a cluster of `N`:

```bash
# 1. Stop the validator process (its stake stays put).
sudo systemctl stop tos-validator@<N>

# 2. Upgrade the binaries / config / data as needed.
sudo install -m755 build/validator-engine/validator-engine \
                   /usr/local/bin/tos-validator-engine
# ...

# 3. Start it back up.
sudo systemctl start tos-validator@<N>

# 4. Confirm it is producing or signing blocks again.
sudo journalctl -u tos-validator@<N> --since "1 min ago" | tail
tos-lite-client -C /data/tos-global.json -v 0 -c "last" -c "quit"
```

The cluster keeps producing blocks throughout, provided the remaining
online validators still meet the BFT-2/3 quorum
(`tos::quorum_threshold(total_weight)` — see `tos/quorum.h`). For an
equal-weight cluster, this means at most one validator may be offline
in `N=3`, at most one in `N=4`, at most two in `N=7`, and so on.

### What you do lose while offline

The validator does not earn block rewards or any signing fees for
blocks it did not contribute to. This is opportunity cost, not a
penalty against existing stake. Plan upgrades during low-throughput
windows if reward smoothness matters to your operator economics.

### Comparison with BSC-style auto-jail

BSC auto-jails a validator after a fixed number of consecutive missed
blocks and requires a "graceful exit" signal to suppress that behavior
during planned maintenance. TOS has neither auto-jail nor an exit
signal: maintenance is a no-op as far as the protocol is concerned. If
your deployment requires automatic liveness enforcement, that has to
be added on top — there is no built-in equivalent today.

## Related Docs

- [FullNode.md](FullNode.md)
- [Validator-Local.md](Validator-Local.md) — local 3-node testnet
- [ConfigParam.md](ConfigParam.md)
