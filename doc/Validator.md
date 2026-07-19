# Running a TOS Validator

This guide describes the operator view of the validator stack in this repository.

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
