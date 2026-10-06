# Production node configuration (design)

Status: **design for review, not an accepted operating procedure.** This
document is the production counterpart of
[Local-PQ-Network.md](Local-PQ-Network.md). The local document describes a
disposable development chain built by one script. This one describes how an
independent operator should configure and start a node on a shared network:

- which roles exist and how each is exposed;
- where each key lives;
- which options a production node sets and which it must never set;
- how disk use is bounded;
- how a validator joins, stays in and leaves the validator set;
- what is still missing before any of this can be followed for real.

Every statement about behaviour is taken from the code at the commit this
document was written against. Section 12 lists the gaps: tooling the
procedure needs but the repository does not yet provide. Until they are
closed, the steps that depend on them cannot be carried out with released
artifacts alone.

## 1. What differs from the local network

| Concern | Local development network | Production |
| --- | --- | --- |
| Genesis | Generated per reset, global ID 3 | One ceremony ([validator-genesis-bootstrap.md](validator-genesis-bootstrap.md)), global ID 1 |
| Consensus keys | Deterministic fixture seeds | Generated once by each operator, never derived, never shared |
| Controller root key | Deterministic seed on the node host | Offline operator domain; never on the validator host |
| Funds | Genesis faucet wallet | Operator wallets; pool principal belongs to its owner |
| Elections (Config15) | 600 / 300 / 60 / 180 s | 65536 / 32768 / 8192 / 32768 s (`gen-zerostate.fif`) |
| Validator set | 4 members plus one standby | At most 21 (`config/pq-launch-limits.json`), enforced at four points |
| Hosts | Seven nodes on one machine, loopback | One validator per host; separate full, RPC, archive and DHT hosts |
| Retention | 1 h states, 2 h archive, consensus cleanup on | Section 6; consensus cleanup is a launch decision |
| Monitoring | Local health stack on the same host | Health stack off the validator host (`production_off_validator`) |
| Install | `setup-testnet.sh --clean` wipes `/data` | Nothing is ever wiped; data moves only through verified snapshots |

Nothing marked as development-only in the local document may be used in
production. That includes:

- `deterministic_pq_initial_validator_seed`;
- the fixture root seeds `SHA256("tos-test-pq-election-controller-root-v1" ‖ index)`;
- `main-wallet.pk` as a funder;
- `local-pq-elections.py`, `local-pq-transfers.py`, `local-pq-privacy.py` and
  `local-pq-fund-controllers.py`;
- the development pool verifying key;
- `--enable-validator-consensus-cleanup` while it is still labelled acceptance-only (section 6.4).

## 2. Node roles

| Role | Holds consensus key | Public listeners | Purpose |
| --- | --- | --- | --- |
| **Validator** | yes | ADNL/QUIC only | Produces and signs blocks while it is in Config34 |
| **Full node** | no | ADNL/QUIC | Follows the chain; source of sync for others |
| **RPC / liteserver node** | no | ADNL/QUIC, liteserver; JSON-RPC behind a proxy | Serves wallets, explorers and services |
| **Archive node** | no | as RPC, usually private | Keeps all blocks and states |
| **DHT node** | no | ADNL (UDP) | Address resolution for the overlay network |

Rules that follow from the code:

- A validator runs no public liteserver and no JSON-RPC. Its console and
  exporter bind to loopback. Wallet and explorer traffic go to RPC nodes, so a
  query load can never starve consensus.
- A validator host holds exactly one consensus key. The node refuses to start
  a validator group unless it holds the exact key that Config34 records for its
  controller (`validator/manager.cpp`, group creation). Running a second copy
  of the same key elsewhere is never a failover mechanism; it is how a
  validator double-signs.
- JSON-RPC with write methods (`sendBoc`, `sendQuery`) may only bind to
  loopback. The node exits with code 2 otherwise, whatever API key is set
  (`validator-engine.cpp`, `json-rpc-listen-policy.h`). A public RPC endpoint is
  therefore either `--json-rpc-readonly` on a public address, or a loopback
  write listener behind an authenticating reverse proxy.
- A validator should keep a trusted full node as its master
  (`--full-node-master-trusted`, see [FullNode.md](FullNode.md)), so that block
  data fetching does not depend only on public peers.

## 3. Key custody

There are three custody domains. A key never moves to a less protected domain.

| Domain | Keys | Where |
| --- | --- | --- |
| **Offline operator domain** | Controller root seed (`tos-pq-key keygen`); next root seed during rotation | Air-gapped machine or HSM-backed signer. The root signs controller actions (`tos-pq-controller`) and nothing else. |
| **Validator host** | PQ consensus seed (32-byte ML-DSA-44 seed); ADNL/DHT transport keys in the keyring; console server key | The node host, owner-only files |
| **Operator wallets** | Pool owner wallet; validator (stake-ordering) wallet; operating-authorization payer wallet | Wallet custody of the operator's choice; the owner wallet ideally offline |

### 3.1 Consensus key

- Generate it on the validator host:
  ```bash
  umask 077
  tos-pq-consensus-key generate /var/lib/tos/validator/keys/pq-consensus.seed
  ```
  The tool refuses to overwrite a key, writes through a temporary file and a
  rename, and fsyncs the file and its directory. It prints the algorithm,
  `key_id` and public key, and never the seed.
- The node and every PQ tool load the seed with the same rules
  (`crypto/pq/seed-file.h`):
  - no symlink;
  - a regular file of exactly 32 bytes;
  - owned by the effective user;
  - no group or other permission bits;
  - a parent directory that is not group- or world-writable.

  A permission error must be fixed, never worked around by loosening modes.
- Back up the seed **offline and encrypted**, never on the host. A lost
  consensus seed is recoverable by binding a new key (kind 3). A leaked seed is
  a double-signing risk until it is rebound.

### 3.2 Controller root key

- Generate it with `tos-pq-key keygen` in the offline domain. The root is
  deliberately not linked into the node: `scripts/check-root-authority-off-the-node.sh`
  fails the build if root symbols reach the validator, overlay, ADNL or
  catchain code.
- Every root action is an internal message body produced offline and submitted
  from a wallet:

  ```bash
  tos-pq-controller send|bind|rotate-root|fund-operations|withdraw-operations \
    ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL ...
  ```

  - `EPOCH` and `NONCE` come from the controller getter `controller_state`.
  - `VALID_UNTIL` must be in the future and at most 3,600 s ahead.
  - Each action spends one nonce. `rotate-root` increments the epoch and
    resets the nonce to 0.
- **Binding a consensus key.** Kinds 2 (rotate root) and 3 (bind consensus
  key) need a cosignature by the incoming key, so a kind 3 `bind` needs the
  consensus seed inside the offline ceremony. To avoid moving the seed at all
  for the initial key, bind it **at birth**: put the consensus `key_id` into the
  controller's initial data, as the test fixture does. Only the public `key_id`
  then crosses domains. Later key rotations (kind 3) need a planned ceremony;
  see gap G5.

## 4. Host layout and service account

One system user per node role, for example `tos`, with no login shell. The
layout below replaces the development `/data/testnet/node<i>` tree.

```
/usr/local/bin/                         release binaries, verified by digest (section 10)
/etc/tos/global-config.json             network global config (section 8), root-owned 0644
/var/lib/tos/<role>/                    -D database root, owned by tos, 0700
/var/lib/tos/<role>/config.json         local config generated on first run (section 5)
/var/lib/tos/<role>/keyring/            transport and console keys, 0700
/var/lib/tos/<role>/keys/pq-consensus.seed   validator only, 0600, in a 0700 directory
/var/log/tos/<role>/                    -l log, --session-logs
```

- Keep the database on dedicated NVMe and the logs on a separate volume.
- `-f` (Fift directory) is accepted but never read (`validator-engine.hpp`),
  so it is omitted.

## 5. First start

The node always runs from `<db>/config.json`. `-c` is read **only when that
file does not exist**. In that case the engine:

1. builds `<db>/config.json` from the given local config and `-I <ip:port>`;
2. creates ADNL, DHT and full-node transport keys;
3. logs "check it manually before continue";
4. exits 0.

A production install therefore has two phases:

1. **Generate.** Run the engine once:

   ```bash
   validator-engine -C /etc/tos/global-config.json -D /var/lib/tos/<role> -I <public-ip>:<port>
   ```

   It creates `config.json` and exits. Review the file.
2. **Configure** before the first real start:
   - Add console control keys. The Docker entrypoint does this with
     `generate-random-id` and a permissions template (`docker/init.sh`,
     `docker/control.template`).
   - On RPC nodes only, add liteserver keys.
   - **Validator only:** add
     `extraconfig.pq_consensus {validator_id, consensus_key_file}`
     (`tl/generate/scheme/tos_api.tl`):
     - `validator_id` is the controller's 256-bit account ID;
     - `consensus_key_file` is the absolute path from section 4.

     The engine aborts at start if `validator_id` is zero or the key fails to
     load. No console command sets this block yet; see gap G3.

The Ed25519 keys created in step 1 are transport identities only (ADNL,
DHT). They have no part in consensus.

## 6. Storage and retention

### 6.1 How data is retired

| Data | Retired when | Code |
| --- | --- | --- |
| States (CellDb) | The GC floor passes them | `ValidatorManagerImpl::try_advance_gc_masterchain_block` |
| Archived blocks | At least `state-ttl + archive-ttl` after their time, per 20,000-seqno package | `ArchiveManager::run_gc`, `archive-gc-floor.h` |
| Session statistics | Self-rotating at 256 MiB, one `.old` copy | `max_session_stats_file_bytes_` |
| Text log (`-l`) | Rotates at 10 MiB, one `.old` copy | `TsFileLog` |
| Retired validator consensus databases | **Never by default** | Section 6.4 |

The GC floor advances only while **all** of the following hold:

- it is behind the last key block;
- it is behind the last validator-set rotation;
- it is behind the persistent-state serializer;
- it is at least 1,024 blocks behind the head;
- it is behind the shard client;
- the state at the floor is older than `--state-ttl`.

The serializer walks every masterchain block and normally keeps up. It pauses
only when a key block starts a new 2^17 s (about 36.4 h) period. Then it waits a
random 0–6 h before writing that persistent state, and the floor cannot pass
it meanwhile. On the local network, with a key block every ten minutes, the
floor ran about `state-ttl` behind the head, and usage levelled off within
hours.

On production elections (`elected_for` 65,536 s), key blocks come from set
rotations about every 18 h, plus configuration changes. The floor can
therefore stop for up to about 18 h behind the last key block, plus up to 6 h
at a persistent-state boundary. **Plan disk for the TTLs plus about one day**,
not for the TTLs alone.

**Short retention also removes old key blocks.** A lite client that proves its
way forward from the zero state needs every key block since Genesis. Once those
blocks are collected, a newly started client fails with
`LITE_SERVER_NOTREADY: block handle not in db`; this was observed on the local
network. Every client therefore needs a recent trusted `init_block`. Section 8
covers how the global config provides it.

### 6.2 Recommended retention per role

| Role | `--state-ttl` | `--archive-ttl` | Other |
| --- | --- | --- | --- |
| Validator | 86400 (default) | 86400 | `--max-archive-fd` default 512 |
| Full node / RPC | 86400 | 604800 (default) | enough history for wallet clients |
| Archive | ≥ 30 d | as policy requires | `--permanent-celldb` only on a dedicated archive host; it cannot be turned off. At `state-ttl` ≥ 30 d CellDb raises its cache to at least 16 GiB. |

### 6.3 Disk sizing

Measured on the local development network: 4 validators, about 2.5–2.8
masterchain blocks/s, ConfigParam 30 target rate 400 ms. Per hour, per
validator:

- consensus databases about 670 MB;
- block files about 330 MB;
- archive about 180 MB;
- state database about 73 MB until GC.

A non-validating node writes about 370 MB/h.

These are **lower bounds** for production. With up to 21 validators, every
block carries more ML-DSA-44 signatures, at 2,420 bytes each. Production
sizing must be measured on the N6 hardware profile with 21 validators before
launch (gap G8). Until then, provision at least:

- (archive + block-file growth) × (TTLs + 2 days of GC lag) × 1.5 safety factor;
- plus the consensus databases (section 6.4);
- with at least 25 % free space ([Validator.md](Validator.md)).

### 6.4 Retired consensus databases — launch decision

Every validator-set session creates a RocksDB directory under
`<db>/consensus/`. A new session starts roughly every 250 s per validated
shard (ConfigParam 28 catchain lifetimes) and on every key block.

When a session retires, the node closes the directory and records a durable
cleanup intent. It deletes the directory only if
`--enable-validator-consensus-cleanup` is set. The option is labelled:

> ACCEPTANCE ONLY: arm live deletion of obsolete validator consensus-DB
> directories (Finding 1). Default off; a normal deployment must not set this.

A production validator built today therefore grows by roughly 16 GB per day
in consensus databases alone, without bound. One of these must happen before
launch:

1. **Accept** the cleanup path, so that it is enabled by default or approved
   for production. The local network runs it from October 2026; its results
   are evidence for this decision.
2. Ship an **offline maintenance procedure** that removes retired directories
   using the durable cleanup records while the node is stopped.

Running without either is not an option for a long-lived validator. The
startup sweep that exists today only removes *observer* directories.

## 7. Service definitions

The repository has no production unit; the `scripts/tos-pq-*.service` files
are development templates. Proposed validator unit:

```ini
[Unit]
Description=TOS validator
After=network-online.target
Wants=network-online.target

[Service]
User=tos
Group=tos
UMask=0077
WorkingDirectory=/var/lib/tos/validator
ExecStart=/usr/local/bin/validator-engine \
  -C /etc/tos/global-config.json \
  -D /var/lib/tos/validator \
  -l /var/log/tos/validator/node.log \
  --session-logs /var/log/tos/validator/session-stats \
  -t 16 \
  --state-ttl 86400 --archive-ttl 86400 \
  --exporter-address 127.0.0.1:9100
Restart=on-failure
RestartSec=10
KillMode=control-group
TimeoutStopSec=120
LimitNOFILE=1572864
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/tos/validator /var/log/tos/validator
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

Notes on each choice:

- **`LimitNOFILE`.** The engine raises its own open-file limit to 1,572,864
  but only logs a failure. The unit grants that limit explicitly.
- **No `MemoryMax`/`CPUQuota`.** No hard cap until steady-state memory has been
  measured on the production profile ([Validator.md](Validator.md)). A cap set
  too low turns a load spike into a validator restart.
- **`TimeoutStopSec`.** Leaves RocksDB time to close cleanly.
- **Further sandboxing.** Options such as `RestrictAddressFamilies` or
  `SystemCallFilter` are deliberately absent until a staging node has run with
  them. A filter that blocks something the network stack needs fails at
  runtime, not at start.
- **Defaults kept on purpose:**
  - `--initial-sync-delay` stays at its default 60 s. It is not an ADNL
    requirement.
  - `--quic-flood-control` stays at its default of 1,000 connections per IP.
    The `-1` used locally disables the protection.
- **Exporter.** The health exporter flags (`--health-node-id`,
  `--health-core-metrics`, `--health-native-core-v3`) require a performance
  acceptance per their help text. Enable them only with the monitoring design
  in section 11.
- **Full node, RPC or archive.** Same unit, plus as needed:
  - liteserver keys;
  - `--json-rpc-address <loopback>:<port>` behind a proxy, or
    `--json-rpc-readonly` on a public address;
  - `--json-rpc-trusted-proxy`;
  - the retention from section 6.2.
- **DHT node.** Uses `dht-server` with `-C -c -D -l -t -u` only. It has no TTL
  or rlimit options.

### 7.1 Options a production node must not set

| Option | Why |
| --- | --- |
| `--enable-validator-consensus-cleanup` (until accepted), `--test-consensus-cleanup-crash-before-erase` | Acceptance and fault injection; the latter exits abruptly by design |
| `-U/--unsafe-catchain-restore`, `-F/--unsafe-catchain-rotate` | Labelled dangerous; PQ rejects a nonzero rotate tag |
| `-T/--truncate-db` | Rewrites the database head; recovery tool only |
| `--disable-state-serializer` | Stops persistent states, which stops GC |
| `--permanent-celldb` | Irreversible; archive hosts only |
| `--quic-flood-control -1`, `--max-archive-fd 0` | Remove protection limits |
| `--unsynced-liteserver`, `--nonfinal-ls` | Serve unsynced or non-final data |
| `--json-rpc-cors-origin "*"`, `--json-rpc-expose-consensus-status` on a non-loopback bind | Expose the node beyond its role |
| `-v` above the default on a validator | Log volume and latency; diagnostics only, time-boxed |

## 8. Joining the network

1. **Global config.** It contains the zero-state, the init block and the DHT
   seeds. Obtain it from the network's signed release, not from an unauthenticated URL, and verify:
   - the zero-state root hash;
   - the file hash;
   - the global ID (1).

   The release must also carry a recent key block as `init_block`, refreshed
   at least as often as the shortest archive retention on the network's
   liteservers. Without it, new clients and new nodes cannot prove their way
   forward once the early key blocks are collected (section 6.1). Publishing
   that refresh is part of gap G7.

   The Docker default `https://tos.network/global-config.json` is
   not authenticated by anything in the repository (gap G7).
2. **Initial sync.** By default the node downloads the last `--sync-before`
   (3,600 s) of blocks and selects the best persistent state from peers.
   Persistent-state import is bounded by the `--persistent-state-*` budgets.
   Their effective values are logged at start; size the spool volume (48 GiB
   per import, 96 GiB total by default) accordingly.
3. **Snapshots.** Only through the digest-checked importer
   (`docker/import-snapshot.sh`) into a new database. A snapshot's zero-state
   check does not authenticate the global config.
4. Confirm sync before anything else depends on the node:
   - the head advances;
   - the node agrees with a second trusted node on the full block ID, not just
     the height;
   - `/readyz`, on RPC nodes, is within its threshold.

## 9. Validator lifecycle

Prerequisites: a synced full node (section 8) on the validator host, and an
operator wallet with funds. Steps marked **(gap)** depend on tooling listed in
section 12.

1. **Keys.** Consensus seed on the host (3.1). Root seed offline (3.2).
2. **Controller (gap G4).**
   - Build the controller's initial data:
     - epoch 0, nonce 0;
     - algorithm 1;
     - the consensus `key_id`;
     - the root public key.
   - Compute the address and birth witness with
     `tos-pq-controller witness CODE_BOC_B64 INITIAL_DATA_BOC_B64`.
   - Check that the code hash is admitted in ConfigParam 47; the Elector refuses
     unadmitted code with reason 10.
   - Deploy the controller from the operator wallet and keep the deployment
     transaction.
   - Register its birth state with
     `tosctl config bind import-birth --node N --transaction-boc B --output /abs/path`.
3. **Pool.** Deploy a single-nominator pool with owner, validator wallet and
   controller (`crypto/smartcont/single-nominator-pool/init.fif`, five
   arguments, see gap G9). Alternatively deploy a nominator pool with the
   controller in its config. Register it with `tosctl config pool add` and
   `tosctl config bind add`.
4. **Operating authorization (gap G2).**
   - Fund the controller with a root-signed kind 4 action, using
     `controller_operating_payload` and then `tos-pq-controller fund-operations`.
   - The payer is a dedicated operator wallet. Operating capital is not pool
     principal.
   - Each relayed stake charges `automatic_value` against funds and allowance:
     about 6.44 TOS at the current fee configuration, so re-derive it from the
     `sr` helpers.
   - In production there is one stake per election, about every 18.2 h, so
     about 8.5 TOS per day. For example, a 1,000 TOS deposit and allowance
     covers about four months. Set the sponsorship expiry to match, and set
     the per-request limit to at least `automatic_value`.
   - Deposits are **additive** and every other field is **replaced**, so renew
     by deficit (`funds_target - funds`).
   - Keep `balance ≥ funds + floor` plus a margin.
   - Monitor expiry: an expired authorization makes every relay fail with exit
     180, and the stake returns through a bounce.
5. **Stake.** `tosctl service` with the elections task enabled:
   - polls `active_election_id`;
   - obtains the PQ stake signature from the node
     (`create-stake-authorization` / `engine.validator.createPqStakeAuthorization`);
   - builds the pool stake order from the birth artifact;
   - recovers returned stakes.

   It does **not** manage the operating authorization (gap G2). Check that its
   console key steps fit a PQ-only node (gap G6).
6. **Verify each election.**
   - The Elector replies `sr::ok` for the query.
   - The controller's recorded result matches.
   - After the set switch, the validator appears in Config34 with its exact
     `key_id`.
   - Its node creates the validator group.

   Elector refusal reasons are listed in `elector-code.fc` (for example
   3 = wrong `stake_at`, 5 = below `min_stake`, 13 = witness mismatch).
7. **Leaving and recovery.** Stop staking. Funds stay frozen until
   `utime_until + stake_held_for` (32,768 s), then return through
   `compute_returned_stake` and the receipt-based recover path. Withdraw
   operating funds with kind 5, which needs no relay pending. Keep the node
   running until the set it belongs to has expired.
8. **Rotation.**
   - **Consensus key:** a kind 3 bind ceremony (3.2), then a restart with the
     new seed, timed between elections.
   - **Root key:** `rotate-root` (kind 2). It changes the epoch, so signed
     bodies prepared earlier become invalid.

## 10. Releases, upgrades and restarts

- Install binaries only from a tagged release, verified by digest and
  attestation (`gh attestation verify`), and container images only by digest.
- Roll a version one validator at a time:
  - only while the chain is live and every other validator is at the head;
  - wait until the restarted node is back at the head before the next one;
  - two validators replaying at once can halt a four-member set.

  See `tools/node-health-monitor/deploy/README.md`, "Rolling an engine".
- Protocol changes ship binary first, then activate by a configuration vote.
  `tosctl vote offer ls|diff|cast` exists; there is no `create` command, see
  gap G10.
- Never restart a validator to change a performance setting; measure on a
  non-validator first.

## 11. Monitoring

Place the health stack **off the validator host**:

- `placement: production_off_validator`, `remote_native_mode: cached_only`;
  see `tools/node-health-monitor/config/production.example.yaml`.
- Its `production_blockers()` refuse to run until the deployment fields are
  bound. That means `network_id`, binary, performance, mTLS, receiver and
  resource digests, and three distinct failure domains.
- On the validator, only `health-edge` runs, bound to the node PID, plus the
  loopback exporter.

Alert at least on:

| Signal | Why |
| --- | --- |
| Head age, agreement with a second node on the full block ID | Liveness and fork detection |
| Election outcome per round (`sr::ok` present, controller refusal or bounce) | A missed election is silent otherwise |
| Operating authorization: remaining funds/allowance below 25 %, expiry within 7 days | Expired or empty authorization stops staking |
| Time since last key block, GC floor progress (`VALCLEANUP pass gc_seqno`), consensus directory count | GC stalls show up hours before the disk does |
| Free disk below 25 %; growth rate above plan | Section 6 |
| Wallet balances of payer and validator wallets | Fees for stake orders and authorizations |

## 12. Gaps before this procedure can be followed

| ID | Gap | Effect |
| --- | --- | --- |
| G1 | Release artifacts and the Docker image do not ship `tos-pq-consensus-key`, `tos-pq-controller`, `tos-pq-key` or `tos-pq-vote` (`scripts/release-artifacts.json`, `assembly/`, `Dockerfile`) | A released node cannot create or use a PQ consensus key; the image is full node only |
| G2 | No production tool submits, checks or renews the kind 4 operating authorization; `tosctl` elections ignore it | Staking fails with exit 180 once the authorization is missing or expired |
| G3 | No console command or template sets `extraconfig.pq_consensus` | Validator configuration is a manual JSON edit |
| G4 | No production tool builds controller initial data or deploys a controller; only test fixtures do | Controller onboarding needs custom tooling |
| G5 | A key generated with `tos-pq-consensus-key` cannot be exported for a kind 3 ceremony; there is no supported transfer path | Key rotation after launch has no tooled procedure |
| G6 | `tosctl` elections still create classical permanent/temporary validator keys through the console | Must be reviewed against PQ-only consensus |
| G7 | No authenticated distribution of the global config; Docker defaults to an unauthenticated URL | Trust in the network starts from an unauthenticated file |
| G8 | Hardware profile is `OWNER_REVIEW_REQUIRED`; no 21-validator disk or memory measurement | Section 6.3 sizing is a lower bound only |
| G9 | Stale operator docs: Validator.md (no PQ setup, legacy unit names, `--initial-sync-delay` and `--quic-flood-control` described as required); FullNode.md (`-f` path, `-c` semantics); single-nominator HOWTO (four arguments instead of five, wrong file name); docker/README.md (ports 43677 vs 30001–30003, upstream example output); tos-upgrade-process.md (`tosctl vote offer create` does not exist) | Operators following existing docs reach wrong states |
| G10 | No tool creates a configuration proposal | Protocol activation by vote is not operable end to end |
| G11 | Retired validator consensus databases are never deleted by default (6.4) | Unbounded disk growth on every validator |
| G12 | No production systemd unit in the repository; dev templates hard-cap memory and disable QUIC flood control | Section 7 is a proposal only |

The order that unblocks a first external validator is:

1. G1, G3 and G4: an operator can create keys, configure the node and deploy
   a controller;
2. G2 and G11: the validator can stay in the set without manual top-ups or
   disk exhaustion;
3. G8: sizing;
4. G9: correct documentation.
