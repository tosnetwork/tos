# Validator Operator Guide

This guide takes an operator from a synchronized node to a post-quantum (PQ)
validator that stands in elections, and covers what has to be done to keep it
there: key rotation, consensus-database cleanup, upgrades, configuration votes
and the global config's init block.

It is generic: it names no network, host, port or amount. Take those from the
network you join. Resource sizing, retention flags and memory tuning are in
[Validator.md](Validator.md); the node itself is described in
[FullNode.md](FullNode.md); the container image is described in
[docker/README.md](../docker/README.md).

## Keys and where they live

A PQ validator has two independent authorities. Keep them apart.

| Authority | Created with | Lives on | Signs |
|---|---|---|---|
| Consensus key (ML-DSA-44, 32-byte seed) | `tos-pq-consensus-key generate` | the validator host, readable only by the node's service account | blocks, stake authorizations, configuration and complaint votes |
| Wallet keys | `tosctl key add` (vault) | wherever the operator's wallets are kept | transfers, including the stake itself |

The validator is named by its staking account: the masterchain account that
sends the stake to the elector. That is the operator's wallet when it stakes
directly, or a nominator pool when the stake comes from one. Its account id is
the validator id the chain records. The elector accepts a stake only with an
ML-DSA-44 authorization, made by the consensus key, over that account, the
election, the weight factor and the node's ADNL address.

## 1. Install the tools

Linux release archives (x86_64 and arm64) and the node image ship, next to
`validator-engine`:

| Tool | Purpose |
|---|---|
| `tos-pq-consensus-key` | create, import, show, export the consensus key; bind it into a stopped node |
| `tos-pq-vote` | sign configuration votes, complaint votes and stake authorizations with the consensus key |

In the image they are in `/usr/local/bin`. From source, `tos-pq-consensus-key`
and `tos-pq-vote` are targets of the main build. The key tools handle files
with POSIX semantics and are not shipped for Windows or macOS.

## 2. Run a full node first

Start the node as a full node and let it synchronize ([FullNode.md](FullNode.md)).
Run it as a dedicated service account: every key check below compares file
ownership with the user that runs the node.

The engine holds `<db>/config.json.lock` for as long as it runs. A second
engine started on the same database, or started while a tool edits the
configuration, exits with status 2 and names the lock.

A validator serves no public queries. Do not configure lite servers on it, and
if it runs the JSON-RPC server, bind `--json-rpc-address` to loopback.
Wallets and explorers use separate RPC nodes.

## 3. Generate the consensus key

On the validator host, as the node's service account:

```bash
umask 077
install -d -m 700 KEYDIR
tos-pq-consensus-key generate KEYDIR/pq-consensus.seed
tos-pq-consensus-key show KEYDIR/pq-consensus.seed
```

Both print `algorithm`, `key_id` and the `public` key in hex; neither prints
the seed. `generate` refuses to replace an existing file. The node, and every
tool that reads the seed, accepts it only if it is a regular file (not a
symbolic link) of exactly 32 bytes, owned by the reading user, with no group or
other permission bits, in a directory that is not group- or world-writable.

Back the seed up encrypted and offline. The only command that writes the seed
is `export`, and it writes only to a pipe or socket, never to a terminal or a
file:

```bash
tos-pq-consensus-key export KEYDIR/pq-consensus.seed | ENCRYPT > BACKUP
```

`ENCRYPT` stands for the encryption program you use. Restore with
`DECRYPT < BACKUP | tos-pq-consensus-key import KEYFILE` (64 hex digits on
standard input).

## 4. Choose the staking account

The staking account is the validator's identity on chain. Pick it before
binding the node, because the node signs every stake authorization for it and
the elector refuses a stake signed for any other account:

- **A wallet.** A masterchain operator wallet (`tosctl config wallet add`, or a
  wallet created with `--workchain -1`) sends the stake itself, with the stake
  as the message value.
- **A single-nominator pool.** The pool holds the principal and sends it; the
  operator wallet sends only the fees. Its address is derived from its owner
  and its validator wallet, so it is fixed before deployment
  (`tosctl config pool add`, or `tosctl deploy pool` to deploy it). Fund the
  pool from its owner.

A consensus key stands for one staking account per election: the elector
refuses a stake whose key another member already uses.

## 5. Bind the node to the staking account

Stop the node, then, as the node's service account:

```bash
tos-pq-consensus-key bind-node DB_ROOT KEYDIR/pq-consensus.seed VALIDATOR_ID
```

`DB_ROOT` is the node's `-D` directory; the tool edits `DB_ROOT/config.json`.
`VALIDATOR_ID` is the staking account's id, as 64 hex digits or
`-1:<64 hex digits>`. The key path must be absolute; the key is checked under
the node's own rules. The tool:

- holds `DB_ROOT/config.json.lock` for the whole edit, and the cell database's
  `LOCK` when it exists, so it refuses while the node runs;
- refuses a leftover `config.json.tmp` (decide which file is correct first),
  a configuration with content the engine's schema would drop, a symbolic
  link, and a file owned by another user;
- refuses a different existing binding unless `--replace` is given; an
  identical binding is a no-op;
- keeps the file's mode and group, and writes through a temporary file,
  `fsync` and rename.

| Exit status | Meaning |
|---|---|
| 0 | bound, or already bound |
| 1 | refused; nothing was written |
| 2 | usage error |
| 3 | written, but the directory flush failed: run `sync` before relying on it |

Start the node. For every consensus key it holds it logs
`post-quantum consensus custody: validator_id <hex> key_id <hex> valid_from <t>
expire_at <t>` at start-up, in the same lower-case hex that
`tos-pq-consensus-key show` prints,
and stops instead of starting as an observer if the key cannot be
loaded. In the container image the binding is made from `VALIDATOR_ID` and
`PQ_CONSENSUS_KEY_FILE`; see [docker/README.md](../docker/README.md#run-a-validator).

## 6. Stand in elections

Configure `tosctl` ([tosctl README](../tosctl/src/node-control/README.md)): the
node's control connection (`config node add`), the validator wallet
(`config wallet add`), the pool if there is one (`config pool add`, or
`deploy pool`), and the binding (`config bind add`, with `--pool` when a pool
stakes). Pass a raw masterchain address to `--to`, `--owner` or `--address` of
these commands either as `--flag -1:<hex>` or `--flag=-1:<hex>`; address flags
accept a value starting with a hyphen, and refuse anything that is not an
address.

Enable the binding (`tosctl config elections enable NODE`) and run
`tosctl service`. Its elections task asks the node to sign each stake
authorization with the consensus key for the binding's staking account, so the
node must be bound to that account and running; it refuses, before any wallet
message, an authorization the node made for another account. Without a pool it
sends the stake from the wallet to the elector; with a pool it sends the pool
the order and only the fees. `tosctl config wallet stake --binding NODE` does
the same once, by hand.

The task does not create temporary validator keys: on the PQ chain the node is
matched to its validator-set entry only through the consensus key. Recovered
stakes are credited to the staking account, and the task asks the elector for
them after each validation round.

## 7. Retired consensus databases

Each validator-set session leaves a RocksDB directory under `<db>/consensus/`.
The engine deletes a retired session's directory once it is provably obsolete;
this is on by default and needs no flag. `--disable-validator-consensus-cleanup`
keeps them (for forensics) and makes the disk grow without bound. See
[Validator.md](Validator.md#retired-consensus-databases) for the conditions and
log lines.

## 8. Rotate the consensus key

A node can hold several consensus keys for its validator at once, so a
rotation from key A to key B needs no downtime. Each key has a window:
`valid_from` is the first election date (unix time) it signs stakes for, and
`expire_at` (0: never) is when the node stops using it at all. The node picks
the key per signature:

- a validator group, and a vote cast as a member of a set, use the key that
  set's descriptor records for this validator, and no other held key;
- a stake for an election uses the held key whose `valid_from` is the greatest
  not after the election date, with no override:
  `create-stake-authorization-with-key` only asserts which key that is, and is
  refused, naming the scheduled key, if the schedule assigns another;
- an expired key is used for nothing, and an older key is never substituted
  for it.

Two keys valid from the same election date, the same key twice, more than
eight keys, or a configuration whose keys have all expired are refused, by the
node at start-up, by the console, and by the offline tool. So is a removal that
would leave only expired keys.

`expire_at` is a hard deadline: from that second on the key signs nothing,
including in a validator group that is already running with it. A signature
whose computation crosses the deadline is discarded, and once the node has seen
the key expired it never signs with it again in that process, even if the clock
is stepped back, a new copy of the seed is added from another file, or the key
is removed and added again. That memory lasts for the life of the process only:
a node restarted with its wall clock rolled back before a configured key's
`expire_at` loads that key again by its window. The deadline is read from the host's wall clock, so clock skew
shifts it by the skew: run NTP. Set it after
the `utime_until` of every set that lists the key, or leave it at 0 and remove
the key instead (step 6).

In `config.json` a single key valid for every election is written as
`consensus_key_file`; any other set of keys is written in `keys` alone, with
`consensus_key_file` empty, and the node refuses a file that states both, or
that names a window field it does not know or leaves one out. The console
makes one key change at a time and reports a change as made only once the new
configuration is flushed to disk.

1. Offline: `tos-pq-consensus-key generate NEXT.seed` and note its `key_id` (B).
2. Move the key: `tos-pq-consensus-key export NEXT.seed | ENCRYPT > MEDIUM`
   offline, then `DECRYPT < MEDIUM | tos-pq-consensus-key import
   KEYDIR/pq-consensus-next.seed` on the host.
3. Add B beside A, valid from the next election's date E (any time after the
   current election's date works):
   - running node, no restart: in `validator-engine-console`,
     `add-pq-consensus-key KEYDIR/pq-consensus-next.seed E 0`;
   - stopped node: `tos-pq-consensus-key add-node-key DB_ROOT
     KEYDIR/pq-consensus-next.seed E`.

   Confirm with `get-pq-consensus-keys` (or `tos-pq-consensus-key
   list-node-keys DB_ROOT`) that both keys are held.
4. The stake for election E is signed with B and carries B; nothing else
   changes, the staking account stays the same. Confirm the elector accepted
   it. Until then, A keeps signing every block and vote of the running set.
5. Keep A until no validator set lists it: the set that lists A has ended (its
   `utime_until` has passed, and ConfigParam 34, and ConfigParam 36 while a
   next set is pending, list this validator with B) and no stake is still held
   under A.
6. Remove A: `del-pq-consensus-key <A key_id>` on the running node (it refuses
   while a current, previous or next set lists A, and refuses the last key),
   or `tos-pq-consensus-key remove-node-key DB_ROOT <A key_id or file>` on a
   stopped one (it cannot see validator sets: check step 5 yourself).
7. Keep B's seed where the node reads it and in its encrypted offline backup.
   Delete `NEXT.seed`, `MEDIUM` and A's seed file; destroy A's backup when you
   no longer need to be able to sign with A.

`bind-node` refuses a node that holds more than one key, even with
`--replace`: remove the extra keys first.

## 9. Refresh the global config's init block

A node or client proves its way forward from the global config's
`validator.init_block` through every later key block. Nodes drop old key
blocks with the rest of their archive, so a global config whose init block is
the zero state stops working for newcomers. Whoever publishes a network's
global config refreshes it to a recent key block, at least as often as the
shortest archive retention among the network's public lite servers:

```bash
python3 scripts/refresh-global-config-init-block.py \
  --rpc http://127.0.0.1:PORT/jsonRPC --global-id GLOBAL_ID \
  CURRENT-global.config.json NEW-global.config.json
```

It reads the trusted node's `getMasterchainInfo`, `getBlockHeader` and
`lookupBlock`, and writes a new file (never overwriting one). Selection walks
backwards to the newest persistent-state key block that is at least one hour
old and has more than eight hours of persistent-state life remaining. The
first key block after genesis is compared with the zerostate's timestamp:
a key block in the genesis period is not a persistent-state boundary. Only
the input config's own init block has no predecessor for this comparison.

When the predecessor is the zerostate, the script reads its timestamp through
`getProofQuery`'s forward proof, checking the state root against the configured
zerostate. If the source cannot serve that proof, or no eligible key block
exists yet, the script refuses and writes nothing. A too-young candidate's
refusal gives its earliest retry time. Wait for a new-period key block to age
one hour and retry; timestamp selection does **not** prove that its persistent
state has finished serializing or is being served.

It also refuses mismatched zero-state or block identities, headers from another
network, and rollback or replacement of an existing init block at the same
height. The node is trusted, not fully proven: compare its full block id with
a second trusted node, and authenticate the published file through the release
that carries it. A chain with no eligible key block is not refreshed to the
zerostate as a fallback.

## 10. Upgrade a validator

Upgrade one validator at a time and keep the quorum: see
[Validator.md](Validator.md#recommended-upgrade-procedure). Stop the old
process completely before starting the new one; while it still holds
`<db>/config.json.lock` the new one exits with status 2. Read the release notes
for changed defaults: for example, consensus-database cleanup is now on unless
`--disable-validator-consensus-cleanup` is given, and the two cleanup flags
together are refused with status 2. The change process is in
[tos-upgrade-process.md](tos-upgrade-process.md).

## 11. Configuration proposals and votes

Protocol changes are activated by configuration votes.

- Create a proposal with `tosctl vote offer create --param N` and one of
  `--value-boc`, `--value-boc-file` or `--remove`. It prices the proposal from
  live ConfigParam 11 and refuses locally what the configuration contract would
  refuse: a parameter listed in ConfigParam 10 without `--critical`, a parameter
  listed in ConfigParam 9 that does not name the value it replaces
  (`--bind-current` or `--if-hash-equal`), and a value that does not decode as
  the parameter's type (`--skip-value-check` overrides only the last). With
  `--wallet` it sends from a configured masterchain wallet after confirmation;
  without it, it prints the body and value for an external masterchain wallet.
- List proposals with `tosctl vote offer ls` and inspect one with
  `tosctl vote offer diff --hash HASH`. Both read at one masterchain block. The
  list comes from the contract's `list_proposals` getter; when that answer is
  larger than the client's 1 MiB response limit, or the getter returns exit
  code 13 (which it does once its walk over many proposals outgrows the node's
  get-method gas, around 130 small proposals), the list is read instead from
  the contract's stored account at the same block. A dictionary too large for
  both is refused with an error naming both limits; a partial list is never
  shown. Reading such a dictionary needs paginated or incremental state reads,
  which `tosctl` does not have yet.
- Vote with the consensus key, on the validator host, as the node's service
  account:

  ```bash
  tos-pq-vote config KEYFILE GLOBAL_ID SET_ID_HEX VALIDATOR_ID_HEX IDX PROPOSAL_HEX
  ```

  `SET_ID_HEX` is the hash of the current ConfigParam 34 cell, `IDX` this
  validator's index in it, and `VALIDATOR_ID_HEX` the staking account id. The tool
  prints a message body; send it from a wallet as an internal message to the
  configuration contract (ConfigParam 0). The contract refuses, before it checks
  the signature, a vote that brings less than the masterchain compute fee for
  one ML-DSA-44 verification (4,000 gas), so send that plus enough for the
  message's own processing.
  `tosctl vote offer cast` does not send PQ votes: it explains why and stops.

A proposal passes after enough rounds in which validators holding strictly
more than three quarters of the total weight voted for it (exactly three
quarters does not win a round: the contract starts the round at
floor(3W/4) remaining weight and requires it to go below zero); the number of rounds and the
proposal lifetime come from ConfigParam 11 (separately for critical
parameters).

## Exit statuses at a glance

| Program | Status | Meaning |
|---|---|---|
| `validator-engine` | 2 | option error, both cleanup flags given, or `<db>/config.json.lock` held by another process |
| `tos-pq-consensus-key bind-node` | 1 / 3 | refused, nothing written / written but not confirmed durable |
| container entrypoint | 4 | validator role refused (see [docker/README.md](../docker/README.md#run-a-validator)) |
