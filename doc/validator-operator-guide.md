# Validator Operator Guide

This guide takes an operator from a synchronized node to a post-quantum (PQ)
validator that stands in elections, and covers what has to be done to keep it
there: funding the controller's operations, key rotation, consensus-database
cleanup, upgrades, configuration votes and the global config's init block.

It is generic: it names no network, host, port or amount. Take those from the
network you join. Resource sizing, retention flags and memory tuning are in
[Validator.md](Validator.md); the node itself is described in
[FullNode.md](FullNode.md); the container image is described in
[docker/README.md](../docker/README.md).

## Keys and where they live

A PQ validator has three independent authorities. Keep them apart.

| Authority | Created with | Lives on | Signs |
|---|---|---|---|
| Consensus key (ML-DSA-44, 32-byte seed) | `tos-pq-consensus-key generate` | the validator host, readable only by the node's service account | blocks, stake authorizations, configuration and complaint votes |
| Controller root key (ML-DSA-44 seed) | `tos-pq-key keygen` | an offline machine | controller actions: binding a consensus key, operating authorizations, root rotation, withdrawals |
| Wallet keys | `tosctl key add` (vault) | wherever the operator's wallets are kept | transfers that carry the above to the chain |

The validator controller is a masterchain contract. Its account id is the
validator id the chain records, and the elector accepts a stake only from such
a controller. The controller is born bound to one consensus key, so the
consensus seed never has to leave the validator host for the first
deployment.

## 1. Install the tools

Linux release archives (x86_64 and arm64) and the node image ship, next to
`validator-engine`:

| Tool | Purpose |
|---|---|
| `tos-pq-consensus-key` | create, import, show, export the consensus key; bind it into a stopped node |
| `tos-pq-key` | create the controller root key and print its public key (offline) |
| `tos-pq-controller` | build the controller's initial data and StateInit; sign controller actions (offline) |
| `tos-pq-vote` | sign configuration votes, complaint votes and stake authorizations with the consensus key |

In the image they are in `/usr/local/bin`. From source, `tos-pq-consensus-key`,
`tos-pq-controller` and `tos-pq-vote` are targets of the main build;
`tos-pq-key` is a separate CMake project in `crypto/pq/tools`, so that the
root signer links into no node binary. The key tools handle files with POSIX
semantics and are not shipped for Windows or macOS.

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

## 4. Create the controller root key (offline)

On the offline machine:

```bash
tos-pq-key keygen ROOTSEED      # prints the 2624-hex-digit root public key
tos-pq-key public ROOTSEED      # prints it again
```

The root seed never goes to the validator host.

## 5. Deploy the controller

1. Build the controller code from the release source and encode it:

   ```bash
   func -W controller.boc -AP -o controller.fif \
     crypto/smartcont/stdlib.fc crypto/smartcont/validator-controller-v1.fc
   FIFTPATH=crypto/fift/lib fift controller.fif
   base64 -w0 controller.boc
   ```

   Its code hash must be one the network admits in ConfigParam 47.

2. Build the initial data from the root public key (or the root seed file)
   and the consensus `key_id` from step 3. It refuses a zero key id and a key id
   equal to the root's own:

   ```bash
   tos-pq-controller init-data ROOT_PUBLIC_HEX CONSENSUS_KEY_ID_HEX
   ```

3. Build the StateInit. The BOC goes to standard output; the controller
   address and code hash go to standard error:

   ```bash
   tos-pq-controller state-init CODE_BOC_B64 INITIAL_DATA_BOC_B64
   ```

4. Deploy it from an operator wallet with a non-bouncing internal message
   (no `--bounce`) and an empty body:

   ```bash
   tosctl wallet send --from WALLET --to=-1:CONTROLLER_HEX --amount TOS \
     --state-init-boc STATE_INIT_BOC_B64
   ```

5. Keep the raw BOC of the deployment transaction (the controller account's
   first transaction; JSON-RPC `getTransactions` returns it base64-encoded in
   `data`). A first stake carries the birth witness derived from it; see
   [section 7](#7-stand-in-elections). `tos-pq-controller witness CODE_BOC_B64
   INITIAL_DATA_BOC_B64` prints that witness for inspection.

## 6. Bind the node to the controller

Stop the node, then, as the node's service account:

```bash
tos-pq-consensus-key bind-node DB_ROOT KEYDIR/pq-consensus.seed VALIDATOR_ID
```

`DB_ROOT` is the node's `-D` directory; the tool edits `DB_ROOT/config.json`.
`VALIDATOR_ID` is the controller's account id, as 64 hex digits or
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
expire_at <t>`, in the same lower-case hex `tos-pq-consensus-key show` prints,
and stops instead of starting as an observer if the key cannot be
loaded. In the container image the binding is made from `VALIDATOR_ID` and
`PQ_CONSENSUS_KEY_FILE`; see [docker/README.md](../docker/README.md#run-a-validator).

## 7. Stand in elections

The stake path is wallet → single-nominator pool → controller → elector. The
pool's address is derived from its owner, its validator wallet and its
controller, so deploy the controller first. Configure `tosctl`
([tosctl README](../tosctl/src/node-control/README.md)): the node's control
connection (`config node add`), the validator wallet (`config wallet add`), the
pool (`config pool add --controller`, or `deploy pool --controller` to deploy
it), and the binding (`config bind add --pool`). Pass a raw masterchain address
to `--to`, `--owner`, `--controller` or `--address` of these commands in the
`--flag=-1:<hex>` form; as a separate word, `-1:<hex>` is read as an option. Then import the controller's
birth from the transaction kept in step 5:

```bash
tosctl config bind import-birth --node NODE \
  --transaction-boc DEPLOYMENT_TX.boc --output /ABSOLUTE/PATH/controller-birth.boc
```

Enable the binding (`tosctl config elections enable NODE`) and run
`tosctl service`. Its elections task asks the node to sign each stake
authorization with the consensus key, so the node must be bound and running.
The task does not create temporary validator keys: on the PQ chain the node is
matched to its validator-set entry only through the consensus key.

A pool's stake is relayed only if the controller holds a current operating
authorization ([section 8](#8-fund-the-controllers-operations)). The elections task re-reads
it every five minutes, logs missing, expired or low authorizations, repeats the
warning when it stakes, and publishes it per node as `operating_authorization`
in `/v1/validators`. It only reports; it cannot renew. Thresholds are set in the
`tosctl` configuration:

```json
"elections": {
  "operating_authorization": {
    "target_days": 30,
    "warn_percent": 25,
    "expiry_warn_days": 7
  }
}
```

## 8. Fund the controller's operations

A controller relays a stake only against a root-signed operating authorization
(action kind 4). Each relay charges a grant, priced from ConfigParam 20 and 24,
against both the recorded funds and the allowance, and is refused once the
authorization has expired. The account balance alone authorizes nothing; keep
capital for the storage floor and fees separate from the recorded funds and
from pool principal.

Check it:

```bash
tosctl controller operations status --controller -1:CONTROLLER_HEX
```

It prints funds, allowance, per-request limit, storage floor, expiry, payer,
the live grant, stakes remaining and the runway at the ConfigParam 15 election
interval. `--target-days`, `--warn-percent` and `--expiry-warn-days` set the
warnings (defaults 30, 25, 7); `--strict` exits non-zero on any warning, for
monitoring; `--format json` is available.

Renew it:

```bash
tosctl controller operations plan --controller -1:CONTROLLER_HEX \
  --payer PAYER_ADDRESS [--floor-nanotos N]
```

A deposit is added to the recorded funds and every other field replaces the
stored one, so the plan renews by deficit. `--floor-nanotos` is required for a
first authorization. `--expiry-only` renews only the expiry. The plan refuses
while a relay is pending or retry fees are held, and when the payer would change
unless `--allow-payer-change` is given. It signs and sends nothing. It prints
the payload and two commands:

1. the exact `tos-pq-controller fund-operations ROOTSEED GLOBAL_ID
   CONTROLLER_HEX EPOCH NONCE VALID_UNTIL PAYLOAD_BOC_B64` line, with the live
   epoch and nonce and a `valid_until` within the contract's window (`--valid-for`,
   default 1800 seconds, at most 3600), to run on the offline machine;
2. the send from the payer wallet, with exactly the printed value:

   ```bash
   tosctl wallet send --from PAYER_WALLET --to=-1:CONTROLLER_HEX \
     --amount-nanotos VALUE --body-boc SIGNED_BODY_B64 --bounce
   ```

   `--bounce` makes a refused request return its value. Write a masterchain
   destination as `--to=-1:...`: `--to` does not accept a value that starts
   with a hyphen as a separate word.

Run `status` again and check that the nonce advanced and the recorded values
are the planned ones.

## 9. Retired consensus databases

Each validator-set session leaves a RocksDB directory under `<db>/consensus/`.
The engine deletes a retired session's directory once it is provably obsolete;
this is on by default and needs no flag. `--disable-validator-consensus-cleanup`
keeps them (for forensics) and makes the disk grow without bound. See
[Validator.md](Validator.md#retired-consensus-databases) for the conditions and
log lines.

## 10. Rotate the consensus key

A node can hold several consensus keys for its validator at once, so a
rotation from key A to key B needs no downtime. Each key has a window:
`valid_from` is the first election date (unix time) it signs stakes for, and
`expire_at` (0: never) is when the node stops using it at all. The node picks
the key per signature:

- a validator group, and a vote cast as a member of a set, use the key that
  set's descriptor records for this validator, and no other held key;
- a stake for an election uses the held key whose `valid_from` is the greatest
  not after the election date (`create-stake-authorization-with-key` names a
  key explicitly, still only inside its window);
- an expired key is used for nothing, and an older key is never substituted
  for it.

Two keys valid from the same election date, the same key twice, more than
eight keys, or a configuration whose keys have all expired are refused, by the
node at start-up, by the console, and by the offline tool.

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
4. Offline, before the stake for election E is due: `tos-pq-controller bind
   ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL NEXT.seed`; send
   the body from a wallet and check that the controller now shows key B.
5. The stake for election E is signed with B. Confirm the elector accepted it.
   Until then, A keeps signing every block and vote of the running set.
6. Keep A until no validator set lists it: the set that lists A has ended (its
   `utime_until` has passed, and ConfigParam 34, and ConfigParam 36 while a
   next set is pending, list this controller with B) and no stake is still held
   under A.
7. Remove A: `del-pq-consensus-key <A key_id>` on the running node (it refuses
   while a current, previous or next set lists A, and refuses the last key),
   or `tos-pq-consensus-key remove-node-key DB_ROOT <A key_id or file>` on a
   stopped one (it cannot see validator sets: check step 6 yourself).
8. Keep B's seed where the node reads it and in its encrypted offline backup.
   Delete `NEXT.seed`, `MEDIUM` and A's seed file; destroy A's backup when you
   no longer need to be able to sign with A.

`bind-node` refuses a node that holds more than one key, even with
`--replace`: remove the extra keys first.

## 11. Refresh the global config's init block

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
`lookupBlock` and writes a new file (it never overwrites one) whose init block
is the latest key block. The one exception is a chain that has no key block
after the zero state yet: then the init block is the zero state itself, checked
against the config's. It refuses, writing nothing, when the node's zero
state differs from the config's, when the key block's identities disagree, when
a header is not a key block or carries another global id, or when the new init
block is older than, or at the same height as but different from, the existing
one. The node is trusted, not proven: compare its last block, on the full block
id, with a second node you trust, and authenticate the published file through
the release that carries it.

## 12. Upgrade a validator

Upgrade one validator at a time and keep the quorum: see
[Validator.md](Validator.md#recommended-upgrade-procedure). Stop the old
process completely before starting the new one; while it still holds
`<db>/config.json.lock` the new one exits with status 2. Read the release notes
for changed defaults: for example, consensus-database cleanup is now on unless
`--disable-validator-consensus-cleanup` is given, and the two cleanup flags
together are refused with status 2. The change process is in
[tos-upgrade-process.md](tos-upgrade-process.md).

## 13. Configuration proposals and votes

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
  `tosctl vote offer diff --hash HASH`.
- Vote with the consensus key, on the validator host, as the node's service
  account:

  ```bash
  tos-pq-vote config KEYFILE GLOBAL_ID SET_ID_HEX VALIDATOR_ID_HEX IDX PROPOSAL_HEX
  ```

  `SET_ID_HEX` is the hash of the current ConfigParam 34 cell, `IDX` this
  validator's index in it, and `VALIDATOR_ID_HEX` the controller id. The tool
  prints a message body; send it from a wallet as an internal message to the
  configuration contract (ConfigParam 0). The contract refuses, before it checks
  the signature, a vote that brings less than the masterchain compute fee for
  50,000 gas, so send that plus enough for the message's own processing.
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
| `tosctl controller operations status --strict` | non-zero | a warning was raised |
