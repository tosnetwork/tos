# Trusted node-data recovery

> The standalone-services release never creates an embedded index, even with
> operator JSON-RPC enabled: wallet indexing is provided by `tos-wallet-index`, and
> `--json-rpc-without-wallet-index` is an accepted no-op. Restore decides from the
> target database, not from that flag.

These commands move chain data between nodes under an independently pinned
publisher key. They trust that key and the publisher's chain database. Hashes,
native reopen checks and reference equality do not make a database dump trustless.
No consensus rule, persistent-state period or storage-retention setting changes.

## Lanes

There are three ways to give a node chain data from elsewhere. They differ in what
they trust and which nodes they accept.

| Lane | Commands | Target | Trust anchor |
|---|---|---|---|
| Same-node fast rejoin | `tosctl node dump create/verify/publish`, then `tosctl node sync restore` (and `recover`) | an existing node, validator or not, that keeps its own identity, signing history and local StateDb records | pinned publisher key, signed manifest, object hashes, held network identity and fork policy, engine digest, native reopen, two references |
| New non-validating node | `tosctl node sync bootstrap` (and `recover`), from the same signed catalog | a node database that has never run: its first-start identity, console client keys and genesis files only | the same as restore, plus native proof that the imported chain descends from the locally held zero state and init block |
| External snapshot archive | `docker/import-snapshot.sh` | a new non-validating container node | only the `DUMP_SHA256` digest the operator configured; see [the container guide](../docker/README.md#database-snapshots) |

Restore and bootstrap use one verification path: the same signed-manifest checks,
download leases, staging, native validation, reference corroboration, journal,
forward-only exchange and recovery. Bootstrap differs only in its target: it never
stops a service, requires the target to be inactive and new, imports no local
records, and refuses every validator binding.

The container importer is a separate, weaker lane. It accepts a `.tar.lz` archive
authenticated by one operator-held digest: no publisher key, no manifest signature,
no build, cell-storage or network check beyond one zero-state hash comparison, and no
native reopen before the node starts. This publisher does not produce such archives,
and its catalog cannot be fed to that importer. Use bootstrap for a new node on an
operator host; the container lane exists for archives produced elsewhere.

A new validator never joins through any of these lanes. Every lane refuses validator
bindings; restore keeps an existing validator's own signing history, which no
snapshot can supply.

The default capture method is a stopped-service cold copy. A filesystem snapshot
backend is a future measured option; these commands do not provision storage.
Capture cadence, maximum useful age and the thirty-minute rejoin target require
the separate local qualification run. They have not been qualified by unit tests.

## Supported targets

Restore supports nodes without an in-process wallet index only. A current engine
never opens one, whatever its JSON-RPC options; the command line therefore decides
nothing, and `--json-rpc-address` with or without the no-op
`--json-rpc-without-wallet-index` is a supported target. Restore is refused when
the installed database has a `wc0-index` entry of any kind (directory, file or
link). It is checked through the held database descriptor before preparation,
after the transfer, after the stop and before start. Main registers no other
index option; any option outside the reviewed subset is refused as unsupported.

An engine that predates the standalone wallet index opens `<db>/wc0-index`
whenever `--json-rpc-address` is given without `--json-rpc-without-wallet-index`.
On an epoch that pins such an engine, disable that index on the target first: add
`--json-rpc-without-wallet-index` to the unit (or remove `--json-rpc-address`),
stop the node, and remove the retired `wc0-index`; the tool never deletes it.
Restoring into a target whose old engine still runs the index would leave the
imported block gap missing from an old index, or start an empty one that omits old
history.

Database-root directories have explicit dispositions:

| Roots | Restore disposition |
|---|---|
| `celldb`, `files`, `archive`, `static` | Import only allowlisted chain files; current temporary packages remain eligible, `archive/tmp` does not. |
| `state` | Reconcile typed chain and target-local records; never copy raw donor StateDb. |
| `keyring`, `consensus`, `catchains`, `adnl`, `overlays`, `dht-*` | Preserve target identity, signing and transport state. |
| `console-client` | Preserve the operator bundle's console client keys exactly (see below); never published or transferred. |
| `keys` | Preserve it as the work-root key directory when the context's `work_root` is the database root; otherwise refuse, since nothing would preserve it. |
| `error` | Preserve target diagnostic records (`common/errorlog.cpp`), never donor diagnostics. |
| `tmp` | Keep recovery material with the frozen old root, never overlay it. |
| `wc0-index` | Refuse; neither preserve across a gap nor silently discard. |
| `import` | Refuse pending operator input; an empty directory may be recreated. |
| `packed` | Refuse unsupported legacy archive layout. |
| Other directories or root symlinks | Refuse and name the path. |

`keyring`, `console-client` and `keys` (when it is in the database) are copied into
the replacement with their exact contents: every directory, including empty ones,
every regular file, and the permission bits of each. Every entry must already belong
to the database root's owner and group, carry no special bits and not be writable
by other accounts; the replacement is handed to that owner and group, so ownership
is kept as well. The trees are opened through the held database descriptor, and
are rechecked (bytes, modes and the complete entry set) after staging, before the
forward-only boundary. Whether `keys` is in the database is decided from the
resolved context: the canonical work root equals the database root and both name
the same directory; a work root that reaches it through another mount refuses.

`static` is created by the engine only on demand: the root database opens it, but
only a hardfork, or an operator placing genesis files, writes into it. A node
without it is a normal target and a normal snapshot source; an absent `static` is
captured as an empty directory.

Preserving `consensus` keeps the target's own-decision log
(`consensus/signing-ledger/`) with its own history. Never take that directory
from a donor or from a backup: a copied ledger is treated as unknown signing
history, and the validator signs again only after the fence described in
[signing-decision-log](signing-decision-log.md).

The wallet index (`validator-engine/wallet-index.cpp`) and this restore path are
absent from the native reference at `857b8a57a178e6ae0fe7fa86e7d81c5233de8560`.

### Files inside chain roots

After mandatory native recovery and reopen, publication excludes only these
named non-chain outputs: `celldb/db_stats.txt`; `LOCK`, `LOG`, `LOG.old`,
`LOG.old.<digits>`, `<digits>.dbtmp` and `OPTIONS-<digits>.dbtmp` inside a
recognised database directory; and `archive/tmp/` staging. A diagnostic basename
in another directory is not an exclusion. Numbered lowercase `.log` files are
WAL recovery data and are carried, alongside `.sst`/`.ldb`, `CURRENT`,
`MANIFEST-<digits>`, `OPTIONS-<digits>` and `IDENTITY`. The latter is database
metadata, not a node signing identity. `CURRENT` and numbered manifests are
required to select and recover the database version.

This inventory follows `validator/db/celldb.cpp` and the vendored
`file/filename.cc` and `db/db_impl/db_impl_files.cc`. Bare `MANIFEST`, malformed
lookalikes, unsupported blob/secondary database layouts, unlisted files and
archive `.pack.new`/`.pack.tmp` rewrite leftovers still refuse publication;
unknown files are never silently ignored. Current `temp.archive.*.pack` files
remain chain data. Native recovery must resolve interrupted work before filtering.

## Reference comparison

The operator reference at `66240cfd0be42934d2f38d811ac3ed77a88b4da6`,
the installer module `dump.py:181–210`, obtains a database dump with checksums
and sizes.
The producer reference at `c62f3eab957c5ea9acaed76920b102a4a50c20d8`,
the stop/capture script under `node/snapshots/` at lines 60–84, stops the service
for capture and uses a
filesystem snapshot for delta transfer. This lane follows the stopped-capture
strategy. Cold copy is the supported backend here; no snapshot backend is assumed.
The references were read for behavior, not copied.

The native reference default branch was checked at
`857b8a57a178e6ae0fe7fa86e7d81c5233de8560`: `validator/db/statedb.cpp:30–39,153–179`
and `validator/manager-init.cpp:405–420` retain native state/fork semantics.
There is no corresponding Rust operator stack there. TOS additionally has local
retirement records (`validator/db/statedb.cpp:123–248`) and import recovery
manifests; the typed boundary and native recovery checks preserve those rules.
This feature changes no inherited native recovery or consensus implementation.
The inspected release notes and dump/restore issue searches supplied no native
operator replacement to port.

## Build and prerequisites

Build the offline database wrapper against the same vendored native database
library as the independently held engine. Never obtain an executable or verifier
from the dump publisher. After configuring the native release build:

```sh
cmake --build build --target validator-engine --parallel 16
export NODE_STORE_NATIVE_DIR="$PWD/build/third-party/rocksdb"
cargo build --manifest-path tosctl/src/Cargo.toml --locked --release \
  -p tosctl --features node-data-sync-native
cargo build --manifest-path tosctl/src/Cargo.toml --locked --release \
  -p node-data-sync --features native --bin node-data-sync-worker
install -m 0755 tosctl/src/target/release/tosctl /opt/node/bin/tosctl
install -m 0755 tosctl/src/target/release/node-data-sync-worker \
  /opt/node/bin/node-data-sync-worker
sha256sum build/validator-engine/validator-engine \
  /opt/node/bin/node-data-sync-worker
```

The native-enabled CLI provides creation, restoration and offline private backup.
A build without that feature provides verification, catalog management and status,
without exposing a restoration fallback. Keep the worker beside the installed
operator tools and pin both executable digests in the private context. Install
regular copies: build outputs may be hard-linked, and the verifier refuses linked
executables. Create the installation directory using the local operator policy.

`systemctl` must be able to stop/start the exact selected unit. The supported
service shapes are listed in [Service accounts](#service-accounts). Native validation requires `unshare` with
user and network namespaces; refusal to create one is fatal. The verifier uses
fresh local credentials and isolated loopback, with no external network access.
On an Ubuntu 24.04 operator host with the default
`kernel.apparmor_restrict_unprivileged_userns=1` sysctl, the restore verifier needs
root/CAP_SYS_ADMIN or an AppArmor user-namespace rule.
A stopped copy is recoverable, not proof that every asynchronous write drained:
every public generation undergoes native recovery, shard-state reads and a second
reopen before it can be signed.

Ancestry is proven, not looked up. For every anchor (the held zero state, the held
init block, each approved fork and, on restore, each target safety anchor) the
verifier asks the reopened engine for one backward block-proof link from the
coherent frontier. It accepts only a Merkle proof of the frontier's masterchain
state whose hash equals the state hash recorded in the frontier block itself (whose
bytes were already checked against the frontier full ID), with the held global id
and the frontier's height, and whose previous-block dictionary holds the anchor
with exactly its root and file hash. No zero-state bytes and no anchor block data
are read. The engine builds that link from the anchor's own stored proof link: the
zero state needs none, key blocks keep theirs, and recent blocks keep theirs until
archive GC removes them. An older ordinary anchor whose proof link the image no
longer holds cannot be proven and refuses with "anchor proof not retained"; there
is no fallback. When validation does not finish within its deadline, the error
names the last failed request, its anchor or frontier, and the engine's answer,
truncated to 4 KiB.

Managed service commands use a conservative subset of native options, with a
separate token for each option and value. Attached or clustered short options,
long equals forms, duplicate path selectors, unknown options and positional tokens
refuse before service stop. For example, use `-v 0`, not `-v0`. This restriction
aligns with the native parser's supported arities without changing that parser
(reference `857b8a57a178e6ae0fe7fa86e7d81c5233de8560`,
`tdutils/td/utils/OptionParser.cpp:137–164`).

`--json-rpc-address` and `--exporter-address` are accepted with a separate value.
The tool checks only their arity, never their address: the allow-list governs how
the command line is parsed and which paths the engine reads and writes, not network
exposure. The engine itself confines plaintext JSON-RPC to loopback unless
`--json-rpc-readonly` is given; where the metrics exporter listens is deployment
policy, and the operator bundle binds it to `127.0.0.1`.

### Service accounts

The service description is checked before every stop, after stop and before every
start. It accepts three shapes and refuses everything else before the node is stopped:

| Unit | Invoked as | Service account |
|---|---|---|
| user-manager unit (`user_manager: true`), no `User=` | any user | the invoking user |
| system unit, `User=` the invoking user (not root) | that user | the invoking user |
| system unit, `User=` a fixed non-root account (for example `tos`) | root | that account |

The third shape is the operator bundle's full node: `User=tos`, `Group=tos`, data
in `/var/lib/tos/fullnode`. Stop and start then go through the system manager. A
system unit is refused when `User=` is missing, is `root` or resolves to uid 0,
uses `DynamicUser=`, or has a `Group=` other than the account's primary group;
these checks apply to the second shape too, not only to a service account. It is
also refused when the invoker is neither that account nor root. A user-manager
unit that names a `User=` is refused, so root cannot address another account
through its own manager.

Ownership is checked against the right account at each boundary:

- The database root must be owned by the service account. The consensus seed
  check uses the same owner.
- The catalog, the restore cache and the operation directory (and its parent) must
  be owned by the invoking user. With a service account they hold what root
  validates, signs and installs, so the service account must not be able to change
  them; a root-owned `/var/lib/tos/node-sync` beside the database is the intended
  layout.
- With a service account, those roots and the database must not be group- or
  other-writable, and every ancestor of each of them must be owned by root and
  writable by no other account (sticky shared directories excepted). The service
  account therefore cannot re-point a path root resolves.
- With a service account, each budget root must belong to root or to the service account.

The service account can rename and replace anything inside the database tree, so
the invoker never resolves a name there. The database root is opened once, and
every directory and file below it is opened relative to that held descriptor with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)`. Listings are
read through the same descriptor that the children are then opened from. A
symlink, a replaced directory, another mount or a hard-linked file refuses. A
kernel without `openat2` refuses; there is no fallback.

The native database library opens paths itself and writes while it opens, so it
never sees the installed tree. To read the installed StateDb's local records,
restore and recovery copy `state/` through descriptors into a private
`state-capture` directory of the operation, open only that copy, and remove it on
success and on failure. Space for the copy, a table flushed from its write-ahead
logs and 64 MiB of native metadata is admitted before copying. A capture left by an
interrupted run is removed before the next one and is never read, so an operation
holds at most one and it never becomes authoritative.

Consistency of that copy rests on the cooperative-node model: the service is
stopped, its native writer has shut down, and no process holds a writable
descriptor on the tree. The copy includes the write-ahead logs and every other
database file. Per-file size and change stamps refuse a change they can detect.
They do not make the copy transactionally consistent against a concurrent writer,
and they do not exclude a deliberate writer running as the service account.

Root never leaves a file the node cannot open. A configuration lock created while
the node is stopped takes the database directory's owner and group. Restore builds
the replacement privately as root, then gives every entry it created to the
installed root's owner before the forward-only boundary. The hand-over walks
descriptors only, never crosses a link or a mount, and refuses hard links,
special files and entries of a third account. Files of the operation, catalog and
cache stay the invoker's.

Restore uses the same service description, so the third shape is also a
supported restore target. The operator bundle's full-node unit is supported as it
is on an engine with the standalone wallet index; on an epoch whose engine
predates it, disable the in-process index on the target as described in
[Supported targets](#supported-targets).

## Private context

Keep the context private. Paths must be absolute, canonical and link-free.
Executables live outside the exchanged database root. For example, replace every
placeholder below with independently held local values:

```json
{
  "unit": "node.service",
  "user_manager": false,
  "database": "/srv/node/db",
  "engine": "/opt/node/bin/validator-engine",
  "engine_sha256": "<64-lowercase-hex>",
  "validation_worker": "/opt/node/bin/node-data-sync-worker",
  "validation_worker_sha256": "<64-lowercase-hex>",
  "global_config": "/srv/node/global.json",
  "global_id": 3,
  "work_root": "/srv/node",
  "working_directory": "/srv/node",
  "operator_config": "/srv/node/operator.json",
  "node_name": "local",
  "vault_config_files": [],
  "references": {"sources": [
    {"name": "reference-a", "endpoint": "https://reference-a.example.invalid/jsonRPC"},
    {"name": "reference-b", "endpoint": "https://reference-b.example.invalid/jsonRPC"}
  ]},
  "budget_roots": ["/srv/node", "/srv/node-sync", "/srv/node-build"],
  "disk_policy": {"max_owned_bytes": 85899345920, "shutdown_free_bytes": null}
}
```

List every task-owned source, retained operation, cache, staging and build root
in `budget_roots`, without overlaps. They must exist. Allocation accounting
counts physical blocks and deduplicates hard-linked build artifacts; payload
handling refuses links. A listed descendant that disappears during a sample
contributes zero; a missing or replaced configured root, or any other filesystem
error, refuses with the operation and path. The walker counts attempted entries,
including vanished ones, and refuses above 2,000,000 entries. It imposes no
elapsed-time failure on a slow disk. Samples do not overlap and are not atomic
snapshots; newly created files can appear in the next sample. Prefer dedicated
operation roots plus their actual shared dependencies over an unrelated workspace,
without excluding any source, target, cache, stage or retained original tree.
The operation, source/target, cache, catalog and every budget root must use the
same filesystem device. Actual paths (including existing ancestors before
creation) are checked, not only lexical containment. The monitor pins root
descriptors and the operation device, checks attachment again on every sample,
and rejects a nested mount before deduplicating or descending into it. A changed
root or device refuses. Use stable parent directories as inventory roots; do not
name the installed database itself as a budget root for an exchanging restore.
Read-only executables may live on another filesystem. Service commands use a
short-lived anonymous temporary output file in the system temporary directory:
this auxiliary file is outside the tree inventory, with the existing 1 MiB
output-limit checks and command deadline (at most 120 seconds), and is closed
when the command completes or fails. It never stores snapshot or signing data.

`disk_policy.max_owned_bytes` is a required, non-zero
aggregate ceiling in bytes, below filesystem capacity. Include the retained
original tree and every earlier operation. Missing input refuses with that field's
name; it is not inferred from this development host. The example sets 80 GiB;
size it for the actual measured trees, not by copying the example. No existing
external automation invokes these new commands; a future operator runbook or
caller must supply this context field.

There is exactly one free-space threshold. Admission requires
`available - entire reservation >= shutdown_free_bytes`; the monitor stops new
work strictly below it. Consuming exactly the admitted reservation is allowed;
one byte more at the boundary stops work. There is no second unused hard floor.
Zero thresholds, thresholds at/above capacity, invalid probe values and arithmetic
overflow refuse. Recovery uses the persisted policy but re-measures available
space and capacity before acquiring a writable operation lock or opening StateDb.
Probe errors refuse. These checks are guards, not filesystem quotas; other writers
can consume space between samples. Restore rechecks the sampled stop signal after
reference corroboration, before authorization, before each forward-only/exchange
boundary, and immediately before starting the installed replacement after final
service validation. A pre-authorization refusal leaves a staged, unexposed tree;
recovery retains that phase until a new approval is durably recorded. Already
forward-only or exchanged operations never revert to staged or overlay older
signing state. These checks use the most recent sample, not a filesystem quota
or an atomic reservation against other writers. A refused capture monitor does
not prevent restarting the original snapshot source.

A null `shutdown_free_bytes` selects `max(16 GiB, ceil(capacity / 20))`.
Basis: retained epoch-4 filesystem-usage samples on 2026-10-19 at approximately
21:17–21:21 UTC observed two consecutive ~70-second growth intervals of
777,609 and 916,990 bytes/s (about 3.30 decimal GB/hour at the higher rate).
These are short-window net filesystem growth observations, not a sustained
validator-only database growth measurement. Conservatively rounding upward to
1 MiB/s gives 10.55 GiB for a two-hour operation plus one-hour restart margin;
16 GiB rounds that allowance upward again. The 5% term protects larger shared
filesystems. It is not evidence that any workload fits: multiple nodes, a higher
measured growth rate or a longer recovery window require a larger explicit value.
At 160 GiB capacity the default is 16 GiB; at 1,000 GiB it is 50 GiB.

New work is stopped after two hours per create/restore/recover invocation; an
already dispatched bounded native child can still settle before returning an
error. Restart safety remains forward-only. Reservations use measured raw data,
compressed objects and target-private trees with checked arithmetic: three raw
copies plus compressed/private bytes and a 1 GiB metadata/WAL allowance. The
monitor also enforces the explicit aggregate ceiling. The rehearsal's separate
320 GiB allocation / 212 GiB free-space guard and 16 GiB build cache limit remain
rehearsal constraints, not deployment defaults.

`vault_config_files` lists local vault configuration files that must be preserved;
non-exportable custody remains at its existing local service/handle. Never put
custody or configuration beneath chain-data or recovery directories. Existing
operator keys and primary/scheduled native consensus seed references are retained;
a seed reference must resolve to an owned private 32-byte regular file. Missing
registered native keys are a refusal. This is same-node recovery, not migration
of a signing key or a vault to another machine.

## Create, verify and publish

The source must be a non-validating full node: no validator registrations, native
consensus signing custody or enabled operator election binding, including aliases.
Supply an existing dedicated publisher seed file, owned by the invoking user,
mode 0600, exactly 32 bytes. It must not be a validator key. The tool does not
create publisher secrets. Keep that file outside the entire source database, public catalog and every operation tree.
The shared creation path checks its provenance before stopping and again before capture;
symlinks, hard links, replacement and capture aliases refuse.

The source may have joined the network at an init block (a refreshed global config
with `init_block`) instead of syncing from the zero state. Such a node never holds a
zero-state file, and none is required: native validation proves the held zero state
and init block from the frontier's state, and a generation publishes only the tip
block as metadata.

### Publisher host prerequisites

Check these before the first `create`; each one otherwise refuses at run time:

- **Two references reachable from the publisher host.** `create` and `publish`
  each query two named, distinct JSON-RPC endpoints (`references` in the context,
  `--reference` on `publish`) from the host that runs them. The source node's own
  loopback JSON-RPC is not an independent reference. Check that both answer from
  that host, for example through the firewall, before stopping anything.
- **An operator config for the source node.** `operator_config` is a tosctl
  configuration that names `node_name` with the node's control `server_address`
  and `server_key` (its public key). Its `client_key` must be a control client the
  node's `config.json` lists under `control`; the tool refuses a client that
  belongs to another node. Build it from the node's console keys without copying
  them out: give the server key as a public key, and keep the client private key in
  the operator vault (`VaultKey`) rather than inline in the file. Keep the file
  private to the invoking user and outside the chain, signing and recovery
  directories. It must not enable an election binding for the source or any alias.
- **One filesystem.** The operation directory, the catalog and every budget root
  must be on the database's filesystem; a root on another device refuses. On the operator bundle that means a root-owned directory such
  as `/var/lib/tos/node-sync` (mode 0700), with `budget_roots` naming its parent
  `/var/lib/tos`, not `/srv` or `/tmp`.

```sh
install -d -m 700 /srv/node-sync/catalog
# Each operation directory must be new and outside the source database.
tosctl node dump create --context source-context.json \
  --operation /srv/node-sync/create-001 --directory /srv/node-sync/catalog \
  --signing-key /srv/node-sync/private/publisher.seed
tosctl node dump verify --manifest /srv/node-sync/create-001/generation.json \
  --objects /srv/node-sync/catalog --publisher-key <PINNED_PUBLIC_KEY> \
  --global-config held-global.json --global-id 3
tosctl node dump publish --manifest /srv/node-sync/create-001/generation.json \
  --objects /srv/node-sync/catalog --directory /srv/node-sync/catalog \
  --publisher-key <PINNED_PUBLIC_KEY> --global-config held-global.json --global-id 3 \
  --reference https://reference-a.example.invalid/jsonRPC \
  --reference https://reference-b.example.invalid/jsonRPC
tosctl node dump list --directory /srv/node-sync/catalog --publisher-key <PINNED_PUBLIC_KEY>
tosctl node dump prune --directory /srv/node-sync/catalog --publisher-key <PINNED_PUBLIC_KEY>
```

Creation stops and locks only the selected source, copies its matched chain and
recovery context privately, then restarts the source before validating/compressing.
Every check that needs no stopped node runs before the stop: role and signing
custody, publisher provenance, budget, account, catalog, operation directory, the
service description, and the shape of every captured root. No unverified generation
is published.

A failure after the stop restarts the source through the same unit and service
manager scope the tool stopped it with. Immediately before that restart the tool
checks again that the source is still non-validating with no signing custody, in
the same cell-storage mode, on the same database root, and under the configuration
lock it froze. If any of these changed, if the stop could not be confirmed and
frozen, or if the start itself fails, the source is left stopped and the command
exits with status **5**. Its message names the unit, the observed service state,
why it was not restarted, every error involved and the exact restart command;
review the cause before restarting. Any other failure exits 1, after the source was
restarted. A panic in the stopped section is handled the same way. A host crash or
`SIGKILL` during the stopped window can still leave the source stopped: check the
service state after any interrupted create. All temporary-package files selected by the native
allowlist are included; `archive/tmp` is staging and is excluded. Raw donor
StateDb, keys, config, sessions and recovery files have no public payload variant.

At least two named, distinct canonical reference endpoints are mandatory. Each
must serve the exact native-validated frontier full ID and have a head at or above
it. Creation checks before signing/preparing; publication checks freshly before
updating latest. Restoration durably binds fresh evidence to the generation and
preservation revision before `FORWARD_ONLY`, exchange and start. Old-installed
recovery restages current own records and rechecks; new-installed recovery keeps
the current tree and checks its current coherent frontier before restart. Any
unavailable, behind or disagreeing named source refuses; there is no fallback.
Endpoint independence is an operator assumption. A base URL and its `/jsonRPC`
spelling identify the same source. Manifest format 3 and journal format 2 require
these receipts; old formats refuse explicitly. Format 3 has no
`metadata/zero-state.boc`; a format-2 generation refuses. The five-minute post-start check remains
separate from this pre-exposure check.

The catalog contains `latest.json`, signed `generations/<digest>.json` and
`objects/<uncompressed-sha256>-<size>-<compressed-sha256>.zst`. Each object is
checked in compressed and decoded form. A publication service may expose only
these public paths; private operation directories, seeds and backups must never
be in its document root. HTTPS/authentication and a public listener are separate
operator setup, not performed by these commands. HTTP transport cannot replace
the independently held publisher key and global-config anchor.

The newest two generations, latest pointer, completed preparation and receiver
leases protect reachable objects. Pruning never removes private frozen trees.
One completed preparation may await publication. Finish or explicitly review it
before starting another capture; do not remove its lease to bypass a refusal.

## Restore and recover

The request is private and binds one exact locally downloaded signed manifest:

```json
{
  "context": "<the complete context object above, not a filename>",
  "manifest": "/srv/node-sync/received/generation.json",
  "cache": "/srv/node-sync/cache",
  "publisher_key": "<PINNED_PUBLIC_KEY>",
  "source_url": "https://snapshot.example.invalid/network/"
}
```

Replace `context` with the JSON object, not a string. `source_url` can be `null`
when every object is already cached. Prepare the cache directory mode 0700.
Global id, zero/init full IDs, approved fork policy, build, schema and cell-storage
mode must match. One checked service description compares the configured mode
with any running process. The selected mode is rechecked after transfer and stop,
before exposure, and at restart, including both recovery branches. A mismatch
refuses the next action; the recovery tool does not select a different mode to
make a dump fit. The target's GC/init/coherent pointers and retirement checkpoints
must be full-ID ancestors of the imported frontier; unknown safety schemas refuse.
No old local fork record overwrites newer imported history. Donor policy is never
authoritative. Requests use bounded deadlines/retries and resume only one immutable
object identity, with complete-file hashing after resumption.

```sh
tosctl node sync restore --request restore.json --operation /srv/node-sync/restore-001 \
  --reference https://reference-a.example.invalid/jsonRPC \
  --reference https://reference-b.example.invalid/jsonRPC --dry-run
tosctl node sync restore --request restore.json --operation /srv/node-sync/restore-001 \
  --reference https://reference-a.example.invalid/jsonRPC \
  --reference https://reference-b.example.invalid/jsonRPC
tosctl node sync recover --operation /srv/node-sync/restore-001 \
  --reference https://reference-a.example.invalid/jsonRPC \
  --reference https://reference-b.example.invalid/jsonRPC
```

Download and object verification precede service stop. Staging is a complete donor
manifest, never a union of directories. Only full-hash/size-matching immutable
SSTs may be copied from the stopped target; mutable files always come from the
donor. Own config, five optional configs (including their absence), keyring,
work-root keys, external custody references, operator/vault/service configuration,
consensus/catchain journals and local StateDb values are preserved privately.
The target's old `tmp`/import material remains with its old CellDb. Replacement
recovery starts empty; service paths that select external recovery inputs refuse.

Before acquiring a receiver lease, restoration durably records its request,
signed generation and operation ID. A bound descriptor naming the original root
(device/inode), selected service context and one staging directory is durable
before stop and before creating that directory. An interrupted preparation is
never resumed. With no restore journal, recovery authenticates its bindings and
refuses later-phase evidence (including staging `preservation.json` records).
Unbound or ambiguous staging is retained, with its allocated size in the refusal.

An unambiguous abort atomically publishes its receipt, releases only its receiver
lease idempotently and uses normal catalog pruning. Completed generations retain
the normal catalog protection, including when a different receiver completed one.
Only the exact staging directory named by the descriptor is removed; cleanup
rechecks the original installed root's device/inode immediately before deletion
and refuses links, mounts and active writers. A crash during cleanup is retried
with the same operation; it does not authorize a new restore or rollback.

A crash after stop may leave the original node inactive. Abort reports the observed
service state and a `restart_command` derived from the recorded selected unit and
service-manager scope, never defaults. It does not automatically start or stop the
node. When identity checks succeed and the service is inactive, use that command
to restart the untouched original tree after confirming the selected unit still points
to it. A unit whose `LoadState` is not `loaded` is reported as unknown.
An unknown state is not proof it is stopped. Only binding-verified preparation
refusals report the last observed service state and conditional restart guidance.
Before authentication, recovery reports that the binding is unverified and gives
no restart command.
Verify the state before starting a new restore with a new operation directory.
Incomplete or mismatched authoritative records refuse cleanup. Receipt publication
uses an operation-owned temporary name: retry removes that temporary and accepts
only a byte-identical complete final receipt; there is no torn-final compatibility.

The fsynced `restore.json` journal outside both trees records the `FORWARD_ONLY`
phase before atomic exchange. There is no standalone `FORWARD_ONLY` file.
It forbids rollback even if a crash occurs before a start marker and a boot-enabled
service has already signed. If the old tree remains installed, recovery stops it
and rebuilds from its **latest** local state. If the new tree is installed, recovery
keeps its current local state and continues forward. Ambiguous identities or a
corrupt journal, or a missing journal without matching preparation records, refuse movement. Do not manually exchange the old root
back or discard these private recovery bundles. Sole managed signing and honest
local administration are explicit assumptions.

The target's original signing history must still be intact. This procedure
preserves it; it cannot reconstruct missing own votes from a donor's chain
snapshot. Do not use bootstrap or `docker/import-snapshot.sh` to recover a
validator: both refuse validator bindings. Do not clear a binding to bypass that
refusal or restore an older consensus journal. If the history is lost, keep the old
signer stopped and retire the affected signing identity before provisioning a new
one for a later validator set.

Restore requires an existing node: a target without its own `state/` is refused
before anything is prepared or stopped.

## Bootstrap a new node

`tosctl node sync bootstrap` installs a published generation into a node database
that has never run. It takes the same private request as restore and the same two
named references:

```sh
tosctl node sync bootstrap --request bootstrap.json --operation /srv/node-sync/bootstrap-001 \
  --reference https://reference-a.example.invalid/jsonRPC \
  --reference https://reference-b.example.invalid/jsonRPC --dry-run
tosctl node sync bootstrap --request bootstrap.json --operation /srv/node-sync/bootstrap-001 \
  --reference https://reference-a.example.invalid/jsonRPC \
  --reference https://reference-b.example.invalid/jsonRPC
```

The request may say `"lane": "bootstrap"`; a bootstrap request given to `restore`
refuses. The context describes the new node's own unit and paths, exactly as for
restore. On the operator bundle, prepare the node and install its unit without
starting it (`install-node.sh prepare`, then `install-node.sh activate --no-start`),
then run bootstrap; it starts the unit once the replacement is installed.

The target must be **new**, checked through the held database descriptor before the
download, after the freeze, at staging and before the exchange. The database root may
hold only:

- `config.json` and `keyring/`, written by the engine's first start (both required);
- `config.json.lock`, empty;
- `error/`, the empty error log of a first start (`files/` and an empty `log.txt`);
- `console-client/`, the bundle's console client keys;
- `static/`, genesis files named by their 64-hex file hash;
- the optional local configuration files listed above.

Every entry must be a regular file or directory on the database's device; a link,
hard link, special file, bind mount or another mount anywhere, including in
`static/`, refuses. The trees are bounded (1,024 entries and 16 MiB per private
tree; 64 files and 4 GiB of genesis files). Anything else, such as chain data,
`state/`, signing or session state, `keys/`, an index or operator input, means the
database has run or is not a plain new node, and bootstrap refuses with its path.

Bootstrap never stops or replaces a running node. The selected service must be
inactive, with no main process, at every check; it is only frozen, never stopped.

Validators are refused. Bootstrap requires, and rechecks at every target check:

- no validator registration and no native signing custody in `config.json`, and no
  referenced signing seed;
- no enabled election binding for the node or any configured alias;
- no `keys/` in the database root, even an empty one;
- no key file in the work root's `keys/` directory.

An absent or empty database `keys/` alone proves nothing about the other places.

A new node has no local records and no safety anchors of its own. Instead, native
validation of the staged replacement runs under the operator's own global config
and must prove that the imported chain descends from the locally held zero state and
init block, with the locally approved fork list. The engine stops when the imported
state neither is nor descends from the held init block, and the verifier then proves,
from a Merkle proof of the frontier's state tied to the tip block, that the held zero
state, the held init block and every approved fork are earlier masterchain blocks of
the imported chain. The journal's safety anchor is the
held init block, so a reference approval cannot precede it. A correctly signed
donor of the same network and build whose history conflicts with the held anchor is
refused before anything is exposed. The replacement's local StateDb records are the
explicit absence of every local key, as a node that never ran has.

The new node's own `config.json`, optional local configs, `keyring/` and
`console-client/` are preserved exactly, as for restore. Its genesis `static/`
stays with the old tree inside the operation; the replacement takes the donor's
chain directories.

Recovery follows the journal. Before the exchange, the installed tree must still be
the new node: if it is, recovery restages it from the verified generation and
continues; if anything started on it, recovery refuses and leaves it and the journal
untouched, because a tree that has run is never treated as new again and its
records are never discarded. After the exchange, the installed replacement is
checked as the existing node it now is: recovery keeps its current local records,
corroborates its current frontier and continues forward, as for restore. An aborted
preparation leaves the original tree installed and never stopped; keep the service
inactive and start a new bootstrap with a new operation directory.

The node's database lock is local to that database. An engine also holds an
exclusive lock on every consensus key file it signs with. A second engine on the
same kernel that opens the same file, by any path, bind mount or hard link, refuses
to load the key. Engines also refuse to load a key file that is on a network,
cluster or FUSE filesystem, where the lock would not exclude anything. That is the
only exclusion: a copy of the seed is another file, and two hosts holding the same
key have no shared exclusion. Prevent the old signing process from restarting
before enabling its replacement; neither a recent snapshot nor the startup catch-up
age threshold establishes exclusive signing or complete vote history. Cross-host
leases or signer-side durable counters are not provided.

After startup the command watches the shared status collector. Completion releases
the receiver lease, but retains the old tree and its matched recovery evidence.
Timeout or health failure never triggers rollback.

## Offline private backup and status

The extended backup requires an already stopped node; it does not change its
service state. Large signing databases remain in the frozen database tree rather
than the identity bundle (64 MiB/file and 1 GiB total):

```sh
tosctl backup create-offline --context target-context.json --output /srv/node-sync/private-backup-001
tosctl node --config operator.json --node local sync status --watch --format json \
  --reference https://reference-a.example.invalid/jsonRPC \
  --reference https://reference-b.example.invalid/jsonRPC
```

The standalone `node status` command retains its earlier RPC-only diagnostic
contract and output; its legacy labels do not authorize restoration completion.
Use `node sync status` for strict qualification.

Strict status captures the target first and immediately fans out reference-head
reads concurrently, before historical identity checks. A reference head cannot
precede the target snapshot and understate lag. A cohort taking more than 500 ms, or lacking references at the
captured target height, is retried within the sample deadline; exhausted retries
are inconclusive. It never subtracts estimated production from observed lag or
widens the two-block limit. Each endpoint remains paced independently.

Strict status reports initial sync, coherent-tip age, block lag and full-ID agreement at
a common height with two separately named sources. At-head requires age <=30 s,
shard/reference lag <=2 and five continuous minutes of agreement. Endpoints are
paced at no more than two requests/s each. A responding RPC alone is not sync.
Exit codes: 0 at head, 2 catching up/observation timeout, 3 policy failure, 4 unknown
or unavailable evidence. Distinct endpoint strings are not proof of independent
operators; select independent references yourself.

Remote cohort qualification remains an acceptance item: measure acquisition
latency, retries and inconclusive results against two non-local references without
relaxing the 500 ms cohort or lag limits. Behind references or six unsuccessful
cohorts produce unknown, not readiness. Locally injected latency is emulation.
Native CI now exercises the lifecycle mode-change boundaries described below.
The separate real signing/crash and backlog rehearsals remain acceptance items;
source-wiring controls alone do not close them.

## Local qualification gate

The PR remains draft until the private global-id-3 rehearsal passes on the fixed
code. Component files standing in for votes do not prove signing-state safety.
Two process-crash cases must use the real managed service, native signing journals
and `sync recover`:

- Interrupt at exchange syscall entry, after durable `FORWARD_ONLY`. Boot the old
  installed tree, observe and independently verify a new own signed vote, then
  stop it. Recovery must rebuild from those latest local records and preserve
  them byte-for-byte before the replacement starts.
- Interrupt at successful exchange syscall return, before acknowledgement. Boot
  the new installed tree, observe a new valid own signed vote, then stop it.
  Recovery must keep that installed inode and its newest records, without an old
  overlay or rollback based on a missing start marker.

Use fresh isolated fixtures for controls that reuse a stale overlay or roll back
on a missing acknowledgement; their pre-start preservation assertions must fail.
No signing record may be injected for a green run. Production engines, real
system services and the actual recovery entry point are required. Keep fork and
rotation checks, the smoke backlog of at least 10,000 blocks, the acceptance
backlog of at least 172,800 blocks, measured phase durations, subsequent signing
and transfer, and five minutes of two-reference qualification as separate gates.
No public deployment, capture cadence or thirty-minute claim follows from the
component receipts.

### Native lifecycle test boundary

The native CI step runs non-ignored tests through production create, restore,
recover and completion entry points. A controllable manager fixture observes real
local engine processes. Tests exercise running/configured mode mismatch, drift
while stop settles, drift during object transfer, and interruption after the real
restore stop before staging. Completion retries authenticate request, generation
and operation records before accepting an already absent receiver lease. The
unauthenticated receiver-release API is not exposed. Creation is exercised on a
source without `static`, on a source without any zero-state file, and with failures
inside the stopped section: an
ordinary error and a panic restart the source, while a role, custody or mode
change found by the restart recheck, or a refused start, leaves it stopped with
exit status 5. Bootstrap is exercised end to end into a new-node layout, against
every validator and used-database refusal, through crashes on both sides of the
exchange (with and without a native start in between), and against a correctly
signed donor whose history does not contain the held init block. The production
verifier is exercised proving a required non-zero ancestor with its header proof.

Interruption hooks and manager overrides are compiled only under `cfg(test)` and
the non-default `native-lifecycle-tests` feature. The build rejects that feature
in the release profile; source guards reject default activation or unguarded hook
calls and pin the native CI command and result tokens. No runtime switch enables
hooks in the operator executable. Without the fixture environment these optional native tests print an explicit skip;
the dedicated CI step requires their result tokens, so it cannot silently skip.
These component tests do not replace the real
signed-vote/crash or full-backlog qualification rehearsals.

A watching sync-status command does not begin a zero-budget observation. If its
observation deadline expires after a successful catching-up observation, it
reports that last observation and exits 2 (observation timeout), not 4 (unknown).
That deadline reprint is labelled `stale=true` in text and `"stale": true` in
JSON; `sample_age` / `sample_age_seconds` measures elapsed monotonic time since
the last successful sample completed. Fresh samples are not labelled stale.
Without a successful catching-up observation it remains unknown; policy failure
and at-head results retain their distinct exits.
