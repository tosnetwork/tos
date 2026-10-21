# Trusted node-data recovery

This is an administrative recovery lane for an **existing** node. It trusts an
independently pinned publisher key and the publisher's chain database. Hashes,
native reopen checks and reference equality do not make a database dump trustless.
No consensus rule, persistent-state period or storage-retention setting changes.

The default capture method is a stopped-service cold copy. A filesystem snapshot
backend is a future measured option; these commands do not provision storage.
Capture cadence, maximum useful age and the thirty-minute rejoin target require
the separate local qualification run. They have not been qualified by unit tests.

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

The invoking user must own the selected service and database. `systemctl` must
be able to stop/start that exact unit. Native validation requires `unshare` with
user and network namespaces; refusal to create one is fatal. The verifier uses
fresh local credentials and isolated loopback, with no external network access.
A stopped copy is recoverable, not proof that every asynchronous write drained:
every public generation undergoes native recovery, shard-state reads and a second
reopen before it can be signed.

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
  "budget_roots": ["/srv/node", "/srv/node-sync", "/srv/node-build"]
}
```

List every task-owned source, retained operation, cache, staging and build root
in `budget_roots`, without overlaps. They must exist. Allocation accounting
counts physical blocks and deduplicates hard-linked build artifacts; payload
handling refuses links. Aggregate admission is 320 GiB, with at least 200 GiB free.
The monitor stops new work at 316 GiB or 212 GiB free, leaving shutdown headroom.
Use the shared build/cache ceiling of 16 GiB. These checks are not filesystem quotas.

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
create publisher secrets. Keep that file outside the public catalog.

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
  --publisher-key <PINNED_PUBLIC_KEY> --global-config held-global.json --global-id 3
tosctl node dump list --directory /srv/node-sync/catalog --publisher-key <PINNED_PUBLIC_KEY>
tosctl node dump prune --directory /srv/node-sync/catalog --publisher-key <PINNED_PUBLIC_KEY>
```

Creation stops and locks only the selected source, copies its matched chain and
recovery context privately, then restarts the source before validating/compressing.
If a capture fails, inspect the private operation and service state; no unverified
generation is published. All temporary-package files selected by the native
allowlist are included; `archive/tmp` is staging and is excluded. Raw donor
StateDb, keys, config, sessions and recovery files have no public payload variant.

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
mode must match. The target's GC/init/coherent pointers and retirement checkpoints
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

A fsynced `FORWARD_ONLY` journal outside both trees precedes atomic exchange.
It forbids rollback even if a crash occurs before a start marker and a boot-enabled
service has already signed. If the old tree remains installed, recovery stops it
and rebuilds from its **latest** local state. If the new tree is installed, recovery
keeps its current local state and continues forward. Ambiguous identities or a
corrupt/missing journal refuse movement. Do not manually exchange the old root
back or discard these private recovery bundles. Sole managed signing and honest
local administration are explicit assumptions.

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

Status reports initial sync, coherent-tip age, block lag and full-ID agreement at
a common height with two separately named sources. At-head requires age <=30 s,
shard/reference lag <=2 and five continuous minutes of agreement. Endpoints are
paced at no more than two requests/s each. A responding RPC alone is not sync.
Exit codes: 0 at head, 2 catching up/observation timeout, 3 policy failure, 4 unknown
or unavailable evidence. Distinct endpoint strings are not proof of independent
operators; select independent references yourself.
