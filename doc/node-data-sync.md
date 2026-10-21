# Trusted node-data recovery

This is an administrative recovery lane for an **existing** node. It trusts an
independently pinned publisher key and the publisher's chain database. Hashes,
native reopen checks and reference equality do not make a database dump trustless.
No consensus rule, persistent-state period or storage-retention setting changes.

The default capture method is a stopped-service cold copy. A filesystem snapshot
backend is a future measured option; these commands do not provision storage.
Capture cadence, maximum useful age and the thirty-minute rejoin target require
the separate local qualification run. They have not been qualified by unit tests.

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

The invoking user must own the selected service and database. `systemctl` must
be able to stop/start that exact unit. Native validation requires `unshare` with
user and network namespaces; refusal to create one is fatal. The verifier uses
fresh local credentials and isolated loopback, with no external network access.
On an Ubuntu 24.04 operator host with the default
`kernel.apparmor_restrict_unprivileged_userns=1` sysctl, the restore verifier needs
root/CAP_SYS_ADMIN or an AppArmor user-namespace rule.
A stopped copy is recoverable, not proof that every asynchronous write drained:
every public generation undergoes native recovery, shard-state reads and a second
reopen before it can be signed.

Managed service commands use a conservative subset of native options, with a
separate token for each option and value. Attached or clustered short options,
long equals forms, duplicate path selectors, unknown options and positional tokens
refuse before service stop. For example, use `-v 0`, not `-v0`. This restriction
aligns with the native parser's supported arities without changing that parser
(reference `857b8a57a178e6ae0fe7fa86e7d81c5233de8560`,
`tdutils/td/utils/OptionParser.cpp:137–164`).

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
handling refuses links. `disk_policy.max_owned_bytes` is a required, non-zero
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
can consume space between samples.

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
If a capture fails, inspect the private operation and service state; no unverified
generation is published. All temporary-package files selected by the native
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
spelling identify the same source. Manifest and journal format 2 require these
receipts; old formats refuse explicitly. The five-minute post-start check remains
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
unauthenticated receiver-release API is not exposed.

Interruption hooks and manager overrides are compiled only under `cfg(test)` and
the non-default `native-lifecycle-tests` feature. The build rejects that feature
in the release profile; source guards reject default activation or unguarded hook
calls and pin the native CI command and result tokens. No runtime switch enables
hooks in the operator executable. These component tests do not replace the real
signed-vote/crash or full-backlog qualification rehearsals.

A watching sync-status command does not begin a zero-budget observation. If its
observation deadline expires after a successful catching-up observation, it
reports that last observation and exits 2 (observation timeout), not 4 (unknown).
Without a successful catching-up observation it remains unknown; policy failure
and at-head results retain their distinct exits.
