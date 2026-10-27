# Own-decision log and unknown signing history

Status: **experimental, off by default, not deployable yet.** The validator
engine flag `--signing-decision-log` turns it on **for local-chain drills
only**. A node started with the flag refuses to start on any network whose
global id is not 3 (local). Mainnet (1) and the public testnet (2) are
refused with a message naming the flag. It also admits no session there if a
later path reaches admission. Do not enable the log anywhere else until the
evidence listed under [Deployment blockers](#deployment-blockers) exists and
the local-only restriction is lifted in a reviewed change. It is enabled
together with the unknown-history fence described here, never without it.

## What it protects against

A validator must never sign two conflicting decisions in one consensus session.
Examples are two different candidates for one slot, or a skip and a finalize for
the same slot. The consensus session journal records what was signed. When that
journal is lost, a restarted node can sign again in a session where it has
already signed. The journal can be lost in several ways:

- `consensus/` is deleted;
- the node is restored from a backup or snapshot;
- the data directory is copied to another host.

The own-decision log closes that gap:

- **Before signing.** Each decision is appended to a small per-session log under
  `<db>/consensus/signing-ledger/`, and synced to disk, before anything is
  signed.
- **Who owns the directory.** A ledger header binds the directory to the
  validator and to the filesystem object the ledger was created in.
- **Untrusted copies.** A copied, restored or recreated directory is untrusted.

## Unknown history

A node with no trusted ledger cannot know what its validator identity signed
before. This happens when the ledger is missing, or when it was copied,
restored or recreated. Such a node:

1. **Starts a pending ledger.** At its first session admission it creates a
   *pending* ledger. The ledger stores `t0`, the node's start time rounded up to
   a second.
   - An untrusted header is set aside as `ledger.untrusted.N` beside the new
     one, and is never deleted. At most four are kept; a fifth untrusted start
     signs nothing until an operator removes old ones.
   - A restart while pending keeps the stored `t0`.
2. **Signs nothing while pending.** Its validator groups run, but quiescent: no
   vote and no candidate.
3. **Fixes the fence at block M.** M is the first masterchain block it applies
   that was generated at `t0 + 91` s or later. The ledger then records, for M:
   - the catchain counter of the masterchain;
   - the catchain counter of every shard in M's configuration.

   At most 256 lineages are recorded. If a lineage has no counter, or there are
   more than 256, nothing is recorded, and the next block is tried.
4. **From then on.** A session of shard `x` with counter `c` is fenced in three
   cases:
   - a recorded lineage is related to `x` (equal, ancestor or descendant) and
     `c <= cc + 2`;
   - no recorded lineage is related to `x`, as for a workchain that did not
     exist at M;
   - the session has no counter.

### What it costs

A restored or reinstalled validator signs again from the first session three
catchain counters above M on each lineage. The time adds up as follows:

- the 91 s margin;
- catching up to M;
- three rotations, about 750 s at a 250 s masterchain catchain lifetime.

Sessions created soon after M, for example the children of a split, can be
fenced as well. That costs availability, not safety. This is a deployment
cost, not a recovery-time guarantee.

### What it assumes

- **Clocks.** Honest validators' clocks are within 30 s of true time.
- **Honest majority.** More than two thirds of the weight is honest, and an
  honest validator refuses blocks generated more than 30 s in its future.
- **No second signer.** The previous process of the identity has stopped
  before this one starts. Two hosts running the same identity at the same time
  are out of scope. The consensus key lock prevents that only for processes
  that open the same key file inode on one kernel.

## Genesis ceremony

A validator identity created fresh for a new zerostate has never signed. It does
not need to wait for an unknown-history fence. Before its node first starts, the
operator can create a *complete* ledger whose history starts at the zerostate:

```bash
tos-pq-consensus-key init-signing-ledger --genesis-ceremony \
  DB_ROOT VALIDATOR_ID ZEROSTATE_ROOT_HASH ZEROSTATE_FILE_HASH
```

- `DB_ROOT` is the node's `-D` directory.
- `VALIDATOR_ID` is the staking account's id, as for `bind-node`.
- The two hashes are the global configuration's `validator.zero_state` root and
  file hashes.

The command:

- holds `DB_ROOT/config.json.lock` while it runs, so the node must be stopped;
- refuses when a signing ledger already exists;
- refuses when `consensus/` holds any `consensus.*` session directory, or cannot
  be listed completely.

When the node starts, it checks the ledger's zerostate against the zerostate in
its own configuration. A ledger made for another zerostate admits nothing.

**Run it only for an identity created for this zerostate that has never
signed.** Running it for a key that signed before, on this network or any other,
removes the protection the log exists for.

## Restores, snapshots and copies

The trusted node-data recovery in [node-data-sync](node-data-sync.md) preserves
the target's own `consensus/`, including its signing ledger, and never imports a
donor's. A validator restored that way keeps its ledger in place and keeps its
history.

The ledger detects a copy by the directory's and each log's inode number and
birth time. Once the log is enabled, a node starts with unknown history in
these cases:

- the database directory is replaced with a snapshot made by copying files;
- the database is moved to a new host;
- an existing identity is installed fresh.

Expect such a node to sign again only after its fence block and three catchain
counters (see [What it costs](#what-it-costs)).

**Excluded residual: a consistent rollback that keeps inodes.** An in-place
rollback of the filesystem or of the whole virtual machine keeps inode numbers
and birth times, for example a block-level, LVM, ZFS, btrfs or hypervisor
snapshot restored onto the same device. It rolls the ledger and the journal
back together. The rolled-back ledger is indistinguishable from the original,
so the node is **not** fenced. It can sign again in a session where it signed
after the snapshot was taken. The log does not protect against this. Never
roll a running or recently running validator back in place. If it has been
rolled back, delete `consensus/signing-ledger/` before starting it, so that it
goes through the unknown-history fence.

Do not copy `consensus/signing-ledger/` between hosts or back it up for restore.
A file copy is detected and treated as unknown history. A copy that keeps inode
numbers and birth times, as above, is not detected.

## Rolling upgrade

The log changes only what a node itself signs. Peers see no new message or
field, so nodes with the log and nodes without it can run in one network.

For one node, enabling the log is the same as losing the journal: the node has
no ledger yet. It goes through the unknown-history fence and signs again three
counters after its fence block. Upgrade validators one at a time, and keep more
than two thirds of the weight signing throughout.

## Deployment blockers

Neither part is deployed before all of the following are recorded:

- the latency of recording a decision before broadcast, measured on the
  production server class (6 vCPU, 12 GB, virtio disk);
- a resident-memory soak of a validator with the log enabled;
- a local-chain drill: `consensus/` deleted while a shard split is pending, and
  the node restarted within one session. Expected result:
  - no own vote or candidate in a session at or below `cc(M) + 2` of its
    lineage;
  - signing resumes at `cc(M) + 3`.
- the local-only restriction of `--signing-decision-log` lifted in a change
  reviewed with the above.

## Release note (for the release that enables the log)

> Validators record each consensus decision in an own-decision log before they
> sign it. This prevents a node from signing twice in a session after its
> consensus journal is lost, or its database is restored from a file copy or
> moved to another host. It does not protect against an in-place filesystem or
> virtual machine snapshot rollback, which keeps inode numbers. Never roll a
> validator back that way, or delete its signing ledger before starting it
> again. A validator whose earlier
> signing is unknown does not sign until three catchain rotations after its
> first fence block. This includes a fresh install of an existing identity, a
> restore, or a node upgrading to this release. New genesis validators can
> skip that wait with `tos-pq-consensus-key init-signing-ledger
> --genesis-ceremony`, run before the node's first start, only for an identity
> that has never signed.
