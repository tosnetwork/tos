# Own-decision log and unknown signing history

Status: **experimental, off by default, not deployable yet.** The validator
manager option `signing_decision_log_enabled` is false, and the validator
engine has no flag that sets it. Do not enable the log on any network until
the pre-merge evidence listed under [Deployment blockers](#deployment-blockers)
exists. It must be enabled together with the unknown-history fence described
here, never without it.

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
  are out of scope. The consensus key lock prevents that on one host only.

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

A restore any other way starts with unknown history once the log is enabled.
This includes replacing the database directory with a snapshot, moving it to a
new host, or a fresh install of an existing identity. Expect such a node to sign
again only after its fence block and three catchain counters (see
[What it costs](#what-it-costs)).

Do not copy `consensus/signing-ledger/` between hosts or back it up for restore.
A copy is detected and treated as unknown history. An old copy that went
undetected would let the node sign against stale records.

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
- a validator engine option that enables the log, reviewed with the above.

## Release note (for the release that enables the log)

> Validators record each consensus decision in an own-decision log before they
> sign it. This prevents a node from signing twice in a session after its
> consensus journal is lost, restored or copied. A validator whose earlier
> signing is unknown does not sign until three catchain rotations after its
> first fence block. This includes a fresh install of an existing identity, a
> restore, or a node upgrading to this release. New genesis validators can
> skip that wait with `tos-pq-consensus-key init-signing-ledger
> --genesis-ceremony`, run before the node's first start, only for an identity
> that has never signed.
