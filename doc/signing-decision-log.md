# Own-decision log and unknown signing history

Status: **on for every validator, on every network.** There is no engine
option to turn it on or off. Every node that holds a consensus key keeps the
log and the unknown-history fence described here; an observer, which holds no
consensus key, keeps neither. A validator group is never built without an
admission from the log: one that somehow is signs nothing. The evidence behind
the change is recorded under [Evidence](#evidence); the gates still open
before the change merges are listed there too.

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
   *pending* ledger. The ledger stores `t0`: the time, rounded up to a second, at
   which this process took custody of the identity's consensus key and its
   binding to the validator id, whichever came later. Custody added, rebound or
   re-added at runtime takes a new `t0`, and anything the process applied
   before it no longer counts for that identity.
   - An untrusted header is set aside as `ledger.untrusted.N` beside the new
     one, and is never deleted. At most four are kept; a fifth untrusted start
     signs nothing until an operator removes old ones.
   - A restart while pending uses the latest of the stored `t0`, the process's
     new custody time and the ledger actor's start time. The manager reads this
     lower bound before choosing M, including when the host clock moved back.
2. **Signs nothing while pending.** Its validator groups run, but quiescent: no
   vote and no candidate.
3. **Fixes the fence at block M.** M is the first masterchain block this
   process applies after `t0` that was generated at `t0 + 91` s or later. The
   process records M for each identity it holds as soon as it applies it,
   whether or not a ledger exists yet, so a validator-elect whose node has run
   long enough is established at its first admission and signs in the first
   session of its set. While the ledger's custody lower bound is loading, the
   manager retains one provisional block, hidden from admissions. It validates
   that block before offering it to the ledger. If a later persisted custody
   time makes it too early, the candidate is discarded and selection resumes
   with the next applied block. A slow read combined with a clock correction can
   therefore conservatively delay M; it cannot release an unvalidated candidate.
   The ledger then records, for M:
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

- **Clocks.** This host's clock and every honest validator's clock are within
  30 s of true time. Time sync (`setup-time.sh` in the operator repository) is
  a requirement, not an option. The 91 s margin is 30 s of host skew, 30 s of
  honest skew, 30 s of block-time tolerance and 1 s of rounding: under these
  assumptions M was produced after the process took custody.
- **Honest majority.** More than two thirds of the weight is honest, and an
  honest validator refuses blocks generated more than 30 s in its future.
- **No second signer.** The previous signer of the identity has stopped
  before this process takes custody of its key. Two hosts running the same
  identity at the same time are out of scope. The consensus key lock prevents
  that only for processes that open the same key file inode on one kernel.

If an assumption fails, M may predate the earlier signer's last signature.

### Liveness: the handover and its prerequisite

An incoming validator is admitted in the first session of its set if its
process has held its key for at least `91 s + catch-up + 3 × masterchain
catchain lifetime` before the set takes office (about 15 min at a 250 s
lifetime; elections close long before office). Operators must keep to:

- **Do not (re)start a validator-elect within `91 s + 3 × lifetime` before it
  takes office.**
- **At any moment, the fenced weight of the current and the incoming sets
  together stays below one third.** This is the one-at-a-time restart rule,
  extended across a validator-set handover.

Limits, stated plainly:

- If more than one third of the weight loses or distrusts its ledger while the
  chain is **halted** (no masterchain block is produced), none of those nodes
  can obtain M and the chain cannot restart. That is the fence doing its job:
  those nodes cannot show what they signed. Recovery needs an operator
  attestation tool, which is not provided; it is on the roadmap with the
  exclusive signer.
- A workchain created after a validator's M has no related lineage at M, so the
  validator never signs in it until it restarts (taking a new `t0` and M).
  Roll-restart validators, one at a time, after a workchain is added.

## Rebinding a stopped node

`bind-node --replace` may bind the same database to another validator identity.
The original `consensus/signing-ledger/` is preserved. When its header names a
different identity, the new identity uses
`consensus/signing-ledger.<VALIDATOR_ID_HEX>/` and passes through the ordinary
unknown-history fence. Switching back reopens that identity's retained ledger,
including its decisions and masterchain floor. An existing identity directory
always takes precedence, even if the original directory is absent or its own
header is damaged; damage causes unknown-history recovery, never fallback to
another history.

At most four identity directories are created in addition to the original.
The fifth new identity is refused until the stopped node's operator preserves
and removes an obsolete retained ledger. There is no automatic eviction; removing
an identity's ledger means it must pass the unknown-history fence on its next use.
Only the bound identity's ledger is opened, so inactive histories add no open
log file descriptors or in-memory session records. Each retained directory has
the same header, session and decision limits as the original.

## Genesis ceremony

A validator identity created fresh for a new zerostate has never signed. It does
not need to wait for an unknown-history fence. **Every genesis validator must
run the ceremony** before its node first starts: if every genesis validator
starts without a ledger, all of them wait for a fence block that a chain with
no signer cannot produce, and the chain never starts. Such a node logs, once,
at the zerostate: `no signing ledger at genesis: run tos-pq-consensus-key
init-signing-ledger --genesis-ceremony ...`. Nothing else changes: a fresh
database cannot prove the key never signed, so the ledger is never made
complete automatically. The ceremony creates a *complete* ledger whose history
starts at the zerostate:

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
- refuses when a signing ledger or any retained identity ledger already exists;
- refuses when `consensus/` holds any `consensus.*` session directory, or cannot
  be listed completely.

When the node starts, it checks the ledger's zerostate against the zerostate in
its own configuration. A ledger made for another zerostate admits nothing.

**Run it only for an identity created for this zerostate that has never
signed.** Running it for a key that signed before, on this network or any other,
removes the protection the log exists for.

Where it runs: the test harness runs it for each genesis PQ validator before
its first start; the local network installer and the operator ceremony's
`install-node.sh activate --genesis-ceremony` run it for each genesis
validator. A validator that joins after genesis never runs it, and goes
through the unknown-history fence once.

## Log size and its ceiling

Each session's log holds at most **2^20 records (64 MiB)**. A record is 64 bytes,
and a log file grows only by the records actually written.

- **At the ceiling the session fails closed.** The log refuses every new decision,
  logs an ERROR ("is full at ... records; this session signs nothing more"), and
  the session signs no vote and produces no candidate for the rest of its life.
  A decision already recorded is still answered.
- **Warnings before that.** A WARNING with the session id and the record count is
  logged when a log reaches 50 % of the ceiling, and again at 75 %, each once per
  process ("signing stops at 1048576"). A log reloaded above either mark warns at
  startup.
- **Refusal at admission.** Before a session is admitted, the validator manager
  computes its *normal-progress estimate*:

  `3 * ceil(lifetime_ms / target_rate_ms) + ceil(slots / slots_per_leader_window)`

  This uses the catchain lifetime from ConfigParam 28 for the session's shard kind
  and the session's Simplex `target_rate` and `slots_per_leader_window`. Per slot
  the log admits at most a notarize, a finalize and a skip, and one record per
  leader window.
  - If the estimate exceeds the ceiling, the session is refused at admission: it is
    fenced and signs nothing, and an ERROR names the session, the estimate, the
    ceiling and the parameters.
  - A zero target rate, a zero leader window, an overflow, or a ConfigParam 28 that
    is missing or does not parse is refused the same way.
  - Above half of the ceiling the session is admitted, with a WARNING.
  - The same estimate is logged once at startup for the current configuration of
    the masterchain and of every workchain. That check is diagnostic; admission
    enforces the refusal.
- **An estimate, not a bound.** A session lives until the next validator group
  replaces it. If the chain stalls, it can outlive its lifetime and keep adding
  skip records. Then only the ceiling and its warnings apply.

What the configurations come to, at the default 400 ms target rate and 4 slots
per leader window:

| Configuration | Lifetime | Estimate | Admission |
|---|---|---|---|
| production | 250 s | 2,032 records | admitted |
| development (tostester default) | 100,000 s | 812,500 records | admitted, WARNING |
| anything above about 129,000 s | | > 1,048,576 | refused |

Memory and disk are measured by `test-decision-log-scale` (modes `memory`,
`full-restart`, `retained`); the numbers are recorded under
[Evidence](#evidence). Every listed session (at most 1,024) keeps its index and
its admission's copy of the decisions in memory until it is pruned. Each holds
only the records it actually has. The startup check between the journal and the
log is linear in their sizes.

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
rolled back, remove every `consensus/signing-ledger/` and `consensus/signing-ledger.*`
identity directory before starting it, so that it
goes through the unknown-history fence.

Do not copy any signing-ledger directory between hosts or back it up for restore.
A file copy is detected and treated as unknown history. A copy that keeps inode
numbers and birth times, as above, is not detected.

## Rolling upgrade

The log changes only what a node itself signs. Peers see no new message or
field, so nodes with the log and nodes without it can run in one network.

For one node, upgrading to a release with the log is the same as losing the
journal: the node has no ledger yet. It goes through the unknown-history fence
and signs again three counters after its fence block (about 15 min on the
testnet). Upgrade validators one at a time, and keep more than two thirds of
the weight signing throughout; with four validators that is strictly one at a
time.

**Downgrade, then upgrade again.** After running a binary without the log,
remove all signing-ledger directories (with the node stopped) before running one
with it again. Otherwise the journal holds votes the log never saw, and the
cross-check fences those sessions.

Non-consensus uses of the consensus key, such as the engine's stake and
governance signatures, are not session decisions and cannot equivocate; the log
does not record them.

## Evidence

Recorded before the log was made mandatory:

- the latency of recording a decision before broadcast, on the production
  server class (6 vCPU, 12 GB, virtio disk): the vote path is not slower; the
  first own-window candidate is 3.5 to 4.6 ms slower at p50; about 10
  `fdatasync`/s per validator at 5.5 ms p50;
- a local-chain drill: `consensus/` deleted while a shard split is pending, and
  the node restarted within one session. Expected result:
  - no own vote or candidate in a session at or below `cc(M) + 2` of its
    lineage;
  - signing resumes at `cc(M) + 3`.

  Recorded in [the drill evidence](evidence/signing-unknown-history-drill/README.md).
  Votes and candidates were both observed where they are signed, not only in
  certificates. Two red controls went red:
  - main signed again at once, in the old masterchain session;
  - a build whose block producer skips its admission checks signed candidates in
    fenced sessions.

Gates for making it mandatory, run on a local chain:

- a validator-set handover that replaces half the weight with fresh identities
  (no ledger, no ceremony): the masterchain advances through the handover with
  counters strictly above each incoming identity's `cc(M) + 2`, each incoming
  identity signs above its fence and never at or below it. Main with the log
  on stalls there;
- a file-copy restore of an active validator, restarted within 90 s;
- a fresh chain with the ceremony (blocks at the normal time) and without it
  (no blocks, the genesis hint on every validator);
- per-process file descriptor attribution and an equal-duration soak with and
  without the log. Both arms must finish with all four validators and two observers
  present in every sample, with complete measurements and unchanged process start
  times. Missing, interrupted or restarted processes fail the comparison before
  resource averages are computed.

Measured for the 2^20-record ceiling (`test-decision-log-scale`, Release build,
x86-64):

- **Memory per record.** The in-memory index takes 111 to 175 bytes per record:
  - 119 B with a notarize and a finalize per slot;
  - 175 B with skips only;
  - 111 B with leader windows only;
  - 118 B for the mix a running chain records.

  An admission's copy of the decisions adds 48 B per record. The restart check's
  lookups add another 167 B per record, but only while the check runs.
- **A full log.** Reloading a 2^20-record (64 MiB) log took 0.86 s. Checking it
  against a journal of its 932,067 votes took 0.40 s. Peak resident memory rose by
  139 MB after the reload and by 210 MB during the check.
- **Every retained session at once.** 1,024 listed sessions of production size
  (2,032 records each) took 133 MB on disk. They reloaded in 1.53 s and held 317 MB
  of heap (152 B per record).
- **The cases that follow:**
  - a production session holds about 0.3 MB in memory;
  - a development-lifetime session (812,500 records) holds about 135 MB;
  - a session stalled at the ceiling holds about 175 to 235 MB, and its log is
    64 MiB.
- **Scaling.** Four times the input took 3.8 times as long for the restart check
  (2^15 to 2^17 decisions). With either old quadratic loop restored, the ratio was
  23 to 48, and the full-size restart exceeded its time limit.

## Release note (for the release that makes the log mandatory)

> Validators record each consensus decision in an own-decision log before they
> sign it. This prevents a node from signing twice in a session after its
> consensus journal is lost, or its database is restored from a file copy or
> moved to another host. It does not protect against an in-place filesystem or
> virtual machine snapshot rollback, which keeps inode numbers. Never roll a
> validator back that way, or delete its signing ledger before starting it
> again. A validator whose earlier
> signing is unknown does not sign until three catchain rotations after its
> first fence block. This includes a fresh install of an existing identity, a
> restore, or a node upgrading to this release. The `--signing-decision-log`
> option is gone: the log is always on. Every genesis validator of a new chain
> must run `tos-pq-consensus-key init-signing-ledger --genesis-ceremony` before
> the node's first start, only for an identity that has never signed; without
> it the chain does not start. Do not restart a validator-elect within about
> 15 minutes of its taking office. After a downgrade, remove
> all signing-ledger directories, including retained identities, before upgrading again.
