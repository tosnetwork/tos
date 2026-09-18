# P0 progress

Companion to [the implementation record](validator-auth-p0-implementation.md),
which states what each boundary implements and what it still owes. This file
reports how far the whole of P0 has moved and what remains, so a reader does not
have to reconstruct completion from the per-boundary table.

Branch `feat/validator-auth-p0`, PR #111, draft. The design is v1 revision 5,
fingerprint `8d4c5dd7a410472956d8ea4b5ae1f76905a3492a0ad18a48efe52675b400f982`.
Nothing here authorizes activation, allocates a PQ suite, or changes any frozen
wire or API artifact.

## How completion is counted

The denominator is the 28 boundaries of the implementation record. Each is split
into three stages, because they fail differently and are evidenced differently:

| Stage | What it means | How it is evidenced |
| --- | --- | --- |
| Library | The behaviour exists and is verified against the frozen model | Cross-language cases and compiled guard removals |
| Node integration | A production call path reaches that behaviour | The node builds and runs it, not a fixture |
| Operational acceptance | The behaviour has been rehearsed and approved for a chain | Multi-node rehearsal, measured production cost, named approvals |

A library boundary is counted complete only when its removals fail named
assertions after compiling. A compilation failure is not a killed mutation.

## Summary

| Stage | Completion | Basis |
| --- | --- | --- |
| Library | 27 of 28 boundaries | Only `Operational release` has no implementation |
| Node integration | Partial, six call paths | Every one of the 28 boundaries still lists remaining integration |
| Operational acceptance | None | No rehearsal has enabled P0 on a chain |
| **P0 overall** | **roughly 55-60%** | Weighted estimate, not a measured figure |

The table above was counted on 2026-09-14 and has not been recounted since. What
has landed after it: the bounded evidence expansion and the single opening on
the admission path, the execution clone that gives a diagnostic retry a fresh
host without re-parsing attacker bytes, the governance finalization of a voted
proposal, the profile's move to v1 revision 4, and external-message provenance
becoming a remote peer or a local origin. None of those is a new call path, so
the node-integration figure is believed unchanged; the library column was not
re-derived and the numbers should be read as of that date rather than as of this
head.

The overall figure is an estimate and should be read as such. It has barely moved
over the last several working sessions, not because progress stalled but because
touching real execution keeps making previously invisible integration work
visible: the boundary table has grown from 14 rows to 28 while the library
column was being filled in.

Since that count (this note added 2026-09-18): the manager now derives the
authenticated committee for a validator group rather than only confirming its
identity, the committed session owner reaches the consensus bus, and the bus
seats its members from that committee rather than from the manager's validator
set -- the first of the remaining production-integration workstreams, "session
consumes the authenticated committee", from memo/Phase1A.md. This is committee
authority at session birth only. C0 certificate verification inside the
consensus message flow, elector/registry operation closure, node-actor commit
wiring, and a P0-enabled multi-node rehearsal remain, so the node-integration
column is no longer "believed unchanged" but is still partial, and operational
acceptance is still none. The 55-60% figure predates all of this and is not
recounted here; read it as of 2026-09-14.

## Library stage

27 of 28 boundaries are implemented and verified in both C++ and Rust where the
boundary spans both. The implementation record carries the per-boundary evidence;
the aggregate is 830 compiled production mutations, each required to compile and
then fail a named behavioural assertion, with restored baselines.

Two results are worth stating separately because they are easy to misread.

**C0 verification cost.** A 400-member certificate first measured 492.5 ms under
the P0 path against 31.3 ms historical. After the hot path was reworked without
changing the frozen verification semantics, the same case measured 32.0 ms, a
median increase of 2.3% and a p95 increase of 1.9%. This is a local macOS/ARM
measurement of certificate verification alone. It is not a production hardware
result and not a whole-node propagation budget.

**Sanitizer coverage.** Address and undefined-behaviour checks run in CI and
locally on Linux. Leak detection is unavailable on macOS and is not claimed
there; leak coverage exists only where the suite runs on Linux.

The one unimplemented boundary, `Operational release`, is unimplemented by
design: it has no code, only gates.

## Node integration stage

Six production call paths now reach P0 behaviour:

| Path | Where | What it establishes |
| --- | --- | --- |
| Key isolation | `keyring/` links the signer library | Protected validator keys refuse raw signing, decryption and export |
| VM capability gate | `validate-query.cpp` passes global capabilities | C0 verification in the VM is gated by configuration, not by the contract |
| Election binding | `crypto/block/mc-config.cpp` | Identity and stake id survive committee selection into the node's validator set |
| Genesis writing | `crypto/fift/lib/Config.fif`, the genesis tool | A genesis can carry an authenticated registry and authenticated descriptors |
| Committee derivation | the genesis rehearsal | The native path derives a committee from a genesis the real writers produced |
| Genesis seeding | the genesis rehearsal | An account the genesis interpreter wrote, carrying parameter 46 and the registry checkpoint together, runs its own first tick-tock and commits; the same account without the checkpoint is refused |
| Session identity confirmation | `validator/manager.cpp`, as a declared insertion | The manager may not create a validator group under a session identity the authenticated producer does not confirm, nor on a state committee derivation would refuse |

The last of these is a binding, not a replacement. The manager builds a session
identity and the producer builds the same identity from the validator set: two
derivations of one fact, which is the shape this repository keeps producing.
Replacing the manager's construction was not available, because a frozen file
admits insertions only and an inserted early return would have left the original
construction present as unreachable code -- still two implementations, with one
of them hidden. The two are bound instead by a check that refuses on
disagreement. It runs only on a chain that has activated P0, behind the same
gate native committee derivation uses, and an unreadable state reports inactive
so that enforcement cannot stop an otherwise healthy node.

Agreement about an identity is not the whole of what the confirmation says. The
identity is a hash of keys, addresses and weights, so it agrees whether or not
the election that produced those members was admissible at all; a confirmation
that said only "these two derivations agree" would let the manager hand
consensus a roster committee derivation refuses, with each side passing its own
tests. Derivation's rules divide into those decided from the masterchain state
alone and those that need an anchor and an archive read. The first are now a
single function that derivation and the confirmation both call, so the
confirmation applies them in full rather than keeping a smaller copy: the
capability and version gate, parameter 46 being mandatory and critical, the
validator-count bounds, the election's own boundary in time, a real catchain
selector, and an elected set in which every member names a registry identity
and no identity, stake or consensus key appears twice.

The registry rules stay out, and that is a statement rather than an omission:
they need an independently established anchor this caller does not have. What
the confirmation can say about the roster itself is that every member it will
run carries a binding, which is derivation's own rule for the members it
selects. What it cannot say is that the roster is the one this state elects --
recomputing the selection needs the shard hashes a full configuration carries,
and what the state yields here is a plain one.

Everything else remains open. The named remaining work, grouped:

| Group | Remaining |
| --- | --- |
| Session and consensus | Consensus call sites; the manager's archive reader and an independently established finalized head. Session birth and committee derivation now exist as a library boundary and are owned by the authenticated birth, but the derived committee still has no consumer in `validator/manager.cpp`: the insertion there confirms the session identity and the state it would run on, and does not yet run consensus against the derived committee. The registry half of derivation's admission remains out of reach there for want of an established anchor, which is the same missing piece as the archive reader |
| Contracts | Elector emission and session admission; configuration authorization and atomic root installation. Both contracts now carry declared P0 entry points, so the row no longer says they carry none: `config-code.fc` declares the VAUTH_APPLY and VAUTH_BIND instructions, persists the registry checkpoint, dispatches the registry action and finalizes a proposal that completed normal voting, and `elector-code.fc` carries the registry identity each elected member named through selection and refund. What is outstanding is emission and admission rather than any entry point at all: the elector work is binding an elected set, not emitting receipts |
| Chain apply | Native block apply, contract data installation, action-phase commit wiring, installed chain root |
| Serving | Remote HTTP/2 with mutual TLS, and installation of the served composition into the node. The node history adapter and the authenticated public composition now exist as library boundaries: the client methods are served behind a transport that supplies an authenticated principal, and that transport is a narrow interface so a mutual-TLS implementation substitutes for the local Unix one without touching the composition. Only the local Unix implementation exists today |
| Provisioning | Provider inventory reconciliation, independent operational trust distribution, the node permit adapter |

Cross-language parity is closed. The Rust scoped object store now exists and a
differential runs both implementations over one corpus, and the record's
separate claim that a Rust global registry apply was missing turned out to be
stale: Rust already composes native authority over its own registry state, and
adding a second apply would have created another source for one state
transition. This is the first of the six groups to reach zero.

These are not independent. The order below is a dependency chain, not a
priority list:

```
genesis can write P0                     done
  -> a session consumes that committee
    -> consensus verifies C0 certificates
      -> config/elector accept registry operations
        -> a multi-node rehearsal runs with P0 enabled
```

The contract step is the largest single item and the most constrained: both
contracts are inside the frozen production boundary, so any change to them has to
arrive as a declared insertion with controls on both the original and the inserted
bytes, not as an ordinary edit.

## Operational acceptance stage

Nothing in this stage is complete.

| Gate | Status |
| --- | --- |
| Testnet rehearsal with P0 enabled | Not started. A four-node rehearsal has run, but over the historical authentication path |
| Genesis approval | Not started |
| Operator recovery rehearsal | Not started |
| Production hardware C0 cost | Not started. The 32.0 ms figure is a local measurement |
| Growth and sustained-load soak | Not started. See below |
| The five `approvals_pending` items in the freeze record | Outstanding |

### Growth and sustained-load soak

Every check in the library stage asks whether a result is correct. None asks how
a quantity grows. P0 deliberately introduces state that is retained rather than
reclaimed, so correctness tests cannot answer the operational question, and
neither can the sanitizers: LeakSanitizer reports memory that has become
unreachable at process exit, while these quantities stay reachable, bounded by
policy, and live in a process that does not exit.

Five retained quantities have no measured growth curve:

| Quantity | Why it grows | What is stated today |
| --- | --- | --- |
| Registry key history | Retired and cancelled key versions must stay independently retainable, so the archive only grows | "Historical keys and retired identities must remain independently retainable" (implementation record) |
| Per-block work against archive size | The native adapter copies and rebuilds derived indexes | One authenticated identity read now measures at 1 entry and 375 bytes across archives of 0, 100, 1000 and 5000 retired key versions, and a scan of the archive fails that measurement. The record's wider claim, that a whole block's work is bounded, is still unmeasured |
| Signer journal and witness | Append-only by design; capacity exhaustion is an explicit error, not a reclaim | Measured. On disk: 36 bytes of framing per record, 2883 bytes per completed signature, so the default 1 GiB limit is reached after roughly 372,000 signatures and then refuses admission without touching stored history. Restart replays every record exactly once at about 9.4 us per record, so a full journal costs a restart of a few seconds and not an outage. In memory: 3436 bytes retained per signature, exactly linear, which is 1220 MiB at that same signature count -- see below |
| Retained session snapshots | Each session holds its committee until its native termination boundary | The boundary now exists: release is driven only by an independently finalized native state for the held shard, resets the committee owner, revokes outstanding member-authority handles and advances an observable release counter, while the durable continuity record is deliberately kept. What is implemented is the boundary, not a measurement: no run has yet shown retention actually falling over sustained session turnover |
| Resumable committee handoff | Each resume replays the whole birth resolution over every retained input rather than holding a continuation, so total work is quadratic in the number of asynchronous rounds | Structural, established by reading the code rather than measured. The declared history budget permits 4096 observations, so the worst case is 4096 rounds each replaying all prior reads; the test fixture carries a two-block history and cannot produce the curve. Deep-history measurement belongs with the birth resolver, not the handoff |

The object store is the one bounded case: four objects and 64 MiB per principal,
256 MiB globally, and the local provider admits at most 4096 retained keys. Both
fail closed on exhaustion rather than evicting history, which is correct and also
means exhaustion is an outage, not a degradation. Because they fail closed, what
matters is whether expiry returns the capacity, and the bytes were only half of
that question: the store also bounds admission by a per-principal object count
and by the size of its principal table, neither of which `reserved()` reports.
Both are now measured to be reclaimed repeatedly -- 64 consecutive rounds each
fill and expire a principal's four object slots at a constant 262148 bytes held,
and a fresh population of 1024 principals is admitted after 1024 have expired.
Releasing the bytes while retaining either the slot or the table entry leaves a
store that reports nothing held and refuses every publish; both mutations are
caught by that measurement and by nothing else in the suite.

This is not a defect list. Each of these is a deliberate choice, and retaining
history is what makes old sessions verifiable. The gap is that no run has yet
measured what they cost over time.

The repository already has the right instruments for this and they are not wired
to P0: `scripts/node3_memory_monitor.sh` samples `/proc/<pid>/status` and records
`RssAnon`, `RssFile` and `VmSwap` separately, which matters because file-backed
growth from a memory-mapped database is not the same finding as heap growth;
`scripts/simplex2-soak.py`, `scripts/soak-mem-monitor.py` and
`scripts/transfer-soak.sh` already drive sustained load.

**The signer's binding limit is memory, not storage.** The safety ledger keeps a
stored request, plan, receipt and result in memory for every signature it has
ever admitted, because that is what lets it answer questions about signatures
from arbitrarily far back. Measured with an exact allocation counter, that is
3436 bytes per signature against 2883 bytes on disk, both exactly linear. At the
372,000 signatures the 1 GiB journal limit permits, the ledger holds 1220 MiB of
heap.

The asymmetry is the finding, not the ratio. The journal refuses admission when
it reaches its bound, which is an outage an operator can see coming and plan
for. The heap has no bound, refuses nothing, and ends in the process being
killed. A node sized against the documented 1 GiB storage limit is under-sized
for its own ledger, and nothing in the configuration says so.

This is not a defect in the retention policy -- the history is what makes
anti-equivocation work -- but it means either a memory bound or a session-scoped
index is required before a validator runs unattended for long periods. It is
recorded here rather than fixed, because choosing between those is a design
decision and not a test.

A soak closes this gate when it reports, over at least 24 hours of sustained
load: the `RssAnon` curve against registry archive size, per-block processing
time as the archive grows, and whether the measured per-signature retention
holds under real signer traffic rather than a fixture. The last of
these is the one that would not be caught by any shorter run, and the one whose
failure mode is a testnet that is fine for three days and a mainnet that is not
fine for three months.

The four version-16 activation gates are tracked separately and remain
independent thresholds: production hardware qualification, a configuration
switch rehearsal, owner approval of the loss model, and validator roster
acknowledgement. None of them may be satisfied by a simulated report.

## What would change these numbers

The library percentage will not move much; it is nearly saturated. The overall
figure moves when a call path reaches a boundary, and it will move in visible
steps once a session consumes an authenticated committee and once the two
contracts accept registry operations.

Expect the denominator to grow again at least once. Each time this work has
reached real execution, it has found integration the specification had folded
into a single phrase. That is the boundary table doing its job, not a regression.
