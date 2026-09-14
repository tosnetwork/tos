# P0 progress

Companion to [the implementation record](validator-auth-p0-implementation.md),
which states what each boundary implements and what it still owes. This file
reports how far the whole of P0 has moved and what remains, so a reader does not
have to reconstruct completion from the per-boundary table.

Branch `feat/validator-auth-p0`, PR #111, draft. The design remains v1 revision 3,
fingerprint `9b118505ab9a3f68118dc50b51f2742b3d29ca81c6be215cf54b28f4de83b568`.
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
| Node integration | Partial, five call paths | Every boundary still lists remaining integration |
| Operational acceptance | None | No rehearsal has enabled P0 on a chain |
| **P0 overall** | **roughly 55-60%** | Weighted estimate, not a measured figure |

The overall figure is an estimate and should be read as such. It has barely moved
over the last several working sessions, not because progress stalled but because
touching real execution keeps making previously invisible integration work
visible: the boundary table has grown from 14 rows to 28 while the library
column was being filled in.

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

Five production call paths now reach P0 behaviour:

| Path | Where | What it establishes |
| --- | --- | --- |
| Key isolation | `keyring/` links the signer library | Protected validator keys refuse raw signing, decryption and export |
| VM capability gate | `validate-query.cpp` passes global capabilities | C0 verification in the VM is gated by configuration, not by the contract |
| Election binding | `crypto/block/mc-config.cpp` | Identity and stake id survive committee selection into the node's validator set |
| Genesis writing | `crypto/fift/lib/Config.fif`, the genesis tool | A genesis can carry an authenticated registry and authenticated descriptors |
| Committee derivation | the genesis rehearsal | The native path derives a committee from a genesis the real writers produced |

Everything else remains open. The named remaining work, grouped:

| Group | Remaining |
| --- | --- |
| Session and consensus | Native session derivation and consensus call sites; the derived committee has no consumer in `validator/manager.cpp` |
| Contracts | Elector emission and session admission; configuration authorization and atomic root installation. `elector-code.fc` and `config-code.fc` contain no P0 entry point |
| Chain apply | Native block apply, contract data installation, action-phase commit wiring, installed chain root |
| Remaining language parity | Rust global registry apply and the Rust storage adapter |
| Serving | Authenticated public RPC wiring, node context and history adapters, remote HTTP/2 with mutual TLS. Only a local Unix socket exists |
| Provisioning | Provider inventory reconciliation, independent operational trust distribution, the node permit adapter |

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

Four retained quantities have no measured growth curve:

| Quantity | Why it grows | What is stated today |
| --- | --- | --- |
| Registry key history | Retired and cancelled key versions must stay independently retainable, so the archive only grows | "Historical keys and retired identities must remain independently retainable" (implementation record) |
| Per-block work against archive size | The native adapter copies and rebuilds derived indexes | "this adapter does not claim constant work independent of archive size" (implementation record) |
| Signer journal and witness | Append-only by design; capacity exhaustion is an explicit error, not a reclaim | No retention policy is specified |
| Retained session snapshots | Each session holds its committee until its native termination boundary | That boundary is not implemented yet |

The object store is the one bounded case: four objects and 64 MiB per principal,
256 MiB globally, and the local provider admits at most 4096 retained keys. Both
fail closed on exhaustion rather than evicting history, which is correct and also
means exhaustion is an outage, not a degradation.

This is not a defect list. Each of these is a deliberate choice, and retaining
history is what makes old sessions verifiable. The gap is that no run has yet
measured what they cost over time.

The repository already has the right instruments for this and they are not wired
to P0: `scripts/node3_memory_monitor.sh` samples `/proc/<pid>/status` and records
`RssAnon`, `RssFile` and `VmSwap` separately, which matters because file-backed
growth from a memory-mapped database is not the same finding as heap growth;
`scripts/simplex2-soak.py`, `scripts/soak-mem-monitor.py` and
`scripts/transfer-soak.sh` already drive sustained load.

A soak closes this gate when it reports, over at least 24 hours of sustained
load: the `RssAnon` curve against registry archive size, signer journal and
witness size against signature count, whether object-store expiry actually
returns storage, and per-block processing time as the archive grows. The last of
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
