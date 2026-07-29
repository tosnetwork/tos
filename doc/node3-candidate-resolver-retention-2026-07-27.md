# Node3 Residual Memory Growth: CandidateResolver Retention (2026-07-27)

## Status

**Fixed in code and validated on node3 with a complete retention-window
turnover.**

**2026-07-29 follow-up:** this conclusion still holds on current `main`.
After the workchain-0 liveness fixes settled, `BufferAllocator` live bytes
were flat over the measured steady window, and the 00:26-00:47 UTC
`jeprof --base` diff contained no CandidateResolver retention stack. The only
net-positive allocation was 37.2 MB in ordinary RocksDB writes. No additional
CandidateResolver memory fix is required.

This report follows:

- [node3-residual-leak-archive-memtable-2026-07-26.md](node3-residual-leak-archive-memtable-2026-07-26.md)
- [node3-bufferallocator-residual-growth-2026-07-27.md](node3-bufferallocator-residual-growth-2026-07-27.md)
- [state-resolver-cache-leak-2026-07-26.md](state-resolver-cache-leak-2026-07-26.md)

The earlier differential heap profiles showed that most of the post-wallet-index
residual growth passed through `td::BufferAllocator::create_reader`, but an
allocation stack alone could not identify the object that continued to own the
buffers. Layered live-stock counters were therefore added and deployed to
node3.

The original retaining container was:

```text
validator/consensus/simplex/candidate-resolver.cpp
CandidateResolverImpl::state_
std::map<CandidateId, CandidateState>
```

Before the fix, `state_` grew with consensus history and had no eviction path.
It retained both historical notarization certificates and progressively loaded
candidates. The small `BufferSlice` signatures inside those objects pinned
16 KiB `BufferAllocator` slabs, producing a much larger physical allocation
than the logical signature payload.

The implemented fix keeps a configurable finalized-slot window, protects
in-flight coroutine references from erasure, persists remotely resolved
candidates and notarization certificates, and reloads evicted history through
current (non-snapshot) database point reads.

## Executive Summary

The live node3 measurements establish the following chain:

1. Two active `CandidateResolverImpl` actors held approximately 119,000
   `CandidateState` entries immediately after startup.
2. Their combined map grew by approximately 300 entries per minute.
3. The same actors retained approximately 450 additional notarization
   signatures and 300 additional candidate signatures per minute.
4. These signatures are small allocations, normally 64 bytes, served by
   `BufferAllocator::create_reader_fast()` from 16 KiB slabs.
5. Over a four-minute observation window, the number of live 16 KiB slabs grew
   by 2,479, or about 620 slabs per minute.
6. Live small-slab capacity grew by 38.8 MiB over the same window, or about
   9.7 MiB/min.
7. Total live `BufferRaw` memory grew by 46.8 MiB, or about 11.7 MiB/min.

QUIC, Plumtree, actor mailboxes, `BlockQ`, and the bounded StateResolver cache
did not contain a matching amount of live data. Their counters either returned
to zero, stayed small, or were independently bounded.

The final implementation and live validation establish that:

1. CandidateResolver state is bounded by finalized slots instead of chain age.
2. Old idle entries are removed, while entries referenced by a suspended
   coroutine or an incomplete database write remain protected.
3. Startup no longer materializes the all-history `candidateInfo` prefix.
4. Candidate and notarization-certificate lookups after eviction use
   `Db::get_latest()`, because `Db::get()` is intentionally a startup snapshot.
5. Notarization certificates now have an exact durable index keyed by
   `CandidateId`.
6. Candidates obtained from another validator are persisted before becoming
   eligible for eviction. This is required for observer nodes, which do not run
   `SimplexConsensus::try_notarize()` and therefore do not receive the normal
   `StoreCandidate` event.
7. With a deliberately aggressive 1,024-slot node3 window, both active
   resolvers completed more than one full window of evictions without their
   maps growing again.

The default is 4,096 retained finalized slots. It can be overridden for
low-memory or accelerated validation nodes with:

```bash
TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS=1024
```

## Diagnostic Instrumentation

All detailed diagnostics are enabled only when:

```bash
TOS_MEMORY_DIAGNOSTICS=1
```

The investigation added or extended the following measurements:

| Area | Live-stock measurements |
|---|---|
| BufferAllocator | Total live `BufferRaw` bytes and objects; live 16 KiB slab count and bytes |
| CandidateResolver | Map entries, unique candidates, candidate data, collated data, candidate signatures, notarization certificates, notarization signatures, proof bytes, and active waiters |
| StateResolver | Cache entries, in-flight entries, waiters, unique retained `BlockData`, and retained block bytes |
| BlockQ | Current and peak logical block-data bytes |
| QUIC | Inbound/outbound buffers, open streams, unsent bytes, unacknowledged bytes, pending responses, and connections |
| Plumtree | Retained payloads, parts, decoders, repair queries, peers, and feedback |
| Actor runtime | Per-actor mailbox high-water marks and drain-to-zero events |
| RocksDB | Per-database memtables, immutable memtables, table readers, block cache, and pinned cache bytes |

The periodic logs use `WARNING`, because node3 runs at verbosity level `-v2`;
`INFO` diagnostics would be suppressed.

## Live Evidence

### Initial BufferAllocator composition

At `2026-07-27 03:49:03 UTC`, node3 reported:

```text
live_bytes=169566728
live_raw_buffers=11178
live_small_slabs=10139
live_small_slab_bytes=166441824
```

In binary units:

- Total live `BufferRaw`: approximately 161.7 MiB
- Live 16 KiB slabs: approximately 158.7 MiB
- Small-slab share: approximately 98.2%

This ruled out large QUIC messages, block BOCs, or RocksDB buffers as the
principal contents of `BufferAllocator`'s retained memory. Almost all of it
was backing storage for small `BufferSlice` objects.

### CandidateResolver contents

At `03:49:28-03:49:40 UTC`, the two active resolvers reported:

| Resolver | State entries | Candidates | Notar certs | Notar signatures | Notar signature bytes |
|---|---:|---:|---:|---:|---:|
| Masterchain validator | 59,444 | 147 | 59,440 | 118,880 | 7,608,320 |
| Workchain observer | 59,803 | 243 | 59,803 | 59,803 | 3,827,392 |
| Combined | 119,247 | 390 | 119,243 | 178,683 | 11,435,712 |

The combined notarization signature payload was only about 10.9 MiB, while
the live small-slab capacity was about 158.7 MiB. This is not a contradiction:
a live slice keeps its complete backing slab alive, including space occupied
earlier by temporary slices that have already been released.

### Four-minute growth

The following measurements compare the same process at approximately
`03:49` and `03:53 UTC`:

| Measurement | Start | End | Four-minute delta | Approximate rate |
|---|---:|---:|---:|---:|
| CandidateResolver state entries | 119,247 | 120,447 | +1,200 | +300/min |
| Unique retained candidates | 390 | 1,590 | +1,200 | +300/min |
| Notarization signatures | 178,683 | 180,483 | +1,800 | +450/min |
| Live 16 KiB slabs | 10,139 | 12,618 | +2,479 | +620/min |
| Live small-slab bytes | 166,441,824 | 207,137,088 | +38.8 MiB | +9.7 MiB/min |
| Total live BufferRaw bytes | 169,566,728 | 218,648,552 | +46.8 MiB | +11.7 MiB/min |

Each new ordinary candidate contributes one candidate signature to each of
the two active resolver views, while notarization certificates contribute
additional validator signatures. The approximately 750 newly retained small
signature slices per minute closely track the approximately 620 newly pinned
slabs per minute.

The difference is expected: multiple live slices can share a slab, and the
allocation stream also contains other short-lived small buffers.

## Source-Level Retention Path

### 1. The map is unbounded

`CandidateResolverImpl` owns:

```cpp
std::map<CandidateId, CandidateState> state_;
```

There is no size limit, LRU, finalized-slot window, or periodic erasure.

### 2. Startup loads historical state

`load_from_db()` performs two history-proportional operations:

- It inserts every bootstrap notarization certificate into
  `state_[candidate_id].candidate_and_cert.notar_cert`.
- It scans all `candidateResolver_candidateInfo` keys and creates a map entry
  for each candidate metadata record.

This explains the large restart baseline before current consensus traffic is
processed. Even metadata-only entries consume `std::map` nodes, and historical
certificates additionally retain vectors and signature buffers.

### 3. Runtime adds candidates and certificates

The runtime paths add more persistent contents:

```text
StoreCandidate
  -> state_[candidate_id]
  -> candidate_and_cert.candidate = CandidateRef

NotarizationObserved
  -> state_[candidate_id]
  -> candidate_and_cert.notar_cert = NotarCertRef
```

The retained `CandidateRef` contains:

- block data;
- collated data;
- candidate signature;
- optional out-message proof buffers.

The retained `NotarCertRef` contains a vector of validator signatures.

### 4. Finalization does not release entries

`CandidateResolverImpl` does not handle `FinalizationObserved`. Unlike
`SimplexPool`, which drops candidate references older than
`first_nonfinalized_slot_`, CandidateResolver never removes completed
historical entries.

Consequently, successful finalization does not reduce the map or its retained
buffers.

## Why the 16 KiB Slab Amplifies the Leak

For requests smaller than 512 bytes, `BufferAllocator::create_reader_fast()`
allocates from a thread-local 16 KiB `BufferRaw` slab.

This design is efficient when small buffers have similar lifetimes. It becomes
memory-expensive when a few long-lived slices are interleaved with many
temporary slices:

```text
16 KiB slab
├── temporary TL object       released
├── temporary network field   released
├── 64-byte signature         still retained by CandidateResolver
├── temporary parser data     released
└── unused/dead space         cannot be reclaimed while signature is live
```

`BufferAllocator` correctly deletes the slab when its final reference is
released. The allocator itself is therefore not leaking. CandidateResolver's
historical signature references prevent that final release.

Calling `malloc_trim()` or a jemalloc purge cannot reclaim these slabs because
they are still reachable C++ objects, not freed allocator pages.

## Components Ruled Out as the Primary Retainer

### QUIC

At periodic sampling points:

```text
pending_responses=0
waiting_ready=0
open_sids=0
unsent_bytes=0
unacked_bytes=0
inbound_streams=0
inbound_stream_bytes=0
```

QUIC allocation traffic is high, but its tracked logical buffers drain.

### Plumtree

Plumtree retained payloads remained in the kilobyte-to-low-megabyte range and
were bounded by broadcast lifetime and repair limits. They did not track the
RSS or small-slab slope.

### Actor mailboxes

Several actors reached large temporary mailbox high-water marks during restart
catch-up. The new drain events confirmed that these queues subsequently
returned to zero. They were transient backlogs, not the persistent owner.

### StateResolver and BlockQ

The bounded StateResolver cache did grow to its configured entry limit, but
its exact retained block-data bytes were much smaller than total live
`BufferRaw` memory. The process-wide `BlockData` counter also ruled out raw
block BOCs as the dominant retained-buffer class.

### RocksDB

RocksDB memtables and block caches are separately visible through native
properties. Their normal growth remains part of total RSS, but it does not
explain `BufferAllocator`'s 16 KiB slab count.

## Comparison with TON

The corresponding implementation in:

```text
~/ton-c/validator/consensus/simplex/candidate-resolver.cpp
```

has the same retention design:

- the same unbounded `std::map<CandidateId, CandidateState> state_`;
- the same bulk loading of bootstrap certificates and candidate metadata;
- the same assignment of candidate and notarization certificate references;
- no finalized-window pruning or `state_.erase()` path.

Therefore, this is an upstream Simplex2 lifecycle defect also present in the
current local TON source, not a TOS-specific merge regression.

## Implemented Production Fix

The production implementation now:

1. Track the latest finalized slot.
2. Keep only a bounded active/recovery window around non-finalized consensus
   slots.
3. Evict entries older than that window only when:
   - `resolve_awaiters` is empty;
   - `store_awaiters` is empty;
   - no coroutine is using a reference to the map entry;
   - required candidate and certificate data are already durable.
4. Avoid loading the complete historical candidate/certificate set into live
   C++ objects during startup.
5. Resolve legitimate historical requests from persistent storage instead of
   relying on an all-history in-memory map.
6. Preserve a bounded recent cache to avoid turning normal near-tip requests
   into unnecessary database reads.

The coroutine condition is important. Existing resolver functions hold
`CandidateState&` across `co_await`; erasing an in-flight entry would create a
dangling reference. Each request now increments `active_operations` before its
first possible suspension and decrements it through a scope guard. Pruning
requires zero active operations, zero resolve/store waiters, no notarization
write in flight, and durable candidate/certificate contents.

The retention arithmetic and map-pruning loop live in:

```text
validator/consensus/simplex/candidate-retention.h
```

The runtime integration, exact certificate persistence, on-demand reads, and
remote-candidate persistence live in:

```text
validator/consensus/simplex/candidate-resolver.cpp
```

### Snapshot-read failure found by testing

The first implementation used `Db::get()` to recover an evicted candidate.
The 8-slot offline catch-up test failed because that method intentionally reads
the database snapshot captured when the consensus group starts. It cannot see
writes performed by the running process.

The recovery paths were changed to asynchronous `Db::get_latest()` point
reads. The same 8-slot catch-up scenario then passed, including three repeated
standalone runs.

### Remote-candidate durability failure found by live turnover

The first node3 deployment kept map sizes bounded until approximately one full
4,096-slot window had been evicted. At that boundary, observer evictions
stopped and its entry count began increasing again.

Diagnostics made the reason explicit:

```text
state_entries=4306
candidate_stored=0
evictions=4101
```

The observer had resolved candidate bodies from peers, but observers do not run
`SimplexConsensus::try_notarize()` and therefore never published the normal
`StoreCandidate` request. The safety predicate correctly refused to discard
memory-only candidate data.

The final fix persists a candidate immediately after a successful remote
resolution when it is not already durable. After redeployment,
`candidate_stored` reached the complete retained set and evictions continued
past a full window.

## Verification Results

The following release checks were completed:

1. A retention unit test finalizes beyond the configured window and verifies
   removal of old completed entries.
2. The same test verifies that active and non-durable entries survive pruning
   and are removed by a later pass when safe.
3. A separate deterministic interleaving test advances finalization across
   the eviction boundary, then steps through network-response, candidate
   persistence, certificate persistence, resolve-waiter, and store-waiter
   completion. It invokes the same extracted `CandidateEvictionState`
   predicate used by production and verifies that erasure becomes legal only
   after the final owner releases the entry.
4. Startup on node3 loaded only the retained recent window into
   CandidateResolver.
5. An 8-slot offline catch-up test exercised retrieval after in-memory
   eviction through `get_latest()`.
6. All 15 registered `test-consensus-simplex2-*` tests passed, including loss,
   restart, partition, malicious observer, relay loop, adaptive Byzantine,
   manager-ingress adversarial, deterministic CandidateResolver interleaving,
   query abuse, cache, and catch-up cases.
7. The 8-slot catch-up scenario additionally passed three consecutive
   standalone runs.
8. The final binary was deployed only to node3 with
   `TOS_MEMORY_DIAGNOSTICS=1`; node1 and node2 were not restarted.
9. Node3 was observed through a complete 1,024-slot turnover and confirmed:
   - CandidateResolver entry counts plateau;
   - notarization and candidate signature counts plateau;
   - live 16 KiB slab count plateaus or oscillates;
   - `BufferAllocator::live_bytes`, jemalloc `allocated`, and RSS no longer
     follow the previous linear slope;
   - consensus continues finalizing blocks without restart or catch-up
     regression.

### Final node3 measurements

The build used for the complete live turnover had SHA-256:

```text
6b64820cbaeab1b2681cb5e7f4c4f873fecdd0dafdbffed9682fc7cbd84a9b4b
```

After that validation, the persistence paths were hardened to retry a
transient candidate write on the next resolution and a transient certificate
write from the periodic alarm. The complete 14-test Simplex2 suite passed
again, and the resulting node3 binary has SHA-256:

```text
d037dc755779853e36f66ee0e872f24cb555e5cdf43a8d9cb993192c984d6983
```

Node3 used the stricter test override:

```text
TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS=1024
```

At `2026-07-27 05:07:06 UTC`, after crossing one complete window:

| Resolver | State entries | Durable candidates | Evictions |
|---|---:|---:|---:|
| Masterchain validator | 869 | 869 | 1,034 |
| Workchain observer | 1,024 | 1,024 | 1,084 |

At `05:09:07-05:09:38 UTC`:

| Measurement | Value |
|---|---:|
| Masterchain entries | 1,024 |
| Masterchain evictions | 1,329 |
| Observer entries | 1,024 |
| Observer evictions | 1,383 |
| Live `BufferRaw` bytes | 276,272,168 |
| Live 16 KiB slabs | 15,825 |
| RSS | approximately 1.84 GiB |
| systemd restarts | 0 |

The final two BufferAllocator samples were unchanged, and RSS changed by less
than 0.1% over the same interval. Journald contained no error-priority records
and no notarization-certificate persistence failures. Both the masterchain
validator group and workchain observer group continued producing
`FinalizeVote` certificates.

## Earlier Diagnostic-Build Validation

The instrumentation build used for this report passed:

- 25 actor runtime tests;
- all 13 registered `test-consensus-simplex2-*` tests;
- the previously executed 11 Plumtree simulation tests.

The instrumented binary was deployed only to node3. At the end of the
observation window:

- `tos-validator@3.service` was active;
- systemd reported `NRestarts=0`;
- journald had no error-priority entries for the run;
- node1 and node2 had not been changed.
