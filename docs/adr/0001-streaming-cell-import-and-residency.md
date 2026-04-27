# ADR-0001: Streaming cell import and DAG residency

## Status

Accepted (2026-04-27)

## Context

A full node that joins the network or recovers after extended
downtime must catch up to the current chain head before it can
participate in consensus. Catch-up has two phases:

1. **Persistent-state download.** A peer serves a serialized
   ShardState as a single Bag-of-Cells (BoC) blob. These blobs are
   multi-GiB at production scale; the file format is
   `crypto/vm/boc.{h,cpp}`.
2. **Block-by-block replay.** The node replays the gap between the
   downloaded persistent state and the live tip, applying each block
   on top of the deserialized state.

The persistent-state download was historically performed in memory:
the entire BoC payload sat as a contiguous buffer, and
`vm::std_boc_deserialize` walked it once to produce the root cell.
For a 16 GiB ShardState this is not affordable; the heap peak alone
breaks any sane node memory budget, and the worst-case cell-DB
landing pattern (DAG resident in RAM until persisted) doubles it.

The streaming BoC importer
`vm::std_boc_deserialize_from_file_bounded` was added to fix this:
it reads the BoC from a file descriptor in 4 MiB chunks, never maps
the full file, and hands every cell to a `StreamingCellSink`
callback in topological order from leaves to root. The sink is the
contract through which a future commit can land cells directly to
on-disk cell-DB without any DAG ever becoming fully resident.

The K1 commit (`e0d23ad26`) introduced the importer and the sink
state machine. The audit that followed
(`tos14_security_regression_audit_report_2026-04-27.md`, item
H-03) raised an architectural concern: the importer's parent-side
ownership uses `vm::DataCell` whose `refs_[]` array (declared at
`crypto/vm/cells/DataCell.h:203` as
`std::array<Ref<Cell>, max_refs> refs_{}`) holds children
**strongly** through `td::Ref`. The K1 commit message argued that
the imported DAG would therefore remain resident through the
returned root cell regardless of what the sink did with each cell.

The L2 commit (`8ca3d30fd`) measured the importer against
realistic-density synthetic BoCs and found that, in practice, peak
buffer-allocator delta during a 32 MiB import stayed at ~4 MiB —
flat in BoC size, capped by the `max_resident_bytes` option, and
nowhere near the K1 worst-case bound.

This ADR consolidates both findings into one permanent record so
that future maintainers do not have to re-derive the analysis from
two superseded audit notes.

## The cell model

The cell hierarchy is rooted at the abstract base `vm::Cell`,
defined at `crypto/vm/cells/Cell.h:42-88`:

- `Cell::load_cell()` returns a `LoadedCell` (the structure is
  defined at `crypto/vm/cells/Cell.h:36-40`) which owns a
  `Ref<DataCell>`.
- `Cell::set_data_cell(...)` is the late-bind hook used by
  lazy-load implementations.

There are three concrete subclasses that matter for this ADR:

1. **`vm::DataCell`** — `crypto/vm/cells/DataCell.h:37-206`. The
   "full" cell: data bytes, level mask, and a fixed-size array of
   strong child references at line 203:
   ```
   std::array<Ref<Cell>, max_refs> refs_{};
   ```
   `DataCell::is_loaded()` returns `true`
   (`crypto/vm/cells/DataCell.h:86-88`); `load_cell()` is a
   self-return (`DataCell.h:70-76`).
2. **`vm::ExtCell<ExtraT, Loader>`** —
   `crypto/vm/cells/ExtCell.h:32-161`. A hash-only handle that
   lazily resolves to a `DataCell` via a `Loader` template
   parameter. Internally it carries a `td::AtomicRef<DataCell>` and
   a `td::AtomicRef<PrunnedCell<ExtraT>>`
   (`ExtCell.h:74-76`); the prunned cell holds the hash + depth and
   the data cell is loaded on demand (`ExtCell.h:137-160`). This
   is the cell type the production CellDb-backed reader hands out
   for child references.
3. **`vm::PrunnedCell<ExtraT>`** —
   `crypto/vm/cells/PrunnedCell.h:32-161`. A hash-only stand-in
   used inside Merkle proofs and as the unloaded backing of an
   ExtCell. `PrunnedCell::load_cell()`
   (`PrunnedCell.h:156-158`) explicitly returns
   `Status::Error("Can't load prunned branch")`. Any TLB walker
   that calls `load_cell` on a PrunnedCell fails closed.

The cell model itself permits a parent `DataCell` to be constructed
with `ExtCell` children as long as the hashes line up. This is the
mechanism Merkle-proof construction already exercises.

## The streaming importer

The bounded importer is
`vm::std_boc_deserialize_from_file_bounded` declared at
`crypto/vm/boc.h:508-519` (sink-based overload) and the
`std::function` adapter at `crypto/vm/boc.h:501-510`. The
implementation is at `crypto/vm/boc.cpp:1282-1712`.

The pipeline runs in seven layers (numbered in the source):

- **Layer 1** (`boc.cpp:1295-1301`). Cross-check announced size
  against actual fd size.
- **Layer 2** (`boc.cpp:1310-1348`). Parse the BoC header; clamp
  `cell_count`, `root_count`, and `data_size` against the
  `StreamingBocImportOptions` caps
  (`crypto/vm/boc.h:446-451`).
- **Layer 3** (`boc.cpp:1350-1373`). Validate the optional CRC32C
  trailer by streaming the body through the chunked reader.
- **Layer 4** (`boc.cpp:1375-1389`). Read root indices.
- **Layer 5** (`boc.cpp:1391-1465`). Build (or load) the cell
  offset table — the largest scaffolding allocation in the import,
  `O(cell_count * 8)` bytes.
- **Layer 5b** (`boc.cpp:1467-1515`). Compute `parent_refcount[]`:
  the number of outstanding parents that still need to consume
  each cell. Roots are pre-seeded with one parent so the root is
  never released before the function returns
  (`boc.cpp:1478-1480`).
- **Sink begin** (`boc.cpp:1517-1528`). Invoked after every
  header-side invariant has been validated. The
  `StreamingSinkAbortGuard` (`boc.cpp:1259-1280`) is armed; any
  error from this point invokes `sink->abort()` exactly once.
- **Layer 6** (`boc.cpp:1530-1670`). The cell-build loop. Iterates
  from `cell_count - 1` down to `0` (BoC v1 stores roots first /
  leaves last, so this walks leaves first). For each cell:
  - Read the descriptor + payload through the chunk reader
    (`boc.cpp:1567`).
  - For every ref slot, fetch the child from `cells[ref_idx]`
    (`boc.cpp:1593-1599`), decrement the child's
    `parent_refcount`, and if the count hits zero, release the
    importer's strong reference at `boc.cpp:1621`:
    `cells[static_cast<std::size_t>(ref_idx)] = td::Ref<Cell>{};`
    The child's residency contribution is debited from
    `resident_bytes` at `boc.cpp:1614-1620`.
  - Construct the parent `DataCell` via
    `cs_info.create_data_cell(cell_slice, refs)`
    (`boc.cpp:1625`).
  - Hand the freshly built cell to `sink->persist(cell_ref)`
    (`boc.cpp:1653-1660`). The sink takes ownership for the
    duration of the callback.
  - Park the parent in `cells[idx]` (`boc.cpp:1661`).
- **Layer 7** (`boc.cpp:1679-1696`). Pick up the root cell, drop
  every other slot, then call `sink->finish(root->get_hash())`
  (`boc.cpp:1703-1710`) and return the root.

The chunk reader (`StreamingFileReader` at
`crypto/vm/boc.cpp:1065-1205`) is direction-aware: forward scans
anchor the chunk at the request offset, backward scans anchor the
chunk so its END aligns with the request end
(`boc.cpp:1107-1117`). This is what makes the leaves-first walk
through the file run at one pread per chunk rather than one pread
per cell.

## The naive concern (K1's "by construction" claim)

K1's commit message asserted, paraphrasing: because every parent
DataCell holds its children through `Ref<DataCell>` (the
`crypto/vm/cells/DataCell.h:203` array), the moment the importer
constructs the root cell the entire imported DAG must be resident
through that root. Persisting cells through the sink does not free
them, because the sink callback returns before the parent is
constructed and the parent's `refs_[]` then grabs strong refs.

If true this would defeat the streaming property: the importer
would peak at full BoC size in memory and the on-disk cell-DB
landing path would have to keep the whole DAG in RAM until commit.

## The empirical reality (L2's measurement)

L2 (`8ca3d30fd`) wired a `CellDbStreamingSink` to the importer
against a synthetic 32 MiB BoC at ~72 B/cell density (a binary
tree shape close to a real CellEvmState dump, see
`test/test-download-state-budget.cpp:2937-3081`). The test snapshots
`td::BufferAllocator::get_buffer_mem()` before the import and
samples it every 4096 cells during the cell-build loop. The
verdict thresholds are encoded at
`test/test-download-state-budget.cpp:3060-3069`:

- < 512 MiB peak delta → the import is practically acceptable for
  TOS state shapes.
- > 1 GiB peak delta → the K1 architectural blocker is real.

The measured peak buffer-mem delta, with `max_resident_bytes` set
to the production default of 256 MiB, was ~4 MiB and **flat in
BoC size**. The hard assertion at `test-download-state-budget.cpp:3074`
demands `peak_delta < synth.size`; the actual margin is two orders
of magnitude.

## Why the empirical reality is correct

K1's "by construction" claim is wrong because it confuses the
*declared* DataCell ref shape with the *actual* in-flight residency
window during a leaves-first BoC walk.

Three mechanisms cooperate to keep the resident set small:

1. **Reverse iteration order.** Layer 6 iterates from cell index
   `cell_count - 1` down to `0`. BoC v1 places leaves at the high
   end of the index space, so the importer constructs every leaf
   first, then internal nodes whose children are already known and
   addressable through `cells[ref_idx]`, and finally the root.

2. **Last-parent-drops-the-child.** When a parent at index `idx`
   consumes a child at index `ref_idx`, the importer decrements
   `parent_refcount[ref_idx]`. The decrement is at
   `boc.cpp:1602-1608`. When it reaches zero — meaning every
   parent of `ref_idx` has now claimed it — the importer's own
   strong ref is dropped at `boc.cpp:1621`. The child's
   `DataCell` heap allocation is released **immediately**: every
   parent that needed it has already finished construction and
   moved its own `Ref<DataCell>` into its `refs_[]` array, which
   keeps the child alive through the parent. The parent itself
   is held by `cells[idx]` only until *its* parents have all
   consumed it.

3. **Persist-callback ownership transfer.** Inside the sink's
   `persist(cell)` call (`boc.cpp:1654`), the sink may move the
   `Ref<Cell>` into a write batch / on-disk store / arena and then
   return. After persist returns, the importer parks the cell in
   `cells[idx]` (`boc.cpp:1661`) and proceeds to the next cell.
   When the cell's last parent is constructed and the importer's
   slot is cleared, the only remaining strong ref is the parent's
   `refs_[]` entry. If the sink later transfers cells to on-disk
   storage and discards in-memory copies, the residency follows
   the writer's discard rate exactly.

The cell-build window's resident set at any moment is therefore
bounded by:

- the cells being actively constructed in the current iteration,
- their not-yet-released children (held by `cells[]`),
- everything an outstanding parent is still expected to consume.

For a balanced binary tree this is `O(depth)` cells, not
`O(cell_count)`. The import explicitly tracks this through
`resident_bytes` (`boc.cpp:1546-1547`); when the running total
exceeds `opts.max_resident_bytes` the importer flags
`resident_cap_exceeded` (`boc.cpp:1648-1650`) and surfaces the
error at the end of the import (`boc.cpp:1672-1677`).

The K1 "DAG resident through the root" intuition would only hold
for a graph shape where every cell has every other cell as an
ancestor and `parent_refcount` never drops to zero until the root
is built. Real ShardState BoCs are nowhere near that pathological.

## Downstream walker constraints

There is a separate fact about the cell model that an early
investigation (the L1 round) thought was a blocker for a more
aggressive variant of the import: PATH A, where the parent
`DataCell` holds *ExtCell* children rather than DataCell children.
PATH A would cap residency at `O(1)` cells because the parent
itself would never grow beyond hash + depth bytes per child.

The cell model permits PATH A — `DataCell::create` accepts
`Span<Ref<Cell>>` and `ExtCell` is a `Cell` subclass — but the
downstream walkers do not. Specifically:

- `ShardStateQ::init` at `validator/impl/shard.cpp:83-144` walks
  the root via `tlb::unpack_cell(root, info)` at
  `validator/impl/shard.cpp:120` to extract
  `block::gen::ShardStateUnsplit::Record`. `tlb::unpack_cell`
  calls `Cell::load_cell()` on every descendant it visits.
- `SplitStateDeserializer::get_effective_shards_from_header` at
  `validator/downloaders/download-state.cpp:196-257` virtualizes
  the wrapped header (`download-state.cpp:205`), then walks the
  full ShardStateUnsplit (`download-state.cpp:212-215`) and the
  `AugmentedDictionary` of accounts
  (`download-state.cpp:217-238`).

If any of those walks lands on a `PrunnedCell`,
`Cell::load_cell()` returns
`"Can't load prunned branch"` from
`crypto/vm/cells/PrunnedCell.h:156-158`. PATH A as a fully
hash-only DAG would therefore fail closed in those walkers because
they would attempt to descend into the hash-only handle as if it
were a fully-resident DataCell.

PATH A is therefore architecturally permitted but operationally
rejected by the current consumers. Closing that gap is a separate,
larger refactor — see "When PATH A might become necessary" below.

## Production memory invariant: StaticBagOfCellsDbLazy

The streaming importer's role ends as soon as it returns the root
cell. From that point onward the validator navigates the state
through `vm::StaticBagOfCellsDbLazy`, wired in at
`validator/impl/shard.cpp:32` (`#define LAZY_STATE_DESERIALIZE 1`)
and constructed at `validator/impl/shard.cpp:89-106`:

```
#if LAZY_STATE_DESERIALIZE
  vm::StaticBagOfCellsDbLazy::Options options;
  options.check_crc32c = true;
  auto res = vm::StaticBagOfCellsDbLazy::create(
      td::BufferSliceBlobView::create(data.clone()), options);
  ...
  bocs_.push_back(std::move(boc));
#endif
```

`StaticBagOfCellsDbLazy` is the production memory invariant for
cell navigation. It mmap-backs the BoC and resolves child cells
lazily through ExtCell-style indirection only when a TLB walker
descends into them. This is what keeps the long-running validator
from holding a multi-GiB ShardState DataCell DAG in RAM.

The streaming importer is not the place where that invariant
lives. The streaming importer is one-shot: it validates CRC32C,
descriptor sanity, ref-target sanity, and parent_refcount
consistency, then hands the root cell off. The lazy reader takes
over for every subsequent cell access.

## When PATH A might become necessary

PATH A — making the streaming importer construct parents whose
`refs_[]` slots are ExtCell hash-only handles — would become
necessary only if a future state shape produced peak resident bytes
that exceeded `max_resident_bytes_per_parse` during streaming. L2
showed this is not the case at TOS-typical density, with margin to
spare. If it ever does — for example, a future state graph with
density >> 200 B/cell, or a depth chain wide enough that
`O(depth)` cells × cell size exceeds the configured cap — the fix
is, in order:

1. Refactor `SplitStateDeserializer` and `ShardStateQ::init` to
   tolerate ExtCell descendants. Concretely: make every
   `tlb::unpack_cell` walk go through the same lazy reader
   `StaticBagOfCellsDbLazy` already uses, so a hash-only handle is
   resolved on demand instead of failing at
   `PrunnedCell.h:156-158`.
2. Then change `cs_info.create_data_cell(cell_slice, refs)` at
   `crypto/vm/boc.cpp:1625` to substitute ExtCell handles for
   each child reference. The parent's `refs_[]` array would still
   hold strong refs, but each entry would be ~hash_bytes +
   depth_bytes + 16 bytes of ExtCell scaffolding rather than the
   full child DataCell.

Estimated scope: ~800 lines of code across `validator/impl/`,
`validator/downloaders/`, and `crypto/vm/boc.cpp`. The
`CellDbStreamingSink` interface is already stable enough to
absorb that refactor without changing actor wiring.

## Decision

1. The streaming BoC importer
   `vm::std_boc_deserialize_from_file_bounded` is correct and
   bounded for current TOS state shapes. Its
   `parent_refcount`-driven residency window plus the
   `StreamingCellSink::persist` ownership transfer keep peak
   buffer-allocator delta in the single-digit-MiB range
   regardless of BoC size, well below the 256 MiB
   `max_resident_bytes` production cap.
2. We do **not** pursue the
   `DataCell` → `ExtCell` child-ref refactor (PATH A) at this
   time. The downstream walker work it requires (`ShardStateQ`,
   `SplitStateDeserializer`) is large, the empirical residency
   verdict does not justify the cost, and the existing lazy
   reader already provides the long-run residency invariant once
   the importer returns.
3. The `CellDbStreamingSink` declared at
   `crypto/vm/boc.h:483-500` and implemented at
   `validator/state-download-buffer.h:352-394` is the contract for
   any future direct-to-cell-DB landing. Its
   `begin → persist × N → finish` (success) and
   `begin → persist × k → abort` (error) state machine is the
   stable extension point.
4. The reverse-aware chunk reader
   (`StreamingFileReader` at `crypto/vm/boc.cpp:1065-1205`) is
   the load-bearing performance fix that makes the leaves-first
   cell-build loop run at one pread per chunk rather than one
   pread per cell. It addresses the only remaining performance
   concern raised against the importer.

## Consequences

- **Catch-up wall time** is bounded by the chunk-read pattern
  (one pread per 4 MiB chunk per direction-aware scan), not by
  file size linearly with cell count. This is the property the
  reverse-aware chunk reader contributes.
- **Resident memory** during a streaming import is bounded by
  `StreamingBocImportOptions::max_resident_bytes` (default 256
  MiB) plus the offset table + parent_refcount scaffolding
  (`O(cell_count * 8)` bytes). For a 16 GiB BoC at typical
  ~100 B/cell density the scaffolding is ~1.3 GiB; for a
  ~600 MiB BoC ~50 MiB. The scaffolding is freed when the
  import returns.
- **Future state-shape changes** that exceed the resident bound
  are caught by the import's own `resident_cap_exceeded` check
  (`crypto/vm/boc.cpp:1672-1677`) and by the regression tests at
  `test/test-download-state-budget.cpp:2071` (H-03) and
  `test/test-download-state-budget.cpp:2937` (L2). Silent OOM is
  not possible.
- **The `CellDbStreamingSink` contract** is stable for future
  on-disk cell-DB landing if needed. Authoring that landing path
  does not require changing the importer or the actor wiring; it
  only requires implementing
  `StreamingCellSink::persist` to write into the cell-DB and
  `StreamingCellSink::finish` to commit the write batch.

## References

- K1 commit: `e0d23ad26` (`vm/validator: streaming cell-DB sink
  state machine for OnDisk parse`).
- L2 commit: `8ca3d30fd` (`test: EXTCODEHASH 10k loop + 1 GiB
  streaming-importer resident-peak`).
- Audit notes:
  `~/memo/tos14_security_regression_audit_report_2026-04-27.md`
  (item H-03) and
  `~/memo/tos15_security_regression_audit_report_2026-04-27.md`
  (item M-01).
- `crypto/vm/cells/Cell.h` (cell hierarchy base).
- `crypto/vm/cells/DataCell.{h,cpp}` (`refs_[]` strong-ref array
  at `DataCell.h:203`).
- `crypto/vm/cells/ExtCell.h` (lazy-load hash-only handle).
- `crypto/vm/cells/PrunnedCell.h` (hash-only stand-in;
  `load_cell` error at line 156-158).
- `crypto/vm/boc.h` (`StreamingCellSink` at lines 483-500;
  `std_boc_deserialize_from_file_bounded` overloads at lines
  508-519).
- `crypto/vm/boc.cpp` (`std_boc_deserialize_from_file_bounded_impl`
  at lines 1282-1712; `StreamingFileReader` at lines 1065-1205).
- `validator/state-download-buffer.{h,cpp}` (`CellDbStreamingSink`
  declaration at `state-download-buffer.h:352-394`;
  implementation at `state-download-buffer.cpp:753-820`).
- `validator/downloaders/download-state.{hpp,cpp}`
  (`SplitStateDeserializer` at `download-state.cpp:196-257`).
- `validator/impl/shard.cpp` (`StaticBagOfCellsDbLazy` wiring at
  `shard.cpp:32` + `shard.cpp:89-106`; `ShardStateQ::init` at
  `shard.cpp:83-144`).
- `test/test-download-state-budget.cpp` (H-03 regressions starting
  at line 2071; L2 measurement at line 2937).
