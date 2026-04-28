/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

/*
 * True CellDb-backed streaming import.
 *
 * OnDisk persistent-state catch-up can route through
 * ValidatorManager::import_persistent_state_streaming when
 * enable_true_cell_db_streaming_import is set. The production path parses the
 * BoC off the CellDbIn actor, spools verified cells, drains them through
 * CellDbIn actor-serialized bounded batches, and returns a hash-only
 * ExtCell-backed root. A GC/rollback lease is held until set_block_state adopts
 * the root; dropping the lease before adoption conditionally erases newly
 * imported refcnt=1 cells.
 *
 * max_returned_dag_bytes_per_parse remains the fail-closed ceiling for
 * operators that keep true streaming disabled. With true streaming enabled,
 * max_total_cell_bytes_per_parse, max_cells_per_parse, max_resident_bytes, and
 * max_scaffolding_bytes_per_parse bound the importer instead.
 *
 * Known streaming limitations (NOT load-bearing for safety):
 *   - The BoC importer still allocates O(cell_count) scaffolding
 *     (offset_table, parent_refcount, cells vector) bounded by
 *     max_scaffolding_bytes_per_parse / max_total_cell_bytes_per_parse.
 *     This is much smaller than the previous returned-DAG residency
 *     but is not yet O(1). Future work could introduce a two-pass
 *     streaming parse (header -> reverse-order cell parse) to reduce
 *     scaffolding to O(parse window). Operators monitoring large-
 *     state catch-up should size scaffolding caps proportionally to
 *     the largest expected persistent-state cell count.
 */

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/int_types.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"

// tos26 P0-2: pulled in for CellDbReaderProvider + the
// `make_static_cell_db_reader_provider` factory used by the legacy
// (raw-reader) template constructor below. CellDbExtCell.h's transitive
// includes (DynamicBagOfCellsDb.h, ExtCell.h, etc.) do NOT depend on
// TDDB_USE_ROCKSDB, so the lightweight `validator-state-download-budget`
// static library this header's .cpp links into can still build cleanly.
#include "vm/db/CellDbExtCell.h"

namespace vm {
// Forward-declared because the streaming sink only stores a
// shared_ptr<CellDbReader>; the full definition arrives transitively
// through CellDbExtCell.h above for the legacy-overload body.
class CellDbReader;
}  // namespace vm

namespace tos {
namespace validator {

// Forward-declared so the streaming sink can hold a unique_ptr without
// pulling validator/db/celldb.hpp (which transitively drags in the actor +
// RocksDB headers) into every TU that includes state-download-buffer.h.
class CellDbStreamingWriter;

namespace fullnode {

// Forward declaration of the platform-specific mmap holder. Owns the file
// descriptor, the page-aligned mapped pointer, and the data offset within
// the mapping. Defined in state-download-buffer.cpp.
class MmapHandle;

// RAII reservation against the global persistent-state download memory
// budget. The reservation is held by a shared_ptr alongside the downloaded
// buffer; the underlying bytes are returned to the global budget only when
// the last reference is dropped (i.e., when downstream consumers have
// finished processing the buffer).
//
// Declared here in a public header (independent of the DownloadState actor
// implementation) so that both the network-side producer and every
// manager/full-node interface boundary can carry the reservation through
// without breaking the reservation lifetime invariant.
struct PersistentStateDownloadReservation {
  td::uint64 bytes{0};

  PersistentStateDownloadReservation() = default;
  explicit PersistentStateDownloadReservation(td::uint64 b) : bytes(b) {
  }
  PersistentStateDownloadReservation(const PersistentStateDownloadReservation &) = delete;
  PersistentStateDownloadReservation &operator=(const PersistentStateDownloadReservation &) = delete;
  PersistentStateDownloadReservation(PersistentStateDownloadReservation &&) = delete;
  PersistentStateDownloadReservation &operator=(PersistentStateDownloadReservation &&) = delete;
  ~PersistentStateDownloadReservation();
};

// Pairs a downloaded persistent-state buffer with its budget reservation.
// As long as a BudgetedBufferSlice (or any copy of `reservation`) is held,
// the corresponding bytes remain accounted against the global budget. The
// reservation is released exactly once when the last shared_ptr ref is
// dropped.
struct BudgetedBufferSlice {
  td::BufferSlice data;
  std::shared_ptr<PersistentStateDownloadReservation> reservation;
};

// On-disk variant of a downloaded persistent state. The downloader writes
// chunked rldp slices via pwrite into a tempfile and renames it to a
// content-addressed final path on success. The reservation accounts the
// full file size against the download budget for as long as any consumer
// keeps a reference to this struct alive (i.e., until the final state is
// parsed and persisted to celldb).
//
// `path` is the path the consumer should read for parsing. If `is_temp`
// is true, the destructor unlinks the file on drop (used for the partial
// tempfile during transit and on the abort path); the producer flips
// `is_temp` to false once a successful rename to the final path has been
// performed and ownership is transferred to the consumer.
struct BudgetedStateFile {
  std::string path;
  td::uint64 size{0};
  std::shared_ptr<PersistentStateDownloadReservation> reservation;
  // If true, the file at `path` is owned by the consumer and should be
  // unlinked when the BudgetedStateFile is dropped (e.g. an abort path or
  // after parsing finishes consuming the file). Default true so an
  // accidentally-leaked struct does not leave residue on disk; producers
  // explicitly set false when they want the file to outlive this handle.
  bool is_temp{true};

  // The default ctor and the (path,size,reservation,temp) ctor are
  // implementable inline because the unique_ptr<MmapHandle> default-
  // constructs to nullptr — no destruction of an incomplete type. The
  // copy/move/destructor that need to interact with the unique_ptr's
  // destructor (which instantiates default_delete<MmapHandle>) are
  // declared inline only and DEFINED out-of-line in the .cpp where the
  // MmapHandle class is complete.
  BudgetedStateFile() noexcept;
  BudgetedStateFile(std::string p, td::uint64 s,
                    std::shared_ptr<PersistentStateDownloadReservation> r,
                    bool temp = true) noexcept;
  BudgetedStateFile(const BudgetedStateFile &) = delete;
  BudgetedStateFile &operator=(const BudgetedStateFile &) = delete;
  BudgetedStateFile(BudgetedStateFile &&other) noexcept;
  BudgetedStateFile &operator=(BudgetedStateFile &&other) noexcept;
  ~BudgetedStateFile();

  // mmap the on-disk file as PROT_READ / MAP_PRIVATE and return a
  // non-owning td::Slice that points into kernel-mapped memory. The
  // returned slice is valid only while *this BudgetedStateFile is alive
  // (the mmap handle is owned by *this). NEVER allocates a heap buffer of
  // size == file size: this is the load-bearing zero-copy entry point
  // that lets the OnDisk parse path avoid the read_full_file heap peak.
  //
  // Calling this twice on the same instance returns the same mapping; the
  // mapping is created lazily on the first call and reused on subsequent
  // calls (so callers can pass the slice to multiple downstream functions
  // without re-mapping). The mapping is dropped together with the temp
  // file when reset() runs.
  td::Result<td::Slice> mmap_view() noexcept;

 private:
  void reset() noexcept;

  // Lazily-created mmap holder. unique_ptr keeps this header free of
  // platform-specific includes and lets the destructor unmap (and close
  // the fd) exactly once when the BudgetedStateFile is dropped.
  std::unique_ptr<MmapHandle> mmap_;
};

// Buffer-or-file variant produced by DownloadState. Small states (<=
// kHeapThreshold) take the InMemory branch and ride the existing heap
// path; large states take the OnDisk branch where the downloader streams
// chunks into a tempfile via pwrite without any single full-state heap
// allocation.
class DownloadedPersistentState {
 public:
  enum class Kind { InMemory, OnDisk };

  DownloadedPersistentState() = default;

  static DownloadedPersistentState memory(BudgetedBufferSlice mem) {
    DownloadedPersistentState r;
    r.kind_ = Kind::InMemory;
    r.memory_ = std::move(mem);
    return r;
  }

  static DownloadedPersistentState file(BudgetedStateFile f) {
    DownloadedPersistentState r;
    r.kind_ = Kind::OnDisk;
    r.file_ = std::move(f);
    return r;
  }

  Kind kind() const {
    return kind_;
  }
  bool is_memory() const {
    return kind_ == Kind::InMemory;
  }
  bool is_file() const {
    return kind_ == Kind::OnDisk;
  }

  BudgetedBufferSlice &memory() {
    return memory_;
  }
  const BudgetedBufferSlice &memory() const {
    return memory_;
  }
  BudgetedStateFile &file() {
    return file_;
  }
  const BudgetedStateFile &file() const {
    return file_;
  }

  td::uint64 size() const {
    if (kind_ == Kind::InMemory) {
      return memory_.data.size();
    }
    return file_.size;
  }

 private:
  Kind kind_{Kind::InMemory};
  BudgetedBufferSlice memory_;
  BudgetedStateFile file_;
};

// RAII reservation against the global persistent-state PROCESSING memory
// budget. This budget is separate from the download budget: it accounts the
// transient extra memory required while parsing/persisting a downloaded
// state buffer (e.g. the BufferSlice clone fed to `create_shard_state`).
//
// The two budgets must be tracked separately because the download budget
// covers the resident original buffer while it is held alive across the
// network -> manager -> disk-write pipeline; the processing budget covers
// the additional clone(s) that exist only during deserialize/validate.
// Mixing them would either over-restrict downloads (counting transient
// peaks against the download cap) or under-account the actual peak
// resident bytes.
struct PersistentStateProcessingReservation {
  td::uint64 bytes{0};

  PersistentStateProcessingReservation() = default;
  explicit PersistentStateProcessingReservation(td::uint64 b) : bytes(b) {
  }
  PersistentStateProcessingReservation(const PersistentStateProcessingReservation &) = delete;
  PersistentStateProcessingReservation &operator=(const PersistentStateProcessingReservation &) = delete;
  PersistentStateProcessingReservation(PersistentStateProcessingReservation &&) = delete;
  PersistentStateProcessingReservation &operator=(PersistentStateProcessingReservation &&) = delete;
  ~PersistentStateProcessingReservation();
};

// Configurable persistent-state budget. The defaults are fail-closed and
// internally consistent: an operator can override any field via the
// validator-engine CLI flags or via a direct call to
// configure_persistent_state_budgets at startup. The reservation hot path
// reads the live config under a single atomic snapshot so a misconfiguration
// cannot leave half-applied state.
//
// Post-Phase-B contract:
//   OnDisk catch-up: file size bounded by max_single_file_bytes;
//   RSS bounded by max_resident_bytes_per_parse during streaming
//   BoC parse + per-cell CellDb writes; the returned ExtCell root
//   is O(1) memory.
//   InMemory catch-up: still returns a full DataCell DAG; bounded
//   by max_returned_dag_bytes_per_parse.
struct PersistentStateBudgetConfig {
  td::uint64 max_download_bytes = 16ULL << 30;
  td::uint64 max_processing_bytes = 16ULL << 30;
  // True-streaming default: the OnDisk catch-up path can stream cells
  // directly into CellDb (returning a hash-only ExtCell root), so a
  // single state file no longer needs to fit inside the returned-DAG
  // ceiling. Default raised to 16 GiB so an unmodified validator-engine
  // binary can bootstrap from large persistent states without operator
  // overrides.
  td::uint64 max_single_file_bytes = 16ULL << 30;
  td::uint64 max_resident_bytes_per_parse = 256ULL << 20;
  // InMemory parse path's full-DAG ceiling. The OnDisk catch-up path no
  // longer produces a full DataCell DAG when true streaming is enabled
  // (cells stream into CellDb and the root is hash-only), so this field bounds
  // only the InMemory branch where the parser still returns a complete
  // DAG. 512 MiB matches the InMemory heap-path cap.
  td::uint64 max_returned_dag_bytes_per_parse = 512ULL << 20;
  // H-03 cell-count cap forwarded to vm::StreamingBocImportOptions.
  // Defaults to vm::kDefaultStreamingBocMaxCells.
  td::uint64 max_cells_per_parse = vm::kDefaultStreamingBocMaxCells;
  // H-03 scaffolding-bytes cap forwarded to vm::StreamingBocImportOptions.
  // Defaults to vm::kDefaultStreamingBocMaxScaffoldingBytes.
  td::uint64 max_scaffolding_bytes_per_parse = vm::kDefaultStreamingBocMaxScaffoldingBytes;
  // H-03 total-cell-bytes cap forwarded to vm::StreamingBocImportOptions.
  // Bounds the streaming BoC importer's declared cells, NOT the returned
  // root DAG residency. Default raised to 16 GiB so a 16 GiB OnDisk
  // catch-up file can declare matching cell bytes; the returned root is
  // O(1) memory under the true-streaming path. The actor caps this
  // further at min(file.size, this value) so a small state cannot declare
  // more cell bytes than its envelope contains.
  td::uint64 max_total_cell_bytes_per_parse = 16ULL << 30;
  // H-02/tos30 long-term feature flag. When enabled, OnDisk catch-up may
  // parse a state whose `file.size` exceeds
  // max_returned_dag_bytes_per_parse because the actor-local importer no
  // longer returns the full DAG. Operators should enable it together with
  // explicit max_cells / max_scaffolding / max_total_cell_bytes budgets.
  bool enable_true_cell_db_streaming_import = false;
};

// Install a new persistent-state budget configuration. Call this exactly
// once at startup, BEFORE the first download starts; calling it after
// downloads are in flight is well-defined (existing reservations remain
// valid) but has the surprising effect of re-validating future requests
// against a different ceiling.
//
// Returns Status::OK() on success. On rejection, the previous configuration
// is preserved unchanged and the returned Status carries an
// operator-actionable error message. `enable_true_cell_db_streaming_import`
// is accepted as an explicit operator opt-in to the actor-local
// ExtCell-backed import path; the remaining budget fields still bound that
// path's declared cells, scaffolding, and resident memory.
td::Status configure_persistent_state_budgets(PersistentStateBudgetConfig cfg);

// Read the live persistent-state budget configuration. The returned
// snapshot is consistent with the value the next reservation will
// observe; the caller can use it for logging or for sizing a streaming
// importer's max_resident_bytes option.
PersistentStateBudgetConfig persistent_state_budget_config();

// Public reservation API for the download budget. Returns true iff `size`
// bytes were CAS'd into the global counter; in that case the caller MUST
// own a `PersistentStateDownloadReservation{size}` (or wrap one in a
// shared_ptr) whose destructor will release the bytes exactly once.
bool try_reserve_persistent_state_download_memory(td::uint64 size);

// Mirror of the download API for the processing budget.
bool try_reserve_persistent_state_processing_memory(td::uint64 size);

// Validate the peer-advertised total persistent-state size against the
// hard download cap. Used by DownloadState before reserving the budget so
// a hostile peer cannot induce an unbounded heap allocation.
td::Status validate_persistent_state_size(td::uint64 size);

// Threshold above which the streaming-tempfile downloader is used.
td::uint64 persistent_state_heap_threshold_bytes();

// Hard upper bound on a single persistent-state download.
td::uint64 persistent_state_max_file_bytes();

// Hard upper bound on the cumulative outstanding persistent-state download
// budget. Exposed so tests pin the value and so the OnDisk parse path can
// reason about whether a single state can occupy the full budget transiently.
td::uint64 persistent_state_total_download_budget_bytes();

// Map an on-disk persistent-state tempfile (the file referenced by the
// BudgetedStateFile produced by the streaming downloader) into the
// process via PROT_READ / MAP_PRIVATE and return a non-owning td::Slice
// view of its bytes. The mapping is owned by `f` for the rest of its
// lifetime; the caller MUST keep the BudgetedStateFile (or the
// DownloadedPersistentState that wraps it) alive until it stops using
// the returned slice.
//
// On error, returns a Status whose message includes the platform error.
// The OnDisk parse path uses this to feed `vm::std_boc_deserialize`
// without ever allocating a BufferSlice of size == file size.
td::Result<td::Slice> mmap_persistent_state_file(BudgetedStateFile &f);

// Helper used by manager/disk recovery: scan the given tempfile root
// directory and remove any *.partial files that look like residue from
// a prior crash. CellDb streaming-import rollback manifests
// (*.celldb-rollback.*.partial) are deliberately preserved here; CellDbIn
// scans and replays them during startup before metadata validation.
//
// Race-safety contract:
//   The validator manager calls this function exactly once during
//   start_up(), BEFORE any DownloadState actor is spawned (DownloadState
//   is the only writer of *.partial files in this process). At that
//   point no in-process writer can exist, so concurrent writers are
//   impossible by construction. The mtime guard below is defense-in-depth
//   against (a) a future caller that invokes cleanup at runtime, and (b)
//   a co-located process (e.g. an admin running a maintenance tool) that
//   shares the same tempfile root and is mid-write when cleanup runs.
//   Files younger than `min_age_seconds` are skipped; files older are
//   unlinked. The default age threshold is 60 seconds, well below any
//   realistic startup -> first-download latency.
//
// `min_age_seconds == 0` disables the age guard entirely; reserved for
// situations where the caller has already proved no concurrent writer
// exists.
td::Status cleanup_persistent_state_tempfiles(td::CSlice tempfile_root,
                                              td::uint64 min_age_seconds = 60);

// Register / retrieve the persistent-state tempfile directory. Called
// once by the validator manager during start_up(); read by DownloadState
// when it decides to switch from heap mode to file mode.
void set_persistent_state_tempfile_dir(std::string dir);
std::string get_persistent_state_tempfile_dir();

// See docs/adr/0001-streaming-cell-import-and-residency.md
//
// Streaming-sink wiring for vm::std_boc_deserialize_from_file_bounded.
// The actor that drives the bounded streaming BoC importer constructs
// a CellDbStreamingSink, hands it to the importer, and once the parse
// returns the root cell, the sink's accumulated cell count + observed
// root hash are available for the downstream archive store /
// set_block_state hand-off.
//
// Design contract:
//   * `begin()` is invoked once at the start of the parse (after the
//     header has been validated). The sink may use it to allocate
//     per-import scratch (in this minimal implementation it's a
//     no-op).
//   * `persist(cell)` is invoked once per unique cell in topological
//     order from leaves to root. The sink validates the cell is
//     non-null and tracks the running cell count + total resident
//     bytes-charged. A non-OK return aborts the import.
//   * `finish(root_hash)` is invoked once after every cell has been
//     persisted, immediately before the importer returns the root
//     cell. The sink records the root hash so the actor can
//     cross-check against the BFT-attested expected root.
//
//     tos26 P0-3: `finish` no longer commits the writer's RocksDB
//     batch. The cells are written to the open batch but remain
//     invisible to readers until `commit_after_root_verified` runs.
//     This lets the caller compare the parsed root against an
//     externally trusted expected root BEFORE any cells become
//     durable; on mismatch, `abort()` discards the pending writes.
//   * `commit_after_root_verified(expected_root_hash)` is called by
//     the actor AFTER `finish` returns and AFTER it has verified
//     that the parsed root equals the BFT-attested expected root.
//     This commits the writer's pending batch and is the single
//     point at which cells become visible.
//   * `abort()` is invoked at most once on any error path (header
//     rejection, descriptor corruption, persist rejection,
//     finish rejection, root-hash mismatch in the caller). After
//     abort the sink's counters reflect what was observed before
//     the error; no DB writes were committed.
//
// Lifecycle (true-streaming sink):
//   begin() -> persist_and_replace()* -> finish(root_hash)
//                                    -> commit_after_root_verified(expected)  (success)
//   begin() -> persist_and_replace()* -> finish(root_hash) -> abort()
//                                                  (root mismatch; nothing durable)
//   begin() -> persist_and_replace()* -> abort()         (any error before finish)
//
// Memory contract (honest documentation of fallback (b) — see audit
// notes):
//   The current implementation does NOT release in-memory ownership
//   of cells after persist; the importer's parent_refcount-driven
//   residency is the only memory bound. True streaming-into-CellDb
//   without DataCell DAG residency requires a deeper refactor of
//   create_data_cell to use ExtCell-style hash-only references for
//   children — that refactor is out of scope here. The sink interface
//   is the load-bearing extension point that lets a future commit
//   land that refactor without changing any of the actor wiring.
class CellDbStreamingSink final : public vm::StreamingCellSink {
 public:
  // Optional callback invoked from inside `persist(cell)` on every
  // cell. Intended for hooking a real CellDb write (or a test sink).
  // Returning a non-OK Status aborts the import. May be empty (the
  // default) — in that case persist is a counters-only no-op.
  using OnCellFn = std::function<td::Status(td::Ref<vm::Cell>)>;
  using ReplaceCellFn = std::function<td::Result<td::Ref<vm::Cell>>(td::Ref<vm::Cell>)>;

  CellDbStreamingSink() = default;
  explicit CellDbStreamingSink(OnCellFn on_cell) : on_cell_(std::move(on_cell)) {
  }
  CellDbStreamingSink(OnCellFn on_cell, ReplaceCellFn replace_cell)
      : on_cell_(std::move(on_cell)), replace_cell_(std::move(replace_cell)) {
  }
  // Phase B "true streaming" constructor. When BOTH `reader_provider` and
  // `writer` are non-null, persist_and_replace writes each cell to CellDb
  // via the shared KeyValue handle wrapped by `writer`, and returns an
  // ExtCell-backed hash-only replacement whose lazy materialization
  // late-binds to whichever reader the provider hands out (NOT the
  // import-time snapshot). The legacy default / 1-arg / 2-arg constructors
  // stay valid and run the counting / fallback path with this flag clear.
  //
  // tos26 P0-2: the constructor takes a `CellDbReaderProvider` instead
  // of a raw `CellDbReader`. The provider is the single point at which
  // the sink can swap to a post-commit reader (via
  // republish_reader / commit_after_root_verified) or invalidate on
  // abort (via abort()). Lazy ExtCells emitted during parse no longer
  // hold a snapshot taken before the per-import RocksDB batch was
  // committed; they reach the canonical reader via the provider on
  // every materialization.
  //
  // The constructor is a TEMPLATE so it is only instantiated in TUs
  // that actually call it (Wave 5's downloader TU, which already has
  // `CellDbStreamingWriter` complete via validator/db/celldb.hpp). The
  // light-weight `validator-state-download-budget` static library this
  // header's .cpp links into intentionally does not pull in tos_db /
  // TDDB_USE_ROCKSDB, so an inline non-template body would fail to
  // compile in every TU that includes this header without the writer
  // definition. The template parameter `WriterT` is constrained at the
  // call site to be `CellDbStreamingWriter` (or a derived test class)
  // by the static_assert below.
  //
  // The body type-erases the writer's vtable methods into std::function
  // members (`writer_begin_batch_`, `writer_store_cell_`,
  // `writer_commit_batch_`, `writer_abort_batch_`) plus a void-typed
  // owner that keeps the unique_ptr alive; the sink's runtime hot path
  // then dispatches through the std::function instances and never
  // touches the writer type's layout from inside this header's .cpp.
  template <typename WriterT>
  CellDbStreamingSink(std::shared_ptr<vm::CellDbReaderProvider> reader_provider,
                      std::unique_ptr<WriterT> writer)
      : reader_provider_(std::move(reader_provider)) {
    static_assert(std::is_base_of_v<CellDbStreamingWriter, WriterT>,
                  "CellDbStreamingSink streaming-writer constructor requires a "
                  "CellDbStreamingWriter (or a derived class)");
    if (reader_provider_ != nullptr && writer != nullptr) {
      auto* raw_writer = writer.get();
      writer_begin_batch_ = [raw_writer]() { return raw_writer->begin_batch(); };
      writer_store_cell_ = [raw_writer](const td::Ref<vm::DataCell>& cell) {
        return raw_writer->store_cell(cell);
      };
      writer_commit_batch_ = [raw_writer]() { return raw_writer->commit_batch(); };
      writer_abort_batch_ = [raw_writer]() { return raw_writer->abort_batch(); };
      // Type-erase the unique_ptr's destruction into a shared_ptr<void>
      // whose deleter is captured here (where the writer type is
      // complete). The sink's destructor just drops the shared_ptr<void>;
      // the lambda captured in the deleter performs the real `delete`.
      writer_owner_ =
          std::shared_ptr<void>(writer.release(), [](void* p) { delete static_cast<WriterT*>(p); });
      true_streaming_active_ = true;
    }
  }

  // tos26 P0-2 backward-compat overload. Existing callers pass a raw
  // `shared_ptr<vm::CellDbReader>`; we wrap it in a degenerate provider
  // (vm::make_static_cell_db_reader_provider) so the sink's lazy
  // ExtCell binding still flows through the provider indirection. This
  // preserves source compatibility for the downloader / test paths
  // that have not yet been migrated to constructing a real
  // (swappable) provider. The wrapping is ONLY instantiated in TUs
  // that actually use this overload AND therefore have
  // vm/db/CellDbExtCell.h already pulled in via validator/db/celldb.hpp;
  // the light-weight `validator-state-download-budget` static library
  // still does not need to see CellDbExtCell.h for its own
  // instantiations of CellDbStreamingSink.
  template <typename WriterT>
  CellDbStreamingSink(std::shared_ptr<vm::CellDbReader> reader, std::unique_ptr<WriterT> writer)
      : CellDbStreamingSink(vm::make_static_cell_db_reader_provider(std::move(reader)),
                             std::move(writer)) {
  }
  // Destructor is inline so the type-erased writer_owner_ deleter
  // (captured at construction time) closes any still-open batch via
  // the writer_abort_batch_ std::function. The dtor's body runs in
  // whatever TU instantiates the sink; it never touches
  // CellDbStreamingWriter's layout directly because both the abort
  // call and the eventual delete go through callables.
  ~CellDbStreamingSink() override {
    if (true_streaming_active_ && batch_open_ && writer_abort_batch_) {
      // Best-effort: the importer's normal finish/abort path runs the
      // commit/abort dance for us; this branch only fires when the
      // sink is dropped without a matching finish/abort (e.g. a test
      // tears the sink down out from under the importer).
      auto status = writer_abort_batch_();
      (void)status;  // status logged at the explicit abort() site; here
                     // we are noexcept and cannot throw.
      batch_open_ = false;
    }
  }

  td::Status begin() override;
  td::Status persist(td::Ref<vm::Cell> cell) override;
  td::Result<td::Ref<vm::Cell>> persist_and_replace(td::Ref<vm::Cell> cell) override;
  td::Status finish(const vm::Cell::Hash &root_hash) override;
  // tos26 P0-3: commit the writer's pending RocksDB batch after the
  // caller has verified the parsed root matches an externally
  // trusted expected hash. Returns Error if the recorded root does
  // not match `expected_root_hash`, leaving the sink uncommitted so
  // the caller can drive abort(). May only be called once, and only
  // after finish() returned OK and before abort().
  td::Status commit_after_root_verified(const vm::Cell::Hash &expected_root_hash) override;
  void abort() override;

  // tos26 P0-2: publish a fresh post-commit reader on the sink's
  // CellDbReaderProvider. Production callers invoke this (via
  // commit_after_root_verified's internal flow, OR explicitly when the
  // surrounding actor materialized a new reader after CellDb's
  // update_snapshot ran) so lazy ExtCells emitted during parse pick up
  // a reader that observes the just-flushed cells. Calling with a null
  // reader is a no-op; use abort() to invalidate.
  void republish_reader(std::shared_ptr<vm::CellDbReader> post_commit_reader);

  bool is_committed() const noexcept {
    return committed_;
  }

  // Diagnostics. Read after finish (or abort) returns.
  td::uint64 cell_count() const {
    return cell_count_.load(std::memory_order_acquire);
  }
  bool finished() const {
    return finished_;
  }
  bool aborted() const {
    return aborted_;
  }
  bool begun() const {
    return begun_;
  }
  // Valid after finish. On abort the contents are unspecified.
  vm::Cell::Hash root_hash() const {
    return root_hash_;
  }
  // Number of cells written to CellDb via the Phase B streaming writer
  // (i.e. the count of successful `writer_->store_cell` calls). Zero
  // when the legacy fallback path is in use. Wave 6 tests assert this
  // equals the cell-count parsed by the importer.
  td::uint64 cells_persisted() const {
    return cells_persisted_;
  }
  // True iff this sink was built with the (reader, writer) Phase B
  // constructor and both handles are non-null. Wave 5 (downloader
  // wire-in) reads this to assert that the real streaming path was
  // actually wired, instead of the legacy counting/fallback sink.
  bool is_true_streaming() const {
    return true_streaming_active_;
  }

 private:
  OnCellFn on_cell_;
  ReplaceCellFn replace_cell_;
  // Phase B handles. `reader_provider_` is the late-binding indirection
  // through which lazy ExtCells emitted during parse reach the canonical
  // reader (see tos26 P0-2). The forward declaration of
  // vm::CellDbReaderProvider is enough for shared_ptr storage; Wave 5's
  // TU pulls vm/db/CellDbExtCell.h to instantiate the provider and to
  // build the (reader, writer) constructor. The writer is type-erased
  // into std::function members + a shared_ptr<void> owner; see the
  // (reader_provider, writer) constructor for the rationale
  // (TDDB_USE_ROCKSDB not propagated into validator-state-download-budget).
  std::shared_ptr<vm::CellDbReaderProvider> reader_provider_;
  std::shared_ptr<void> writer_owner_;
  std::function<td::Status()> writer_begin_batch_;
  std::function<td::Status(const td::Ref<vm::DataCell>&)> writer_store_cell_;
  std::function<td::Status()> writer_commit_batch_;
  std::function<td::Status()> writer_abort_batch_;
  bool true_streaming_active_{false};
  bool batch_open_{false};
  td::uint64 cells_persisted_{0};
  std::atomic<td::uint64> cell_count_{0};
  bool begun_{false};
  bool finished_{false};
  // tos26 P0-3: commit_after_root_verified flips this to true once the
  // pending batch has been flushed. While false, abort() (or the
  // destructor) is responsible for rolling back any open batch so the
  // CellDb stays byte-for-byte identical to its pre-import snapshot.
  bool committed_{false};
  bool aborted_{false};
  vm::Cell::Hash root_hash_{};
};

namespace testing {

// Test-only handle to the global persistent-state download budget. These
// helpers exist so a unit test can exercise the reservation lifetime
// invariant without bringing up the full DownloadState actor stack.
td::uint64 test_get_persistent_state_download_bytes();
bool test_try_reserve_persistent_state_download_memory(td::uint64 size);

// Test-only handle to the global persistent-state processing budget.
// Mirrors the download counterpart so the parse/persist clone accounting
// can be validated without standing up the DownloadShardState actor.
td::uint64 test_get_persistent_state_processing_bytes();
bool test_try_reserve_persistent_state_processing_memory(td::uint64 size);

}  // namespace testing

}  // namespace fullnode
}  // namespace validator
}  // namespace tos
