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

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once
#include <functional>
#include <map>
#include <set>

#include "td/utils/CancellationToken.h"
#include "td/utils/HashMap.h"
#include "td/utils/HashSet.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/Timer.h"
#include "td/utils/buffer.h"
#include "td/utils/port/FileFd.h"
#include "vm/cells.h"
#include "vm/db/DynamicBagOfCellsDb.h"

namespace vm {
using td::Ref;

class NewCellStorageStat {
 public:
  NewCellStorageStat() {
  }

  struct Stat {
    Stat() {
    }
    Stat(td::uint64 cells_, td::uint64 bits_, td::uint64 internal_refs_ = 0, td::uint64 external_refs_ = 0)
        : cells(cells_), bits(bits_), internal_refs(internal_refs_), external_refs(external_refs_) {
    }
    td::uint64 cells{0};
    td::uint64 bits{0};
    td::uint64 internal_refs{0};
    td::uint64 external_refs{0};

    auto key() const {
      return std::make_tuple(cells, bits, internal_refs, external_refs);
    }
    bool operator==(const Stat& other) const {
      return key() == other.key();
    }
    Stat(const Stat& other) = default;
    Stat& operator=(const Stat& other) = default;
    Stat& operator+=(const Stat& other) {
      cells += other.cells;
      bits += other.bits;
      internal_refs += other.internal_refs;
      external_refs += other.external_refs;
      return *this;
    }
    Stat operator+(const Stat& other) const {
      return Stat{cells + other.cells, bits + other.bits, internal_refs + other.internal_refs,
                  external_refs + other.external_refs};
    }
    bool fits_uint32() const {
      return !((cells | bits | internal_refs | external_refs) >> 32);
    }
    void set_zero() {
      cells = bits = internal_refs = external_refs = 0;
    }
  };

  Stat get_stat() const {
    return stat_;
  }

  Stat get_proof_stat() const {
    return proof_stat_;
  }

  Stat get_total_stat() const {
    return stat_ + proof_stat_;
  }

  void add_cell(Ref<Cell> cell);
  void add_proof(Ref<Cell> cell, const CellUsageTree* usage_tree);
  void add_cell_and_proof(Ref<Cell> cell, const CellUsageTree* usage_tree);
  Stat tentative_add_cell(Ref<Cell> cell) const;
  Stat tentative_add_proof(Ref<Cell> cell, const CellUsageTree* usage_tree) const;
  void set_zero() {
    stat_.set_zero();
    proof_stat_.set_zero();
  }

 private:
  const CellUsageTree* usage_tree_;
  td::HashSet<vm::Cell::Hash> seen_;
  Stat stat_;
  td::HashSet<vm::Cell::Hash> proof_seen_;
  Stat proof_stat_;
  const NewCellStorageStat* parent_{nullptr};

  void dfs(Ref<Cell> cell, bool need_stat, bool need_proof_stat);
};

struct CellStorageStat {
  unsigned long long cells;
  unsigned long long bits;
  struct CellInfo {
    td::uint32 max_merkle_depth = 0;
  };
  td::HashMap<vm::Cell::Hash, CellInfo> seen;
  CellStorageStat() : cells(0), bits(0) {
  }
  explicit CellStorageStat(unsigned long long limit_cells) : cells(0), bits(0), limit_cells(limit_cells) {
  }
  void clear_seen() {
    seen.clear();
  }
  void clear() {
    cells = bits = 0;
    clear_limit();
    clear_seen();
  }
  void clear_limit() {
    limit_cells = std::numeric_limits<unsigned long long>::max();
    limit_bits = std::numeric_limits<unsigned long long>::max();
  }
  td::Result<CellInfo> compute_used_storage(Ref<vm::CellSlice> cs_ref, bool kill_dup = true,
                                            unsigned skip_count_root = 0);
  td::Result<CellInfo> compute_used_storage(const CellSlice& cs, bool kill_dup = true, unsigned skip_count_root = 0);
  td::Result<CellInfo> compute_used_storage(CellSlice&& cs, bool kill_dup = true, unsigned skip_count_root = 0);
  td::Result<CellInfo> compute_used_storage(Ref<vm::Cell> cell, bool kill_dup = true, unsigned skip_count_root = 0);

  td::Result<CellInfo> add_used_storage(Ref<vm::CellSlice> cs_ref, bool kill_dup = true, unsigned skip_count_root = 0);
  td::Result<CellInfo> add_used_storage(const CellSlice& cs, bool kill_dup = true, unsigned skip_count_root = 0);
  td::Result<CellInfo> add_used_storage(CellSlice&& cs, bool kill_dup = true, unsigned skip_count_root = 0);
  td::Result<CellInfo> add_used_storage(Ref<vm::Cell> cell, bool kill_dup = true, unsigned skip_count_root = 0);
  td::Result<CellInfo> add_used_storage(td::Span<Ref<Cell>> cells, bool kill_dup = true, unsigned skip_count_root = 0);

  unsigned long long limit_cells = std::numeric_limits<unsigned long long>::max();
  unsigned long long limit_bits = std::numeric_limits<unsigned long long>::max();
};

struct VmStorageStat {
  td::uint64 cells{0}, bits{0}, refs{0}, limit;
  td::HashSet<CellHash> visited;
  VmStorageStat(td::uint64 _limit) : limit(_limit) {
  }
  bool add_storage(Ref<Cell> cell);
  bool add_storage(const CellSlice& cs);
  bool check_visited(const CellHash& cell_hash) {
    return visited.insert(cell_hash).second;
  }
  bool check_visited(const Ref<Cell>& cell) {
    return check_visited(cell->get_hash());
  }
};

class ProofStorageStat {
 public:
  void add_loaded_cell(const Ref<DataCell>& cell, td::uint8 max_level = Cell::max_level);
  void add_loaded_cells(const ProofStorageStat& other);
  td::uint64 estimate_proof_size() const;

  enum CellStatus { c_none = 0, c_prunned = 1, c_loaded = 2 };
  CellStatus get_cell_status(const Cell::Hash& hash) const;
  bool is_loaded(const Cell::Hash& hash) const {
    return get_cell_status(hash) == c_loaded;
  }

  static td::uint64 estimate_prunned_size();
  static td::uint64 estimate_serialized_size(const Ref<DataCell>& cell);

 private:
  td::HashMap<Cell::Hash, std::pair<CellStatus, td::uint64>> cells_;
  td::uint64 proof_size_ = 0;
};

struct CellSerializationInfo {
  bool special;
  Cell::LevelMask level_mask;

  bool with_hashes;
  size_t hashes_offset;
  size_t depth_offset;

  size_t data_offset;
  size_t data_len;
  bool data_with_bits;

  size_t refs_offset;
  int refs_cnt;

  size_t end_offset;

  td::Status init(td::Slice data, int ref_byte_size);
  td::Status init(td::uint8 d1, td::uint8 d2, int ref_byte_size);
  td::Result<int> get_bits(td::Slice cell) const;

  td::Result<Ref<DataCell>> create_data_cell(td::Slice data, td::Span<Ref<Cell>> refs) const;
};

class BagOfCellsLogger {
 public:
  BagOfCellsLogger() = default;
  explicit BagOfCellsLogger(td::CancellationToken cancellation_token)
      : cancellation_token_(std::move(cancellation_token)) {
  }

  void start_stage(std::string stage) {
    log_speed_at_ = td::Timestamp::in(LOG_SPEED_PERIOD);
    last_speed_log_ = td::Timestamp::now();
    processed_cells_ = 0;
    last_token_check_ = 0;
    timer_ = {};
    stage_ = std::move(stage);
  }
  void finish_stage(td::Slice desc) {
    LOG(ERROR) << "serializer: " << stage_ << " took " << timer_.elapsed() << "s, " << desc;
  }
  td::Status on_cells_processed(size_t count) {
    processed_cells_ += count;
    if (processed_cells_ / 1000 > last_token_check_) {
      TRY_STATUS(cancellation_token_.check());
      last_token_check_ = processed_cells_ / 1000;
    }
    if (log_speed_at_.is_in_past()) {
      double period = td::Timestamp::now().at() - last_speed_log_.at();

      LOG(WARNING) << "serializer: " << stage_ << " " << (double)processed_cells_ / period << " cells/s";
      TRY_STATUS(cancellation_token_.check());
      processed_cells_ = 0;
      last_token_check_ = 0;
      last_speed_log_ = td::Timestamp::now();
      log_speed_at_ = td::Timestamp::in(LOG_SPEED_PERIOD);
    }
    return td::Status::OK();
  }

 private:
  std::string stage_;
  td::Timer timer_;
  td::CancellationToken cancellation_token_;
  td::Timestamp log_speed_at_;
  size_t processed_cells_ = 0;
  size_t last_token_check_ = 0;
  td::Timestamp last_speed_log_;
  static constexpr double LOG_SPEED_PERIOD = 120.0;
};
class BagOfCells {
 public:
  enum { hash_bytes = vm::Cell::hash_bytes, default_max_roots = 16384 };
  enum Mode { WithIndex = 1, WithCRC32C = 2, WithTopHash = 4, WithIntHashes = 8, WithCacheBits = 16, max = 31 };
  enum { max_cell_whs = 64 };
  using Hash = Cell::Hash;
  struct Info {
    enum : td::uint32 { boc_idx = 0x68ff65f3, boc_idx_crc32c = 0xacc3a728, boc_generic = 0xb5ee9c72 };

    unsigned magic;
    int root_count;
    int cell_count;
    int absent_count;
    int ref_byte_size;
    int offset_byte_size;
    bool valid;
    bool has_index;
    bool has_roots{false};
    bool has_crc32c;
    bool has_cache_bits;
    unsigned long long roots_offset, index_offset, data_offset, data_size, total_size;
    Info() : magic(0), valid(false) {
    }
    void invalidate() {
      valid = false;
    }
    long long parse_serialized_header(const td::Slice& slice);
    unsigned long long read_int(const unsigned char* ptr, unsigned bytes);
    unsigned long long read_ref(const unsigned char* ptr) {
      return read_int(ptr, ref_byte_size);
    }
    unsigned long long read_offset(const unsigned char* ptr) {
      return read_int(ptr, offset_byte_size);
    }
    void write_int(unsigned char* ptr, unsigned long long value, int bytes);
    void write_ref(unsigned char* ptr, unsigned long long value) {
      write_int(ptr, value, ref_byte_size);
    }
    void write_offset(unsigned char* ptr, unsigned long long value) {
      write_int(ptr, value, offset_byte_size);
    }
  };

 private:
  int cell_count{0}, root_count{0}, dangle_count{0}, int_refs{0};
  int int_hashes{0}, top_hashes{0};
  int max_depth{1024};
  Info info;
  unsigned long long data_bytes{0};
  td::HashMap<Hash, int> cells;
  struct CellInfo {
    Ref<DataCell> dc_ref;
    std::array<int, 4> ref_idx;
    unsigned char ref_num;
    unsigned char wt;
    unsigned char hcnt;
    int new_idx;
    bool should_cache{false};
    bool is_root_cell{false};
    CellInfo() : ref_num(0) {
    }
    CellInfo(Ref<DataCell> _dc) : dc_ref(std::move(_dc)), ref_num(0) {
    }
    CellInfo(Ref<DataCell> _dc, int _refs, const std::array<int, 4>& _ref_list)
        : dc_ref(std::move(_dc)), ref_idx(_ref_list), ref_num(static_cast<unsigned char>(_refs)) {
    }
    bool is_special() const {
      return !wt;
    }
  };
  std::vector<CellInfo> cell_list_;
  struct RootInfo {
    RootInfo() = default;
    RootInfo(Ref<Cell> cell, int idx) : cell(std::move(cell)), idx(idx) {
    }
    Ref<Cell> cell;
    int idx{-1};
  };
  std::vector<CellInfo> cell_list_tmp;
  std::vector<RootInfo> roots;
  std::vector<unsigned char> serialized;
  const unsigned char* index_ptr{nullptr};
  const unsigned char* data_ptr{nullptr};
  std::vector<unsigned long long> custom_index;
  BagOfCellsLogger* logger_ptr_{nullptr};

 public:
  void clear();
  int set_roots(const std::vector<td::Ref<vm::Cell>>& new_roots);
  int set_root(td::Ref<vm::Cell> new_root);
  int add_roots(const std::vector<td::Ref<vm::Cell>>& add_roots);
  int add_root(td::Ref<vm::Cell> add_root);
  td::Status import_cells() TD_WARN_UNUSED_RESULT;
  BagOfCells() = default;
  void set_logger(BagOfCellsLogger* logger_ptr) {
    logger_ptr_ = logger_ptr;
  }
  std::size_t estimate_serialized_size(int mode = 0);
  td::Status serialize(int mode = 0);
  td::string serialize_to_string(int mode = 0);
  td::Result<td::BufferSlice> serialize_to_slice(int mode = 0);
  td::Result<std::size_t> serialize_to(unsigned char* buffer, std::size_t buff_size, int mode = 0);
  td::Status serialize_to_file(td::FileFd& fd, int mode = 0);
  template <typename WriterT>
  td::Result<std::size_t> serialize_to_impl(WriterT& writer, int mode = 0);
  std::string extract_string() const;

  td::Result<long long> deserialize(const td::Slice& data, int max_roots = default_max_roots);
  td::Result<long long> deserialize(const unsigned char* buffer, std::size_t buff_size,
                                    int max_roots = default_max_roots) {
    return deserialize(td::Slice{buffer, buff_size}, max_roots);
  }
  int get_root_count() const {
    return root_count;
  }
  Ref<Cell> get_root_cell(int idx = 0) const {
    return (idx >= 0 && idx < root_count) ? roots.at(idx).cell : Ref<Cell>{};
  }

  static int precompute_cell_serialization_size(const unsigned char* cell, std::size_t len, int ref_size,
                                                int* refs_num_ptr = nullptr);

 private:
  int rv_idx;
  td::Result<int> import_cell(td::Ref<vm::Cell> cell, int depth);
  void cells_clear() {
    cell_count = 0;
    int_refs = 0;
    data_bytes = 0;
    cells.clear();
    cell_list_.clear();
  }
  td::uint64 compute_sizes(int mode, int& r_size, int& o_size);
  void reorder_cells();
  int revisit(int cell_idx, int force = 0);
  unsigned long long get_idx_entry_raw(int index);
  unsigned long long get_idx_entry(int index);
  bool get_cache_entry(int index);
  td::Result<td::Slice> get_cell_slice(int index, td::Slice data);
  td::Result<td::Ref<vm::DataCell>> deserialize_cell(int index, td::Slice data, td::Span<td::Ref<DataCell>> cells,
                                                     std::vector<td::uint8>* cell_should_cache);
};

td::Result<Ref<Cell>> std_boc_deserialize(td::Slice data, bool can_be_empty = false, bool allow_nonzero_level = false);
td::Result<td::BufferSlice> std_boc_serialize(Ref<Cell> root, int mode = 0);

// See docs/adr/0001-streaming-cell-import-and-residency.md
//
// Bounded streaming BoC importer. Reads a serialized BoC directly from a
// file descriptor in chunks, deserializes each cell as soon as its
// references are known, hands the freshly-built cell to `persist_cell`,
// and immediately drops every intermediate cell that no longer has an
// outstanding parent reference. Peak resident memory is therefore bounded
// by `opts.max_resident_bytes` (a small queue of cells that have not yet
// been visited as a reference target) PLUS the BoC header and per-cell
// scaffolding (offset table, ref counts, work queue), regardless of the
// total file size.
//
// Contract:
//   * The function returns the root cell on success. The DataCell payload
//     of the root is owned by the caller; every other cell in the DAG is
//     reachable via the root only if `persist_cell` chose to keep it.
//     Callers that persist cells to a CellDb typically immediately
//     re-resolve the root through their CellDbReader.
//   * `persist_cell` is invoked exactly once per unique cell in the DAG,
//     in topological order from leaves to root. Returning a non-OK status
//     aborts the import and surfaces the error verbatim.
//   * `opts.max_cells` (when non-zero) caps the cell count declared in
//     the BoC header; `opts.max_total_cell_bytes` (when non-zero) caps
//     the data-size field of the header. Both are first-line defenses
//     against a hostile peer announcing an absurd BoC structure. The
//     `size` argument is independently checked against the file's
//     actual length so a truncated tempfile cannot smuggle past the
//     declared header.
//   * The file is read in 4 MiB chunks via pread; no mmap of the full
//     file is performed. The chunk reader is direction-aware: a forward
//     scan (parent-walk pass) anchors the chunk at the request offset,
//     while a backward scan (cell-build pass — BoC v1 places the root
//     at file start and leaves at file end, so the cell-build loop
//     iterates from cell_count-1 down to 0) anchors the chunk so its
//     END aligns with the request end. Both walks therefore see one
//     pread per chunk_bytes / cell_size cells rather than one pread
//     per cell. CRC32C trailer (when the BoC carries one) is validated
//     incrementally against the same chunked reader so a corrupted
//     trailer fails closed at the same stage a one-shot deserialize
//     would.
//   * The function is NOT thread-safe with respect to `file`: the
//     caller MUST own the FileFd for the duration of the call.
// Default ceilings applied by the streaming BoC importer when the caller
// passes a zero in the corresponding StreamingBocImportOptions field. The
// importer treats every "0 = use default" branch as a request for these
// values; an explicit non-zero override always wins. The defaults are
// sized so:
//   * `kDefaultStreamingBocMaxCells` (50,000,000) absorbs any realistic
//     persistent-state DAG yet rejects an attacker who declares a billion
//     cells in the BoC header.
//   * `kDefaultStreamingBocMaxScaffoldingBytes` (512 MiB) caps the sum
//     `(cell_count+1)*8 + cell_count*4 + cell_count*sizeof(Ref<Cell>)` so
//     even a header that announces the full max_cells default cannot pull
//     more than ~512 MiB of importer scaffolding into RAM.
//   * `kDefaultStreamingBocMaxTotalCellBytes` (16 GiB) matches the
//     persistent-state single-file ceiling so a hostile peer cannot
//     declare more cell data than a legitimate state contains.
inline constexpr td::uint64 kDefaultStreamingBocMaxCells = 50'000'000;
inline constexpr td::uint64 kDefaultStreamingBocMaxScaffoldingBytes = 512ULL << 20;
inline constexpr td::uint64 kDefaultStreamingBocMaxTotalCellBytes = 16ULL << 30;

struct StreamingBocImportOptions {
  // Maximum declared cell count. Zero is treated as
  // `kDefaultStreamingBocMaxCells` — the comment "0 = use default" is a
  // guarantee, not a description; the importer never accepts an
  // unbounded `cell_count` regardless of what the caller passes.
  td::uint64 max_cells = kDefaultStreamingBocMaxCells;
  td::uint64 max_roots = 1;
  // Maximum declared total cell bytes (BoC header `data_size`). Zero is
  // treated as `kDefaultStreamingBocMaxTotalCellBytes`.
  td::uint64 max_total_cell_bytes = kDefaultStreamingBocMaxTotalCellBytes;
  // Per-parse peak resident-byte budget enforced inside the cell-build
  // loop. The streaming importer charges each cell's serialized size
  // when the cell becomes the next leaf-to-root frontier and credits the
  // bytes back when the cell is released by its last outstanding parent.
  td::uint64 max_resident_bytes = 256ULL << 20;  // resident-memory peak cap
  // Maximum total bytes the importer is allowed to allocate for its
  // O(cell_count) scaffolding tables (`offset_table`, `parent_refcount`,
  // `cells`). The sum is computed with overflow checks BEFORE any of the
  // four vectors is constructed; if the budget is exceeded the importer
  // returns Status::Error("BoC scaffolding budget exceeded") without
  // ever allocating. Zero is treated as
  // `kDefaultStreamingBocMaxScaffoldingBytes`.
  td::uint64 max_scaffolding_bytes = kDefaultStreamingBocMaxScaffoldingBytes;
  // Optional cooperative cancellation hook. The bounded importer checks
  // this before and during every O(file_size) / O(cell_count) phase,
  // including the pre-sink header, CRC, index, offset synthesis, parent
  // walk, and cell-build loops. Returning true aborts with a structured
  // "import cancelled" error; the sink is not begun if cancellation is
  // observed before `begin()`.
  std::function<bool()> is_cancelled;
};

// Per-cell sink invoked from inside the streaming BoC importer. Each
// cell flows through `persist` exactly once, in topological order from
// leaves to root. Returning a non-OK status aborts the import.
//
// Lifecycle invariants:
//   * `begin` is invoked exactly once after every header invariant
//     has been validated, immediately before the cell-build loop. If
//     the import fails BEFORE begin (e.g. header truncation, file-size
//     mismatch, oversized cell-count) NEITHER begin NOR abort runs.
//   * `persist(cell)` is invoked exactly cell_count times in
//     topological order from leaves to root, AFTER begin.
//   * `finish(root_hash)` runs exactly once on the success path, after
//     every cell has been persisted, immediately before the importer
//     returns the root cell. `abort()` does NOT run on the success
//     path.
//   * `abort()` runs exactly once on any error path AFTER begin
//     succeeded — including persist returning Status::Error, finish
//     returning Status::Error, or any internal importer error caught
//     during the cell-build loop. abort never runs before begin.
//
// State-machine summary:
//   begin() -> persist(cell) * N -> finish(root_hash)
//                                -> commit_after_root_verified(expected)  (success, durable)
//   begin() -> persist(cell) * N -> finish(root_hash) -> abort()
//                                                  (root mismatch; nothing durable)
//   begin() -> persist(cell) * k -> abort()                   (any error after begin)
//   (no callbacks at all)                                     (error before begin)
//
// Sinks that have no durable state to commit (counting / validation /
// legacy paths) treat `commit_after_root_verified` as a no-op and may
// be skipped by callers; CellDb-backed sinks REQUIRE the explicit
// commit-after-verify step or the parsed cells are discarded.
//
// Implementations must be re-entrant only across distinct sinks: a
// single sink instance is owned by a single std_boc_deserialize_from_file_bounded
// call for the duration of that call. The importer never invokes any
// sink method from a different thread than the one that called
// std_boc_deserialize_from_file_bounded.
class StreamingCellSink {
 public:
  virtual ~StreamingCellSink() = default;

  virtual td::Status begin() {
    return td::Status::OK();
  }

  virtual td::Status persist(td::Ref<Cell> cell) = 0;

  // Phase-B extension point. A sink that writes cells into a persistent
  // backend may return a hash-only / lazy replacement for the cell it
  // just persisted. The importer will keep the returned cell in its
  // parent-ref table. The default implementation preserves legacy
  // behavior by persisting and returning the original DataCell-backed
  // reference. Implementations MUST return a non-null cell with the
  // same hash as the input; the importer checks this fail-closed.
  virtual td::Result<td::Ref<Cell>> persist_and_replace(td::Ref<Cell> cell) {
    auto keep = cell;
    TRY_STATUS(persist(std::move(cell)));
    return keep;
  }

  // The importer drives `finish` once the root cell has been parsed.
  // After tos26 P0-3 the contract is split: `finish` only RECORDS the
  // parsed root for sinks that override `commit_after_root_verified`,
  // and durable visibility (e.g. committing a CellDb write batch) is
  // deferred until the caller invokes `commit_after_root_verified`
  // with an externally trusted expected root. Sinks that have nothing
  // durable to commit (counting / validation / legacy paths) keep the
  // historical "finish == done" semantics and need not override the
  // commit hook.
  virtual td::Status finish(const Cell::Hash& root_hash) {
    (void)root_hash;
    return td::Status::OK();
  }

  // tos26 P0-3: split commit from finish so callers can verify the
  // imported root against an external expected hash before any cells
  // become visible to subsequent readers. The default implementation
  // is a no-op so legacy sinks (counting / validation) continue to
  // work. Real CellDb-backed sinks override this to commit their
  // pending batch only after the caller has confirmed `expected_root_hash`
  // matches the parsed root; on mismatch, the caller MUST instead call
  // `abort()` so the pending writes are discarded.
  virtual td::Status commit_after_root_verified(const Cell::Hash& expected_root_hash) {
    (void)expected_root_hash;
    return td::Status::OK();
  }

  virtual void abort() {
  }
};

// Backward-compatible callback type. A std::function<Status(Ref<Cell>)>
// is wrapped in an internal StreamingCellSink adapter by the importer;
// the adapter's begin/finish/abort are no-ops. Existing callers that
// already pass a raw lambda continue to compile unchanged.
using StreamingPersistCellFn = std::function<td::Status(td::Ref<Cell>)>;

td::Result<td::Ref<Cell>> std_boc_deserialize_from_file_bounded(
    td::FileFd& file, td::uint64 size, const StreamingBocImportOptions& opts,
    StreamingPersistCellFn persist_cell);

// Sink-based overload. Equivalent to the std::function variant but
// surfaces begin/finish/abort to the caller for a clean state-machine
// hook. `sink` may be nullptr — in that case the importer behaves
// exactly like the legacy std::function-empty path (cells live only
// through the returned root cell's DAG).
td::Result<td::Ref<Cell>> std_boc_deserialize_from_file_bounded(
    td::FileFd& file, td::uint64 size, const StreamingBocImportOptions& opts,
    StreamingCellSink* sink);

td::Result<std::vector<Ref<Cell>>> std_boc_deserialize_multi(td::Slice data,
                                                             int max_roots = BagOfCells::default_max_roots);
td::Result<td::BufferSlice> std_boc_serialize_multi(std::vector<Ref<Cell>> root, int mode = 0);

td::Status std_boc_serialize_to_file(Ref<Cell> root, td::FileFd& fd, int mode = 0,
                                     td::CancellationToken cancellation_token = {});
td::Status boc_serialize_to_file_large(std::shared_ptr<CellDbReader> reader, Cell::Hash root_hash, td::FileFd& fd,
                                       int mode = 0, td::CancellationToken cancellation_token = {});

}  // namespace vm
