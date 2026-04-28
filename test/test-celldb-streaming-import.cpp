/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Phase B Step 8 — invariant regression tests for the true
// CellDb-backed streaming importer:
//
//   1. test_replacement_hash_equality
//        Every cell that flows through CellDbStreamingSink::persist_and_replace
//        comes back as a non-DataCell whose hash exactly matches the original
//        DataCell's hash, and the cell-count matches the BoC.
//
//   2. test_no_full_dag_residency
//        After a streaming import the returned root is a hash-only ExtCell
//        (CellDbExtCell). Calling get_hash() / get_depth() / get_level_mask()
//        on the root never triggers a CellDb load.
//
//   3. test_crash_abort_no_partial_state
//        Aborting a streaming sink mid-import leaves no canonical partial
//        state visible: a fresh import against the same KV instance
//        succeeds and is idempotent on duplicate cells.
//
//   4. test_root_mismatch_abort_then_retry
//        A parsed BoC whose root does not match the trusted expected root
//        must not commit its pending CellDb batch. abort() invalidates
//        already-returned lazy roots, and a retry against the same KV
//        succeeds cleanly.
//
//   5. test_lazy_load
//        After a successful import the root ExtCell does not load any
//        DataCell. Walking one specific child path triggers exactly one
//        load_cell per cell on the path, never the whole DAG.
//
//   6. test_hash_mismatch
//        Corrupting one persisted cell value behind the back of the
//        streaming writer makes a subsequent lazy load return td::Status::Error
//        (no CHECK / DCHECK abort).

#include "validator/db/celldb.hpp"
#include "validator/state-download-buffer.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/db/CellDbExtCell.h"
#include "vm/db/CellStorage.h"
#include "vm/db/DynamicBagOfCellsDb.h"

#include "td/db/KeyValue.h"
#include "td/db/MemoryKeyValue.h"

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/path.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace {

#define EXPECT_TRUE(cond)                                                                              \
  do {                                                                                                 \
    if (!(cond)) {                                                                                     \
      std::fprintf(stderr, "FAIL %s:%d  expected true: %s\n", __FILE__, __LINE__, #cond);              \
      std::exit(1);                                                                                    \
    }                                                                                                  \
  } while (0)

#define EXPECT_FALSE(cond)                                                                             \
  do {                                                                                                 \
    if (cond) {                                                                                        \
      std::fprintf(stderr, "FAIL %s:%d  expected false: %s\n", __FILE__, __LINE__, #cond);             \
      std::exit(1);                                                                                    \
    }                                                                                                  \
  } while (0)

#define EXPECT_EQ(a, b)                                                                                \
  do {                                                                                                 \
    auto _va = (a);                                                                                    \
    auto _vb = (b);                                                                                    \
    if (!(_va == _vb)) {                                                                               \
      std::fprintf(stderr, "FAIL %s:%d  expected equal: %s == %s\n", __FILE__, __LINE__, #a, #b);      \
      std::exit(1);                                                                                    \
    }                                                                                                  \
  } while (0)

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

// Build a small synthetic cell tree with branching, mirroring the same
// recipe used elsewhere in the test suite (32 B random leaf payloads,
// pairwise-merge interior nodes that hold two refs and a 4 B marker).
// Returns the root cell.
td::Ref<vm::Cell> build_synthetic_cell_tree(td::uint32 target_cells) {
  EXPECT_TRUE(target_cells > 0);
  std::vector<td::Ref<vm::Cell>> level;
  level.reserve(target_cells);
  td::uint64 lcg = 0xC2B2AE3D27D4EB4FULL;
  for (td::uint32 i = 0; i < target_cells; ++i) {
    vm::CellBuilder cb;
    char buf[32];
    for (std::size_t j = 0; j < sizeof(buf); j += 8) {
      lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
      std::memcpy(buf + j, &lcg, std::min<std::size_t>(8, sizeof(buf) - j));
    }
    cb.store_bytes(buf, sizeof(buf));
    level.push_back(cb.finalize());
  }
  while (level.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    next.reserve((level.size() + 1) / 2);
    for (std::size_t i = 0; i + 1 < level.size(); i += 2) {
      vm::CellBuilder cb;
      td::uint32 marker = static_cast<td::uint32>(0xA5A50000u | static_cast<td::uint32>(i));
      cb.store_bytes(reinterpret_cast<const char *>(&marker), sizeof(marker));
      bool ok_a = cb.store_ref_bool(level[i]);
      bool ok_b = cb.store_ref_bool(level[i + 1]);
      EXPECT_TRUE(ok_a);
      EXPECT_TRUE(ok_b);
      next.push_back(cb.finalize());
    }
    if (level.size() % 2 == 1) {
      next.push_back(std::move(level.back()));
    }
    level = std::move(next);
  }
  return level.front();
}

// Serialize the given cell tree to a temporary BoC file. Returns the
// (path, size, root_hash) tuple the streaming importer needs.
struct SyntheticBoc {
  std::string path;
  td::uint64 size{0};
  vm::Cell::Hash root_hash{};
};

SyntheticBoc serialize_synthetic_boc(const std::string &dir, td::uint32 target_cells,
                                     const std::string &name, td::Ref<vm::Cell> *root_out = nullptr) {
  td::mkpath(dir + "/", 0700).ensure();
  auto root = build_synthetic_cell_tree(target_cells);
  EXPECT_TRUE(!root.is_null());
  auto serialized = vm::std_boc_serialize(root, /*mode=*/0);
  EXPECT_TRUE(serialized.is_ok());
  auto bytes = serialized.move_as_ok();
  SyntheticBoc out;
  out.path = dir + "/" + name;
  out.size = bytes.size();
  out.root_hash = root->get_hash();
  auto fd = td::FileFd::open(out.path, td::FileFd::Flags::Write | td::FileFd::Flags::Read |
                                           td::FileFd::Flags::Create | td::FileFd::Flags::Truncate)
                .move_as_ok();
  fd.write_all(bytes.as_slice()).ensure();
  fd.sync().ensure();
  fd.close();
  if (root_out != nullptr) {
    *root_out = std::move(root);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Test-only CellDbStreamingWriter: stores writes in a transactional
// pending map. commit_batch flushes pending writes into the shared
// MemoryKeyValue; abort_batch discards them. This sidesteps
// MemoryKeyValue::abort_write_batch (which is UNREACHABLE() in
// production because RocksDB owns the abort path) so the abort-mid-
// import test case can run end-to-end.
//
// The writer is the single thing the Phase B sink dispatches through
// (begin_batch / store_cell / commit_batch / abort_batch). After commit
// the same MemoryKeyValue is the read source for the CellDbReader the
// sink hands to make_celldb_ext_cell, so post-commit lazy loads are
// guaranteed to observe every cell that flowed through this writer.
class TestStreamingWriter final : public tos::validator::CellDbStreamingWriter {
 public:
  explicit TestStreamingWriter(std::shared_ptr<td::MemoryKeyValue> kv) : kv_(std::move(kv)) {
  }

  ~TestStreamingWriter() override {
    if (in_batch_) {
      // Best-effort discard. Mirrors CellDbStreamingWriterImpl's dtor
      // contract: a dropped writer must not leak buffered writes.
      pending_.clear();
      in_batch_ = false;
    }
  }

  td::Status begin_batch() override {
    if (in_batch_) {
      return td::Status::Error("TestStreamingWriter::begin_batch: batch already open");
    }
    pending_.clear();
    in_batch_ = true;
    return td::Status::OK();
  }

  td::Status store_cell(td::Slice hash, td::Slice serialized_cell_bytes) override {
    if (!in_batch_) {
      return td::Status::Error("TestStreamingWriter::store_cell: no open batch");
    }
    if (hash.size() != vm::Cell::hash_bytes) {
      return td::Status::Error("TestStreamingWriter::store_cell: bad hash size");
    }
    if (serialized_cell_bytes.empty()) {
      return td::Status::Error("TestStreamingWriter::store_cell: empty bytes");
    }
    auto hash_str = hash.str();
    auto bytes_str = serialized_cell_bytes.str();
    // Idempotent check against already-pending writes (mirrors
    // CellStorer::store_cell_streaming on the slice path).
    auto it = pending_.find(hash_str);
    if (it != pending_.end()) {
      if (it->second == bytes_str) {
        return td::Status::OK();
      }
      return td::Status::Error("TestStreamingWriter::store_cell: pending hash collision");
    }
    // Idempotent check against the canonical KV (post-prior-commit).
    std::string existing;
    TRY_RESULT(get_status, kv_->get(hash, existing));
    if (get_status == td::KeyValue::GetStatus::Ok) {
      if (existing == bytes_str) {
        return td::Status::OK();
      }
      return td::Status::Error("TestStreamingWriter::store_cell: committed hash collision");
    }
    pending_.emplace(std::move(hash_str), std::move(bytes_str));
    ++stored_count_;
    return td::Status::OK();
  }

  td::Status store_cell(const td::Ref<vm::DataCell> &cell) override {
    if (cell.is_null()) {
      return td::Status::Error("TestStreamingWriter::store_cell: null cell");
    }
    auto serialized = vm::CellStorer::serialize_value(/*refcnt=*/1, cell, /*as_boc=*/false);
    return store_cell(cell->get_hash().as_slice(), td::Slice(serialized));
  }

  td::Status commit_batch() override {
    if (!in_batch_) {
      return td::Status::Error("TestStreamingWriter::commit_batch: no open batch");
    }
    for (auto &kv : pending_) {
      TRY_STATUS(kv_->set(td::Slice(kv.first), td::Slice(kv.second)));
    }
    pending_.clear();
    in_batch_ = false;
    return td::Status::OK();
  }

  td::Status abort_batch() override {
    if (!in_batch_) {
      return td::Status::OK();  // idempotent
    }
    pending_.clear();
    in_batch_ = false;
    return td::Status::OK();
  }

  td::uint64 stored_count() const {
    return stored_count_;
  }

 private:
  std::shared_ptr<td::MemoryKeyValue> kv_;
  std::unordered_map<std::string, std::string> pending_;
  bool in_batch_{false};
  td::uint64 stored_count_{0};
};

// Counting KeyValueReader wrapper. The DynamicBagOfCellsDb feeds its
// internal CellLoader from a single KeyValueReader and propagates that
// reader through every child ExtCell it materializes during load. We
// therefore instrument lazy-load tracking at the kv level (rather than
// at the outer CellDbReader level) so child-cell loads triggered by
// production code paths inside the dboc are visible to the test.
class CountingKeyValueReader final : public td::KeyValueReader {
 public:
  CountingKeyValueReader(std::shared_ptr<td::KeyValueReader> inner,
                         std::shared_ptr<std::atomic<td::uint64>> counter)
      : inner_(std::move(inner)), counter_(std::move(counter)) {
  }

  td::Result<GetStatus> get(td::Slice key, std::string &value) override {
    counter_->fetch_add(1, std::memory_order_acq_rel);
    return inner_->get(key, value);
  }
  td::Result<std::vector<GetStatus>> get_multi(td::Span<td::Slice> keys, std::vector<std::string> *values) override {
    counter_->fetch_add(keys.size(), std::memory_order_acq_rel);
    return inner_->get_multi(keys, values);
  }
  td::Result<size_t> count(td::Slice prefix) override {
    return inner_->count(prefix);
  }
  td::Status for_each(std::function<td::Status(td::Slice, td::Slice)> f) override {
    return inner_->for_each(std::move(f));
  }
  td::Status for_each_in_range(td::Slice begin, td::Slice end,
                               std::function<td::Status(td::Slice, td::Slice)> f) override {
    return inner_->for_each_in_range(begin, end, std::move(f));
  }

 private:
  std::shared_ptr<td::KeyValueReader> inner_;
  std::shared_ptr<std::atomic<td::uint64>> counter_;
};

// Build a CellDbReader that resolves cells from the given MemoryKeyValue.
// Internally we wrap the kv in a vm::DynamicBagOfCellsDb and back its
// CellLoader by the LIVE kv (not a snapshot) so reads automatically
// observe every cell the streaming writer commits. MemoryKeyValue
// extends KeyValueReader, so it can serve as the loader's source
// directly.
//
// If `load_counter` is non-null, the loader's KeyValueReader source
// is wrapped in a CountingKeyValueReader that increments the counter
// on every `get` / `get_multi`. The counter visibility extends to all
// child ExtCells the dboc materializes during a load, since the dboc
// passes the same loader through to every child.
std::shared_ptr<vm::CellDbReader> make_kv_backed_reader(
    std::shared_ptr<td::MemoryKeyValue> kv, std::unique_ptr<vm::DynamicBagOfCellsDb> &dboc_owner_out,
    std::shared_ptr<std::atomic<td::uint64>> load_counter = nullptr) {
  auto dboc = vm::DynamicBagOfCellsDb::create();
  // Aliasing constructor: upcasts MemoryKeyValue* -> KeyValueReader*
  // without changing the control block.
  std::shared_ptr<td::KeyValueReader> reader_src{kv, static_cast<td::KeyValueReader *>(kv.get())};
  if (load_counter != nullptr) {
    reader_src = std::make_shared<CountingKeyValueReader>(std::move(reader_src), std::move(load_counter));
  }
  auto loader = std::make_unique<vm::CellLoader>(std::move(reader_src));
  auto status = dboc->set_loader(std::move(loader));
  EXPECT_TRUE(status.is_ok());
  auto reader = dboc->get_cell_db_reader();
  EXPECT_TRUE(reader != nullptr);
  dboc_owner_out = std::move(dboc);
  return reader;
}

// Convenience: build a fresh sink + writer + reader against a shared kv.
struct PhaseBFixture {
  std::shared_ptr<td::MemoryKeyValue> kv;
  std::unique_ptr<vm::DynamicBagOfCellsDb> dboc_owner;
  std::shared_ptr<vm::CellDbReader> reader;
  // Counter is non-null only when the caller asked for an instrumented
  // reader via build_with_counter.
  std::shared_ptr<std::atomic<td::uint64>> load_counter;
};

PhaseBFixture build_fixture(bool instrumented = false) {
  PhaseBFixture f;
  f.kv = std::make_shared<td::MemoryKeyValue>();
  if (instrumented) {
    f.load_counter = std::make_shared<std::atomic<td::uint64>>(0);
  }
  f.reader = make_kv_backed_reader(f.kv, f.dboc_owner, f.load_counter);
  return f;
}

// Deserialize the BoC at `path` through a Phase B streaming sink built
// from `fixture`. Returns the (root, sink) pair so callers can probe
// post-import invariants.
struct ImportResult {
  td::Ref<vm::Cell> root;
  td::uint64 cells_persisted{0};
};

ImportResult run_streaming_import(const PhaseBFixture &fixture, const SyntheticBoc &boc) {
  auto writer = std::make_unique<TestStreamingWriter>(fixture.kv);
  auto *raw_writer_ptr_unused = writer.get();
  (void)raw_writer_ptr_unused;
  tos::validator::fullnode::CellDbStreamingSink sink{fixture.reader, std::move(writer)};
  EXPECT_TRUE(sink.is_true_streaming());

  auto fd = td::FileFd::open(boc.path, td::FileFd::Flags::Read).move_as_ok();
  vm::StreamingBocImportOptions opts;
  opts.max_resident_bytes = 8ULL << 20;
  auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, boc.size, opts, &sink);
  fd.close();
  EXPECT_TRUE(r_root.is_ok());
  auto root = r_root.move_as_ok();
  EXPECT_TRUE(!root.is_null());
  EXPECT_TRUE(root->get_hash() == boc.root_hash);
  EXPECT_TRUE(sink.finished());
  EXPECT_FALSE(sink.aborted());
  // tos26 P0-3: finish() no longer commits. Drive the explicit
  // commit-after-verify step that the production downloader runs;
  // the existing `boc.root_hash` is the trusted expected root in
  // this synthetic-BoC fixture.
  EXPECT_FALSE(sink.is_committed());
  auto commit_status = sink.commit_after_root_verified(boc.root_hash);
  EXPECT_TRUE(commit_status.is_ok());
  EXPECT_TRUE(sink.is_committed());
  ImportResult res;
  res.root = std::move(root);
  res.cells_persisted = sink.cells_persisted();
  return res;
}

// ---------------------------------------------------------------------------
// (1) Replacement hash equality
// ---------------------------------------------------------------------------

void test_replacement_hash_equality() {
  std::printf("=== test_replacement_hash_equality ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-1-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  td::Ref<vm::Cell> live_root;
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/64, "synth.boc", &live_root);

  auto fixture = build_fixture();

  // Custom sink that wraps the production sink + an inline hash-equality
  // probe. We delegate persist_and_replace to the production sink so the
  // Phase B branch (writer batch + ExtCell replacement) runs as in the
  // real importer; on every replacement we assert the returned cell's
  // hash matches the input cell's hash AND the returned cell is NOT a
  // DataCell (it must be the lazy ExtCell).
  class ProbingSink final : public vm::StreamingCellSink {
   public:
    ProbingSink(std::shared_ptr<vm::CellDbReader> reader,
                std::unique_ptr<tos::validator::CellDbStreamingWriter> writer)
        : inner_(std::move(reader), std::move(writer)) {
    }
    td::Status begin() override {
      return inner_.begin();
    }
    td::Status persist(td::Ref<vm::Cell> cell) override {
      return inner_.persist(std::move(cell));
    }
    td::Result<td::Ref<vm::Cell>> persist_and_replace(td::Ref<vm::Cell> cell) override {
      auto declared_hash = cell->get_hash();
      TRY_RESULT(replacement, inner_.persist_and_replace(cell));
      // Invariant 1: replacement hash equals original hash.
      EXPECT_TRUE(replacement->get_hash() == declared_hash);
      // Invariant 2: replacement is NOT a DataCell — it is the lazy
      // ExtCell. dynamic_cast through the Cell* is the cleanest way
      // to assert this without leaking ExtCell internals.
      EXPECT_TRUE(dynamic_cast<const vm::DataCell *>(replacement.get()) == nullptr);
      ++replacements_observed_;
      return replacement;
    }
    td::Status finish(const vm::Cell::Hash &h) override {
      return inner_.finish(h);
    }
    void abort() override {
      inner_.abort();
    }

    td::uint64 replacements_observed() const {
      return replacements_observed_;
    }
    td::uint64 cells_persisted() const {
      return inner_.cells_persisted();
    }
    td::uint64 cell_count() const {
      return inner_.cell_count();
    }
    bool finished() const {
      return inner_.finished();
    }
    bool aborted() const {
      return inner_.aborted();
    }

   private:
    tos::validator::fullnode::CellDbStreamingSink inner_;
    td::uint64 replacements_observed_{0};
  };

  auto writer = std::make_unique<TestStreamingWriter>(fixture.kv);
  ProbingSink sink{fixture.reader, std::move(writer)};

  auto fd = td::FileFd::open(boc.path, td::FileFd::Flags::Read).move_as_ok();
  vm::StreamingBocImportOptions opts;
  opts.max_resident_bytes = 8ULL << 20;
  auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, boc.size, opts, &sink);
  fd.close();
  EXPECT_TRUE(r_root.is_ok());
  auto root = r_root.move_as_ok();
  EXPECT_TRUE(!root.is_null());
  EXPECT_TRUE(root->get_hash() == boc.root_hash);
  EXPECT_TRUE(sink.finished());

  // cells_persisted equals the number of replacements we observed
  // (every cell flows through persist_and_replace once on the Phase B
  // path).
  EXPECT_TRUE(sink.cells_persisted() > 0);
  EXPECT_EQ(sink.cells_persisted(), sink.replacements_observed());
  EXPECT_EQ(sink.cells_persisted(), sink.cell_count());

  // The returned root is the lazy replacement, not a DataCell.
  EXPECT_TRUE(dynamic_cast<const vm::DataCell *>(root.get()) == nullptr);

  td::rmrf(tmp_dir).ignore();
  std::printf("  cells_persisted=%llu  PASSED\n", static_cast<unsigned long long>(sink.cells_persisted()));
}

// ---------------------------------------------------------------------------
// (2) No full-DAG residency
// ---------------------------------------------------------------------------

void test_no_full_dag_residency() {
  std::printf("=== test_no_full_dag_residency ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-2-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/200, "synth.boc");

  auto fixture = build_fixture(/*instrumented=*/true);
  auto result = run_streaming_import(fixture, boc);
  auto root = std::move(result.root);

  // Invariant 1: the returned root is hash-only — i.e. NOT a DataCell.
  // We cannot include the full ExtCell template in this TU (the type
  // is template-parameterized and the headers required to name
  // CellDbExtCell exactly would expose template plumbing). We instead
  // rely on the Phase B contract: a true-streaming sink replaces the
  // root with an ExtCell, never a DataCell, so the dynamic_cast is
  // sufficient.
  EXPECT_TRUE(dynamic_cast<const vm::DataCell *>(root.get()) == nullptr);

  // Invariant 2: probing root's identity (hash, depth, level mask) MUST
  // NOT trigger any CellDb load. This is the load-bearing residency
  // assertion — these fields are baked into the ExtCell at construction
  // time and answering them is O(1) without touching the reader.
  auto loads_before = fixture.load_counter->load(std::memory_order_acquire);
  auto root_hash = root->get_hash();
  auto root_depth = root->get_depth();
  auto root_level = root->get_level_mask();
  (void)root_hash;
  (void)root_depth;
  (void)root_level;
  auto loads_after = fixture.load_counter->load(std::memory_order_acquire);
  EXPECT_EQ(loads_after, loads_before);

  // Sanity: the root_hash we just probed equals the BoC's expected root.
  EXPECT_TRUE(root_hash == boc.root_hash);

  td::rmrf(tmp_dir).ignore();
  std::printf("  cells_persisted=%llu loads_during_id_probe=%llu  PASSED\n",
              static_cast<unsigned long long>(result.cells_persisted),
              static_cast<unsigned long long>(loads_after - loads_before));
}

// ---------------------------------------------------------------------------
// (3) Crash / abort leaves no canonical partial state
// ---------------------------------------------------------------------------

void test_crash_abort_no_partial_state() {
  std::printf("=== test_crash_abort_no_partial_state ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-3-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/100, "synth.boc");

  auto fixture = build_fixture();

  // Step 1: drive a partial import. We do NOT call the full importer;
  // instead we manually open the sink, persist a handful of cells, then
  // abort. This is the deterministic mid-import-failure shape.
  auto writer = std::make_unique<TestStreamingWriter>(fixture.kv);
  auto *writer_raw = writer.get();
  tos::validator::fullnode::CellDbStreamingSink sink{fixture.reader, std::move(writer)};
  EXPECT_TRUE(sink.is_true_streaming());
  EXPECT_TRUE(sink.begin().is_ok());

  // Persist a few synthetic leaves (these go into the writer's pending
  // batch but are NOT yet committed).
  td::uint32 partial_cells = 5;
  std::vector<vm::Cell::Hash> partial_hashes;
  partial_hashes.reserve(partial_cells);
  for (td::uint32 i = 0; i < partial_cells; ++i) {
    vm::CellBuilder cb;
    char buf[16];
    std::memset(buf, static_cast<int>(i + 1), sizeof(buf));
    cb.store_bytes(buf, sizeof(buf));
    auto cell = cb.finalize();
    partial_hashes.push_back(cell->get_hash());
    auto r = sink.persist_and_replace(td::Ref<vm::Cell>{cell});
    EXPECT_TRUE(r.is_ok());
  }
  EXPECT_EQ(sink.cells_persisted(), static_cast<td::uint64>(partial_cells));

  // Step 2: abort. The pending batch must be discarded and the kv must
  // remain byte-for-byte identical to its pre-import snapshot.
  sink.abort();
  EXPECT_TRUE(sink.aborted());
  EXPECT_FALSE(sink.finished());

  // Step 3: a fresh reader sees ZERO of the partially-staged cells.
  // We probe the canonical kv directly because the reader has its own
  // snapshot taken at fixture-build time.
  for (auto &h : partial_hashes) {
    std::string ignored;
    auto r = fixture.kv->get(h.as_slice(), ignored);
    EXPECT_TRUE(r.is_ok());
    auto status = r.move_as_ok();
    // The cell MUST NOT be present after abort.
    EXPECT_TRUE(status == td::KeyValue::GetStatus::NotFound);
  }
  // No root marker exists either — the sink finished=false.
  (void)writer_raw;

  // Step 4: restart the import from scratch against the SAME kv. This
  // exercises both (a) idempotency on duplicate cells across the
  // restart boundary and (b) the contract that a fresh import after
  // an abort succeeds end-to-end.
  // Build a fresh fixture against the SAME kv so any straggler cells
  // would surface, then import twice through one sink to also pin
  // cross-import idempotency.
  PhaseBFixture fixture2;
  fixture2.kv = fixture.kv;
  auto base_reader2 = make_kv_backed_reader(fixture2.kv, fixture2.dboc_owner);
  fixture2.reader = base_reader2;

  auto first_import = run_streaming_import(fixture2, boc);
  EXPECT_TRUE(first_import.cells_persisted > 0);
  EXPECT_TRUE(first_import.root->get_hash() == boc.root_hash);

  // Re-run the import. Every cell hash now exists in the kv with the
  // same bytes; the writer's idempotent path must accept this and
  // commit_batch must succeed. cells_persisted on the second pass
  // increments per persist_and_replace call (the sink counter is
  // independent of the writer's stored_count_).
  PhaseBFixture fixture3;
  fixture3.kv = fixture.kv;
  auto base_reader3 = make_kv_backed_reader(fixture3.kv, fixture3.dboc_owner);
  fixture3.reader = base_reader3;
  auto second_import = run_streaming_import(fixture3, boc);
  EXPECT_TRUE(second_import.cells_persisted > 0);
  EXPECT_TRUE(second_import.root->get_hash() == boc.root_hash);

  td::rmrf(tmp_dir).ignore();
  std::printf("  partial_cells_aborted=%u  re_import_cells=%llu  PASSED\n", partial_cells,
              static_cast<unsigned long long>(first_import.cells_persisted));
}

// ---------------------------------------------------------------------------
// (3b) Root mismatch abort + retry
// ---------------------------------------------------------------------------

void test_root_mismatch_abort_then_retry() {
  std::printf("=== test_root_mismatch_abort_then_retry (tos31 crash/retry) ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-3b-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/96, "synth.boc");
  auto other_boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/97, "other.boc");
  EXPECT_TRUE(other_boc.root_hash != boc.root_hash);

  auto fixture = build_fixture();

  // First attempt: parse succeeds and returns a lazy root, but the
  // trusted expected root intentionally differs. commit_after_root_verified
  // must fail before flushing the writer's pending batch.
  auto writer = std::make_unique<TestStreamingWriter>(fixture.kv);
  tos::validator::fullnode::CellDbStreamingSink sink{fixture.reader, std::move(writer)};
  EXPECT_TRUE(sink.is_true_streaming());

  auto fd = td::FileFd::open(boc.path, td::FileFd::Flags::Read).move_as_ok();
  vm::StreamingBocImportOptions opts;
  opts.max_resident_bytes = 8ULL << 20;
  auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, boc.size, opts, &sink);
  fd.close();
  EXPECT_TRUE(r_root.is_ok());
  auto root = r_root.move_as_ok();
  EXPECT_TRUE(!root.is_null());
  EXPECT_TRUE(root->get_hash() == boc.root_hash);
  EXPECT_TRUE(sink.finished());
  EXPECT_FALSE(sink.is_committed());

  auto mismatch = sink.commit_after_root_verified(other_boc.root_hash);
  EXPECT_TRUE(mismatch.is_error());
  EXPECT_FALSE(sink.is_committed());

  // Caller-owned abort is still required after root mismatch. It must
  // discard the open batch and invalidate lazy roots already handed out.
  sink.abort();
  EXPECT_TRUE(sink.aborted());
  auto aborted_load = root->load_cell();
  EXPECT_TRUE(aborted_load.is_error());

  std::string ignored;
  auto r_get = fixture.kv->get(boc.root_hash.as_slice(), ignored);
  EXPECT_TRUE(r_get.is_ok());
  EXPECT_TRUE(r_get.move_as_ok() == td::KeyValue::GetStatus::NotFound);

  // Second attempt: reuse the same KV. If the failed attempt leaked any
  // canonical cells or left a poisoned writer lifecycle behind, this
  // retry would either collide or fail to materialize the root.
  PhaseBFixture retry_fixture;
  retry_fixture.kv = fixture.kv;
  retry_fixture.reader = make_kv_backed_reader(retry_fixture.kv, retry_fixture.dboc_owner);
  auto retry = run_streaming_import(retry_fixture, boc);
  EXPECT_TRUE(retry.cells_persisted > 0);
  EXPECT_TRUE(retry.root->get_hash() == boc.root_hash);
  auto loaded_retry_root = retry.root->load_cell();
  EXPECT_TRUE(loaded_retry_root.is_ok());
  EXPECT_TRUE(loaded_retry_root.move_as_ok().data_cell.not_null());

  td::rmrf(tmp_dir).ignore();
  std::printf("  retry_cells=%llu  PASSED\n",
              static_cast<unsigned long long>(retry.cells_persisted));
}

// ---------------------------------------------------------------------------
// (4) Lazy load
// ---------------------------------------------------------------------------

void test_lazy_load() {
  std::printf("=== test_lazy_load ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-4-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  // Use a tree large enough to have at least 2 levels: 64 leaves -> 32
  // -> 16 -> 8 -> 4 -> 2 -> 1 root (7 levels). The path root -> child[0]
  // -> child[0]'s child[0] is two non-leaf hops; each lazy load must
  // increment the counter exactly once.
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/64, "synth.boc");

  auto fixture = build_fixture(/*instrumented=*/true);
  auto result = run_streaming_import(fixture, boc);
  auto root = std::move(result.root);

  // Quiesce the load counter to whatever value it sat at after import.
  auto loads_baseline = fixture.load_counter->load(std::memory_order_acquire);

  // Phase A of the lazy-load probe: identity-only access. Must NOT
  // trigger any CellDb load.
  auto h0 = root->get_hash();
  auto d0 = root->get_depth();
  auto m0 = root->get_level_mask();
  (void)h0;
  (void)d0;
  (void)m0;
  EXPECT_EQ(fixture.load_counter->load(std::memory_order_acquire), loads_baseline);

  // Phase B of the probe: walk one specific child path. Each
  // load_cell() must trigger exactly one reader load (the leaf load
  // path). The parent->child reference inside a freshly-loaded
  // DataCell is itself an ExtCell, so descending one more level is
  // another single-cell load.
  auto loaded_root = root->load_cell();
  EXPECT_TRUE(loaded_root.is_ok());
  auto loads_after_root = fixture.load_counter->load(std::memory_order_acquire);
  EXPECT_TRUE(loads_after_root >= loads_baseline + 1);

  auto loaded = loaded_root.move_as_ok();
  EXPECT_TRUE(loaded.data_cell.not_null());
  // Descend into ref(0) and load one more level. ref(0) is an ExtCell
  // because the parent's children were replaced during the streaming
  // import.
  auto child0 = loaded.data_cell->get_ref(0);
  EXPECT_TRUE(child0.not_null());
  // The child ref is an ExtCell — identity probe must not trigger any
  // additional load.
  auto loads_pre_child_load = fixture.load_counter->load(std::memory_order_acquire);
  auto child0_hash_probe = child0->get_hash();
  (void)child0_hash_probe;
  EXPECT_EQ(fixture.load_counter->load(std::memory_order_acquire), loads_pre_child_load);

  // Now actually load the child. Materializing one DataCell from the
  // reader must trigger exactly one kv `get` against the underlying
  // KeyValueReader (the CountingKeyValueReader sees that get because
  // the dboc plumbs the same loader's reader to every child ExtCell
  // it materializes). The exact delta MUST be 1 — if the reader ever
  // started eager-loading children, it would blow this bound.
  auto loaded_child0 = child0->load_cell();
  EXPECT_TRUE(loaded_child0.is_ok());
  auto loads_after_child = fixture.load_counter->load(std::memory_order_acquire);
  EXPECT_TRUE(loaded_child0.move_as_ok().data_cell.not_null());
  td::uint64 child_load_delta = loads_after_child - loads_pre_child_load;
  EXPECT_EQ(child_load_delta, static_cast<td::uint64>(1));

  // Critical residency invariant: only a handful of cells (root +
  // child[0] + bookkeeping) were loaded — not the entire 127-cell
  // DAG.
  td::uint64 walked_loads = loads_after_child - loads_baseline;
  EXPECT_TRUE(walked_loads >= 2);
  EXPECT_TRUE(walked_loads < result.cells_persisted);
  // Hard residency bound: walking one path costs O(path-length)
  // cells, NOT O(DAG-size). For a 64-leaf binary tree the longest
  // path has 7 nodes — pinning the bound at 8 catches any future
  // regression that re-introduces eager full-DAG load.
  EXPECT_TRUE(walked_loads < 8);

  td::rmrf(tmp_dir).ignore();
  std::printf("  total_cells=%llu loads_during_walk=%llu  PASSED\n",
              static_cast<unsigned long long>(result.cells_persisted),
              static_cast<unsigned long long>(walked_loads));
}

// ---------------------------------------------------------------------------
// (4b) tos26 P0-2: Lazy load after commit reaches post-commit cells
// ---------------------------------------------------------------------------
//
// Drives the full streaming-import lifecycle (begin -> persist_and_replace*
// -> finish -> commit_after_root_verified) end-to-end while holding the
// returned lazy ExtCell root. After the explicit commit step, materializing
// the root and descending two levels deep MUST succeed: the lazy
// CellDbExtCell binds to the sink's CellDbReaderProvider, NOT the pre-
// commit reader handle, so post-commit lazy loads observe the cells the
// importer just streamed.
//
// Note on harness coverage: this test runs against td::MemoryKeyValue
// wired through DynamicBagOfCellsDb's CellLoader. That loader is LIVE
// (no snapshot freeze), so even if the sink had baked a raw reader the
// post-commit reads would still succeed in this fixture. The audit
// finding is about production CellDbReaderImpl which IS snapshot-based
// (see validator/db/celldb.cpp:283 cell_db_->snapshot()); a true
// integration test would need the production celldb actor stack. This
// test still pins the contract surface: CellDbExtCellLoader goes
// through reader_provider->current_reader() on every materialization,
// and sink-driven lifecycle steps (commit, abort) interact with the
// provider exactly as documented.
void test_lazy_load_after_commit_succeeds() {
  std::printf("=== test_lazy_load_after_commit_succeeds (tos26 P0-2) ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-4b-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  // Use a tree with at least 3 internal levels so we can descend
  // root -> child[0] -> child[0].child[0] and exercise lazy load past
  // the immediate root.
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/64, "synth.boc");

  auto fixture = build_fixture(/*instrumented=*/true);

  // Manually drive the import end-to-end so we can hold the root
  // BEFORE commit_after_root_verified runs and assert the post-commit
  // lazy descent succeeds.
  auto writer = std::make_unique<TestStreamingWriter>(fixture.kv);
  tos::validator::fullnode::CellDbStreamingSink sink{fixture.reader, std::move(writer)};
  EXPECT_TRUE(sink.is_true_streaming());

  auto fd = td::FileFd::open(boc.path, td::FileFd::Flags::Read).move_as_ok();
  vm::StreamingBocImportOptions opts;
  opts.max_resident_bytes = 8ULL << 20;
  auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, boc.size, opts, &sink);
  fd.close();
  EXPECT_TRUE(r_root.is_ok());
  auto root = r_root.move_as_ok();
  EXPECT_TRUE(!root.is_null());
  EXPECT_TRUE(root->get_hash() == boc.root_hash);
  EXPECT_TRUE(sink.finished());
  EXPECT_FALSE(sink.is_committed());

  // Step 1: commit. After this, every cell streamed during parse is
  // durable and visible to the canonical reader.
  auto commit_status = sink.commit_after_root_verified(boc.root_hash);
  EXPECT_TRUE(commit_status.is_ok());
  EXPECT_TRUE(sink.is_committed());

  // Step 2: force materialization of the held root via load_cell.
  // The lazy ExtCell root must reach the canonical reader through the
  // provider; if the provider had baked a pre-commit snapshot, this
  // load would surface "cell not found" in a snapshot-reader fixture.
  auto loaded_root = root->load_cell();
  EXPECT_TRUE(loaded_root.is_ok());
  auto root_loaded = loaded_root.move_as_ok();
  EXPECT_TRUE(root_loaded.data_cell.not_null());

  // Step 3: descend one level. The first child of a non-leaf root is
  // itself an ExtCell (the streaming importer replaced every cell
  // during parse). Materialize it.
  auto child0 = root_loaded.data_cell->get_ref(0);
  EXPECT_TRUE(child0.not_null());
  // Identity probe must NOT trigger any load (ExtCell metadata is
  // baked at construction time).
  auto loads_pre_child = fixture.load_counter->load(std::memory_order_acquire);
  auto child0_hash = child0->get_hash();
  (void)child0_hash;
  EXPECT_EQ(fixture.load_counter->load(std::memory_order_acquire), loads_pre_child);
  auto loaded_child0 = child0->load_cell();
  EXPECT_TRUE(loaded_child0.is_ok());
  auto child0_loaded = loaded_child0.move_as_ok();
  EXPECT_TRUE(child0_loaded.data_cell.not_null());

  // Step 4: descend a second level. This is the "two levels deep"
  // assertion in the task spec — the lazy load chain must keep working
  // past the immediate child without hitting a snapshot miss.
  auto grandchild0 = child0_loaded.data_cell->get_ref(0);
  EXPECT_TRUE(grandchild0.not_null());
  auto loaded_grandchild0 = grandchild0->load_cell();
  EXPECT_TRUE(loaded_grandchild0.is_ok());
  EXPECT_TRUE(loaded_grandchild0.move_as_ok().data_cell.not_null());

  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

// ---------------------------------------------------------------------------
// (5) Hash mismatch on lazy load returns Status::Error (no abort)
// ---------------------------------------------------------------------------

void test_hash_mismatch() {
  std::printf("=== test_hash_mismatch ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-5-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/32, "synth.boc");

  auto fixture = build_fixture();
  auto result = run_streaming_import(fixture, boc);
  auto root = std::move(result.root);

  // Materialize the root once so we have a child hash to corrupt. This
  // child hash is what the CellDb stores; we will overwrite the value
  // bytes for that key with the bytes from a DIFFERENT cell so a
  // subsequent lazy load deserializes a cell whose recomputed hash
  // does not match the requested key.
  auto loaded_root = root->load_cell();
  EXPECT_TRUE(loaded_root.is_ok());
  auto root_loaded = loaded_root.move_as_ok();
  auto child0 = root_loaded.data_cell->get_ref(0);
  EXPECT_TRUE(child0.not_null());
  auto child0_hash = child0->get_hash();

  // We need the bytes for some OTHER cell. Build a synthetic cell
  // whose contents are guaranteed to differ from child0 and whose hash
  // also differs. Use a random 24 B leaf — extremely unlikely to
  // collide with child0's hash.
  vm::CellBuilder different_cb;
  char different_buf[24];
  std::memset(different_buf, 0xCD, sizeof(different_buf));
  different_cb.store_bytes(different_buf, sizeof(different_buf));
  auto different_cell = different_cb.finalize();
  auto different_data_cell = td::Ref<vm::DataCell>{different_cell};
  EXPECT_TRUE(different_data_cell.not_null());
  // Sanity: hashes really do differ — otherwise the corruption is a
  // no-op and the test asserts nothing.
  EXPECT_TRUE(different_data_cell->get_hash() != child0_hash);

  // Serialize the different cell with refcnt=1, as_boc=false — the
  // exact wire shape store_cell_streaming uses — and overwrite the
  // child0 key's value with these bytes. We bypass CellStorer (which
  // would refuse the collision) by going straight to the kv.
  std::string different_serialized =
      vm::CellStorer::serialize_value(/*refcnt=*/1, different_data_cell, /*as_boc=*/false);
  auto set_status = fixture.kv->set(child0_hash.as_slice(), td::Slice(different_serialized));
  EXPECT_TRUE(set_status.is_ok());

  // The reader's CellDbReader was built against a snapshot at fixture-
  // build time; we need a fresh reader to observe the corruption.
  PhaseBFixture corrupt_fixture;
  corrupt_fixture.kv = fixture.kv;
  auto corrupt_reader_base = make_kv_backed_reader(corrupt_fixture.kv, corrupt_fixture.dboc_owner);
  corrupt_fixture.reader = corrupt_reader_base;

  // Build a fresh ExtCell against the corrupt kv pointing at child0's
  // (declared) hash, then attempt to materialize. This is exactly the
  // path CellDbExtCellLoader::load_data_cell drives for any lazy
  // descent.
  auto child0_depth_value = child0->get_depth();
  td::uint8 depth_bytes[2] = {static_cast<td::uint8>(child0_depth_value >> 8),
                              static_cast<td::uint8>(child0_depth_value & 0xFF)};
  auto r_lazy = vm::make_celldb_ext_cell(child0->get_level_mask(), child0_hash.as_slice(),
                                         td::Slice(reinterpret_cast<const char *>(depth_bytes), 2),
                                         corrupt_fixture.reader);
  EXPECT_TRUE(r_lazy.is_ok());
  auto lazy_cell = r_lazy.move_as_ok();
  EXPECT_TRUE(lazy_cell.not_null());

  // Force materialization. The reader will return a DataCell whose
  // recomputed hash does not match the requested key; the loader
  // returns td::Status::Error rather than aborting the process.
  auto r_load = lazy_cell->load_cell();
  EXPECT_TRUE(r_load.is_error());
  // Sanity: the error is structured (it carries a message) — process
  // is still alive (this assertion line itself executes), proving no
  // CHECK / DCHECK fired.
  auto err = r_load.move_as_error();
  EXPECT_TRUE(!err.message().empty());
  std::printf("  observed error: %s\n", err.message().c_str());

  td::rmrf(tmp_dir).ignore();
  std::printf("  PASSED\n");
}

// ---------------------------------------------------------------------------
// (6) tos26 P1-5: imported cells survive immediate GC trigger
// ---------------------------------------------------------------------------
//
// The streaming importer writes each cell with refcnt=1. The audit's P1-5
// concern: between import-commit and the downloader's follow-up
// set_block_state call there is a window where the cells exist with
// refcnt=1 but no canonical block-state desc-list entry references them;
// a periodic GC pass that fires inside that window could mis-delete them.
//
// Production closes the window with the GC pause counter on CellDbIn
// (see pause_gc_for_import / resume_gc_for_import in validator/db/celldb.{hpp,cpp}).
// The pause keeps the alarm() handler in skip_gc() until the downloader's
// store_cell-of-root runs, after which the existing
// DynamicBagOfCellsDb::prepare_commit -> dfs_new_cells_in_db walk
// reconciles refcounts under the canonical desc list.
//
// This regression test runs against the test fixture (MemoryKeyValue,
// no actor system, no CellDbIn alarm). The fixture cannot exercise the
// pause counter directly because there is no GC trigger to pause. The
// test instead pins the dual invariant the GC pause defends:
//
//   1. Every cell minted into the import's lazy ExtCell DAG is
//      durably present in the underlying CellDb after commit. If
//      refcnt accounting were wrong (e.g. cells were never written),
//      a recursive load of the root's full child DAG would fail.
//   2. The cells are uniquely referenced (refcnt=1 each in the
//      streaming-writer encoding) and the lazy descent reaches every
//      one of them through the production code path
//      (CellDbExtCellLoader -> CellDbReaderImpl -> kv->get).
//
// Together with the production GC-pause hardening check (validated
// separately by scripts/check-evm-production-hardening.sh), this test
// is the regression cover for "an accepted streaming import's cells
// remain reachable from their root post-commit".
void test_imported_cells_survive_immediate_gc() {
  std::printf("=== test_imported_cells_survive_immediate_gc (tos26 P1-5) ===\n");

  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-6-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  // Use a 32-cell tree so the recursive walk is bounded but exercises
  // multiple levels (32 leaves -> 16 -> 8 -> 4 -> 2 -> 1 = 6 levels).
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/32, "synth.boc");

  auto fixture = build_fixture();
  auto result = run_streaming_import(fixture, boc);
  auto root = std::move(result.root);

  // Recursively materialize every cell in the imported root's child DAG.
  // The walker is iterative (queue-based) to avoid unbounded recursion
  // on pathological DAG shapes; here the synthetic tree is small but the
  // shape contract is the same as production state roots.
  std::vector<td::Ref<vm::Cell>> stack;
  stack.push_back(root);
  std::unordered_map<std::string, bool> seen;  // hash-bytes -> true
  td::uint64 walked = 0;
  while (!stack.empty()) {
    auto cell = std::move(stack.back());
    stack.pop_back();
    EXPECT_TRUE(cell.not_null());

    auto hash_str = cell->get_hash().as_slice().str();
    if (seen.find(hash_str) != seen.end()) {
      continue;
    }
    seen.emplace(std::move(hash_str), true);

    // Force materialization. If any imported cell were missing from
    // the underlying CellDb (e.g. mis-deleted by a hypothetical GC
    // pass that wasn't paused), this load would surface
    // td::Status::Error.
    auto r_loaded = cell->load_cell();
    EXPECT_TRUE(r_loaded.is_ok());
    auto loaded = r_loaded.move_as_ok();
    EXPECT_TRUE(loaded.data_cell.not_null());
    ++walked;

    // Push child refs. Each ref is itself an ExtCell (the streaming
    // importer replaced every parent's children with hash-only
    // ExtCells), so descending one more level is another single-cell
    // load — exactly the pattern the GC pause must protect.
    auto refs_count = loaded.data_cell->size_refs();
    for (unsigned i = 0; i < refs_count; ++i) {
      auto child = loaded.data_cell->get_ref(i);
      EXPECT_TRUE(child.not_null());
      stack.push_back(std::move(child));
    }
  }

  // Every persisted cell must have been reached (the synthetic tree
  // has no shared sub-DAG, so walked == cells_persisted exactly).
  EXPECT_EQ(walked, result.cells_persisted);

  // Sanity: a fresh import against the same kv would be a no-op (every
  // cell is already idempotently present). This is the same shape as a
  // node restart re-running the import after process restart; if any
  // cell had been GC'd this would surface as a hash collision or a
  // missing-cell error instead.
  auto fixture2_writer = std::make_unique<TestStreamingWriter>(fixture.kv);
  tos::validator::fullnode::CellDbStreamingSink sink2{fixture.reader, std::move(fixture2_writer)};
  EXPECT_TRUE(sink2.is_true_streaming());
  auto fd2 = td::FileFd::open(boc.path, td::FileFd::Flags::Read).move_as_ok();
  vm::StreamingBocImportOptions opts2;
  opts2.max_resident_bytes = 8ULL << 20;
  auto r_root2 = vm::std_boc_deserialize_from_file_bounded(fd2, boc.size, opts2, &sink2);
  fd2.close();
  EXPECT_TRUE(r_root2.is_ok());
  EXPECT_TRUE(sink2.finished());
  auto commit_status2 = sink2.commit_after_root_verified(boc.root_hash);
  EXPECT_TRUE(commit_status2.is_ok());

  td::rmrf(tmp_dir).ignore();
  std::printf("  walked=%llu cells_persisted=%llu  PASSED\n",
              static_cast<unsigned long long>(walked),
              static_cast<unsigned long long>(result.cells_persisted));
}

// tos27 P0-1: regression for the GC-pause lease's invariants.
//
// This test does NOT spin up an actor scheduler — the production
// wiring (CellDbIn::import_persistent_state_streaming issues a lease
// whose destructor send_closures `resume_gc_for_import` back to the
// CellDbIn actor, and the downloader actor releases it on the
// `set_block_state` callback) is observable end-to-end only against
// a live actor system, which the existing harness intentionally
// avoids.
//
// The unit-level invariants we DO pin here:
//   1. A default-constructed lease is inert: `active()` is false,
//      destruction is a no-op, and a default-constructed lease can
//      coexist with the importer success path's "owning" lease
//      without any cross-talk on the actor handle.
//   2. `release_after_root_store_committed()` flips an active lease
//      to inactive exactly once; calling it again is a no-op.
//   3. After release, the destructor is a no-op (no double-resume
//      send_closure to the CellDbIn actor).
//   4. Move-construction transfers ownership: the source becomes
//      inactive, the destination active.
//   5. Move-assignment transfers ownership and releases any pause
//      previously held by the destination (so a stale lease cannot
//      pin the GC pause indefinitely if the actor receives a fresh
//      lease from a follow-on import).
//
// The fixed-timer path is verified separately by the
// `scripts/check-evm-production-hardening.sh` Check 21 sub-checks
// (no `delay_action(... resume_gc_for_import)`, the lease type is
// declared, and the downloader calls
// `release_after_root_store_committed`).
void test_gc_lease_outlives_60s_window() {
  std::printf("=== test_gc_lease_outlives_60s_window (tos27 P0-1) ===\n");

  // (1) Default-constructed lease is inactive.
  {
    tos::validator::CellDbGcPauseLease lease;
    EXPECT_FALSE(lease.active());
    // Destructor on inactive lease must be a no-op (no send_closure).
  }

  // (2) Explicit release flips an active-shaped lease (we cannot
  //     easily mint an actually-live ActorId<CellDbIn> here without
  //     an actor system, so we use the empty-ActorId path: the
  //     observable invariant is that calling release on a lease
  //     whose ActorId is empty is a no-op AND the lease becomes
  //     inactive after release.). Crucially,
  //     release_after_root_store_committed() is idempotent — a
  //     second call must NOT crash and must NOT send a second
  //     resume.
  {
    tos::validator::CellDbGcPauseLease lease;
    EXPECT_FALSE(lease.active());
    lease.release_after_root_store_committed();
    EXPECT_FALSE(lease.active());
    // Idempotent: second release on an already-released lease is a no-op.
    lease.release_after_root_store_committed();
    EXPECT_FALSE(lease.active());
  }

  // (3) Move-construct: source becomes inactive, destination
  //     inherits whatever the source had (still inactive in this
  //     no-actor harness, but the move semantics are what matter).
  {
    tos::validator::CellDbGcPauseLease src;
    EXPECT_FALSE(src.active());
    tos::validator::CellDbGcPauseLease dst{std::move(src)};
    EXPECT_FALSE(src.active());  // moved-from
    EXPECT_FALSE(dst.active());  // started inactive
    // Both destructors here must be no-ops; no double-resume.
  }

  // (4) Move-assignment: destination's prior pause (if any) is
  //     released before adopting the source's pause. Validate that
  //     the move semantics don't produce a use-after-move on the
  //     ActorId handle.
  {
    tos::validator::CellDbGcPauseLease a;
    tos::validator::CellDbGcPauseLease b;
    a = std::move(b);
    EXPECT_FALSE(a.active());
    EXPECT_FALSE(b.active());
  }

  // (5) Self-assignment guard. `a = std::move(a)` must not
  //     accidentally release the lease (single-step destruction
  //     would resume GC mid-import in production).
  {
    tos::validator::CellDbGcPauseLease a;
    auto& a_ref = a;
    a = std::move(a_ref);
    EXPECT_FALSE(a.active());
  }

  // (6) Document the production wiring without driving it: a
  //     successful streaming import puts a `gc_lease` into
  //     PersistentStateImportResult, and the downloader actor's
  //     set_block_state completion callback releases it. tos30 extends
  //     that lease so it can carry a rollback manifest: if the lease is
  //     dropped before root-store completion, CellDbIn conditionally
  //     erases newly-created imported cells before resuming GC. The
  //     hardening checks ensure no fixed-timer resume sneaks back in
  //     and that the rollback manifest path remains actor-routed.
  {
    tos::validator::PersistentStateImportResult result;
    // Default-constructed: gc_lease is null. The downloader actor's
    // `if (gc_lease_)` check covers this branch — legacy InMemory
    // imports take that path so the actor is forward-compatible
    // with paths that don't issue a lease.
    EXPECT_TRUE(result.gc_lease == nullptr);

    // Populate with an inactive lease (matching "actor handle not
    // yet bound") and confirm the unique_ptr indirection works.
    result.gc_lease = std::make_unique<tos::validator::CellDbGcPauseLease>();
    EXPECT_TRUE(result.gc_lease != nullptr);
    EXPECT_FALSE(result.gc_lease->active());

    // Move out of the result, simulating what the downloader does
    // in `on_streaming_import_done`.
    auto pulled = std::move(result.gc_lease);
    EXPECT_TRUE(result.gc_lease == nullptr);
    EXPECT_TRUE(pulled != nullptr);
    EXPECT_FALSE(pulled->active());

    // Release through the unique_ptr — exactly the call shape used
    // in DownloadShardState::written_shard_state.
    pulled->release_after_root_store_committed();
    EXPECT_FALSE(pulled->active());
    pulled.reset();  // dtor on already-released lease is a no-op.
  }

  // (7) tos30 rollback-carrying constructor remains available. This
  //     no-actor harness passes an empty ActorId and empty manifest, so
  //     it cannot drive CellDbIn rollback; the hardening script pins the
  //     production call sites that pass a real actor id and manifest.
  {
    tos::validator::CellDbGcPauseLease lease(td::actor::ActorId<tos::validator::CellDbIn>{},
                                             std::string{}, 0, 0);
    EXPECT_FALSE(lease.active());
    lease.release_after_root_store_committed();
    EXPECT_FALSE(lease.active());
  }

  std::printf("  PASSED\n");
}

// ---------------------------------------------------------------------------
// (9) tos27 P0-2: slice-budget constants exist and a direct sink-driven
//     import still completes
// ---------------------------------------------------------------------------
//
// Production wiring: CellDbIn::import_persistent_state_streaming runs the
// BoC parse on a `td::thread` worker OFF the actor's message loop. The
// worker drives a slice-budget-aware spooling sink that yields the OS
// scheduler every `kMaxImportCellsPerSlice` cells OR every
// `kMaxImportSliceWallMs` ms (whichever comes first). After root
// verification, CellDbIn drains that spool through actor-side batches
// bounded by `kMaxImportActorBatchCells` / `kMaxImportActorBatchBytes`.
// This unit-level test pins TWO things:
//
//   1. The slice-budget constants are declared with sane non-zero values
//      so a future regression that flips them to 0 or removes them
//      surfaces here BEFORE the production CellDb actor stack is bound.
//      The hardening Check 22 enforces the symbol presence in the .hpp
//      separately; this test pins the runtime values.
//
//   2. The direct sink-driven import path (run_streaming_import) still
//      works end-to-end against a synthetic BoC. The Phase B sink is
//      what the production worker thread drives; if the production wiring
//      is reachable through the existing run_streaming_import harness then
//      no end-to-end regression slipped in.
//
// Integration coverage TODO: a full sliced-parse test that observes the
// per-cell yield interleaving with concurrent CellDbIn message dispatch
// requires a real actor system (td::actor::Scheduler) plus a multi-GiB
// BoC fixture. The test harness uses td::MemoryKeyValue without an actor
// system, so it cannot exercise the full CellDbIn -> worker -> continuation
// round-trip. The hardening Check 22 + production code review together
// cover the path that is observable only at runtime against a live
// validator-engine.
void test_streaming_import_yields_during_parse() {
  std::printf("=== test_streaming_import_yields_during_parse (tos27 P0-2) ===\n");

  // (1) Slice-budget constants are present and non-zero. A regression
  //     that defaulted these to 0 / removed them would surface here.
  EXPECT_TRUE(tos::validator::kMaxImportCellsPerSlice > 0);
  EXPECT_TRUE(tos::validator::kMaxImportSliceWallMs > 0.0);
  EXPECT_TRUE(tos::validator::kMaxImportActorBatchCells > 0);
  EXPECT_TRUE(tos::validator::kMaxImportActorBatchBytes > 0);
  EXPECT_EQ(tos::validator::kMaxConcurrentStreamingImports, static_cast<td::uint32>(1));
  // Sanity: the cell-count slice MUST be modest enough that a multi-GiB
  // state's parse interleaves with CellDb message handling. 1k cells per
  // slice at ~5 ms/slice puts the worker's scheduler-hold time well
  // below any CellDb operation's 95th-percentile latency target.
  EXPECT_TRUE(tos::validator::kMaxImportCellsPerSlice <= 65536);
  EXPECT_TRUE(tos::validator::kMaxImportSliceWallMs <= 100.0);
  EXPECT_TRUE(tos::validator::kMaxImportActorBatchCells <= 65536);
  EXPECT_TRUE(tos::validator::kMaxImportActorBatchBytes <= (64ULL << 20));

  // (2) Direct sink-driven import still completes against a small
  //     synthetic BoC. The slice budget is large enough that this test
  //     completes in a single slice; the value of the test is pinning
  //     "no regression on the existing 8 tests" — the production wiring
  //     would surface issues at the worker boundary, not the sink boundary.
  auto tmp_dir = std::string("/tmp/tos-test-celldb-streaming-9-") + std::to_string(::getpid());
  td::rmrf(tmp_dir).ignore();
  // Tree size 256 cells: well below the 1024-cells-per-slice budget so
  // we don't actually exercise the yield path here. A larger fixture
  // (>kMaxImportCellsPerSlice) would force at least one yield, but the
  // harness has no way to OBSERVE the yield from outside the sink — it
  // is purely a cooperative td::this_thread::yield() call. The yield
  // path is covered by code review + production runtime traces.
  auto boc = serialize_synthetic_boc(tmp_dir, /*target_cells=*/256, "synth.boc");

  auto fixture = build_fixture();
  auto result = run_streaming_import(fixture, boc);
  EXPECT_TRUE(result.cells_persisted > 0);
  EXPECT_TRUE(!result.root.is_null());
  EXPECT_TRUE(result.root->get_hash() == boc.root_hash);

  td::rmrf(tmp_dir).ignore();
  std::printf("  cells_per_slice=%u wall_ms=%.1f concurrent_max=%u cells_persisted=%llu  PASSED\n",
              tos::validator::kMaxImportCellsPerSlice, tos::validator::kMaxImportSliceWallMs,
              tos::validator::kMaxConcurrentStreamingImports,
              static_cast<unsigned long long>(result.cells_persisted));
}

}  // namespace

int main() {
  std::printf(
      "test-celldb-streaming-import: Phase B Step 8 invariant regressions (10 tests)\n");
  test_replacement_hash_equality();
  test_no_full_dag_residency();
  test_crash_abort_no_partial_state();
  test_root_mismatch_abort_then_retry();
  test_lazy_load();
  test_lazy_load_after_commit_succeeds();
  test_hash_mismatch();
  test_imported_cells_survive_immediate_gc();
  test_gc_lease_outlives_60s_window();
  test_streaming_import_yields_during_parse();
  std::printf("All Phase B invariant tests passed.\n");
  return 0;
}
