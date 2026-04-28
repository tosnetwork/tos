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
#include "vm/db/CellDbExtCell.h"

#include <utility>

#include "td/utils/Status.h"
#include "td/utils/format.h"

namespace vm {

namespace {

// Degenerate provider used by the legacy `make_celldb_ext_cell` overload
// that takes a raw `shared_ptr<CellDbReader>`. The reader handed in at
// construction time is the answer to every `current_reader()` call —
// there is no swap path. New code SHOULD construct a real provider
// (e.g. validator::LiveCellDbReaderProvider) so the lazy load can pick
// up a post-commit reader; this wrapper exists only so existing tests
// and pre-provider call sites compile unchanged.
class StaticCellDbReaderProvider final : public CellDbReaderProvider {
 public:
  explicit StaticCellDbReaderProvider(std::shared_ptr<CellDbReader> reader) : reader_(std::move(reader)) {
  }
  std::shared_ptr<CellDbReader> current_reader() override {
    return reader_;
  }

 private:
  std::shared_ptr<CellDbReader> reader_;
};

}  // namespace

td::Result<td::Ref<DataCell>> CellDbExtCellLoader::load_data_cell(const Cell& ext_cell,
                                                                  const CellDbExtCellExtra& extra) {
  if (extra.reader_provider == nullptr) {
    return td::Status::Error("CellDbExtCell: missing reader provider at materialization time");
  }
  // Late-bind the reader on every materialization: the streaming sink
  // may have published a fresh post-commit reader (or invalidated the
  // provider on abort) AFTER this ExtCell was minted. Honoring that
  // swap is the load-bearing contract of CellDbReaderProvider.
  auto reader = extra.reader_provider->current_reader();
  if (reader == nullptr) {
    return td::Status::Error("CellDbExtCell: reader provider invalidated");
  }

  // Resolve via the abstract reader; the reader owns CellDb access details.
  auto declared_hash = ext_cell.get_hash();
  TRY_RESULT(data_cell, reader->load_cell(declared_hash.as_slice()));
  if (data_cell.is_null()) {
    return td::Status::Error(PSLICE() << "CellDbExtCell: reader returned null cell for hash "
                                      << declared_hash.to_hex());
  }

  // Defense-in-depth hash check. ExtCell::load_data_cell() already invokes
  // PrunnedCell::check_equals_unloaded() against the returned cell, but a
  // direct mismatch detected here yields a clearer operator-facing message
  // than the generic "unloaded mismatch" the parent template would emit.
  if (data_cell->get_hash() != declared_hash) {
    return td::Status::Error(PSLICE() << "CellDbExtCell: hash mismatch on materialization (declared="
                                      << declared_hash.to_hex() << ", loaded=" << data_cell->get_hash().to_hex()
                                      << ")");
  }

  return std::move(data_cell);
}

td::Result<td::Ref<Cell>> make_celldb_ext_cell(Cell::LevelMask level_mask, td::Slice hashes, td::Slice depths,
                                               std::shared_ptr<CellDbReaderProvider> reader_provider) {
  if (reader_provider == nullptr) {
    return td::Status::Error("CellDbExtCell: cannot build replacement cell with null reader provider");
  }

  // Per-level buffer-size validation MUST precede the PrunnedCell::create call
  // below, because PrunnedCell::init() asserts the same equalities via CHECK
  // and would otherwise abort the whole process on a malformed input. By
  // surfacing the mismatch here as a structured td::Status::Error we let the
  // streaming importer's abort path roll the partial RocksDB batch back
  // cleanly instead of taking the validator down.
  const auto n = level_mask.get_hashes_count();
  const auto expected_hashes_size = static_cast<size_t>(n) * Cell::hash_bytes;
  const auto expected_depths_size = static_cast<size_t>(n) * Cell::depth_bytes;
  if (hashes.size() != expected_hashes_size) {
    return td::Status::Error(PSLICE() << "make_celldb_ext_cell: hashes.size()=" << hashes.size()
                                       << " expected " << expected_hashes_size << " for level "
                                       << level_mask.get_level() << " (hashes_count=" << n << ")");
  }
  if (depths.size() != expected_depths_size) {
    return td::Status::Error(PSLICE() << "make_celldb_ext_cell: depths.size()=" << depths.size()
                                       << " expected " << expected_depths_size << " for level "
                                       << level_mask.get_level() << " (hashes_count=" << n << ")");
  }

  PrunnedCellInfo info{level_mask, hashes, depths};
  TRY_RESULT(ext_cell, CellDbExtCell::create(info, CellDbExtCellExtra{std::move(reader_provider)}));
  return td::Ref<Cell>{std::move(ext_cell)};
}

td::Result<td::Ref<Cell>> make_celldb_ext_cell(Cell::LevelMask level_mask, td::Slice hashes, td::Slice depths,
                                               std::shared_ptr<CellDbReader> reader) {
  if (reader == nullptr) {
    return td::Status::Error("CellDbExtCell: cannot build replacement cell with null reader");
  }
  // Wrap the raw reader in a degenerate provider so every code path
  // ultimately funnels through the same `current_reader()` indirection.
  // The wrapper has zero observable cost on the hot path (one extra
  // shared_ptr copy per lazy materialization).
  auto provider = make_static_cell_db_reader_provider(std::move(reader));
  return make_celldb_ext_cell(level_mask, hashes, depths, std::move(provider));
}

std::shared_ptr<CellDbReaderProvider> make_static_cell_db_reader_provider(std::shared_ptr<CellDbReader> reader) {
  if (reader == nullptr) {
    return nullptr;
  }
  return std::make_shared<StaticCellDbReaderProvider>(std::move(reader));
}

}  // namespace vm
