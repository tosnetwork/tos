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

#include <memory>

#include "td/utils/Status.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellTraits.h"
#include "vm/cells/DataCell.h"
#include "vm/cells/ExtCell.h"
#include "vm/cells/PrunnedCell.h"
#include "vm/db/DynamicBagOfCellsDb.h"

namespace vm {

// Late-binding reader provider for CellDb-backed lazy ExtCells.
//
// Why this exists:
//   The streaming-state importer mints lazy ExtCells DURING parse, while
//   the per-import RocksDB write batch is still open. The reader handle
//   the importer holds at that moment may be a snapshot taken BEFORE the
//   batch is committed; if we baked that snapshot into every ExtCell at
//   construction time, the cells we just streamed would be invisible to
//   any lazy materialization that triggers AFTER commit (the snapshot
//   missed them).
//
//   The provider lets the streaming sink publish a post-commit reader
//   once `commit_after_root_verified` flushes the write batch; ExtCells
//   minted before commit then transparently see the new cells via the
//   provider's `current_reader()` indirection. On the abort path the
//   provider is invalidated so any subsequent lazy materialization
//   surfaces a structured Status::Error instead of silently reading
//   from a stale snapshot.
//
// Thread-safety contract:
//   The streaming sink is single-threaded inside its parser, but the
//   ExtCells it emits are handed off to downstream consumers that may
//   materialize cells from any thread (e.g. a separate import-finish
//   actor running on the celldb actor's strand). Implementations of
//   `current_reader()` MUST therefore be safe to call from multiple
//   threads concurrently. A non-null return is the canonical reader at
//   the call moment; a null return signals the provider has been
//   invalidated (e.g. the import aborted) and the loader should fail
//   closed.
class CellDbReaderProvider {
 public:
  virtual ~CellDbReaderProvider() = default;
  // Returns the current canonical reader, or a null shared_ptr if the
  // provider has been invalidated. MUST be thread-safe; see the class-
  // level contract above.
  virtual std::shared_ptr<CellDbReader> current_reader() = 0;

  // Optional swap hook. The streaming sink calls this after
  // commit_after_root_verified flushes the per-import write batch so
  // lazy ExtCells minted during parse pick up a reader that observes
  // the just-flushed cells. The default implementation is a no-op so
  // a degenerate provider (e.g. legacy tests, the static wrapper used
  // by the backward-compat make_celldb_ext_cell overload) can ignore
  // the call without breaking the contract. Implementations that DO
  // own a swappable reader (e.g. validator::LiveCellDbReaderProvider)
  // override this to atomically replace the current handle.
  virtual void publish(std::shared_ptr<CellDbReader> /*next*/) {
  }

  // Optional invalidation hook. The streaming sink calls this on
  // abort() so any subsequent lazy materialization fails closed with
  // a structured Status::Error rather than reading from a stale
  // snapshot. Default is a no-op for the same reason as publish.
  virtual void invalidate() {
  }
};

// Extra payload carried by a CellDb-backed ExtCell. The provider is
// the only dependency the loader needs at materialization time; we
// hold a shared_ptr so multiple ExtCells produced by a single
// streaming-import session share the same provider instance.
struct CellDbExtCellExtra {
  std::shared_ptr<CellDbReaderProvider> reader_provider;
};

// Loader functor used by ExtCell<>'s template machinery. Stays stateless on
// purpose; all state lives in the CellDbExtCellExtra attached to the cell.
class CellDbExtCellLoader {
 public:
  // Called lazily on first DataCell materialization (e.g., load_cell()).
  // Resolves the canonical reader from the attached provider, then
  // dispatches `load_cell(hash)` against it. Returns
  // td::Status::Error on a hash mismatch, on a reader miss, or if the
  // provider has been invalidated; never aborts the process.
  static td::Result<td::Ref<DataCell>> load_data_cell(const Cell& ext_cell, const CellDbExtCellExtra& extra);
};

using CellDbExtCell = ExtCell<CellDbExtCellExtra, CellDbExtCellLoader>;

// Build a hash-only / lazy replacement cell whose materialization is
// late-bound through `reader_provider`. The returned cell exposes the
// supplied hashes/depths/level_mask immediately (no I/O on construction)
// and only invokes `reader_provider->current_reader()` on first DataCell
// materialization. On a CellDb miss, hash mismatch, or invalidated
// provider the materialization path returns a structured td::Status::Error
// rather than aborting the process.
//
// CONTRACT: `hashes` must be exactly `n * Cell::hash_bytes` bytes and `depths`
// must be exactly `n * Cell::depth_bytes` bytes, where
// `n = level_mask.get_hashes_count()`. The buffers carry one entry per
// significant level in `level_mask` (the same layout used by
// `DataCell::serialize` for the with-hashes header). For a plain level-0 cell
// (`n == 1`) this collapses to a single 32-byte hash + single 2-byte depth.
//
// Buffer sizes are validated up front; a size mismatch returns
// `td::Status::Error` rather than tripping the `CHECK` in `PrunnedCell::init`,
// so the importer can recover via its abort path instead of taking down the
// process.
td::Result<td::Ref<Cell>> make_celldb_ext_cell(Cell::LevelMask level_mask, td::Slice hashes, td::Slice depths,
                                               std::shared_ptr<CellDbReaderProvider> reader_provider);

// Backward-compatible overload for callers that still hold a raw
// `shared_ptr<CellDbReader>` (e.g. existing tests, legacy code paths
// that have not yet wired a provider). The reader is wrapped in a
// degenerate provider that always returns the same handle. New code
// SHOULD use the provider overload directly so it can later swap to a
// post-commit reader or invalidate on abort.
td::Result<td::Ref<Cell>> make_celldb_ext_cell(Cell::LevelMask level_mask, td::Slice hashes, td::Slice depths,
                                               std::shared_ptr<CellDbReader> reader);

// Factory for a degenerate provider that always returns the supplied
// reader. Exposed here so callers that hold a raw `shared_ptr<CellDbReader>`
// (older test harnesses, legacy downloader paths) can adapt to the new
// provider-based sink constructor without taking a dependency on
// validator/db/celldb.hpp's LiveCellDbReaderProvider. The returned
// provider's `publish` and `invalidate` are no-ops; the underlying
// reader is fixed for the provider's lifetime. Returns nullptr if
// `reader` is null so the sink's "no provider" branch can short-circuit.
std::shared_ptr<CellDbReaderProvider> make_static_cell_db_reader_provider(std::shared_ptr<CellDbReader> reader);

}  // namespace vm
