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

// Extra payload carried by a CellDb-backed ExtCell. The reader is the only
// dependency the loader needs at materialization time; we hold a shared_ptr
// because multiple ExtCells produced by a single streaming-import session
// share the same CellDbReader instance.
struct CellDbExtCellExtra {
  std::shared_ptr<CellDbReader> reader;
};

// Loader functor used by ExtCell<>'s template machinery. Stays stateless on
// purpose; all state lives in the CellDbExtCellExtra attached to the cell.
class CellDbExtCellLoader {
 public:
  // Called lazily on first DataCell materialization (e.g., load_cell()).
  // Resolves the underlying DataCell via the attached CellDbReader, then
  // re-checks that the loaded cell's hash matches the ExtCell's declared
  // hash. Returns td::Status::Error on mismatch or read failure; never
  // aborts the process.
  static td::Result<td::Ref<DataCell>> load_data_cell(const Cell& ext_cell, const CellDbExtCellExtra& extra);
};

using CellDbExtCell = ExtCell<CellDbExtCellExtra, CellDbExtCellLoader>;

// Build a hash-only / lazy replacement cell backed by `reader`. The returned
// cell exposes the supplied hash/depth/level_mask immediately (no I/O on
// construction) and only touches the reader on first DataCell materialization.
// On a CellDb miss or hash mismatch the materialization path returns an error
// rather than crashing.
td::Result<td::Ref<Cell>> make_celldb_ext_cell(Cell::LevelMask level_mask, td::Slice hash, td::Slice depth,
                                               std::shared_ptr<CellDbReader> reader);

}  // namespace vm
