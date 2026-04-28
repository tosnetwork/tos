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

td::Result<td::Ref<DataCell>> CellDbExtCellLoader::load_data_cell(const Cell& ext_cell,
                                                                  const CellDbExtCellExtra& extra) {
  if (extra.reader == nullptr) {
    return td::Status::Error("CellDbExtCell: missing reader at materialization time");
  }

  // Resolve via the abstract reader; the reader owns CellDb access details.
  auto declared_hash = ext_cell.get_hash();
  TRY_RESULT(data_cell, extra.reader->load_cell(declared_hash.as_slice()));
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

td::Result<td::Ref<Cell>> make_celldb_ext_cell(Cell::LevelMask level_mask, td::Slice hash, td::Slice depth,
                                               std::shared_ptr<CellDbReader> reader) {
  if (reader == nullptr) {
    return td::Status::Error("CellDbExtCell: cannot build replacement cell with null reader");
  }

  PrunnedCellInfo info{level_mask, hash, depth};
  TRY_RESULT(ext_cell, CellDbExtCell::create(info, CellDbExtCellExtra{std::move(reader)}));
  return td::Ref<Cell>{std::move(ext_cell)};
}

}  // namespace vm
