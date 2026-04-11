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
*/
#pragma once
#include <string>
#include <vector>

#include "interfaces/block.h"
#include "tos/tos-types.h"
#include "vm/cells.h"
#include "vm/db/DynamicBagOfCellsDb.h"

namespace tos::validator {

struct PermanentCellDbUpdate {
  BlockIdExt block_id;
  RootHash state_root_hash;
  std::vector<std::pair<vm::CellHash, std::string>> to_store;
};
void calculate_permanent_celldb_update(const std::map<BlockIdExt, td::Ref<BlockData>>& blocks,
                                       std::shared_ptr<vm::DynamicBagOfCellsDb::AsyncExecutor> executor,
                                       td::Promise<std::vector<PermanentCellDbUpdate>> promise);

}  // namespace tos::validator
