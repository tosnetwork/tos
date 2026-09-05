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
#include "adnl/adnl.h"
#include "validator/validator.h"

namespace tos {

namespace validator {

class ValidatorManagerDiskFactory {
 public:
  static td::actor::ActorOwn<ValidatorManagerInterface> create(PublicKeyHash local_id,
                                                               td::Ref<ValidatorManagerOptions> opts, ShardIdFull shard,
                                                               BlockIdExt shard_top_block_id, std::string db_root,
                                                               td::Ref<vm::Cell> block_candidate = {},
                                                               std::string export_candidate = {},
                                                               std::string import_candidate = {});
};

}  // namespace validator

}  // namespace tos
