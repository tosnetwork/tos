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

#include "block/validator-set.h"
#include "crypto/block/mc-config.h"
#include "crypto/common/refcnt.hpp"
#include "tos/tos-types.h"

namespace tos {

namespace validator {

using McShardHash = block::McShardHashI;

class ConfigHolder : public td::CntObject {
 public:
  virtual ~ConfigHolder() = default;

  virtual td::Ref<block::ValidatorSet> get_total_validator_set(
      int next) const = 0;  // next = -1 -> prev, next = 0 -> cur
  virtual td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull shard, UnixTime utime,
                                                         CatchainSeqno seqno) const = 0;
  virtual std::pair<UnixTime, UnixTime> get_validator_set_start_stop(int next) const = 0;
};

}  // namespace validator

}  // namespace tos
