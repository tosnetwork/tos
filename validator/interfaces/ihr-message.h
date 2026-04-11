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

#include "crypto/common/refcnt.hpp"
#include "crypto/vm/cells.h"
#include "tos/tos-types.h"

namespace tos {

namespace validator {

class IhrMessage : public td::CntObject {
 public:
  using Hash = Bits256;

  virtual ~IhrMessage() = default;
  virtual AccountIdPrefixFull shard() const = 0;
  virtual td::BufferSlice serialize() const = 0;
  virtual td::Ref<vm::Cell> root_cell() const = 0;
  virtual Hash hash() const = 0;
};

}  // namespace validator

}  // namespace tos
