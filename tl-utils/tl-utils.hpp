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

#include "auto/tl/tos_api.h"
#include "crypto/common/bitstring.h"
#include "td/utils/tl_parsers.h"
#include "tl/tl_object_parse.h"

#include "common-utils.hpp"

namespace tos {
td::BufferSlice serialize_tl_object(const tos_api::Object *T, bool boxed);
td::BufferSlice serialize_tl_object(const tos_api::Function *T, bool boxed);
td::BufferSlice serialize_tl_object(const tos_api::Object *T, bool boxed, td::BufferSlice &&suffix);
td::BufferSlice serialize_tl_object(const tos_api::Function *T, bool boxed, td::BufferSlice &&suffix);
td::BufferSlice serialize_tl_object(const tos_api::Object *T, bool boxed, td::Slice suffix);
td::BufferSlice serialize_tl_object(const tos_api::Function *T, bool boxed, td::Slice suffix);

td::UInt256 get_tl_object_sha256(const tos_api::Object *T);

template <class Tp, std::enable_if_t<std::is_base_of<tos_api::Object, Tp>::value>>
td::UInt256 get_tl_object_sha256(const Tp &T) {
  return get_tl_object_sha256(static_cast<const tos_api::Object *>(&T));
}

td::Bits256 get_tl_object_sha_bits256(const tos_api::Object *T);

template <class Tp, std::enable_if_t<std::is_base_of<tos_api::Object, Tp>::value>>
td::Bits256 get_tl_object_sha_bits256(const Tp &T) {
  return get_tl_object_sha_bits256(static_cast<const tos_api::Object *>(&T));
}
}  // namespace tos
