#pragma once
#include "vm/cells/Cell.h"

#include "crypto.h"
namespace tos::auth {
Result<td::Ref<vm::Cell>> pack_bytes(std::span<const std::uint8_t> bytes);
Result<Bytes> unpack_bytes(td::Ref<vm::Cell> cell, std::size_t remaining_bytes = max_object_bytes);
Result<Bytes> serialize_bytes(std::span<const std::uint8_t> bytes);
Result<Bytes> deserialize_bytes(std::span<const std::uint8_t> boc);
}  // namespace tos::auth
