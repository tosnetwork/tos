#include <sodium.h>

#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include "cells.h"
namespace tos::auth {
namespace {
td::Slice slice(std::span<const std::uint8_t> b) {
  return td::Slice(reinterpret_cast<const char*>(b.data()), b.size());
}
std::size_t capacity(std::size_t size) {
  std::size_t n = 120;
  while (size > 4 * n)
    n *= 4;
  return n;
}
td::Ref<vm::Cell> pack_node(std::span<const std::uint8_t> raw) {
  vm::CellBuilder b;
  if (raw.size() <= 120)
    b.store_long(0, 1).store_long(raw.size(), 7).store_bytes(slice(raw));
  else {
    auto cap = capacity(raw.size());
    b.store_long(1, 1).store_long((raw.size() + cap - 1) / cap, 3).store_long(raw.size(), 32);
    for (std::size_t offset = 0; offset < raw.size(); offset += cap)
      b.store_ref(pack_node(raw.subspan(offset, std::min(cap, raw.size() - offset))));
  }
  return b.finalize();
}
bool unpack_node(td::Ref<vm::Cell> cell, std::size_t expected, unsigned depth, unsigned& occurrences, Bytes& out) {
  if (cell.is_null() || depth > 10 || ++occurrences > 400000 || cell->get_level() != 0)
    return false;
  vm::CellSlice s{vm::NoVm{}, cell};
  if (!s.is_valid() || s.is_special() || s.size() < 1)
    return false;
  auto branch = s.fetch_ulong(1);
  if (expected <= 120) {
    if (branch != 0 || s.size() < 7)
      return false;
    auto n = s.fetch_ulong(7);
    if (n != expected || n == 0 || s.size() != 8 * n || s.size_refs() != 0)
      return false;
    std::array<char, 120> bytes{};
    if (!s.fetch_bytes(td::MutableSlice(bytes.data(), n)))
      return false;
    out.insert(out.end(), bytes.begin(), bytes.begin() + n);
    return true;
  }
  if (branch != 1 || s.size() != 35)
    return false;
  auto n = s.fetch_ulong(3), length = s.fetch_ulong(32);
  auto cap = capacity(expected);
  if (length != expected || n != (expected + cap - 1) / cap || n < 2 || n > 4 || s.size_refs() != n)
    return false;
  for (std::size_t offset = 0; offset < expected; offset += cap)
    if (!unpack_node(s.fetch_ref(), std::min(cap, expected - offset), depth + 1, occurrences, out))
      return false;
  return true;
}
}  // namespace
Result<td::Ref<vm::Cell>> pack_bytes(std::span<const std::uint8_t> bytes) {
  if (bytes.empty() || bytes.size() > max_object_bytes)
    return Error{"object-bound"};
  Hash hash;
  if (crypto_hash_sha256(hash.data(), bytes.data(), bytes.size()) != 0)
    return Error{"backend-error"};
  vm::CellBuilder b;
  b.store_long(0x76616231, 32)
      .store_long(1, 16)
      .store_long(bytes.size(), 32)
      .store_bytes(slice(hash))
      .store_ref(pack_node(bytes));
  return td::Ref<vm::Cell>(b.finalize());
}
Result<Bytes> unpack_bytes(td::Ref<vm::Cell> cell) {
  if (cell.is_null() || cell->get_level() != 0)
    return Error{"cell-level"};
  vm::CellSlice s{vm::NoVm{}, cell};
  if (!s.is_valid() || s.is_special() || s.size() != 336 || s.size_refs() != 1)
    return Error{"auth-bytes-shape"};
  if (s.fetch_ulong(32) != 0x76616231 || s.fetch_ulong(16) != 1)
    return Error{"auth-bytes-version"};
  auto length = s.fetch_ulong(32);
  if (length == 0 || length > max_object_bytes)
    return Error{"object-bound"};
  Hash expected;
  if (!s.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(expected.data()), 32)))
    return Error{"auth-bytes-hash"};
  Bytes raw;
  raw.reserve(length);
  unsigned occurrences = 0;
  if (!unpack_node(s.fetch_ref(), length, 0, occurrences, raw))
    return Error{"tree-canonical"};
  Hash actual;
  if (crypto_hash_sha256(actual.data(), raw.data(), raw.size()) != 0)
    return Error{"backend-error"};
  if (actual != expected)
    return Error{"auth-bytes-hash"};
  return raw;
}
Result<Bytes> serialize_bytes(std::span<const std::uint8_t> bytes) {
  auto root = pack_bytes(bytes);
  if (!root.ok())
    return root.error();
  auto boc = vm::std_boc_serialize(root.value(), 31);
  if (boc.is_error())
    return Error{"boc-serialize"};
  auto value = boc.move_as_ok();
  if (value.size() > 67108864)
    return Error{"boc-bound"};
  return Bytes(value.as_slice().ubegin(), value.as_slice().uend());
}
Result<Bytes> deserialize_bytes(std::span<const std::uint8_t> boc) {
  if (boc.empty() || boc.size() > 67108864)
    return Error{"boc-bound"};
  vm::BagOfCells::Info info;
  auto size = info.parse_serialized_header(slice(boc).substr(0, std::min<std::size_t>(256, boc.size())));
  if (size <= 0 || static_cast<std::size_t>(size) != boc.size() || info.root_count != 1 || info.cell_count <= 0 ||
      info.cell_count > 400001 || info.absent_count != 0)
    return Error{"boc-header-bound"};
  vm::BagOfCells parsed;
  auto consumed = parsed.deserialize(slice(boc), 1);
  if (consumed.is_error())
    return Error{"boc-decode"};
  if (consumed.ok() != static_cast<long long>(boc.size()) || parsed.get_root_count() != 1)
    return Error{"boc-trailing"};
  return unpack_bytes(parsed.get_root_cell());
}
}  // namespace tos::auth
