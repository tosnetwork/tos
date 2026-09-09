#pragma once

#include <array>
#include "common/refint.h"
#include "uno/core/amount.h"

namespace uno_workchain {

// Native Tomis uses VarUInteger 16 (at most 15 bytes). This is an encoding
// boundary, not the global supply limit or the UNO aggregate accounting limit.
inline td::Result<td::RefInt256> checked_native_tomis(const Amount& amount) {
  if (amount.high() >> 56) {
    return td::Status::Error("UNO amount exceeds Native Tomis encoding range");
  }
  std::array<unsigned char, 16> bytes{};
  for (unsigned i = 0; i < 8; ++i) {
    bytes[i] = static_cast<unsigned char>(amount.high() >> (56 - 8 * i));
    bytes[i + 8] = static_cast<unsigned char>(amount.low() >> (56 - 8 * i));
  }
  auto result = td::make_refint(0);
  if (!result.write().import_bytes(bytes.data(), bytes.size(), false)) {
    return td::Status::Error("cannot construct Native Tomis amount");
  }
  return result;
}

inline td::Result<Amount> checked_amount_from_native_tomis(const td::RefInt256& value) {
  if (value.is_null() || !value->unsigned_fits_bits(120)) {
    return td::Status::Error("invalid Native Tomis amount");
  }
  std::array<unsigned char, 16> bytes{};
  if (!value->export_bytes(bytes.data(), bytes.size(), false)) {
    return td::Status::Error("cannot decode Native Tomis amount");
  }
  td::uint64 high = 0, low = 0;
  for (unsigned i = 0; i < 8; ++i) {
    high = (high << 8) | bytes[i];
    low = (low << 8) | bytes[i + 8];
  }
  return Amount::from_words(high, low);
}

}  // namespace uno_workchain
