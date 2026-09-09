#pragma once

#include <limits>

#include "td/utils/Status.h"
#include "td/utils/uint128.h"

namespace uno_workchain {

// Candidate wide accounting range, measured in nanotomi. No wire codec or
// monetary authority is defined here; production activation must freeze both.
class Amount {
 public:
  Amount() = default;
  static Amount from_nanotomi(td::uint64 value) {
    return Amount(td::uint128::from_unsigned(value));
  }
  static Amount from_words(td::uint64 high, td::uint64 low) {
    return Amount(td::uint128(high, low));
  }
  td::uint64 high() const { return value_.hi(); }
  td::uint64 low() const { return value_.lo(); }

  td::Result<Amount> checked_add(const Amount& other) const {
    auto sum = value_.add(other.value_);
    if (less(sum, value_)) {
      return td::Status::Error("UNO amount addition overflow");
    }
    return Amount(sum);
  }
  td::Result<Amount> checked_sub(const Amount& other) const {
    if (less(value_, other.value_)) {
      return td::Status::Error("UNO amount subtraction underflow");
    }
    return Amount(value_.sub(other.value_));
  }
  td::Result<td::uint64> checked_note_value() const {
    if (high() != 0) {
      return td::Status::Error("UNO amount exceeds Note value range");
    }
    return low();
  }
  td::Result<Amount> checked_mul(const Amount& other) const {
    if (other.value_.is_zero()) {
      return Amount{};
    }
    const auto max_word = std::numeric_limits<td::uint64>::max();
    const auto limit = td::uint128(max_word, max_word).div(other.value_);
    if (less(limit, value_)) {
      return td::Status::Error("UNO amount multiplication overflow");
    }
    return Amount(value_.mult(other.value_));
  }
  // Convert a public magnitude with an explicit sign; INT64_MIN is excluded.
  td::Result<td::int64> checked_bundle_balance(bool negative) const {
    TRY_RESULT(value, checked_note_value());
    if (value > static_cast<td::uint64>(std::numeric_limits<td::int64>::max())) {
      return td::Status::Error("UNO amount exceeds bundle balance range");
    }
    auto magnitude = static_cast<td::int64>(value);
    return negative ? -magnitude : magnitude;
  }

 private:
  static bool less(td::uint128 lhs, td::uint128 rhs) {
    return lhs.hi() < rhs.hi() || (lhs.hi() == rhs.hi() && lhs.lo() < rhs.lo());
  }
  explicit Amount(td::uint128 value) : value_(value) {}
  td::uint128 value_{};
};

}  // namespace uno_workchain
