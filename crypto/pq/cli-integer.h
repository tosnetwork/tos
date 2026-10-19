/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <charconv>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

namespace tos::pq {

// Parse into the wire field's type, so neither a partial conversion nor a narrowing
// cast can change the operator's requested signing domain or authorisation fields.
// Leading zeroes are decimal; a minus is allowed only for signed fields. Whitespace,
// a plus sign, prefixes and suffixes are deliberately not part of this grammar.
template <class T>
T cli_integer(std::string_view text, const char* field) {
  static_assert(std::is_integral_v<T> && !std::is_same_v<T, bool>);
  T value{};
  if (!text.empty()) {
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (result.ec == std::errc{} && result.ptr == text.data() + text.size()) {
      return value;
    }
  }
  throw std::runtime_error(std::string(field) + " must be a whole decimal integer in [" +
                           std::to_string(std::numeric_limits<T>::min()) + ", " +
                           std::to_string(std::numeric_limits<T>::max()) + "]");
}

}  // namespace tos::pq
