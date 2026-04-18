// Minimal magic_enum shim for silkworm-core compilation.
// Only provides enum_count, enum_integer, and enum_values used by eip_7685_requests.
#pragma once
#include <array>
#include <cstddef>
#include <type_traits>

namespace magic_enum {

template <typename E>
constexpr auto enum_integer(E value) noexcept {
    return static_cast<std::underlying_type_t<E>>(value);
}

// Fallback: returns 0. Specialised where needed.
template <typename E>
constexpr std::size_t enum_count() noexcept { return 0; }

template <typename E>
constexpr auto enum_values() noexcept {
    return std::array<E, 0>{};
}

}  // namespace magic_enum
