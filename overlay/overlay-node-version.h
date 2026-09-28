/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 * Licensed under the GNU Lesser General Public License v2 or later.
 */
#pragma once

#include <cstdint>

namespace tos::overlay {

// Widen before arithmetic: the signed wire timestamp can be negative or INT32_MAX.
inline constexpr bool overlay_node_version_is_fresh(std::int32_t version, std::int64_t now) {
  auto signed_version = static_cast<std::int64_t>(version);
  return signed_version >= now - 600 && signed_version <= now + 60;
}

}  // namespace tos::overlay
