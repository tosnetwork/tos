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

#include <cstdint>

namespace tos::overlay {

struct OverlayMemberFlags {
  enum Values : std::uint32_t {
    DoNotReceiveBroadcasts = 1u << 0,
    DoNotReceivePlumtreeBroadcasts = 1u << 1,
  };
  static constexpr std::uint32_t plumtree_deny_mask() {
    return DoNotReceiveBroadcasts | DoNotReceivePlumtreeBroadcasts;
  }
  static constexpr bool valid(std::uint32_t flags) {
    return (flags & ~plumtree_deny_mask()) == 0;
  }
  static constexpr bool receives_regular(std::uint32_t flags) {
    return valid(flags) && !(flags & DoNotReceiveBroadcasts);
  }
  static constexpr bool receives_plumtree(std::uint32_t flags) {
    return valid(flags) && !(flags & plumtree_deny_mask());
  }
  static constexpr std::uint32_t public_flags(std::uint32_t configured, bool enabled, bool original_sender) {
    return configured | ((!enabled || original_sender) ? DoNotReceivePlumtreeBroadcasts : 0u);
  }
};

}  // namespace tos::overlay
