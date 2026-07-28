/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <utility>

#include "td/utils/int_types.h"

namespace tos::rldp_http_proxy::detail {

inline constexpr td::uint64 kCapabilityRldp2 = 1;

// Keep the dispatcher cache aligned with the authoritative capability entry.
// The callback is deliberately invoked even when `received` is false: an
// independently bounded dispatcher cache may still contain a stale `true`
// after the capability entry was evicted, so unknown state must explicitly
// restore the safe RLDP1 fallback.
template <class SetSupportsRldp2>
void resync_dispatcher_capability(bool received, td::uint64 capabilities, SetSupportsRldp2 &&set_supports_rldp2) {
  std::forward<SetSupportsRldp2>(set_supports_rldp2)(received && (capabilities & kCapabilityRldp2));
}

}  // namespace tos::rldp_http_proxy::detail
