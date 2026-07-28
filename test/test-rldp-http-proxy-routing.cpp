/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

#include "rldp-http-proxy/PeerCapabilityRouting.h"
#include "td/utils/LRUCache.h"
#include "td/utils/tests.h"

namespace {

struct Capability {
  bool received = false;
  td::uint64 capabilities = 0;
};

void resync(const Capability &capability, td::LRUCache<int, bool> &dispatch, int peer) {
  tos::rldp_http_proxy::detail::resync_dispatcher_capability(
      capability.received, capability.capabilities,
      [&](bool supports_rldp2) { dispatch.put(peer, supports_rldp2); });
}

}  // namespace

TEST(RldpHttpProxyRouting, known_capability_repopulates_dispatcher_after_eviction) {
  constexpr td::uint64 capacity = 3;
  td::LRUCache<int, Capability> capabilities(capacity);
  td::LRUCache<int, bool> dispatch(capacity);

  constexpr int target_peer = 0;
  capabilities.put(target_peer,
                   Capability{.received = true,
                              .capabilities = tos::rldp_http_proxy::detail::kCapabilityRldp2});
  dispatch.put(target_peer, true);

  for (int other = 1; other <= static_cast<int>(capacity); ++other) {
    dispatch.put(other, true);
  }
  CHECK(dispatch.get_if_exists(target_peer) == nullptr);

  auto *capability = capabilities.get_if_exists(target_peer);
  CHECK(capability != nullptr);
  resync(*capability, dispatch, target_peer);

  auto *route = dispatch.get_if_exists(target_peer);
  CHECK(route != nullptr);
  CHECK(*route);
}

TEST(RldpHttpProxyRouting, unknown_capability_clears_stale_dispatcher_entry) {
  constexpr td::uint64 capacity = 3;
  td::LRUCache<int, Capability> capabilities(capacity);
  td::LRUCache<int, bool> dispatch(capacity);

  constexpr int target_peer = 0;
  capabilities.put(target_peer,
                   Capability{.received = true,
                              .capabilities = tos::rldp_http_proxy::detail::kCapabilityRldp2});
  dispatch.put(target_peer, true);

  for (int other = 1; other <= static_cast<int>(capacity); ++other) {
    capabilities.put(other, Capability{.received = true, .capabilities = 0});
  }
  CHECK(capabilities.get_if_exists(target_peer) == nullptr);
  CHECK(*dispatch.get_if_exists(target_peer, /* update = */ false));

  auto &fresh_capability = capabilities.get(target_peer);
  CHECK(!fresh_capability.received);
  resync(fresh_capability, dispatch, target_peer);

  auto *route = dispatch.get_if_exists(target_peer);
  CHECK(route != nullptr);
  CHECK(!*route);
}

TEST(RldpHttpProxyRouting, resync_callback_is_unconditional) {
  int calls = 0;
  bool route = true;
  tos::rldp_http_proxy::detail::resync_dispatcher_capability(false, 0, [&](bool supports_rldp2) {
    ++calls;
    route = supports_rldp2;
  });
  CHECK(calls == 1);
  CHECK(!route);
}
