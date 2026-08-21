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

// ─── .tos DNS lifecycle gate and bounded cache (DNSLifecycle.h) ──────────────

#include "rldp-http-proxy/DNSLifecycle.h"

TEST(RldpHttpProxyDns, lifecycle_fails_closed_under_auction) {
  // an active auction and an ended-but-unfinalized auction both present a
  // nonzero auction_end_time; neither may serve records
  CHECK(tos::dns::check_domain_lifecycle(2000, 0, 1000).is_error());
  CHECK(tos::dns::check_domain_lifecycle(2000, 0, 3000).is_error());
}

TEST(RldpHttpProxyDns, lifecycle_fails_closed_when_overdue_or_clockless) {
  constexpr td::int64 lease = tos::dns::DNS_LEASE_SECONDS;
  constexpr td::int64 lfut = 1000;
  // exactly at the deadline still serves; one second past does not
  CHECK(tos::dns::check_domain_lifecycle(0, lfut, lfut + lease).is_ok());
  CHECK(tos::dns::check_domain_lifecycle(0, lfut, lfut + lease + 1).is_error());
  // a missing renewal clock is refused, not defaulted
  CHECK(tos::dns::check_domain_lifecycle(0, 0, 1000).is_error());
}

TEST(RldpHttpProxyDns, lifecycle_returns_the_renewal_deadline) {
  auto r = tos::dns::check_domain_lifecycle(0, 5000, 6000);
  CHECK(r.is_ok());
  CHECK(r.ok() == 5000 + tos::dns::DNS_LEASE_SECONDS);
}

TEST(RldpHttpProxyDns, cache_expiry_never_outlives_the_lease) {
  // plenty of lease left: the base ttl applies
  CHECK(tos::dns::bounded_cache_expiry(100.0, 300.0, 2'000'000, 1'000'000) == 400.0);
  // 10 seconds of lease left: the entry expires with the lease
  CHECK(tos::dns::bounded_cache_expiry(100.0, 300.0, 1'000'010, 1'000'000) == 110.0);
  // lease already over: the entry is born expired
  CHECK(tos::dns::bounded_cache_expiry(100.0, 300.0, 999'000, 1'000'000) == 100.0);
}

TEST(RldpHttpProxyDns, cache_evicts_expired_first_then_stalest) {
  constexpr size_t max_entries = 1024;
  std::map<std::string, tos::dns::DnsCacheEntry> cache;
  double now = 1000.0;
  for (size_t i = 0; i < max_entries; i++) {
    auto &e = cache["host" + std::to_string(i)];
    e.created_at_ = now - 500.0 + static_cast<double>(i);  // host0 is stalest
    e.expires_at_ = now + 100.0;                           // all still live
  }
  // full cache, all live: the stalest entry makes room
  tos::dns::evict_for_insert(cache, "newhost", now, max_entries);
  CHECK(cache.size() == max_entries - 1);
  CHECK(cache.find("host0") == cache.end());
  CHECK(cache.find("host1") != cache.end());
  cache["newhost"] = {"addr", now, now + 100.0};
  CHECK(cache.size() == max_entries);

  // expire a specific entry: it is evicted before any live entry
  cache["host7"].expires_at_ = now - 1.0;
  tos::dns::evict_for_insert(cache, "another", now, max_entries);
  CHECK(cache.find("host7") == cache.end());
  CHECK(cache.find("host1") != cache.end());
  CHECK(cache.size() == max_entries - 1);

  // re-inserting an existing key never evicts anything
  cache["another"] = {"addr", now, now + 100.0};
  auto before = cache.size();
  tos::dns::evict_for_insert(cache, "newhost", now, max_entries);
  CHECK(cache.size() == before);
}
