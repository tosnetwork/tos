/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

#include "td/utils/tests.h"

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
  // hostile getter values cannot overflow the signed deadline calculation
  CHECK(tos::dns::check_domain_lifecycle(0, std::numeric_limits<td::int64>::max(), 1000).is_error());
}

TEST(RldpHttpProxyDns, domain_item_is_the_canonical_third_hop_not_the_last) {
  std::vector<std::string> direct{"root", "collection", "item"};
  auto r_direct = tos::dns::select_tos_domain_item("alice.tos", direct);
  CHECK(r_direct.is_ok());
  CHECK(r_direct.ok().collection == "collection");
  CHECK(r_direct.ok().item == "item");
  CHECK(r_direct.ok().label == "alice");

  std::vector<std::string> delegated{"root", "collection", "item", "delegate", "terminal"};
  auto r_delegated = tos::dns::select_tos_domain_item("site.alice.tos.", delegated);
  CHECK(r_delegated.is_ok());
  CHECK(r_delegated.ok().item == "item");
  CHECK(r_delegated.ok().item != delegated.back());
  CHECK(r_delegated.ok().label == "alice");

  CHECK(tos::dns::select_tos_domain_item("tos", direct).is_error());
  CHECK(tos::dns::select_tos_domain_item("alice.example", direct).is_error());
  CHECK(tos::dns::select_tos_domain_item("alice.tos", {"root", "collection"}).is_error());
}

TEST(RldpHttpProxyDns, loaded_contract_cleanup_runs_exactly_once_on_every_exit) {
  int cleanup_calls = 0;
  {
    tos::dns::SharedCleanup outer([&] { cleanup_calls++; });
    {
      auto nested = outer;
      auto deepest = nested;
      CHECK(cleanup_calls == 0);
    }
    CHECK(cleanup_calls == 0);
  }
  CHECK(cleanup_calls == 1);
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
  // extreme hostile values are saturated by the TTL without integer overflow
  CHECK(tos::dns::bounded_cache_expiry(100.0, 300.0, std::numeric_limits<td::int64>::max(),
                                       std::numeric_limits<td::int64>::min()) == 400.0);
  CHECK(tos::dns::bounded_cache_expiry(100.0, 300.0, std::numeric_limits<td::int64>::min(),
                                       std::numeric_limits<td::int64>::max()) == 100.0);
}

TEST(RldpHttpProxyDns, checkpoint_identity_detects_progress_and_reorganization) {
  tos::dns::DnsCheckpoint original{0, -1, 42, "root-a", "file-a"};
  auto identical = original;
  CHECK(original == identical);

  auto next_height = original;
  next_height.seqno++;
  CHECK(original != next_height);

  // Reorgs may replace a block without changing its logical height.
  auto same_height_reorg = original;
  same_height_reorg.root_hash = "root-b";
  CHECK(original != same_height_reorg);

  auto different_file = original;
  different_file.file_hash = "file-b";
  CHECK(original != different_file);
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
