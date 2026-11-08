/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

// The external server derives an anonymous identity for every unauthenticated
// peer from its address. The liteserver itself sets no admission limits of its
// own; those properties are exercised end to end by test-adnl-ext-query-refusal.

#include <algorithm>
#include <string>

#include "adnl/adnl-ext-server-limits.h"
#include "td/utils/tests.h"

namespace tos {
namespace {

TEST(LiteServerAdmission, AnonymousIdentityIsStablePerIp) {
  auto first = adnl::external_peer_ip_identity("192.0.2.1");
  EXPECT(first == adnl::external_peer_ip_identity("192.0.2.1"));
  EXPECT(first != adnl::external_peer_ip_identity("192.0.2.2"));
  // The zero id is the "not yet authenticated" sentinel on the connection, so
  // a derived anonymous identity must never collide with it.
  auto bytes = first.as_slice();
  EXPECT(std::any_of(bytes.begin(), bytes.end(), [](char c) { return c != 0; }));
}

TEST(LiteServerAdmission, ConnectionIdentityPairsAddressWithItsKey) {
  // The anonymous identity and the logging key are derived together so the
  // derivation cannot depend on the order a call site happens to evaluate its
  // arguments in. If the address were consumed before being hashed, every peer
  // would share the identity of the empty string, silently.
  for (std::string ip : {std::string{"1.2.3.4"}, std::string{"203.0.113.9"}, std::string{"::1"}}) {
    auto identity = adnl::make_ext_connection_identity(ip);
    // The address must survive the derivation: it is the logging key.
    EXPECT(identity.peer_ip == ip);
    // And the identity must be the one derived from that same address, not
    // from an emptied or unrelated string.
    EXPECT(identity.anonymous_id == adnl::external_peer_ip_identity(ip));
    EXPECT(identity.anonymous_id != adnl::external_peer_ip_identity(td::Slice()));
  }

  // Distinct addresses must stay distinct.
  auto a = adnl::make_ext_connection_identity("198.51.100.1");
  auto b = adnl::make_ext_connection_identity("198.51.100.2");
  EXPECT(a.anonymous_id != b.anonymous_id);
  EXPECT(a.peer_ip != b.peer_ip);
}

}  // namespace
}  // namespace tos
