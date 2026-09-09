/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Tests for per-IP source attribution from X-Forwarded-For. The critical case
// is an appending edge proxy (e.g. nginx $proxy_add_x_forwarded_for): the
// leftmost XFF entry is a value the client invented, so trusting it lets a
// caller spoof its source IP for the per-IP rate gate. resolve_client_source_ip
// must instead take the rightmost entry that is not a configured trusted proxy.

#include <string>
#include <vector>

#include "td/utils/tests.h"
#include "validator-engine/json-rpc-source-ip.h"

namespace {
const std::vector<std::string> kNoProxies;
}  // namespace

// The client forges the leftmost entry; the trusted edge appends the real
// client IP on the right. We must attribute to the appended (rightmost
// non-proxy) entry, never the forged leftmost one.
TEST(JsonRpcSourceIp, AppendingProxyRejectsForgedLeftmostEntry) {
  std::vector<std::string> proxies{"10.0.0.1"};
  auto source = tos::resolve_client_source_ip(
      /*peer_ip=*/"10.0.0.1", /*forwarded_for=*/"6.6.6.6, 1.2.3.4", /*real_ip=*/"",
      /*trust_proxy_headers=*/true, proxies);
  ASSERT_EQ(source, std::string("1.2.3.4"));
}

// Multi-hop: two trusted proxies appended their views; peel both trusted hops
// from the right and attribute to the first untrusted entry — not the forged
// leftmost and not a trusted proxy address.
TEST(JsonRpcSourceIp, MultiHopPeelsTrustedProxies) {
  std::vector<std::string> proxies{"10.0.0.1", "10.0.0.2"};
  auto source = tos::resolve_client_source_ip(
      /*peer_ip=*/"10.0.0.1", /*forwarded_for=*/"6.6.6.6, 1.2.3.4, 10.0.0.2", /*real_ip=*/"",
      /*trust_proxy_headers=*/true, proxies);
  ASSERT_EQ(source, std::string("1.2.3.4"));
}

// Replace-style edge proxy with a single entry: the one entry is the client.
TEST(JsonRpcSourceIp, ReplacingProxySingleEntry) {
  std::vector<std::string> proxies{"10.0.0.1"};
  auto source = tos::resolve_client_source_ip("10.0.0.1", "1.2.3.4", "", true, proxies);
  ASSERT_EQ(source, std::string("1.2.3.4"));
}

// An untrusted peer must not be able to set its own source via headers.
TEST(JsonRpcSourceIp, UntrustedPeerIgnoresForwardingHeaders) {
  auto source = tos::resolve_client_source_ip("5.5.5.5", "1.2.3.4", "9.9.9.9", true, kNoProxies);
  ASSERT_EQ(source, std::string("5.5.5.5"));
}

// Trust disabled: the TCP peer is authoritative regardless of headers.
TEST(JsonRpcSourceIp, TrustDisabledUsesPeer) {
  std::vector<std::string> proxies{"10.0.0.1"};
  auto source = tos::resolve_client_source_ip("10.0.0.1", "1.2.3.4", "", false, proxies);
  ASSERT_EQ(source, std::string("10.0.0.1"));
}

// Loopback peer is an implicit trust anchor; with no XFF, X-Real-IP is used.
TEST(JsonRpcSourceIp, LoopbackPeerHonoursRealIpFallback) {
  auto source = tos::resolve_client_source_ip("127.0.0.1", "", "1.2.3.4", true, kNoProxies);
  ASSERT_EQ(source, std::string("1.2.3.4"));
}

// All hops are trusted proxies (no client hop): fall back to the leftmost
// rather than attributing to a proxy address.
TEST(JsonRpcSourceIp, AllHopsTrustedFallsBackToLeftmost) {
  std::vector<std::string> proxies{"10.0.0.1", "10.0.0.2"};
  auto source = tos::resolve_client_source_ip("10.0.0.1", "10.0.0.2, 10.0.0.1", "", true, proxies);
  ASSERT_EQ(source, std::string("10.0.0.2"));
}

int main(int argc, char** argv) {
  td::TestsRunner& runner = td::TestsRunner::get_default();
  if (argc > 1) {
    runner.add_substr_filter(argv[1]);
  }
  runner.run_all();
  return runner.any_test_failed() ? 1 : 0;
}
