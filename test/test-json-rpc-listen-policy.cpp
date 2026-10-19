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

// A write-enabled plaintext JSON-RPC listener binds loopback only. These cases
// pin the address classification and the admission decision that the engine
// applies at startup; the engine-level refusal itself is exercised by
// scripts/check-json-rpc-startup-refusal.py against the real binary.

#include <string>

#include "td/utils/tests.h"
#include "validator-engine/json-rpc-listen-policy.h"

namespace {

td::IPAddress parse(const char* host_port) {
  td::IPAddress addr;
  addr.init_host_port(td::CSlice(host_port)).ensure();
  return addr;
}

bool accepts(const char* host_port, bool readonly) {
  return tos::json_rpc::check_listen_admission(parse(host_port), readonly).is_ok();
}

}  // namespace

TEST(JsonRpcListenPolicy, LoopbackAddressesAreRecognised) {
  ASSERT_TRUE(tos::json_rpc::is_loopback_bind_address(parse("127.0.0.1:8081")));
  ASSERT_TRUE(tos::json_rpc::is_loopback_bind_address(parse("127.1.2.3:8081")));
  ASSERT_TRUE(tos::json_rpc::is_loopback_bind_address(parse("[::1]:8081")));
}

TEST(JsonRpcListenPolicy, NonLoopbackAddressesAreNotLoopback) {
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("0.0.0.0:8081")));
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("10.0.0.5:8081")));
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("8.8.8.8:8081")));
  // 126.x and 128.x sit on either side of the loopback block.
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("126.0.0.1:8081")));
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("128.0.0.1:8081")));
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("[::]:8081")));
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("[::2]:8081")));
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("[2001:db8::1]:8081")));
  // An IPv4-mapped loopback is not classified as loopback: the conservative
  // answer is a refusal, never an exposure.
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(parse("[::ffff:127.0.0.1]:8081")));
  ASSERT_TRUE(!tos::json_rpc::is_loopback_bind_address(td::IPAddress()));
}

TEST(JsonRpcListenPolicy, WriteEnabledListenerBindsLoopbackOnly) {
  ASSERT_TRUE(accepts("127.0.0.1:8081", /*readonly=*/false));
  ASSERT_TRUE(accepts("[::1]:8081", /*readonly=*/false));
  ASSERT_TRUE(!accepts("0.0.0.0:8081", /*readonly=*/false));
  ASSERT_TRUE(!accepts("10.0.0.5:8081", /*readonly=*/false));
  ASSERT_TRUE(!accepts("[::]:8081", /*readonly=*/false));
  ASSERT_TRUE(!accepts("[::ffff:127.0.0.1]:8081", /*readonly=*/false));
}

TEST(JsonRpcListenPolicy, ReadOnlyListenerMayBindAnywhere) {
  ASSERT_TRUE(accepts("0.0.0.0:8081", /*readonly=*/true));
  ASSERT_TRUE(accepts("10.0.0.5:8081", /*readonly=*/true));
  ASSERT_TRUE(accepts("127.0.0.1:8081", /*readonly=*/true));
}

TEST(JsonRpcListenPolicy, RefusalNamesTheSafeAlternatives) {
  auto status = tos::json_rpc::check_listen_admission(parse("0.0.0.0:8081"), /*readonly=*/false);
  ASSERT_TRUE(status.is_error());
  const std::string message = status.message().str();
  ASSERT_TRUE(message.find("non-loopback") != std::string::npos);
  ASSERT_TRUE(message.find("TLS reverse proxy") != std::string::npos);
  ASSERT_TRUE(message.find("--json-rpc-readonly") != std::string::npos);
}

int main(int argc, char** argv) {
  td::TestsRunner& runner = td::TestsRunner::get_default();
  if (argc > 1) {
    runner.add_substr_filter(argv[1]);
  }
  runner.run_all();
  return runner.any_test_failed() ? 1 : 0;
}
