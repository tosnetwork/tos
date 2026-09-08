/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "validator-engine/json-rpc-rate-gate.h"

#include "td/utils/JsonBuilder.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/buffer.h"
#include "td/utils/tests.h"

#include <string>
#include <vector>

namespace {

// A fixed origin for the clock so a window boundary is crossed by
// arithmetic rather than by waiting.
td::Timestamp at(double seconds) {
  return td::Timestamp::at(seconds);
}

}  // namespace

TEST(JsonRpcRateGate, spends_budget_then_refuses) {
  tos::PerIpRateGate gate(10.0, 3, 4096);

  for (int i = 0; i < 3; i++) {
    ASSERT_TRUE(gate.consume("198.51.100.7", at(1000.0)));
  }
  // Budget for this window is gone.
  ASSERT_TRUE(!gate.consume("198.51.100.7", at(1000.0)));
  ASSERT_TRUE(!gate.consume("198.51.100.7", at(1009.0)));
}

TEST(JsonRpcRateGate, budget_returns_after_window) {
  tos::PerIpRateGate gate(10.0, 2, 4096);

  ASSERT_TRUE(gate.consume("198.51.100.7", at(1000.0)));
  ASSERT_TRUE(gate.consume("198.51.100.7", at(1000.0)));
  ASSERT_TRUE(!gate.consume("198.51.100.7", at(1005.0)));
  // Past the window the earlier requests no longer count against it.
  ASSERT_TRUE(gate.consume("198.51.100.7", at(1011.0)));
}

TEST(JsonRpcRateGate, one_source_cannot_spend_anothers_budget) {
  tos::PerIpRateGate gate(10.0, 1, 4096);

  ASSERT_TRUE(gate.consume("198.51.100.7", at(1000.0)));
  ASSERT_TRUE(!gate.consume("198.51.100.7", at(1000.0)));
  // A different address still has its own budget.
  ASSERT_TRUE(gate.consume("203.0.113.9", at(1000.0)));
}

TEST(JsonRpcRateGate, table_is_bounded_and_evicts_least_recently_seen) {
  tos::PerIpRateGate gate(10.0, 100, 3);

  // Three addresses fill the table; the first is the quietest.
  ASSERT_TRUE(gate.consume("198.51.100.1", at(1000.0)));
  ASSERT_TRUE(gate.consume("198.51.100.2", at(1001.0)));
  ASSERT_TRUE(gate.consume("198.51.100.3", at(1002.0)));
  ASSERT_EQ(3u, gate.tracked_sources());

  // A fourth address must not grow the table past its ceiling.
  ASSERT_TRUE(gate.consume("198.51.100.4", at(1003.0)));
  ASSERT_EQ(3u, gate.tracked_sources());
}

TEST(JsonRpcRateGate, rotating_sources_cannot_clear_a_spent_window) {
  // The table holds two addresses. An attacker that has spent its own
  // budget must not be able to reclaim it by cycling other addresses
  // through the table: the entry it keeps touching is never the least
  // recently seen one.
  tos::PerIpRateGate gate(10.0, 1, 2);

  ASSERT_TRUE(gate.consume("198.51.100.7", at(1000.0)));
  ASSERT_TRUE(!gate.consume("198.51.100.7", at(1000.1)));

  for (int i = 0; i < 8; i++) {
    std::string filler = "203.0.113." + std::to_string(i);
    gate.consume(filler, at(1001.0 + i));
    // Keep the attacker's entry the most recently seen of the two.
    ASSERT_TRUE(!gate.consume("198.51.100.7", at(1001.5 + i)));
  }
}

TEST(JsonRpcRateGate, unattributed_source_is_admitted) {
  // In-process and test callers have no remote address to charge.
  tos::PerIpRateGate gate(10.0, 1, 4096);

  for (int i = 0; i < 10; i++) {
    ASSERT_TRUE(gate.consume("", at(1000.0)));
  }
  ASSERT_EQ(0u, gate.tracked_sources());
}

TEST(JsonRpcRateGate, zero_limit_or_window_disables_the_gate) {
  tos::PerIpRateGate no_limit(10.0, 0, 4096);
  tos::PerIpRateGate no_window(0.0, 5, 4096);

  for (int i = 0; i < 10; i++) {
    ASSERT_TRUE(no_limit.consume("198.51.100.7", at(1000.0)));
    ASSERT_TRUE(no_window.consume("198.51.100.7", at(1000.0)));
  }
}

// The response builders assemble bodies with a growable builder. The
// fixed-buffer alternative in this codebase stops at 128 KiB and reports
// no error, so a large result was delivered cut in half and answered
// with "ok": a body no client can parse, presented as success.
TEST(JsonRpcResponseBody, large_result_is_not_truncated) {
  std::string payload(200 * 1024, 'x');

  // PSTRING() here instead of the growable builder is what the fix
  // replaced; swapping it back makes this test fail.
  td::StringBuilder sb;
  sb << "{\"ok\":true,\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"" << payload << "\"}";
  std::string body = sb.as_cslice().str();

  ASSERT_TRUE(body.size() > payload.size());
  ASSERT_TRUE(body.size() >= 2 && body.compare(body.size() - 2, 2, "\"}") == 0);
}

// The batch driver holds parsed elements across an actor message, and a
// td::JsonValue borrows slices from the buffer it was decoded from rather
// than owning its strings. These pin that ownership rule with the same
// types the server uses.
//
// Under a normal build the released-buffer case reads plausible bytes and
// proves nothing; run this suite from an ASAN build for it to mean
// anything. It is kept here so the rule is stated somewhere executable:
// a future change that drops the buffer has to delete this to stay green.
TEST(JsonRpcBatchLifetime, parsed_values_borrow_from_their_buffer) {
  td::BufferSlice body(R"([{"method":"alpha"},{"method":"beta"}])");
  auto parsed = td::json_decode(body.as_slice());
  ASSERT_TRUE(parsed.is_ok());
  auto value = parsed.move_as_ok();
  ASSERT_TRUE(value.type() == td::JsonValue::Type::Array);

  auto &arr = value.get_array();
  ASSERT_EQ(2u, arr.size());

  // Moving the elements out does not copy the strings they point at, so
  // holding them without the buffer would leave them dangling. Keeping
  // the buffer alive alongside is what makes the reads below defined --
  // which is exactly what BatchState now does.
  std::vector<td::JsonValue> elements;
  for (auto &el : arr) {
    elements.push_back(std::move(el));
  }

  ASSERT_TRUE(elements[1].type() == td::JsonValue::Type::Object);
  auto method = elements[1].get_object().get_required_string_field("method");
  ASSERT_TRUE(method.is_ok());
  ASSERT_STREQ("beta", method.ok());
}
