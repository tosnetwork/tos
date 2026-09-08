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

#include "td/utils/tests.h"

#include <string>

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
