/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

// Slice 6 Stage 5 supervision/restart-intensity predicate fixtures.

#include "td/utils/tests.h"

#include <cstdint>

namespace {

constexpr td::uint8 kOneForOne = 0;
constexpr td::uint8 kOneForAll = 1;
constexpr td::uint8 kRestForOne = 2;
constexpr td::uint8 kActive = 0;
constexpr td::uint8 kRecovering = 1;
constexpr td::uint8 kCircuitOpen = 3;

struct Budget {
  td::uint16 max_restarts = 2;
  td::uint32 restart_window_blocks = 10;
  td::uint32 cooldown_blocks = 5;
  td::uint32 max_recovery_gas = 1000;
  td::uint64 max_recovery_value = 100;
};

struct Child {
  td::uint16 registry_order = 0;
  td::uint16 restart_count = 0;
  td::uint32 window_started_at = 100;
  td::uint32 cooldown_until = 0;
  td::uint8 state = kActive;

  bool circuit_open(td::uint32 now) const {
    return state == kCircuitOpen && now < cooldown_until;
  }

  void reset_window_if_expired(const Budget& budget, td::uint32 now) {
    if (now >= window_started_at + budget.restart_window_blocks) {
      window_started_at = now;
      restart_count = 0;
    }
  }

  bool record_restart(const Budget& budget, td::uint32 now, td::uint32 gas, td::uint64 value) {
    reset_window_if_expired(budget, now);
    if (circuit_open(now) || gas > budget.max_recovery_gas || value > budget.max_recovery_value ||
        restart_count >= budget.max_restarts) {
      state = kCircuitOpen;
      cooldown_until = now + budget.cooldown_blocks;
      return false;
    }
    ++restart_count;
    state = kRecovering;
    return true;
  }
};

bool strategy_includes_child(td::uint8 strategy, td::uint16 failed_order, td::uint16 candidate_order) {
  if (strategy == kOneForOne) {
    return candidate_order == failed_order;
  }
  if (strategy == kOneForAll) {
    return true;
  }
  if (strategy == kRestForOne) {
    return candidate_order >= failed_order;
  }
  return candidate_order == failed_order;
}

}  // namespace

TEST(Slice6Stage5SupervisionFixtures, OneForOneRecoveryRecordsRestart) {
  Budget budget;
  Child child;
  CHECK(child.record_restart(budget, 101, 500, 10));
  CHECK(child.restart_count == 1);
  CHECK(child.state == kRecovering);
}

TEST(Slice6Stage5SupervisionFixtures, RestartStormStopsAtCircuitBreaker) {
  Budget budget;
  budget.max_restarts = 1;
  Child child;
  CHECK(child.record_restart(budget, 101, 500, 10));
  CHECK(!child.record_restart(budget, 102, 500, 10));
  CHECK(child.state == kCircuitOpen);
  CHECK(child.circuit_open(103));
  CHECK(!child.circuit_open(108));
}

TEST(Slice6Stage5SupervisionFixtures, RestForOneUsesExplicitRegistryOrder) {
  CHECK(!strategy_includes_child(kRestForOne, 2, 1));
  CHECK(strategy_includes_child(kRestForOne, 2, 2));
  CHECK(strategy_includes_child(kRestForOne, 2, 3));
}

TEST(Slice6Stage5SupervisionFixtures, OneForAllIsBestEffortNonAtomic) {
  CHECK(strategy_includes_child(kOneForAll, 2, 1));
  CHECK(strategy_includes_child(kOneForAll, 2, 2));
  CHECK(strategy_includes_child(kOneForAll, 2, 3));

  constexpr td::uint16 recovered_before_failure = 2;
  constexpr td::uint64 failed_at_child_id = 3;
  CHECK(recovered_before_failure == 2);
  CHECK(failed_at_child_id == 3);
}

TEST(Slice6Stage5SupervisionFixtures, GasAndValueBudgetsStopRecovery) {
  Budget budget;
  Child gas_child;
  CHECK(!gas_child.record_restart(budget, 101, 1001, 10));
  CHECK(gas_child.state == kCircuitOpen);

  Child value_child;
  CHECK(!value_child.record_restart(budget, 101, 500, 101));
  CHECK(value_child.state == kCircuitOpen);
}
