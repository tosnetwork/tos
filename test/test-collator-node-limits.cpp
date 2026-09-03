/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "validator/collator-node/collator-node-limits.h"

#include <cstdio>
#include <vector>

using tos::validator::at_capacity;
using tos::validator::collation_slot_in_flight;
using tos::validator::CollationSlot;
using tos::validator::count_in_flight_collations;

static int failures = 0;

#define CHECK_EQ(actual, expected)                                                              \
  do {                                                                                          \
    auto a_ = (actual);                                                                         \
    auto e_ = (expected);                                                                       \
    if (!(a_ == e_)) {                                                                          \
      std::fprintf(stderr, "%s:%d: %s == %s failed (%lld vs %lld)\n", __FILE__, __LINE__,       \
                   #actual, #expected, (long long)a_, (long long)e_);                           \
      ++failures;                                                                               \
    }                                                                                           \
  } while (0)

#define CHECK_TRUE(cond)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      std::fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #cond);   \
      ++failures;                                                             \
    }                                                                          \
  } while (0)

int main() {
  // A slot counts as in flight only while started and not yet resolved.
  CHECK_TRUE(!collation_slot_in_flight(CollationSlot{.started = false, .has_result = false}));
  CHECK_TRUE(collation_slot_in_flight(CollationSlot{.started = true, .has_result = false}));
  // The load-bearing case: a started collation that has produced a result no
  // longer occupies a slot. If this counted, a shard that stops finalizing
  // would keep its cached results and wedge all further collation.
  CHECK_TRUE(!collation_slot_in_flight(CollationSlot{.started = true, .has_result = true}));
  // A not-yet-started entry (a bare cache placeholder) never counts.
  CHECK_TRUE(!collation_slot_in_flight(CollationSlot{.started = false, .has_result = true}));

  std::vector<CollationSlot> empty;
  CHECK_EQ(count_in_flight_collations(empty), 0u);

  std::vector<CollationSlot> mixed{
      {.started = true, .has_result = false},   // in flight
      {.started = true, .has_result = true},    // finished, cached
      {.started = false, .has_result = false},  // placeholder
      {.started = true, .has_result = false},   // in flight
      {.started = true, .has_result = true},    // finished, cached
  };
  CHECK_EQ(count_in_flight_collations(mixed), 2u);

  // A pile of finished results must not exhaust the concurrency budget.
  std::vector<CollationSlot> all_finished(100, CollationSlot{.started = true, .has_result = true});
  CHECK_EQ(count_in_flight_collations(all_finished), 0u);
  CHECK_TRUE(!at_capacity(count_in_flight_collations(all_finished), 4));

  // The cap is inclusive: the boundary is reached at exactly the cap.
  CHECK_TRUE(!at_capacity(0, 4));
  CHECK_TRUE(!at_capacity(3, 4));
  CHECK_TRUE(at_capacity(4, 4));
  CHECK_TRUE(at_capacity(5, 4));

  // With four in flight and a cap of four, a fifth is refused; dropping one
  // below the cap admits again.
  std::vector<CollationSlot> four_in_flight(4, CollationSlot{.started = true, .has_result = false});
  CHECK_EQ(count_in_flight_collations(four_in_flight), 4u);
  CHECK_TRUE(at_capacity(count_in_flight_collations(four_in_flight), 4));
  four_in_flight.back().has_result = true;  // one finishes
  CHECK_EQ(count_in_flight_collations(four_in_flight), 3u);
  CHECK_TRUE(!at_capacity(count_in_flight_collations(four_in_flight), 4));

  if (failures != 0) {
    std::fprintf(stderr, "collator-node-limits: %d checks failed\n", failures);
    return 1;
  }
  return 0;
}
