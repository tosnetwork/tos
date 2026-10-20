/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// Deterministic transitions of the running count of unfinalized finalization entries. Every
// step compares the count with a full walk of the map and with the value the step must
// produce, so a missed or doubled adjustment on any transition fails here, without an actor,
// a scheduler or a race to arrange.

#include <cstdio>
#include <cstdlib>
#include <string>

#include "consensus/simplex/counted-finalizations.h"

namespace {

enum class State { Idle, InFlight, Finalized, Stalled };

struct Entry {
  State state = State::Idle;
  int attempts = 0;
};

using Entries = tos::validator::consensus::simplex::CountedFinalizations<int, Entry, State, State::Finalized>;

int checks = 0;

void expect(const Entries& entries, size_t count, size_t peak, const char* step) {
  ++checks;
  const size_t walked = entries.count_by_walk();
  if (entries.unfinalized() != walked || entries.unfinalized() != count || entries.unfinalized_peak() != peak) {
    std::fprintf(stderr,
                 "COUNTED_FINALIZATIONS_FAILED at %s: count %zu, walk %zu, expected %zu; peak %zu, expected %zu\n",
                 step, entries.unfinalized(), walked, count, entries.unfinalized_peak(), peak);
    std::exit(1);
  }
}

void require(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "COUNTED_FINALIZATIONS_FAILED: %s\n", what);
    std::exit(1);
  }
}

}  // namespace

int main() {
  Entries entries;
  expect(entries, 0, 0, "empty");

  // New entries are constructed in their initial state.
  auto& a = entries.entry_for(1, State::Idle);
  require(a.state == State::Idle, "a new Idle entry is Idle");
  expect(entries, 1, 1, "new Idle insert");
  auto& f = entries.entry_for(2, State::Finalized);
  require(f.state == State::Finalized, "a new Finalized entry is Finalized");
  expect(entries, 1, 1, "new Finalized insert");

  // An existing entry is returned untouched, whatever state the lookup names.
  a.attempts = 3;
  auto& again = entries.entry_for(1, State::Finalized);
  require(&again == &a && again.state == State::Idle && again.attempts == 3, "lookup leaves the entry untouched");
  auto& f_again = entries.entry_for(2, State::Idle);
  require(&f_again == &f && f_again.state == State::Finalized, "lookup of a Finalized entry leaves it Finalized");
  expect(entries, 1, 1, "repeated lookup");
  require(entries.size() == 2, "lookup inserts nothing");

  // Between unfinalized states the count does not move.
  entries.set_state(a, State::InFlight);
  expect(entries, 1, 1, "Idle -> InFlight");
  entries.set_state(a, State::InFlight);
  expect(entries, 1, 1, "repeated InFlight");

  // Each unfinalized state crossing into Finalized is counted once.
  auto& b = entries.entry_for(3, State::Idle);
  auto& c = entries.entry_for(4, State::Idle);
  entries.set_state(c, State::Stalled);
  expect(entries, 3, 3, "three unfinalized");
  entries.set_state(a, State::Finalized);
  expect(entries, 2, 3, "InFlight -> Finalized");
  entries.set_state(b, State::Finalized);
  expect(entries, 1, 3, "Idle -> Finalized");
  entries.set_state(c, State::Finalized);
  expect(entries, 0, 3, "Stalled -> Finalized");

  // Assigning Finalized again changes nothing.
  entries.set_state(c, State::Finalized);
  expect(entries, 0, 3, "repeated Finalized");

  // Leaving Finalized is counted too.
  entries.set_state(c, State::Idle);
  expect(entries, 1, 3, "Finalized -> Idle");
  entries.set_state(c, State::Finalized);
  expect(entries, 0, 3, "back to Finalized");

  // A finalized entry is evicted without touching the count.
  entries.erase_finalized(entries.find(2));
  require(entries.find(2) == entries.end() && entries.size() == 3, "the finalized entry is gone");
  expect(entries, 0, 3, "finalized eviction");

  // The durable-marker path: an attempt created the entry and is running when the marker read
  // returns. The lookup finds the running entry, leaves it as it is, and the overwrite to
  // Finalized is counted exactly once -- and the attempt's own Finalized afterwards is not.
  auto& running = entries.entry_for(5, State::Idle);
  entries.set_state(running, State::InFlight);
  expect(entries, 1, 3, "attempt in flight");
  auto& marker = entries.entry_for(5, State::Finalized);
  require(&marker == &running && marker.state == State::InFlight, "the marker lookup finds the running entry");
  entries.set_state(marker, State::Finalized);
  expect(entries, 0, 3, "durable marker overwrites the running entry");
  entries.set_state(running, State::Finalized);
  expect(entries, 0, 3, "the attempt then finalizes the same entry");

  // The peak is the most there were at once, not a running total.
  for (int key = 10; key < 15; ++key) {
    entries.entry_for(key, State::Idle);
  }
  expect(entries, 5, 5, "peak rises with the count");
  for (int key = 10; key < 15; ++key) {
    entries.set_state(entries.find(key)->second, State::Finalized);
  }
  expect(entries, 0, 5, "peak keeps its high-water mark");

  std::printf("COUNTED_FINALIZATIONS_OK %d checks\n", checks);
  return 0;
}
