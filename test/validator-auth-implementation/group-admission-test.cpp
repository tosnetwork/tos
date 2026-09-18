// Two asynchronous startup reads, either order, and a chain that has to start.
//
// A validator group on a chain that activated the design needs the cleanup
// records loaded and this node's chain context established. Both arrive from
// unrelated asynchronous reads, and group creation is otherwise driven by a new
// masterchain block -- so if the context is late, every group is refused, and on
// a chain whose validators are all in that state the block that would drive the
// next attempt is the one none of them is producing. Nothing asks again.
//
// These cases are that ordering. They do not run the manager, an actor or a
// chain: they establish that the decision is right for every order the two
// reads can complete in, and that a read which fails once is asked again.
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "validator/auth/manager-group-admission.h"

using namespace tos::auth;

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

void expect(bool condition, const char* name) {
  if (!condition) {
    std::cerr << "ASSERTION: " << name << '\n';
    std::exit(1);
  }
}
}  // namespace

int main() {
  // The order of these cases is load-bearing. Each rule below is removed by a
  // mutation, and the suite stops at its first failure, so a case that
  // exercises several rules at once has to come after the cases that isolate
  // them -- otherwise two separate rules fail the same case and read as one.
  // A node that refused nothing creates nothing. Both conditions holding is not
  // a reason to drive a pass; a pass that nothing asked for would retire live
  // groups and fence the sessions they were running.
  {
    GroupAdmissionGate gate;
    gate.cleanup_records_loaded();
    expect(!gate.create_deferred_groups(true), "a-node-that-refused-nothing-drives-no-pass");
    expect(!gate.groups_deferred(), "a-node-that-refused-nothing-drives-no-pass");
    ok("a-node-that-refused-nothing-drives-no-pass");
  }

  // And the barrier alone is not enough, in either direction: a deferral with no
  // context stays deferred however many times it is asked.
  {
    GroupAdmissionGate gate;
    gate.defer_groups();
    for (int attempt = 0; attempt < 3; ++attempt) {
      expect(!gate.create_deferred_groups(false), "neither-condition-alone-creates-a-group");
    }
    gate.cleanup_records_loaded();
    expect(!gate.create_deferred_groups(false), "neither-condition-alone-creates-a-group");
    expect(gate.cleanup_records_are_loaded(), "neither-condition-alone-creates-a-group");
    ok("neither-condition-alone-creates-a-group");
  }

  // The order the race produces when the context is late. This is the genesis
  // deadlock: the barrier is crossed, the startup pass refuses every group
  // because there is no context, and the context then arrives with no block
  // coming to drive a second pass.
  {
    GroupAdmissionGate gate;
    gate.cleanup_records_loaded();
    // The startup pass runs and refuses.
    expect(!gate.create_deferred_groups(false), "the-late-context-creates-the-groups-it-refused");
    gate.defer_groups();
    // Nothing has changed yet, so nothing is created twice over.
    expect(!gate.create_deferred_groups(false), "the-late-context-creates-the-groups-it-refused");
    // And the arrival is what creates them.
    expect(gate.create_deferred_groups(true), "the-late-context-creates-the-groups-it-refused");
    // Once, not on every later arrival: a second pass would retire the groups
    // the first one created and fence their session ids.
    expect(!gate.create_deferred_groups(true), "the-late-context-creates-the-groups-it-refused");
    ok("the-late-context-creates-the-groups-it-refused");
  }

  // The other order. A context that arrives first must not create a group,
  // because the records that say which consensus directories may be deleted are
  // not loaded, and a group created before them can have its own directory
  // deleted under it.
  {
    GroupAdmissionGate gate;
    gate.defer_groups();
    expect(!gate.create_deferred_groups(true), "an-early-context-creates-nothing-before-the-records");
    expect(gate.groups_deferred(), "an-early-context-creates-nothing-before-the-records");
    // Crossing the barrier is then what releases it.
    gate.cleanup_records_loaded();
    expect(gate.create_deferred_groups(true), "an-early-context-creates-nothing-before-the-records");
    expect(!gate.groups_deferred(), "an-early-context-creates-nothing-before-the-records");
    ok("an-early-context-creates-nothing-before-the-records");
  }

  // A catchain transition has a third arrival besides startup context/store
  // readiness: the transition block can be applied before its finality is
  // durably published. The first update pass then refuses the new session and
  // remembers it. Once that same transition block becomes the independently
  // finalized head, the remembered pass must run even if no new block can be
  // produced yet by the new session.
  {
    GroupAdmissionGate gate;
    gate.cleanup_records_loaded();
    gate.defer_groups();
    expect(gate.groups_deferred(), "a-new-finalized-head-redrives-the-transition-session");
    expect(gate.create_deferred_groups(true), "a-new-finalized-head-redrives-the-transition-session");
    expect(!gate.groups_deferred(), "a-new-finalized-head-redrives-the-transition-session");
    // Re-publishing the same authority coordinate must not create a second pass.
    expect(!gate.create_deferred_groups(true), "a-new-finalized-head-redrives-the-transition-session");
    ok("a-new-finalized-head-redrives-the-transition-session");
  }

  // The read that failed once has to be asked again, and the waiting has to
  // grow and then stop growing. A fixed retry hammers the archive that is
  // already failing; an unbounded one becomes a stall nobody is waiting for.
  {
    double interval = next_chain_context_retry(0.0);
    expect(std::abs(interval - chain_context_retry_floor) < 1e-9, "a-failed-read-is-asked-again");
    std::vector<double> seen{interval};
    for (int attempt = 0; attempt < 12; ++attempt) {
      auto next = next_chain_context_retry(interval);
      expect(next >= interval, "a-failed-read-is-asked-again");
      expect(next <= chain_context_retry_ceiling, "a-failed-read-is-asked-again");
      interval = next;
      seen.push_back(interval);
    }
    // It grew at all, and it reached the ceiling rather than creeping.
    expect(seen[1] > seen[0], "a-failed-read-is-asked-again");
    expect(std::abs(interval - chain_context_retry_ceiling) < 1e-9, "a-failed-read-is-asked-again");
    // A success resets it, so a node that recovers does not carry the last
    // failure's patience into the next one.
    expect(std::abs(next_chain_context_retry(0.0) - chain_context_retry_floor) < 1e-9,
           "a-failed-read-is-asked-again");
    ok("a-failed-read-is-asked-again");
  }

  {
    ChainContextRetryGate retry;
    auto ticket = retry.failed();
    expect(ticket.has_value(), "a-pending-retry-blocks-an-admission-read");
    expect(!retry.read_may_start(), "a-pending-retry-blocks-an-admission-read");
    ok("a-pending-retry-blocks-an-admission-read");
  }

  {
    ChainContextRetryGate retry;
    expect(retry.failed().has_value(), "one-failure-stream-has-one-pending-retry");
    expect(!retry.failed().has_value(), "one-failure-stream-has-one-pending-retry");
    expect(retry.retry_scheduled(), "one-failure-stream-has-one-pending-retry");
    ok("one-failure-stream-has-one-pending-retry");
  }

  {
    ChainContextRetryGate retry;
    auto old = retry.failed();
    expect(old.has_value() && retry.due(old->generation), "a-stale-retry-cannot-consume-the-current-one");
    auto current = retry.failed();
    expect(current.has_value(), "a-stale-retry-cannot-consume-the-current-one");
    expect(!retry.due(old->generation), "a-stale-retry-cannot-consume-the-current-one");
    expect(retry.retry_scheduled(), "a-stale-retry-cannot-consume-the-current-one");
    expect(retry.due(current->generation), "a-stale-retry-cannot-consume-the-current-one");
    ok("a-stale-retry-cannot-consume-the-current-one");
  }

  {
    ChainContextRetryGate retry;
    auto ticket = retry.failed();
    expect(ticket.has_value(), "success-invalidates-an-already-scheduled-retry");
    retry.succeeded();
    expect(retry.read_may_start(), "success-invalidates-an-already-scheduled-retry");
    expect(!retry.due(ticket->generation), "success-invalidates-an-already-scheduled-retry");
    expect(std::abs(retry.retry_delay()) < 1e-9, "success-invalidates-an-already-scheduled-retry");
    ok("success-invalidates-an-already-scheduled-retry");
  }

  // The whole sequence the review names: the first read fails, the second
  // succeeds, and the group exists at the end of it.
  {
    GroupAdmissionGate gate;
    gate.cleanup_records_loaded();
    gate.defer_groups();
    double interval = 0.0;
    bool created = false;
    for (int attempt = 0; attempt < 2 && !created; ++attempt) {
      bool read_succeeded = attempt == 1;
      if (!read_succeeded) {
        interval = next_chain_context_retry(interval);
        expect(interval > 0.0, "a-group-refused-for-a-failed-read-is-created-after-a-later-one");
        // Still refused, and still remembered.
        expect(!gate.create_deferred_groups(false), "a-group-refused-for-a-failed-read-is-created-after-a-later-one");
        expect(gate.groups_deferred(), "a-group-refused-for-a-failed-read-is-created-after-a-later-one");
        continue;
      }
      created = gate.create_deferred_groups(true);
    }
    expect(created, "a-group-refused-for-a-failed-read-is-created-after-a-later-one");
    ok("a-group-refused-for-a-failed-read-is-created-after-a-later-one");
  }

  std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
  return 0;
}
