#include "block/workchain-execution-ledger.h"
#include "td/actor/TestScheduler.h"
#include "td/actor/coro_utils.h"
#include <cstdlib>
#include <iostream>
#include <type_traits>

namespace {
using Claim = block::WorkchainExecutionClaim;
using Ledger = block::WorkchainExecutionLedger;
static_assert(!std::is_copy_constructible_v<Ledger> && !std::is_move_constructible_v<Ledger>);
static_assert(!std::is_copy_assignable_v<Ledger> && !std::is_move_assignable_v<Ledger>);
static_assert(!std::is_default_constructible_v<Ledger>);
static_assert(std::is_invocable_v<decltype(&Ledger::record_attempt), Ledger&, const vm::CellHash&>);
static_assert(!std::is_invocable_v<decltype(&Ledger::record_attempt), Ledger&, const vm::CellHash&, std::uint64_t>);

void require(bool condition, const char* identity) {
  if (!condition) {
    std::cerr << identity << '\n';
    std::exit(1);  // A coroutine assertion must not be swallowed by task detachment.
  }
}
vm::CellHash root(unsigned char value) {
  vm::CellHash hash{};
  hash.as_slice()[0] = value;
  return hash;
}

struct Allocations {
  unsigned calls = 0;
  unsigned live = 0;
  bool fail = false;
};
template <class T> struct ObservedAllocator {
  using value_type = T;
  Allocations* state;
  explicit ObservedAllocator(Allocations& value) : state(&value) {}
  template <class U> ObservedAllocator(const ObservedAllocator<U>& other) : state(other.state) {}
  T* allocate(std::size_t n) {
    ++state->calls;
    if (state->fail) throw std::bad_alloc();
    auto* p = std::allocator<T>{}.allocate(n);
    ++state->live;
    return p;
  }
  void deallocate(T* p, std::size_t n) {
    require(state->live > 0, "allocator.live_nonzero_before_release");
    --state->live;
    std::allocator<T>{}.deallocate(p, n);
  }
  template <class U> bool operator==(const ObservedAllocator<U>& other) const { return state == other.state; }
};

void allocation_and_capacity() {
  Allocations allocation;
  using MeteredLedger = block::BasicWorkchainExecutionLedger<ObservedAllocator<vm::CellHash>>;
  {
    MeteredLedger ledger{0, ObservedAllocator<vm::CellHash>{allocation}};
    require(ledger.record_attempt(root(1)) == Claim::BoundExceeded, "bound.zero_is_not_allocation_failure");
    require(allocation.calls == 0 && ledger.size() == 0, "bound.before_first_allocation");
  }
  {
    MeteredLedger ledger{2, ObservedAllocator<vm::CellHash>{allocation}};
    require(ledger.record_attempt(root(1)) == Claim::Recorded, "first.recorded");
    require(ledger.size() == 1 && ledger.contains(root(1)), "first.root_is_present");
    require(allocation.calls == 1, "allocation.positive_control");
    require(ledger.record_attempt(root(2)) == Claim::Recorded, "bound.exact_limit_allowed");
    require(ledger.size() == 2 && ledger.contains(root(2)), "bound.second_root_is_present");
    const auto before = allocation.calls;
    allocation.fail = true;
    require(ledger.record_attempt(root(3)) == Claim::BoundExceeded, "bound.not_allocator_failure");
    require(allocation.calls == before, "bound.no_insertion_allocation");
    require(ledger.size() == 2 && !ledger.contains(root(3)), "bound.no_mutation");
    require(ledger.record_attempt(root(1)) == Claim::DuplicateInput, "duplicate.at_capacity_is_distinct");
    require(allocation.calls == before, "duplicate.no_allocation");
  }
  require(allocation.live == 0, "scope.releases_nodes");
  {
    MeteredLedger ledger{2, ObservedAllocator<vm::CellHash>{allocation}};
    require(ledger.record_attempt(root(1)) == Claim::AllocationFailure, "allocator.failure_is_distinct");
    require(ledger.size() == 0 && !ledger.contains(root(1)), "allocator.failure_no_permission_or_record");
    allocation.fail = false;
    require(ledger.record_attempt(root(1)) == Claim::Recorded, "allocator.retry_after_unrecorded_attempt");
  }
  require(allocation.live == 0, "scope.retry_nodes_released");
}

struct Observations {
  unsigned executed = 0;
  unsigned destroyed = 0;
};
struct Snapshot {
  Claim claim;
  std::size_t size;
  bool contains;
};
class StatefulProbe {
 public:
  explicit StatefulProbe(Observations& observations) : observations_(observations) {}
  void execute() { ++observations_.executed; }  // Real method body, not its caller.
 private:
  Observations& observations_;
};
class CandidateScope final : public td::actor::Actor {
 public:
  explicit CandidateScope(Observations& observations) : observations_(observations), engine_(observations) {}
  ~CandidateScope() override { ++observations_.destroyed; }
  void attempt(vm::CellHash hash, td::Promise<Snapshot> promise) {
    const auto result = ledger_.record_attempt(hash);
    if (result == Claim::Recorded) engine_.execute();
    promise.set_value(Snapshot{result, ledger_.size(), ledger_.contains(hash)});
  }
  void finish() { stop(); }
 private:
  Observations& observations_;
  StatefulProbe engine_;
  Ledger ledger_{2};  // Private synthetic bound; actual actor member, no exit reset.
};

void actor_scopes() {
  Observations first, second;
  bool completed = false;
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto a = td::actor::create_actor<CandidateScope>("candidate-a", first);
    auto b = td::actor::create_actor<CandidateScope>("independent-validator", second);
    auto one = co_await td::actor::ask(a.get(), &CandidateScope::attempt, root(1));
    require(one.claim == Claim::Recorded && one.size == 1 && one.contains && first.executed == 1,
            "actor.first_execution_and_record");
    auto duplicate = co_await td::actor::ask(a.get(), &CandidateScope::attempt, root(1));
    require(duplicate.claim == Claim::DuplicateInput, "actor.same_scope_duplicate_identity");
    require(first.executed == 1 && duplicate.size == 1, "actor.duplicate_cannot_execute");
    auto independent = co_await td::actor::ask(b.get(), &CandidateScope::attempt, root(1));
    require(independent.claim == Claim::Recorded && independent.contains && second.executed == 1,
            "actor.independent_scope_allowed");
    td::actor::send_closure(a.get(), &CandidateScope::finish);
    td::actor::send_closure(b.get(), &CandidateScope::finish);
    co_await scheduler.wait_sync_work();
    require(first.destroyed == 1 && second.destroyed == 1, "actor.actual_destruction_observed");
    auto retry = td::actor::create_actor<CandidateScope>("new-candidate-attempt", first);
    auto fresh = co_await td::actor::ask(retry.get(), &CandidateScope::attempt, root(1));
    require(fresh.claim == Claim::Recorded && fresh.size == 1 && fresh.contains && first.executed == 2,
            "actor.new_instance_has_fresh_ledger");
    completed = true;
    co_return td::Unit{};
  });
  require(completed, "actor.coroutine_completed_all_checks");
  require(first.destroyed == 2 && second.destroyed == 1, "actor.cleanup_destruction");
}
}  // namespace

int main() {
  td::Time::allow_freezes();  // Required by the private single-thread actor scheduler.
  allocation_and_capacity();
  actor_scopes();
  std::cout << "ledger mechanism: first/duplicate/bound/allocation and actor lifecycle passed; no live enforcement\n";
}
