/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <map>
#include <utility>

#include "td/actor/actor.h"
#include "td/actor/coro_utils.h"
#include "td/utils/ScopeGuard.h"
#include "validator/fabric.h"
#include "validator/manager-resource-policy.h"

namespace {

using namespace tos;
using namespace tos::validator;

class ValidatorManagerResourcePolicyHarness final : public td::actor::Actor {
 public:
  td::actor::Task<> run() {
    auto self = actor_id(this);
    CHECK(td::actor::detail::get_current_actor_id() == self);

    // Exercise the real detached shard-description worker from an actor. Its
    // production invariant checks that the worker continuation is off-actor;
    // the masterchain input then provides a deterministic error path.
    BlockIdExt masterchain_block{masterchainId, shardIdAll, 0, {}, {}};
    auto description =
        co_await generate_shard_block_description(masterchain_block, {}, td::Timestamp::in(1.0), {}).wrap();
    CHECK(description.is_error());
    CHECK(td::actor::detail::get_current_actor_id() == self);

    co_await test_shard_description_admission();
    co_await test_nonfinal_ingress_idempotence();
    CHECK(td::actor::detail::get_current_actor_id() == self);
    stop();
    co_return td::Unit{};
  }

 private:
  using NonfinalKey = std::pair<int, int>;

  td::actor::Task<> generate_description(int block, double delay) {
    using StartResult = BoundedActiveOperations<int>::StartResult;
    auto result = active_descriptions_.try_start(block);
    if (result == StartResult::AlreadyActive) {
      ++duplicate_descriptions_;
      co_return td::Unit{};
    }
    if (result == StartResult::Full) {
      ++rejected_descriptions_;
      co_return td::Unit{};
    }

    ++description_starts_[block];
    SCOPE_EXIT {
      active_descriptions_.finish(block);
    };
    co_await td::actor::coro_sleep(td::Timestamp::in(delay));
    ++description_completions_[block];
    co_return td::Unit{};
  }

  td::actor::Task<> test_shard_description_admission() {
    generate_description(1, 0.03).start().detach();
    generate_description(1, 0.03).start().detach();
    generate_description(1, 0.03).start().detach();
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    CHECK(active_descriptions_.size() == 1);
    CHECK(description_starts_[1] == 1);
    CHECK(duplicate_descriptions_ == 2);

    generate_description(2, 0.03).start().detach();
    generate_description(3, 0.03).start().detach();
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    CHECK(active_descriptions_.size() == active_descriptions_.capacity());
    CHECK(rejected_descriptions_ == 1);

    co_await td::actor::coro_sleep(td::Timestamp::in(0.04));
    CHECK(active_descriptions_.size() == 0);
    CHECK(description_completions_[1] == 1);
    CHECK(description_completions_[2] == 1);

    generate_description(3, 0.001).start().detach();
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    CHECK(description_starts_[3] == 1);
    CHECK(description_completions_[3] == 1);
    co_return td::Unit{};
  }

  td::actor::Task<> process_nonfinal(NonfinalKey key, double delay, bool state_available = true) {
    if (key.second < minimum_group_) {
      co_return td::Unit{};
    }

    using StartResult = BoundedIdempotentOperations<NonfinalKey>::StartResult;
    auto result = nonfinal_operations_.try_start(key);
    if (result == StartResult::AlreadyInFlight || result == StartResult::AlreadyProcessed) {
      ++duplicate_nonfinal_;
      co_return td::Unit{};
    }
    if (result == StartResult::Full) {
      ++rejected_nonfinal_;
      co_return td::Unit{};
    }

    ++nonfinal_waits_[key];
    bool completed = false;
    SCOPE_EXIT {
      if (!completed) {
        nonfinal_operations_.finish_failure_if_present(key);
      }
    };
    co_await td::actor::coro_sleep(td::Timestamp::in(delay));
    if (!state_available || !nonfinal_operations_.is_in_flight(key) || key.second < minimum_group_) {
      co_return td::Unit{};
    }

    ++published_nonfinal_[key];
    nonfinal_operations_.finish_success(key);
    completed = true;
    co_return td::Unit{};
  }

  void candidate_ingress(NonfinalKey key, double delay = 0.01, bool state_available = true) {
    process_nonfinal(key, delay, state_available).start().detach();
  }

  void finality_ingress(NonfinalKey key, double delay = 0.01, bool state_available = true) {
    process_nonfinal(key, delay, state_available).start().detach();
  }

  void shard_description_ingress(NonfinalKey key, double delay = 0.01, bool state_available = true) {
    process_nonfinal(key, delay, state_available).start().detach();
  }

  void rotate_to_group(int minimum_group) {
    minimum_group_ = minimum_group;
    auto obsolete = [&](const NonfinalKey &key) { return key.second < minimum_group_; };
    nonfinal_operations_.prune_in_flight(obsolete);
    nonfinal_operations_.prune_processed(obsolete);
  }

  td::actor::Task<> test_nonfinal_ingress_idempotence() {
    NonfinalKey duplicate_key{100, 7};
    candidate_ingress(duplicate_key);
    finality_ingress(duplicate_key);
    shard_description_ingress(duplicate_key);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
    CHECK(nonfinal_waits_[duplicate_key] == 1);
    CHECK(published_nonfinal_[duplicate_key] == 1);
    CHECK(duplicate_nonfinal_ == 2);

    // A processed duplicate remains suppressed, while distinct blocks in the
    // same group are exact-key idempotent even when delivered out of order.
    NonfinalKey later_block{300, 7};
    NonfinalKey earlier_block{200, 7};
    finality_ingress(duplicate_key, 0.001);
    finality_ingress(later_block, 0.001);
    finality_ingress(earlier_block, 0.001);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    CHECK(published_nonfinal_[duplicate_key] == 1);
    CHECK(published_nonfinal_[later_block] == 1);
    CHECK(published_nonfinal_[earlier_block] == 1);

    // A failed state wait releases admission and allows a legitimate retry.
    NonfinalKey retry_key{400, 7};
    candidate_ingress(retry_key, 0.005, false);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.01));
    CHECK(!nonfinal_operations_.is_in_flight(retry_key));
    finality_ingress(retry_key, 0.001, true);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    CHECK(nonfinal_waits_[retry_key] == 2);
    CHECK(published_nonfinal_[retry_key] == 1);

    // Rotation while suspended cancels the old exact key without a publish or
    // double erase, and stale ingress cannot start a replacement wait.
    NonfinalKey rotated_key{500, 7};
    finality_ingress(rotated_key, 0.03);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    CHECK(nonfinal_operations_.is_in_flight(rotated_key));
    rotate_to_group(8);
    CHECK(!nonfinal_operations_.is_in_flight(rotated_key));
    candidate_ingress(rotated_key, 0.001);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.04));
    CHECK(published_nonfinal_[rotated_key] == 0);
    CHECK(nonfinal_waits_[rotated_key] == 1);

    // The distinct-key cap rejects excess work and admits it after earlier
    // waits release their entries.
    NonfinalKey capacity_a{600, 8};
    NonfinalKey capacity_b{601, 8};
    NonfinalKey capacity_c{602, 8};
    candidate_ingress(capacity_a, 0.03);
    candidate_ingress(capacity_b, 0.03);
    candidate_ingress(capacity_c, 0.001);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    CHECK(nonfinal_operations_.in_flight_size() == nonfinal_operations_.in_flight_capacity());
    CHECK(rejected_nonfinal_ == 1);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.035));
    finality_ingress(capacity_c, 0.001);
    co_await td::actor::coro_sleep(td::Timestamp::in(0.005));
    CHECK(published_nonfinal_[capacity_a] == 1);
    CHECK(published_nonfinal_[capacity_b] == 1);
    CHECK(published_nonfinal_[capacity_c] == 1);
    co_return td::Unit{};
  }

  void tear_down() override {
    td::actor::SchedulerContext::get().stop();
  }

  BoundedActiveOperations<int> active_descriptions_{2};
  BoundedIdempotentOperations<NonfinalKey> nonfinal_operations_{2, 8};
  int minimum_group_{7};
  int duplicate_descriptions_{0};
  int rejected_descriptions_{0};
  int duplicate_nonfinal_{0};
  int rejected_nonfinal_{0};
  std::map<int, int> description_starts_;
  std::map<int, int> description_completions_;
  std::map<NonfinalKey, int> nonfinal_waits_;
  std::map<NonfinalKey, int> published_nonfinal_;
};

}  // namespace

int main() {
  td::actor::Scheduler scheduler({4});
  td::actor::ActorOwn<ValidatorManagerResourcePolicyHarness> harness;
  scheduler.run_in_context([&] {
    harness = td::actor::create_actor<ValidatorManagerResourcePolicyHarness>("manager-resource-policy-harness");
    td::actor::ask(harness, &ValidatorManagerResourcePolicyHarness::run).detach();
  });
  while (scheduler.run(1)) {
  }
  harness.reset();
  scheduler.stop();
  return 0;
}
