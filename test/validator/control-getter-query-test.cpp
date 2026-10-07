/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>
#include <bit>
#include <cstdio>
#include <future>
#include <limits>
#include <mutex>
#include <sys/wait.h>
#include <unistd.h>

#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "validator-engine/control-getter-service.h"
#include "vm/vm.h"

#include "control-getter-fixture.h"

using namespace control_fixture;
namespace cg = tos::control_getter;
int checks = 0;
int failures = 0;
void check(const char* name, bool ok) {
  ++checks;
  if (!ok) {
    ++failures;
    std::fprintf(stderr, "CONTROL_QUERY_FAIL %s\n", name);
  }
}
std::string zero;
std::string fixtures;

struct Harness {
  td::actor::Scheduler scheduler{std::vector<td::actor::Scheduler::NodeInfo>{2}};
  td::actor::ActorOwn<cg::Service> service;
  std::atomic<int> lookups{0};
  getter_fixture::State state;
  std::atomic<bool> wrong_block{false};
  std::atomic<bool> hold{false};
  std::mutex held_mutex;
  std::vector<td::Promise<cg::LoadedState>> held;
  explicit Harness(getter_fixture::State value) : state(std::move(value)) {
    scheduler.run_in_context([&] {
      service = td::actor::create_actor<cg::Service>(
          "query-service", [this](td::optional<tos::BlockIdExt> target, td::Promise<cg::LoadedState> promise) {
            ++lookups;
            if (hold.load()) {
              std::lock_guard lock(held_mutex);
              held.push_back(std::move(promise));
              return;
            }
            if (target && target.value() != state.id && !wrong_block) {
              promise.set_error(td::Status::Error("historical state unavailable"));
              return;
            }
            promise.set_value(cg::LoadedState{state.id, state.root});
          });
    });
  }
  td::BufferSlice request(cg::ReadKind kind, std::vector<td::Bits256> wallets = {}, int perm = 1, int flags = 0,
                          td::optional<tos::BlockIdExt> block = {}, td::Bits256 hash = {}) {
    std::mutex mutex;
    td::Result<td::BufferSlice> response{td::Status::Error("no response")};
    bool done = false;
    scheduler.run_in_context([&] {
      td::actor::send_closure(service.get(), &cg::Service::query, perm, flags, block, cg::Request{kind, wallets, hash},
                              [&](td::Result<td::BufferSlice> value) {
                                std::lock_guard lock(mutex);
                                response = std::move(value);
                                done = true;
                              });
    });
    const auto deadline = td::Timestamp::in(40);
    for (;;) {
      scheduler.run(0.001);
      {
        std::lock_guard lock(mutex);
        if (done) {
          break;
        }
      }
      require(!deadline.is_in_past(), "query watchdog");
    }
    return must(std::move(response), "query answered");
  }
  ~Harness() {
    scheduler.run_in_context([&] { service.reset(); });
  }
};
std::string error(const td::BufferSlice& value) {
  auto decoded = tos::fetch_tl_object<tos::tos_api::engine_validator_controlQueryError>(value, true);
  return decoded.is_ok() ? decoded.ok()->message_ : "not a control error";
}
void service_test() {
  auto saved = split(load(fixtures + "/elector-data.boc"));
  saved.elect = grow_members(saved.elect, 256, Book::DeepestMaxStake);
  saved.past = past_shape(saved.past, 16, 256, true);
  saved.credits = deepest_credits();
  auto state = production_build(zero, fixtures, "", 17, true, join(saved), config_proposals(200, false, 21));
  auto snap = must(cg::Snapshot::create(state.id, state.root), "direct snapshot");
  auto direct = cg::read(*snap, cg::Request{cg::ReadKind::Elector, {}, {}});
  if (direct.is_error()) {
    setup_failed("direct read: " + direct.error().message().str());
  }
  Harness server{std::move(state)};
  auto denied = server.request(cg::ReadKind::Elector, {}, 0);
  check("authorization-before-lookup", error(denied) == "not authorized" && server.lookups.load() == 0);
  denied = server.request(cg::ReadKind::Proposals, {}, 2);
  check("read-permission-required", error(denied) == "not authorized" && server.lookups.load() == 0);
  auto flags = server.request(cg::ReadKind::Elector, {}, 1, 2);
  check("unknown-flags-before-lookup",
        error(flags) == "invalid control getter flags or block" && server.lookups.load() == 0);
  auto duplicate = server.request(cg::ReadKind::Elector, {chain_key(1), chain_key(1)});
  check("duplicates-before-lookup",
        error(duplicate) == "duplicate returned-stake wallet" && server.lookups.load() == 0);
  std::vector<td::Bits256> wallets;
  for (int index = 240; index <= 256; ++index) {
    wallets.push_back(chain_key(index));
  }
  auto overflow = server.request(cg::ReadKind::Elector, wallets);
  check("wallet-cap-before-lookup",
        error(overflow).find("more than 16") != std::string::npos && server.lookups.load() == 0);
  wallets.erase(wallets.begin());
  auto reply = server.request(cg::ReadKind::Elector, wallets);
  auto state_reply = tos::fetch_tl_object<tos::tos_api::engine_validator_electorState>(reply, true);
  if (state_reply.is_error()) {
    setup_failed("elector reply: " + error(reply));
  }
  auto& result = *state_reply.ok();
  check("elector-256-whole", result.participants_.size() == 256);
  check("history-16-4096-whole",
        result.past_elections_.size() == 16 && result.past_elections_[0]->frozen_.size() == 256);
  check("returned-order", result.returned_.size() == 16 && result.returned_[0]->wallet_ == wallets[0] &&
                              result.returned_[15]->wallet_ == wallets[15]);
  check("full-answer-block", tos::create_block_id(result.block_) == server.state.id);
  check("maximum-coins-15-bytes", result.participants_[0]->stake_.size() == 15 &&
                                      result.participants_[0]->stake_.as_slice()[0] == static_cast<char>(0xff));
  check("one-state-lookup", server.lookups.load() == 1);
  auto proposals = server.request(cg::ReadKind::Proposals);
  auto list = tos::fetch_tl_object<tos::tos_api::engine_validator_configProposals>(proposals, true);
  if (list.is_error()) {
    setup_failed("proposal list: " + error(proposals));
  }
  check("proposal-200-whole", list.ok()->proposals_.size() == 200 && list.ok()->proposals_[0]->voters_.size() == 21);
  auto key = list.ok()->proposals_[0]->hash_;
  auto detail = server.request(cg::ReadKind::Proposal, {}, 1, 1, server.state.id, key);
  auto one = tos::fetch_tl_object<tos::tos_api::engine_validator_configProposalDetail>(detail, true);
  if (one.is_error()) {
    setup_failed("proposal detail: " + error(detail));
  }
  check("detail-metadata-not-deletion",
        one.ok()->flags_ == 1 && one.ok()->meta_ && !one.ok()->meta_->has_value_ && one.ok()->value_.empty());
  auto absent = server.request(cg::ReadKind::Proposal, {}, 1, 0, {}, getter_fixture::filled(0xab));
  auto missing = must(tos::fetch_tl_object<tos::tos_api::engine_validator_configProposalDetail>(absent, true),
                      "absent proposal reply");
  check("detail-absent", missing->flags_ == 0 && !missing->meta_);
  auto old = server.state.id;
  old.file_hash[0] = !old.file_hash[0];
  auto wrong = server.request(cg::ReadKind::Proposals, {}, 1, 1, old);
  check("historical-unavailable", error(wrong) == "historical state unavailable");
  server.wrong_block = true;
  wrong = server.request(cg::ReadKind::Proposals, {}, 1, 1, old);
  check("wrong-file-hash-refused", error(wrong) == "control getter state answers for another block");
  auto present_wallet = chain_key(256);
  auto absent_wallet = getter_fixture::filled(0xab);
  auto returned_reply = server.request(cg::ReadKind::Elector, {present_wallet, absent_wallet});
  auto returned = must(tos::fetch_tl_object<tos::tos_api::engine_validator_electorState>(returned_reply, true),
                       "returned-wallet binding response");
  check("returned-wallet-amount-binding",
        returned->returned_.size() == 2 && returned->returned_[0]->wallet_ == present_wallet &&
            !returned->returned_[0]->amount_.empty() && returned->returned_[1]->wallet_ == absent_wallet &&
            returned->returned_[1]->amount_.empty());
}

void boundary_test() {
  auto saved = split(load(fixtures + "/elector-data.boc"));
  saved.elect.clear();
  auto original_past = saved.past;
  saved.past = past_shape(original_past, 16, 256, true);
  saved.credits = deepest_credits();
  auto value = vm::CellBuilder{}.store_long(1234, 32).finalize_novm();
  auto proposal = config_proposals(1, false, 0, value, td::Bits256::ones());
  Harness server{production_build(zero, fixtures, "", 17, true, join(saved), proposal)};
  auto empty = server.request(cg::ReadKind::Elector, {chain_key(256)});
  auto state =
      must(tos::fetch_tl_object<tos::tos_api::engine_validator_electorState>(empty, true), "no-open-election response");
  check("empty-election-retains-history-credit", state->elect_at_ == 0 && state->participants_.empty() &&
                                                     state->past_elections_.size() == 16 &&
                                                     !state->returned_[0]->amount_.empty());
  auto detail = server.request(cg::ReadKind::Proposal, {}, 1, 0, {}, hashed_key("proposal-", 0));
  auto full =
      must(tos::fetch_tl_object<tos::tos_api::engine_validator_configProposalDetail>(detail, true), "value response");
  check("value-present-flags", full->flags_ == 3 && full->meta_ && full->meta_->has_value_ &&
                                   full->meta_->flags_ == 1 && full->meta_->param_hash_ == td::Bits256::ones());
  auto decoded = must(vm::std_boc_deserialize(full->value_.as_slice()), "value BOC");
  check("value-boc-exact", decoded->get_hash() == value->get_hash());
  for (bool too_many_frozen : {false, true}) {
    auto data = saved;
    data.past = past_shape(original_past, too_many_frozen ? 1 : 17, too_many_frozen ? 257 : 256, false);
    Harness excessive{production_build(zero, fixtures, "", 17, true, join(data))};
    auto refused = excessive.request(cg::ReadKind::Elector);
    check(too_many_frozen ? "frozen-count-refused" : "history-count-refused",
          error(refused) ==
              (too_many_frozen ? "frozen stake count limit exceeded" : "control getter list count limit exceeded"));
  }
  auto excess = saved;
  auto source = split(load(fixtures + "/elector-data.boc"));
  excess.elect = grow_members(source.elect, 257, Book::Hashed);
  Harness participants{production_build(zero, fixtures, "", 17, true, join(excess))};
  auto refused = participants.request(cg::ReadKind::Elector);
  check("participant-count-refused", error(refused) == "control getter list count limit exceeded");
  Harness count{production_build(zero, fixtures, "", 17, true, {}, config_proposals(4097, false, 0))};
  refused = count.request(cg::ReadKind::Proposals);
  check("proposal-count-refused", error(refused) == "control getter list count limit exceeded");
  Harness gas{production_build(zero, fixtures, "", 17, true, {}, config_proposals(512, true, 21))};
  auto accepted = gas.request(cg::ReadKind::Proposals);
  auto supported = must(tos::fetch_tl_object<tos::tos_api::engine_validator_configProposals>(accepted, true),
                        "deep proposal response");
  check("proposal-operational-envelope", supported->proposals_.size() == 512);
  Harness exhausted{production_build(zero, fixtures, "", 17, true, {}, config_proposals(4096, true, 21))};
  refused = exhausted.request(cg::ReadKind::Proposals);
  check("proposal-gas-refused", error(refused) == "control getter per-run gas limit exceeded");

  std::vector<td::Ref<vm::Cell>> level;
  for (int index = 0; index < 68000; ++index) {
    vm::CellBuilder leaf;
    require(leaf.store_long_bool(index, 32) && leaf.store_zeroes_bool(928), "large parameter leaf");
    level.push_back(leaf.finalize_novm());
  }
  while (level.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t index = 0; index < level.size(); index += 4) {
      vm::CellBuilder node;
      for (std::size_t offset = 0; offset < 4 && index + offset < level.size(); ++offset) {
        require(node.store_ref_bool(level[index + offset]), "large parameter branch");
      }
      next.push_back(node.finalize_novm());
    }
    level = std::move(next);
  }
  Harness bytes{production_build(zero, fixtures, "", 17, true, {}, config_proposals(1, false, 0, level[0]))};
  refused = bytes.request(cg::ReadKind::Proposal, {}, 1, 0, {}, hashed_key("proposal-", 0));
  check("proposal-byte-limit-refused", error(refused) == "proposal value exceeds reply byte limit");
  // Metadata listing does not serialize the parameter's potentially large value.
  auto meta_only = bytes.request(cg::ReadKind::Proposals);
  auto metas = must(tos::fetch_tl_object<tos::tos_api::engine_validator_configProposals>(meta_only, true),
                    "large-value metadata list");
  check("metadata-independent-of-value-size", metas->proposals_.size() == 1 && metas->proposals_[0]->has_value_);

  // Frozen stake weights are unsigned 64-bit, independent of the owner address.
  vm::Dictionary frozen{256};
  auto validator = getter_fixture::filled(0x12);
  auto owner = getter_fixture::filled(0x34);
  vm::CellBuilder entry;
  require(entry.store_bits_bool(owner.cbits(), 256) && entry.store_long_bool(-1, 64) && entry.store_long_bool(1, 4) &&
              entry.store_long_bool(1, 8) && entry.store_long_bool(0, 1),
          "unsigned frozen entry");
  require(frozen.set_builder(validator.cbits(), 256, entry), "unsigned frozen dictionary");
  vm::CellBuilder past;
  require(past.store_long_bool(1900000000, 32) && past.store_long_bool(65536, 32) &&
              past.store_bits_bool(getter_fixture::filled(0x51).cbits(), 256) &&
              past.store_maybe_ref(frozen.get_root_cell()) && past.store_long_bool(1, 4) &&
              past.store_long_bool(1, 8) && past.store_long_bool(0, 4) && past.store_long_bool(0, 1),
          "unsigned past entry");
  vm::Dictionary epochs{32};
  td::BitArray<32> epoch{static_cast<long long>(1780000000)};
  require(epochs.set_builder(epoch.cbits(), 32, past), "unsigned history");
  auto weighted = saved;
  weighted.past = epochs.get_root_cell();
  Harness weights{production_build(zero, fixtures, "", 17, true, join(weighted))};
  auto weighted_reply = weights.request(cg::ReadKind::Elector);
  auto decoded_weights = must(tos::fetch_tl_object<tos::tos_api::engine_validator_electorState>(weighted_reply, true),
                              "unsigned-weight response");
  auto& stake = decoded_weights->past_elections_[0]->frozen_[0];
  check("frozen-owner-distinct-from-id", stake->id_ == validator && stake->owner_ == owner);
  check("frozen-u64-max-weight", std::bit_cast<td::uint64>(stake->weight_) == std::numeric_limits<td::uint64>::max());
  // A getter with an incompatible seven-value result is refused at the first
  // scalar check, before later getters can contribute any partial answer.
  auto invalid_code = must(
      fift::compile_asm(
          "DROP 1 PUSHINT 0 PUSHINT 0x1000000000000000000000000000000 PUSHINT 0 PUSHINT PUSHNULL 0 PUSHINT 0 PUSHINT"),
      "oversized Coins guest");
  auto malformed =
      getter_fixture::build(zero, fixtures, "", 17, true, {}, {}, {}, {}, invalid_code, current_code(false));
  Harness coin_limit{std::move(malformed)};
  refused = coin_limit.request(cg::ReadKind::Elector);
  check("coins-2-to-120-refused", error(refused) == "control getter integer range mismatch");
}

void admission_test() {
  Harness server{production_build(zero, fixtures, "")};
  server.hold = true;
  std::vector<std::future<td::BufferSlice>> pending;
  server.scheduler.run_in_context([&] {
    for (int index = 0; index < 10; ++index) {
      auto promise = std::make_shared<std::promise<td::BufferSlice>>();
      pending.push_back(promise->get_future());
      td::actor::send_closure(server.service.get(), &cg::Service::query, 1, 0, td::optional<tos::BlockIdExt>{},
                              cg::Request{cg::ReadKind::Proposals, {}, {}},
                              [promise](td::Result<td::BufferSlice> result) {
                                promise->set_value(must(std::move(result), "admitted reply"));
                              });
    }
  });
  auto deadline = td::Timestamp::in(5);
  while (server.lookups.load() != 10) {
    server.scheduler.run(0.001);
    require(!deadline.is_in_past(), "ten lazy lookups admitted");
  }
  auto busy = server.request(cg::ReadKind::Proposals);
  check("busy-before-eleventh-lookup", error(busy) == "control getter executor busy" && server.lookups.load() == 10);
  check("pending-state-is-retained", pending[0].wait_for(std::chrono::seconds(0)) != std::future_status::ready);
  server.hold = false;
  server.scheduler.run_in_context([&] {
    std::lock_guard lock(server.held_mutex);
    for (auto& promise : server.held) {
      promise.set_value(cg::LoadedState{server.state.id, server.state.root});
    }
    server.held.clear();
  });
  for (auto& response : pending) {
    deadline = td::Timestamp::in(5);
    while (response.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
      server.scheduler.run(0.001);
      require(!deadline.is_in_past(), "held state query completes");
    }
    auto result = response.get();
    check("admitted-query-completed",
          tos::fetch_tl_object<tos::tos_api::engine_validator_configProposals>(result, true).is_ok());
  }
}

void completion_test() {
  auto child = fork();
  require(child >= 0, "completion child fork");
  if (child == 0) {
    auto executor = must(cg::Executor::create(), "completion executor");
    auto first = must(executor->admit(), "completion admission");
    std::atomic<bool> throwing{false};
    first
        ->dispatch([] { return td::Status::OK(); },
                   [&](td::Status) {
                     throwing = true;
                     throw std::runtime_error("completion control");
                   })
        .ensure();
    auto deadline = td::Timestamp::in(5);
    while (!throwing.load() || executor->counts().active != 0) {
      if (deadline.is_in_past()) {
        _exit(2);
      }
      std::this_thread::yield();
    }
    auto next = must(executor->admit(), "after completion exception");
    std::atomic<bool> done{false};
    next->dispatch([] { return td::Status::OK(); }, [&](td::Status result) { done = result.is_ok(); }).ensure();
    while (!done.load()) {
      if (deadline.is_in_past()) {
        _exit(2);
      }
      std::this_thread::yield();
    }
    executor->shutdown();
    _exit(0);
  }
  int status = 0;
  require(waitpid(child, &status, 0) == child, "completion child reaped");
  check("completion-exception-survived", WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  vm::init_vm().ensure();
  require(argc == 4, "query test ZEROSTATE FIXTURES CASE");
  zero = argv[1];
  fixtures = argv[2];
  if (std::string(argv[3]) == "service") {
    service_test();
  }
  if (std::string(argv[3]) == "boundary") {
    boundary_test();
  }
  if (std::string(argv[3]) == "admission") {
    admission_test();
  }
  if (std::string(argv[3]) == "completion") {
    completion_test();
  }
  require(checks > 0, "selected query test runs assertions");
  std::printf("CONTROL_QUERY_RESULT checks=%d failures=%d\n", checks, failures);
  return failures ? 1 : 0;
}
