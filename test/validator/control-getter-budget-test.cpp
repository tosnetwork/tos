/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>

#include "validator-engine/control-getter.h"
#include "vm/vm.h"

#include "control-getter-fixture.h"

using namespace control_fixture;
namespace cg = tos::control_getter;

std::string zero_path;
std::string fixture_path;

struct Execution {
  getter_fixture::State state;
  std::shared_ptr<const cg::Snapshot> snapshot;
  cg::Account account;
};

Execution prepare(const Elector& data) {
  auto state = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                 join(data));
  auto snapshot = must(cg::Snapshot::create(state.id, state.root), "production snapshot");
  auto account = must(snapshot->account(filled(0x33)), "production elector account");
  require(account.root.not_null() && account.data->get_hash() == join(data)->get_hash(), "snapshot has the grown data");
  return {std::move(state), std::move(snapshot), std::move(account)};
}

void measure(const std::string& name, Execution& execution, cg::Getter getter, long long ceiling,
             std::vector<td::RefInt256> arguments, const std::function<td::Status(const vm::Stack&)>& decode) {
  cg::GasBudget request{cg::kElectorStateGasLimit};
  cg::RunStats stats;
  auto status = cg::run(*execution.snapshot, execution.account, getter, std::move(arguments), request, decode, &stats);
  if (status.is_error()) {
    std::fprintf(stderr, "BUDGET_MEASUREMENT_FAILURE %s exit=%d gas=%lld reason=%s\n", name.c_str(), stats.exit_code,
                 stats.gas_used, status.error().message().str().c_str());
    std::exit(1);
  }
  require(stats.exit_code == 0 && request.used() == stats.gas_used && stats.gas_used > 0,
          "measurement executes and charges");
  auto margin = ceiling - stats.gas_used;
  if (stats.gas_used > ceiling / 13 * 10 + ceiling % 13 * 10 / 13) {
    std::fprintf(stderr, "BUDGET_GATE_FAIL %s: production-context headroom below 30 percent (gas=%lld budget=%lld)\n",
                 name.c_str(), stats.gas_used, ceiling);
    std::exit(1);
  }
  std::cout << name << " gas=" << stats.gas_used << " budget=" << ceiling << " headroom_percent=" << std::fixed
            << std::setprecision(4) << 100.0 * static_cast<double>(margin) / static_cast<double>(stats.gas_used)
            << " unused_percent=" << 100.0 * static_cast<double>(margin) / static_cast<double>(ceiling) << '\n';
}

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  vm::init_vm().ensure();
  std::cout << std::unitbuf;
  require(argc == 3, "usage: test-control-getter-budget ZEROSTATE FIXTURES");
  zero_path = argv[1];
  fixture_path = argv[2];
  auto saved = split(load(fixture_path + "/elector-data.boc"));
  for (auto shape : {Book::Hashed, Book::Deepest, Book::DeepestMaxStake}) {
    for (int count : {0, 21, 99, 256}) {
      auto grown = saved;
      grown.elect = grow_members(saved.elect, count, shape);
      auto execution = prepare(grown);
      int observed = 0;
      auto decoder = [&](const vm::Stack& stack) -> td::Status {
        require(stack.depth() == 7, "participants returns seven values");
        auto result = cg::walk_cons(stack[2], cg::kMaxElectorParticipants, [&](const vm::StackEntry& head) {
          require(head.is_tuple() && head.as_tuple()->size() == 2, "participant pair");
          auto entry = head.as_tuple()->at(1);
          require(entry.is_tuple() && entry.as_tuple()->size() == 6, "participant six fields");
          if (shape == Book::DeepestMaxStake) {
            auto expected = (td::make_refint(1) << 120) - td::make_refint(1);
            require(entry.as_tuple()->at(0).is_int() && td::cmp(entry.as_tuple()->at(0).as_int(), expected) == 0,
                    "maximum stake is returned");
          }
          ++observed;
          return td::Status::OK();
        });
        require(observed == count, "participant count is exact");
        return result;
      };
      measure("participants-shape=" + std::to_string(static_cast<int>(shape)) + "-n=" + std::to_string(count),
              execution, cg::Getter::Participants, cg::kElectorParticipantsGasLimit, {}, decoder);
    }
  }
  for (int shape : {-1, 0, 1}) {
    for (int entries : {21, 256}) {
      auto grown = saved;
      grown.past = shape < 0 ? grow_past(saved.past, 16, entries) : past_shape(saved.past, 16, entries, shape != 0);
      auto execution = prepare(grown);
      std::size_t elections = 0;
      std::size_t frozen = 0;
      measure("past-shape=" + std::to_string(shape) + "-k=16-f=" + std::to_string(entries), execution,
              cg::Getter::PastElections, cg::kPastElectionsGasLimit, {}, [&](const vm::Stack& stack) {
                require(stack.depth() == 1, "past elections returns one value");
                auto status = cg::walk_cons(stack[0], cg::kMaxPastElections, [&](const vm::StackEntry& head) {
                  require(head.is_tuple() && head.as_tuple()->size() == 8, "past election has eight fields");
                  auto book = head.as_tuple()->at(4);
                  require(book.is_cell(), "frozen book is present");
                  vm::Dictionary dictionary{book.as_cell(), 256};
                  std::size_t per_election = 0;
                  require(dictionary.check_for_each([&](Ref<CellSlice> value, td::ConstBitPtr, int) {
                    require(per_election < cg::kMaxFrozenEntriesPerElection && frozen < cg::kMaxFrozenEntriesTotal,
                            "frozen bound");
                    CellSlice entry = *value;
                    require(entry.advance(256 + 64), "frozen owner and weight");
                    vm_amount_skip(entry);
                    require(entry.advance(1) && entry.empty_ext(), "frozen entry exact end");
                    ++per_election;
                    ++frozen;
                    return true;
                  }),
                          "frozen book walk");
                  require(per_election == static_cast<std::size_t>(entries), "frozen per-election count");
                  ++elections;
                  return td::Status::OK();
                });
                require(elections == 16 && frozen == static_cast<std::size_t>(16 * entries), "complete history count");
                return status;
              });
    }
  }
  auto argument = [](td::Bits256 key) {
    td::RefInt256 result{true};
    require(result.write().import_bits(key.cbits(), 256, false), "wallet as unsigned integer");
    return result;
  };
  for (int credits : {1, 65536}) {
    auto grown = saved;
    grown.credits = grow_credits(credits);
    auto execution = prepare(grown);
    for (bool present : {false, true}) {
      measure("returned-c=" + std::to_string(credits) + (present ? "-present" : "-absent"), execution,
              cg::Getter::ReturnedStake, cg::kReturnedStakeGasLimit,
              {argument(hashed_key(present ? "credit-" : "absent-", 0))}, [&](const vm::Stack& stack) {
                require(stack.depth() == 1 && stack[0].is_int(), "returned value is an integer");
                require(stack[0].as_int()->to_long() == (present ? 1000000000LL : 0), "returned value is exact");
                return td::Status::OK();
              });
    }
  }
  auto grown = saved;
  grown.credits = deepest_credits();
  auto execution = prepare(grown);
  td::Bits256 all;
  all.set_ones();
  measure("returned-deepest", execution, cg::Getter::ReturnedStake, cg::kReturnedStakeGasLimit, {argument(all)},
          [&](const vm::Stack& stack) {
            require(stack.depth() == 1 && stack[0].is_int() && stack[0].as_int()->to_long() == 1000000000LL,
                    "deepest returned stake found");
            return td::Status::OK();
          });

  // All elector facts are measured from one grown snapshot with distinct wallets.
  grown.elect = grow_members(saved.elect, 256, Book::DeepestMaxStake);
  grown.past = past_shape(saved.past, 16, 256, true);
  auto combined = prepare(grown);
  cg::GasBudget aggregate{cg::kElectorStateGasLimit};
  cg::RunStats aggregate_stats;
  auto discard = [](const vm::Stack&) { return td::Status::OK(); };
  cg::run(*combined.snapshot, combined.account, cg::Getter::Participants, {}, aggregate, discard, &aggregate_stats)
      .ensure();
  cg::run(*combined.snapshot, combined.account, cg::Getter::PastElections, {}, aggregate, discard, &aggregate_stats)
      .ensure();
  for (int index = 241; index <= 256; ++index) {
    cg::run(*combined.snapshot, combined.account, cg::Getter::ReturnedStake, {argument(chain_key(index))}, aggregate,
            discard, &aggregate_stats)
        .ensure();
  }
  const auto aggregate_margin = cg::kElectorStateGasLimit - aggregate.used();
  if (aggregate.used() > cg::kElectorStateGasLimit / 13 * 10 + cg::kElectorStateGasLimit % 13 * 10 / 13) {
    std::fprintf(stderr, "BUDGET_GATE_FAIL aggregate: production-context headroom below 30 percent\n");
    std::exit(1);
  }
  std::cout << "aggregate-distinct-wallets=16 gas=" << aggregate.used() << " budget=" << cg::kElectorStateGasLimit
            << " headroom_percent="
            << 100.0 * static_cast<double>(aggregate_margin) / static_cast<double>(aggregate.used())
            << " unused_percent="
            << 100.0 * static_cast<double>(aggregate_margin) / static_cast<double>(cg::kElectorStateGasLimit) << '\n';
  cg::GasBudget injected{1114595 + 19528 + 26804 - 1};
  cg::run(*combined.snapshot, combined.account, cg::Getter::Participants, {}, injected, discard).ensure();
  cg::run(*combined.snapshot, combined.account, cg::Getter::PastElections, {}, injected, discard).ensure();
  bool accepted = false;
  auto rejected_aggregate = cg::run(
      *combined.snapshot, combined.account, cg::Getter::ReturnedStake, {argument(all)}, injected,
      [&](const vm::Stack&) {
        accepted = true;
        return td::Status::OK();
      },
      &aggregate_stats);
  if (rejected_aggregate.is_ok() ||
      rejected_aggregate.error().message() != "control getter aggregate gas limit exceeded" ||
      aggregate_stats.exit_code != 0 || aggregate_stats.gas_used != 26804 || accepted) {
    std::fprintf(stderr, "BUDGET_GATE_FAIL independent aggregate guard\n");
    std::exit(1);
  }

  for (bool deep : {false, true}) {
    for (int voters : {0, 21}) {
      for (int count : {0, 62, 63, 200, 512, 4096}) {
        auto data = config_proposals(count, deep, voters);
        auto state = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17,
                                                       true, {}, data);
        auto snapshot = must(cg::Snapshot::create(state.id, state.root), "proposal snapshot");
        auto account = must(snapshot->account(getter_fixture::filled(0x55)), "proposal account");
        cg::GasBudget gas{cg::kConfigProposalsGasLimit};
        cg::RunStats stats;
        std::size_t observed = 0;
        auto status = cg::run(
            *snapshot, account, cg::Getter::Proposals, {}, gas,
            [&](const vm::Stack& stack) {
              require(stack.depth() == 1, "proposal result depth");
              return cg::walk_cons(stack[0], cg::kMaxConfigProposals, [&](const vm::StackEntry& head) {
                require(head.is_tuple() && head.as_tuple()->size() == 2, "proposal pair");
                auto fields = head.as_tuple()->at(1).as_tuple();
                require(fields.not_null() && fields->size() == 9, "proposal fields");
                std::size_t seen_voters = 0;
                auto voter_status = cg::walk_cons(fields->at(4), 65536, [&](const vm::StackEntry& voter) {
                  require(voter.is_int(), "voter index");
                  ++seen_voters;
                  return td::Status::OK();
                });
                require(seen_voters == static_cast<std::size_t>(voters), "voter count");
                ++observed;
                return voter_status;
              });
            },
            &stats);
        if (count == 4096 && status.is_error()) {
          require(status.error().message() == "control getter per-run gas limit exceeded" && observed == 0,
                  "operational ceiling refuses without partial decoding");
          std::cout << "proposals-deep=" << deep << "-v=" << voters << "-n=" << count
                    << " REFUSED gas=" << stats.gas_used << '\n';
        } else {
          if (status.is_error() || observed != static_cast<std::size_t>(count)) {
            std::fprintf(stderr, "BUDGET_GATE_FAIL proposal measurement did not complete n=%d v=%d gas=%lld\n", count,
                         voters, stats.gas_used);
            std::exit(1);
          }
          auto margin = cg::kConfigProposalsGasLimit - stats.gas_used;
          std::cout << "proposals-deep=" << deep << "-v=" << voters << "-n=" << count << " gas=" << stats.gas_used
                    << " budget=" << cg::kConfigProposalsGasLimit
                    << " headroom_percent=" << 100.0 * static_cast<double>(margin) / static_cast<double>(stats.gas_used)
                    << " unused_percent="
                    << 100.0 * static_cast<double>(margin) / static_cast<double>(cg::kConfigProposalsGasLimit) << '\n';
        }
        if (count > 0) {
          cg::GasBudget single{cg::kConfigProposalsGasLimit};
          auto single_status = cg::run(
              *snapshot, account, cg::Getter::Proposal, {argument(proposal_key(count - 1, count, deep))}, single,
              [&](const vm::Stack& stack) {
                require(stack.depth() == 1 && stack[0].is_tuple() && stack[0].as_tuple()->size() == 9,
                        "single proposal found");
                return td::Status::OK();
              },
              &stats);
          single_status.ensure();
          std::cout << "single-proposal-deep=" << deep << "-v=" << voters << "-n=" << count << " gas=" << stats.gas_used
                    << '\n';
        }
      }
    }
  }

  // A successful VM result above the count bound is still refused as a whole.
  auto over_data = config_proposals(4097, false, 0);
  auto over_state = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17,
                                                      true, {}, over_data);
  auto over_snapshot = must(cg::Snapshot::create(over_state.id, over_state.root), "count boundary snapshot");
  auto over_account = must(over_snapshot->account(getter_fixture::filled(0x55)), "count boundary account");
  cg::GasBudget over_gas{cg::kConfigProposalsGasLimit};
  cg::RunStats over_stats;
  auto over_status = cg::run(
      *over_snapshot, over_account, cg::Getter::Proposals, {}, over_gas,
      [&](const vm::Stack& stack) {
        return cg::walk_cons(stack[0], cg::kMaxConfigProposals, [](const vm::StackEntry&) { return td::Status::OK(); });
      },
      &over_stats);
  if (over_status.is_ok() || over_status.error().message() != "control getter list count limit exceeded" ||
      over_stats.exit_code != 0) {
    std::fprintf(stderr, "BUDGET_BEHAVIOR_FAIL proposal count boundary\n");
    std::exit(1);
  }
  std::cout << "proposals-count=4097 REFUSED gas=" << over_stats.gas_used << " vm_exit=" << over_stats.exit_code
            << '\n';

  // Cross the VM ceiling with the next hashed, unvoted proposal after the last
  // measured success. Gas failure must happen before any result decoder runs.

  int low = 4096;
  int high = 8192;
  auto gas_edge = [&](int count) {
    auto data = config_proposals(count, false, 0);
    auto state = control_fixture::production_build(zero_path, fixture_path, fixture_path + "/config-code.boc", 17, true,
                                                   {}, data);
    auto snapshot = must(cg::Snapshot::create(state.id, state.root), "gas edge snapshot");
    auto account = must(snapshot->account(getter_fixture::filled(0x55)), "gas edge account");
    cg::GasBudget gas{cg::kConfigProposalsGasLimit};
    cg::RunStats stats;
    bool decoder_called = false;
    auto status = cg::run(
        *snapshot, account, cg::Getter::Proposals, {}, gas,
        [&](const vm::Stack&) {
          decoder_called = true;
          return td::Status::OK();
        },
        &stats);
    if (status.is_error()) {
      if (status.error().message() != "control getter per-run gas limit exceeded" || decoder_called) {
        std::fprintf(stderr, "BUDGET_BEHAVIOR_FAIL proposal gas boundary\n");
        std::exit(1);
      }
    } else {
      require(decoder_called && stats.exit_code == 0, "gas edge success is complete");
    }
    return std::make_pair(status.is_ok(), stats.gas_used);
  };
  require(gas_edge(low).first && !gas_edge(high).first, "gas ceiling has both success and refusal anchors");
  while (high - low > 1) {
    int middle = low + (high - low) / 2;
    if (gas_edge(middle).first) {
      low = middle;
    } else {
      high = middle;
    }
  }
  auto below = gas_edge(low);
  auto above = gas_edge(high);
  if (!below.first || above.first) {
    std::fprintf(stderr, "BUDGET_BEHAVIOR_FAIL adjacent gas boundary\n");
    std::exit(1);
  }
  std::cout << "proposals-adjacent-gas-boundary last_success=" << low << " gas=" << below.second
            << " first_refusal=" << high << " gas=" << above.second << '\n';

  cg::ReplyBudget reply;
  if (reply.reserve(64).is_error() || reply.reserve(cg::kControlGetterReplyBytes - 64).is_error()) {
    std::fprintf(stderr, "BUDGET_BEHAVIOR_FAIL exact reply byte boundary\n");
    std::exit(1);
  }
  auto byte_status = reply.reserve(1);
  if (byte_status.is_ok() || byte_status.message() != "control getter reply byte limit exceeded") {
    std::fprintf(stderr, "BUDGET_BEHAVIOR_FAIL reply byte boundary\n");
    std::exit(1);
  }
  std::cout << "CONTROL_GETTER_BUDGET_RESULT gate_failures=0\n";
  return 0;
}
