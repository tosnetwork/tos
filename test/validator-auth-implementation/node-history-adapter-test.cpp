#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "node-history-adapter-fixture.h"

namespace {
using namespace tos::auth;
using namespace p0_node_history_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

template <class T>
void expect_error(const Result<T>& result, std::string_view code,
                  const std::string& assertion) {
  require(!result.ok() && result.error().code == code, assertion);
}

// Two fixture headers reach this translation unit and each declares a Fixture
// in its own namespace, so the unqualified name is ambiguous here.
std::unique_ptr<NativeNodeHistoryAdapter> open_adapter(
    p0_node_history_fixture::Fixture& fixture, NativeNodeHistoryBudget budget,
    const std::string& assertion) {
  auto opened = NativeNodeHistoryAdapter::open(
      fixture.head_state, fixture.head, fixture.chain,
      fixture.readers(), budget);
  require(opened.ok(), assertion);
  return std::move(opened.value());
}

std::unique_ptr<NativeNodeHistoryAdapter> open_adapter(
    p0_node_history_fixture::Fixture& fixture, const std::string& assertion) {
  return open_adapter(
      fixture, NativeNodeHistoryBudget{}, assertion);
}

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests(
    const std::filesystem::path& owner_inputs,
    const std::filesystem::path& committee_fixtures) {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("complete_source_surface", [=] {
    auto fixture = make_fixture(owner_inputs, committee_fixtures);
    auto adapter =
        open_adapter(fixture, "complete_source_surface");

    auto chain = adapter->chain_context();
    require(chain.ok() && chain.value() == fixture.chain,
            "complete_source_surface");

    auto state = adapter->state(fixture.head);
    require(state.ok() &&
                state.value()->get_hash() ==
                    fixture.head_state->get_hash(),
            "complete_source_surface");

    auto duty =
        adapter->expected_duty(fixture.head, fixture.duty);
    require(duty.ok() && duty.value() == fixture.duty,
            "complete_source_surface");

    auto certificate =
        adapter->certificate(fixture.head, fixture.certificate_id);
    require(certificate.ok() &&
                certificate.value() == fixture.certificate,
            "complete_source_surface");
  });

  add("missing_coordinate_refuses_substitution", [=] {
    auto fixture = make_fixture(owner_inputs, committee_fixtures);
    auto adapter = open_adapter(
        fixture, "missing_coordinate_refuses_substitution");

    auto result = adapter->state(fixture.missing);
    require(!result.ok() &&
                result.error().code ==
                    "finalized-anchor-unavailable" &&
                fixture.state_reads == 0,
            "missing_coordinate_refuses_substitution");
  });

  add("exact_anchor_binding", [=] {
    auto fixture = make_fixture(owner_inputs, committee_fixtures);
    auto adapter =
        open_adapter(fixture, "exact_anchor_binding");

    auto changed = fixture.head;
    changed.root_[0] ^= 1;
    expect_error(adapter->state(changed),
                 "node-history-anchor-conflict",
                 "exact_anchor_binding");

    changed = fixture.head;
    changed.file_[0] ^= 1;
    expect_error(adapter->state(changed),
                 "node-history-anchor-conflict",
                 "exact_anchor_binding");

    changed = fixture.head;
    changed.state_[0] ^= 1;
    expect_error(adapter->state(changed),
                 "node-history-anchor-conflict",
                 "exact_anchor_binding");

    require(fixture.state_reads == 0, "exact_anchor_binding");
    fixture.substitute_state = true;
    expect_error(adapter->state(fixture.head),
                 "session-history-state-binding",
                 "exact_anchor_binding");
  });

  add("outage_provenance", [=] {
    auto fixture = make_fixture(owner_inputs, committee_fixtures);
    auto adapter =
        open_adapter(fixture, "outage_provenance");

    fixture.state_outage = true;
    expect_error(adapter->state(fixture.head),
                 "storage-unavailable", "outage_provenance");
    fixture.state_outage = false;

    fixture.block_outage = true;
    expect_error(adapter->finalized_anchor(fixture.old.seqno_),
                 "archive-offline", "outage_provenance");
    fixture.block_outage = false;

    fixture.identity_outage = true;
    expect_error(
        adapter->expected_duty(fixture.head, fixture.duty),
        "storage-unavailable", "outage_provenance");
    fixture.identity_outage = false;

    fixture.archive_outage = true;
    expect_error(
        adapter->certificate(fixture.head, fixture.certificate_id),
        "archive-offline", "outage_provenance");
  });

  add("budget_not_refreshed", [=] {
    {
      auto fixture = make_fixture(owner_inputs, committee_fixtures);
      NativeNodeHistoryBudget budget;
      budget.finalized.blocks = 1;
      budget.finalized.bytes = fixture.old_block.size();
      auto adapter = open_adapter(
          fixture, budget, "budget_not_refreshed");
      require(adapter->finalized_anchor(fixture.old.seqno_).ok(),
              "budget_not_refreshed");
      expect_error(
          adapter->finalized_anchor(fixture.predecessor.seqno_),
          "history-resource", "budget_not_refreshed");
    }

    {
      auto fixture = make_fixture(owner_inputs, committee_fixtures);
      NativeNodeHistoryBudget budget;
      budget.state_reads = 1;
      auto adapter = open_adapter(
          fixture, budget, "budget_not_refreshed");
      auto states = adapter->state_reader();
      require(states(fixture.head).ok(), "budget_not_refreshed");
      expect_error(states(fixture.head),
                   "history-resource", "budget_not_refreshed");
    }

    {
      auto fixture = make_fixture(owner_inputs, committee_fixtures);
      NativeNodeHistoryBudget budget;
      budget.identity_reads = 1;
      auto adapter = open_adapter(
          fixture, budget, "budget_not_refreshed");
      auto identities = adapter->identity_reader();
      tos::ShardIdFull target{
          fixture.identity.workchain, fixture.identity.shard};
      auto first = identities(
          fixture.head, fixture.head_state, target);
      require(first.ok() &&
                  same_identity_input(first.value(), fixture.identity),
              "budget_not_refreshed");
      expect_error(
          identities(fixture.head, fixture.head_state, target),
          "history-resource", "budget_not_refreshed");
    }

    {
      auto fixture = make_fixture(owner_inputs, committee_fixtures);
      NativeNodeHistoryBudget budget;
      budget.session_blocks.blocks = 1;
      budget.session_blocks.bytes = fixture.old_block.size();
      auto adapter = open_adapter(
          fixture, budget, "budget_not_refreshed");
      auto blocks = adapter->block_reader();
      auto id = block_id(fixture.old);
      require(blocks(id, fixture.old_block.size()).ok(),
              "budget_not_refreshed");
      expect_error(blocks(id, fixture.old_block.size()),
                   "history-resource", "budget_not_refreshed");
    }

    {
      auto fixture = make_fixture(owner_inputs, committee_fixtures);
      NativeNodeHistoryBudget budget;
      budget.duty_reads = 1;
      auto adapter = open_adapter(
          fixture, budget, "budget_not_refreshed");
      require(adapter->expected_duty(
                  fixture.head, fixture.duty).ok(),
              "budget_not_refreshed");
      expect_error(
          adapter->expected_duty(fixture.head, fixture.duty),
          "history-resource", "budget_not_refreshed");
    }

    {
      auto fixture = make_fixture(owner_inputs, committee_fixtures);
      NativeNodeHistoryBudget budget;
      budget.certificate_reads = 1;
      auto adapter = open_adapter(
          fixture, budget, "budget_not_refreshed");
      require(adapter->certificate(
                  fixture.head, fixture.certificate_id).ok(),
              "budget_not_refreshed");
      expect_error(
          adapter->certificate(fixture.head, fixture.certificate_id),
          "history-resource", "budget_not_refreshed");
    }
  });

  add("retained_history", [=] {
    auto fixture = make_fixture(owner_inputs, committee_fixtures);
    auto adapter =
        open_adapter(fixture, "retained_history");

    require(adapter->state(fixture.head).ok(),
            "retained_history");
    auto old = adapter->state(fixture.old);
    require(old.ok() &&
                old.value()->get_hash() ==
                    fixture.old_state->get_hash(),
            "retained_history");

    auto anchor =
        adapter->finalized_anchor(fixture.old.seqno_);
    require(anchor.ok() && anchor.value() == fixture.old,
            "retained_history");
  });

  add("session_reader_surface", [=] {
    auto fixture = make_fixture(owner_inputs, committee_fixtures);
    auto adapter =
        open_adapter(fixture, "session_reader_surface");

    auto blocks = adapter->block_reader();
    auto raw = blocks(
        block_id(fixture.old), fixture.old_block.size());
    require(raw.ok() && raw.value() == fixture.old_block,
            "session_reader_surface");

    auto states = adapter->state_reader();
    auto state = states(fixture.head);
    require(state.ok() &&
                state.value()->get_hash() ==
                    fixture.head_state->get_hash(),
            "session_reader_surface");

    auto identities = adapter->identity_reader();
    tos::ShardIdFull target{
        fixture.identity.workchain, fixture.identity.shard};
    auto identity =
        identities(fixture.head, fixture.head_state, target);
    require(identity.ok() &&
                same_identity_input(
                    identity.value(), fixture.identity),
            "session_reader_surface");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3 || argc > 4) {
    std::cerr
        << "USAGE: test-p0-node-history-adapter "
           "OWNER_INPUTS COMMITTEE_FIXTURES "
           "[case-name|--list|--exclude=case]\n";
    return 2;
  }

  const std::filesystem::path owner_inputs(argv[1]);
  const std::filesystem::path committee_fixtures(argv[2]);
  const auto all = tests(owner_inputs, committee_fixtures);

  if (argc == 4 && std::string_view(argv[3]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }

  std::string selected;
  std::string excluded;
  if (argc == 4) {
    std::string argument(argv[3]);
    constexpr std::string_view prefix = "--exclude=";
    if (argument.starts_with(prefix))
      excluded = argument.substr(prefix.size());
    else
      selected = std::move(argument);
  }

  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (!selected.empty() && name != selected)
      continue;
    if (!excluded.empty() && name == excluded)
      continue;
    try {
      std::cout << "SETUP_OK " << name << '\n';
      fn();
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    } catch (const AssertionFailure& error) {
      std::cerr << "ASSERTION_FAILED " << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION " << name << ": "
                << error.what() << '\n';
      return 2;
    }
  }

  if (ran == 0) {
    std::cerr << "UNKNOWN_CASE\n";
    return 2;
  }
  std::cout << "SUMMARY cases=" << ran
            << " passed=" << ran << '\n';
  return 0;
}
