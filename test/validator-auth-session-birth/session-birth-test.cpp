#include "validator/auth/session-birth.h"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace tos::auth;

namespace {
struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};
void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}
Hash h(std::uint8_t byte) {
  Hash result{};
  result.fill(byte);
  return result;
}
SessionBirthBlock block(std::uint32_t seqno) {
  return {seqno, h(11), h(12), h(13)};
}
SessionBirthEpoch epoch(std::uint8_t id = 21) {
  return {h(id), h(22), h(23), -1, std::uint64_t{1} << 63, 7, 0, 3};
}
SessionBirthObservation observation(std::uint32_t seqno, std::optional<SessionBirthEpoch> current) {
  return {block(seqno), seqno ? std::optional{block(seqno - 1)} : std::nullopt, std::move(current)};
}
std::vector<SessionBirthObservation> history(std::uint32_t tip = 8, std::uint32_t birth = 5) {
  std::vector<SessionBirthObservation> result;
  for (auto n = tip;; --n) {
    result.push_back(observation(n, n >= birth ? epoch() : epoch(31)));
    if (n == 0 || n < birth)
      break;
  }
  return result;
}
void expect_birth(const Result<SessionBirthResult>& result, std::uint32_t seqno,
                  const std::string& name, std::optional<std::size_t> used = {}) {
  require(result.ok(), name);
  require(result.value().block == block(seqno), name);
  require(result.value().epoch == epoch(), name);
  if (used)
    require(result.value().observations_used == *used, name);
}
void expect_error(const Result<SessionBirthResult>& result, std::string_view error, const std::string& name) {
  require(!result.ok() && result.error().code == error, name);
}
void setup() {
  // Keep setup independent of the boundary whose removal a case may test.
  const auto rows = history(0, 0);
  expect_birth(resolve_session_birth(block(0), epoch(), rows), 0, "fixture_accepts", 1);
}

using Test = std::pair<std::string, std::function<void()>>;
std::vector<Test> tests() {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) { result.emplace_back(std::move(name), std::move(fn)); };
  add("first_current_state", [] {
    auto rows = history();
    expect_birth(resolve_session_birth(block(8), epoch(), rows), 5, "first_current_state", 5);
  });
  add("delayed_start_same_birth", [] {
    const auto early = history(5), late = history(12);
    expect_birth(resolve_session_birth(block(5), epoch(), early), 5, "delayed_start_same_birth", 2);
    expect_birth(resolve_session_birth(block(12), epoch(), late), 5, "delayed_start_same_birth", 9);
  });
  add("restart_without_cache", [] {
    for (int n = 0; n != 3; ++n) {
      const auto rows = history(10);
      expect_birth(resolve_session_birth(block(10), epoch(), rows), 5, "restart_without_cache", 7);
    }
  });
  add("genesis_birth", [] {
    const auto rows = history(3, 0);
    expect_birth(resolve_session_birth(block(3), epoch(), rows), 0, "genesis_birth", 4);
  });
  add("nearest_contiguous_epoch", [] {
    auto rows = history(8, 7);
    rows.push_back(observation(5, epoch()));
    expect_birth(resolve_session_birth(block(8), epoch(), rows), 7, "nearest_contiguous_epoch", 3);
  });
  add("split_new_shard", [] {
    auto rows = history();
    rows.back().current = std::optional<SessionBirthEpoch>{};
    expect_birth(resolve_session_birth(block(8), epoch(), rows), 5, "split_new_shard", 5);
  });
  add("merge_new_shard", [] {
    auto rows = history();
    auto parent_epoch = epoch(31);
    parent_epoch.shard ^= std::uint64_t{1} << 62;
    rows.back().current = std::optional{parent_epoch};
    expect_birth(resolve_session_birth(block(8), epoch(), rows), 5, "merge_new_shard", 5);
  });
  add("future_not_current", [] {
    auto rows = history(0, 0);
    rows.front().current = std::optional{epoch(31)};
    expect_error(resolve_session_birth(block(0), epoch(), rows), "session-birth-not-current", "future_not_current");
  });
  add("absent_not_current", [] {
    auto rows = history(0, 0);
    rows.front().current = std::optional<SessionBirthEpoch>{};
    expect_error(resolve_session_birth(block(0), epoch(), rows), "session-birth-not-current", "absent_not_current");
  });
  add("truncated_history", [] {
    auto rows = history();
    rows.pop_back();
    expect_error(resolve_session_birth(block(8), epoch(), rows), "session-birth-history-incomplete", "truncated_history");
  });
  add("empty_history", [] {
    expect_error(resolve_session_birth(block(8), epoch(), {}), "session-birth-history-incomplete", "empty_history");
  });
  add("source_error_is_not_boundary", [] {
    auto rows = history();
    rows.back().current = Error{"native-history-read-failed"};
    expect_error(resolve_session_birth(block(8), epoch(), rows), "native-history-read-failed", "source_error_is_not_boundary");
  });
  add("default_source_is_unavailable", [] {
    auto rows = history();
    rows.back().current = SessionBirthObservation{}.current;
    expect_error(resolve_session_birth(block(8), epoch(), rows), "session-birth-history-unavailable", "default_source_is_unavailable");
  });
  add("budget_exceeded", [] {
    const auto rows = history(5);
    expect_error(resolve_session_birth(block(5), epoch(), rows, 1), "session-birth-budget", "budget_exceeded");
  });
  add("zero_budget", [] {
    const auto rows = history(0, 0);
    expect_error(resolve_session_birth(block(0), epoch(), rows, 0), "session-birth-budget", "zero_budget");
  });
  add("exact_budget", [] {
    const auto rows = history(5);
    expect_birth(resolve_session_birth(block(5), epoch(), rows, rows.size()), 5, "exact_budget", 2);
  });
  add("hard_budget", [] {
    const auto unit = observation(0, epoch());
    const std::vector<SessionBirthObservation> rows(65537, unit);
    expect_error(resolve_session_birth(block(0), epoch(), rows, 65537), "session-birth-budget", "hard_budget");
  });
  add("missing_parent_is_not_birth", [] {
    auto rows = history(5);
    rows.resize(1);
    rows.front().parent.reset();
    expect_error(resolve_session_birth(block(5), epoch(), rows), "session-birth-parent", "missing_parent_is_not_birth");
  });
  add("genesis_has_no_parent", [] {
    auto rows = history(0, 0);
    rows.front().parent = block(0);
    expect_error(resolve_session_birth(block(0), epoch(), rows), "session-birth-parent", "genesis_has_no_parent");
  });
  add("parent_step_no_gaps", [] {
    auto rows = history(5);
    rows.front().parent = block(3);
    rows.back().block = block(3);
    expect_error(resolve_session_birth(block(5), epoch(), rows), "session-birth-parent-step", "parent_step_no_gaps");
  });
  add("parent_step_no_cycle", [] {
    auto rows = history(5);
    rows.front().parent = block(5);
    rows.back().block = block(5);
    expect_error(resolve_session_birth(block(5), epoch(), rows), "session-birth-parent-step", "parent_step_no_cycle");
  });
  add("wrong_link", [] {
    auto rows = history(5);
    rows.front().parent->root = h(44);
    expect_error(resolve_session_birth(block(5), epoch(), rows), "session-birth-link", "wrong_link");
  });
  add("maximum_coordinate", [] {
    const auto last = std::numeric_limits<std::uint32_t>::max();
    const std::vector<SessionBirthObservation> rows{observation(last, epoch()), observation(last - 1, epoch(31))};
    expect_error(resolve_session_birth(block(last), epoch(), rows), "session-birth-anchor", "maximum_coordinate");
  });
  for (auto member : {&SessionBirthBlock::root, &SessionBirthBlock::file, &SessionBirthBlock::state}) {
    const std::string part = member == &SessionBirthBlock::root ? "root" : member == &SessionBirthBlock::file ? "file" : "state";
    const std::string zero_name = "zero_" + part;
    add(zero_name, [member, zero_name] {
      auto tip = block(0);
      tip.*member = {};
      auto rows = history(0, 0);
      rows.front().block = tip;
      expect_error(resolve_session_birth(tip, epoch(), rows), "session-birth-anchor", zero_name);
    });
    const std::string pin_name = "tip_pins_" + part;
    add(pin_name, [member, pin_name] {
      auto rows = history();
      rows.front().block.*member = h(55);
      expect_error(resolve_session_birth(block(8), epoch(), rows), "session-birth-link", pin_name);
    });
  }
  for (auto member : {&SessionBirthEpoch::native_session_id, &SessionBirthEpoch::election_cell_hash}) {
    const std::string name = member == &SessionBirthEpoch::native_session_id ? "zero_native_id" : "zero_election_hash";
    add(name, [member, name] {
      auto wanted = epoch();
      wanted.*member = {};
      auto rows = history(0, 0);
      rows.front().current = std::optional{wanted};
      expect_error(resolve_session_birth(block(0), wanted, rows), "session-birth-epoch", name);
    });
  }
  add("invalid_boundary_epoch", [] {
    auto rows = history();
    auto invalid = epoch(31);
    invalid.election_cell_hash = {};
    rows.back().current = std::optional{invalid};
    expect_error(resolve_session_birth(block(8), epoch(), rows), "session-birth-epoch", "invalid_boundary_epoch");
  });
  const std::vector<std::pair<std::string, std::function<void(SessionBirthEpoch&)>>> changes{
      {"epoch_election", [](auto& e) { e.election_cell_hash = h(45); }},
      {"epoch_options", [](auto& e) { e.native_options_hash = h(46); }},
      {"epoch_workchain", [](auto& e) { e.workchain = 0; }},
      {"epoch_shard", [](auto& e) { e.shard ^= std::uint64_t{1} << 62; }},
      {"epoch_catchain", [](auto& e) { e.catchain = 8; }},
      {"epoch_vertical", [](auto& e) { e.vertical_seqno = 1; }},
      {"epoch_key_block", [](auto& e) { e.key_block_seqno = 4; }},
  };
  for (const auto& [name, change] : changes) {
    add(name, [name, change] {
      auto current = epoch();
      change(current);
      auto rows = history(0, 0);
      rows.front().current = std::optional{current};
      expect_error(resolve_session_birth(block(0), epoch(), rows), "session-birth-not-current", name);
    });
  }
  // Metadata alone cannot rotate the native actor. A twin with a different
  // native ID proves that the changed metadata is a valid boundary fixture.
  for (const auto& [part, change] : changes) {
    const auto name = "boundary_conflict_" + part.substr(6);
    add(name, [name, change] {
      auto different_session = epoch(31);
      change(different_session);
      auto control = history();
      control.back().current = std::optional{different_session};
      expect_birth(resolve_session_birth(block(8), epoch(), control), 5, name + "_control", 5);
      auto same_session = different_session;
      same_session.native_session_id = epoch().native_session_id;
      auto rows = control;
      rows.back().current = std::optional{same_session};
      expect_error(resolve_session_birth(block(8), epoch(), rows), "session-birth-epoch-conflict", name);
    });
  }
  add("conflict_inside_current_suffix", [] {
    auto rows = history();
    auto conflicting = epoch();
    conflicting.election_cell_hash = h(45);
    rows.at(1).current = std::optional{conflicting};
    expect_error(resolve_session_birth(block(8), epoch(), rows), "session-birth-epoch-conflict",
                 "conflict_inside_current_suffix");
  });
  add("conflict_before_incomplete_history", [] {
    auto rows = history();
    rows.resize(2);
    auto conflicting = epoch();
    conflicting.election_cell_hash = h(45);
    rows.back().current = std::optional{conflicting};
    expect_error(resolve_session_birth(block(8), epoch(), rows), "session-birth-epoch-conflict",
                 "conflict_before_incomplete_history");
  });
  add("read_only_and_owned_result", [] {
    auto rows = history();
    const auto previous = rows.front().block;
    auto birth = resolve_session_birth(block(8), epoch(), rows);
    expect_birth(birth, 5, "read_only_and_owned_result", 5);
    require(rows.front().block == previous, "read_only_and_owned_result");
    for (auto& row : rows)
      row.block = {};
    expect_birth(birth, 5, "read_only_and_owned_result", 5);
  });
  return result;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc > 2) {
    std::cerr << "USAGE: test-p0-session-birth [case-name|--list]\n";
    return 2;
  }
  const auto all = tests();
  if (argc == 2 && std::string_view(argv[1]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }
  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (argc == 2 && name != argv[1])
      continue;
    try {
      setup();
      std::cout << "SETUP_OK " << name << '\n';
      fn();
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    } catch (const AssertionFailure& error) {
      std::cerr << "ASSERTION_FAILED " << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION " << name << ": " << error.what() << '\n';
      return 2;
    }
  }
  if (ran == 0) {
    std::cerr << "UNKNOWN_CASE\n";
    return 2;
  }
  std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
  return 0;
}
