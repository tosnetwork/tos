#include "validator/auth/session-admission.h"

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
  return {seqno, h(static_cast<std::uint8_t>(11 + seqno % 17)),
          h(static_cast<std::uint8_t>(41 + seqno % 17)), h(static_cast<std::uint8_t>(71 + seqno % 17))};
}
SessionBirthEpoch epoch(std::uint8_t id = 21, std::uint8_t options = 23, std::uint64_t shard = std::uint64_t{1} << 63) {
  return {h(id), h(22), h(options), -1, shard, 7, 0, 3};
}
SessionBirthObservation observation(std::uint32_t seqno, std::optional<SessionBirthEpoch> current) {
  return {block(seqno), seqno ? std::optional{block(seqno - 1)} : std::nullopt, std::move(current)};
}
std::vector<SessionBirthObservation> history(std::uint32_t tip = 8, std::uint32_t birth = 5,
                                             SessionBirthEpoch current = epoch(),
                                             std::optional<SessionBirthEpoch> before = epoch(31)) {
  std::vector<SessionBirthObservation> result;
  for (auto n = tip;; --n) {
    result.push_back(observation(n, n >= birth ? std::optional{current} : before));
    if (n == 0 || n < birth)
      break;
  }
  return result;
}
AuthenticatedSessionHistoryRead reader_for(const std::vector<SessionBirthObservation>& rows,
                                           std::vector<std::uint32_t>* calls = nullptr) {
  return [&rows, calls](const SessionBirthBlock& expected) -> Result<SessionBirthObservation> {
    if (calls)
      calls->push_back(expected.seqno);
    for (const auto& row : rows)
      if (row.block == expected)
        return row;
    return Error{"native-history-read-failed"};
  };
}
void expect_error(const auto& result, std::string_view error, const std::string& assertion) {
  require(!result.ok() && result.error().code == error, assertion);
}
AuthenticatedSessionBirth authenticated(std::uint32_t tip = 8, std::uint32_t birth = 5,
                                        SessionBirthEpoch current = epoch(),
                                        std::optional<SessionBirthEpoch> before = epoch(31)) {
  const auto rows = history(tip, birth, current, before);
  auto result = resolve_authenticated_session_birth(block(tip), current, reader_for(rows));
  require(result.ok(), "authenticated_fixture");
  return result.value();
}
NativeSessionEpochInput epoch_input(std::uint8_t id = 21) {
  return {h(id), h(22), h(23), -1, std::uint64_t{1} << 63, 7, 0, 3, false};
}
struct FakeCommittee {
  std::vector<int> members;
};
using Context = SessionCommitteeContext<FakeCommittee>;
std::shared_ptr<const Context> context_for(AuthenticatedSessionBirth birth, std::vector<int> members = {1, 2, 3}) {
  auto result = derive_session_committee<FakeCommittee>(
      std::move(birth), [members = std::move(members)](const SessionBirthBlock&) mutable -> Result<FakeCommittee> {
        return FakeCommittee{std::move(members)};
      });
  require(result.ok(), "context_fixture");
  return result.value();
}
void setup() {
  const auto rows = history(0, 0);
  auto selected = resolve_authenticated_session_birth(block(0), epoch(), reader_for(rows));
  require(selected.ok() && selected.value().selected().block == block(0), "fixture_accepts");
}

using Test = std::pair<std::string, std::function<void()>>;
std::vector<Test> tests() {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) { result.emplace_back(std::move(name), std::move(fn)); };

  add("walks_exact_authenticated_chain", [] {
    const auto rows = history();
    std::vector<std::uint32_t> calls;
    auto selected = resolve_authenticated_session_birth(block(8), epoch(), reader_for(rows, &calls));
    require(selected.ok(), "walks_exact_authenticated_chain");
    require(selected.value().selected().block == block(5), "walks_exact_authenticated_chain");
    require(selected.value().selected().observations_used == 5, "walks_exact_authenticated_chain");
    require(calls == std::vector<std::uint32_t>({8, 7, 6, 5, 4}), "walks_exact_authenticated_chain");
  });
  add("stops_after_authenticated_boundary", [] {
    auto rows = history();
    rows.push_back(observation(3, epoch(41)));
    std::vector<std::uint32_t> calls;
    auto selected = resolve_authenticated_session_birth(block(8), epoch(), reader_for(rows, &calls));
    require(selected.ok() && calls.back() == 4 && calls.size() == 5, "stops_after_authenticated_boundary");
  });
  add("reader_error_is_not_boundary", [] {
    const auto rows = history();
    auto read = [&rows](const SessionBirthBlock& expected) -> Result<SessionBirthObservation> {
      if (expected.seqno == 6)
        return Error{"native-history-read-failed"};
      return reader_for(rows)(expected);
    };
    expect_error(resolve_authenticated_session_birth(block(8), epoch(), read), "native-history-read-failed",
                 "reader_error_is_not_boundary");
  });
  add("wrong_reader_link_is_refused", [] {
    auto rows = history();
    rows.at(1).block.root = h(99);
    expect_error(resolve_authenticated_session_birth(block(8), epoch(), reader_for(rows)), "native-history-read-failed",
                 "wrong_reader_link_is_refused");
  });
  add("empty_reader_is_unavailable", [] {
    expect_error(resolve_authenticated_session_birth(block(8), epoch(), {}), "session-birth-history-unavailable",
                 "empty_reader_is_unavailable");
  });
  add("budget_never_falls_back", [] {
    const auto rows = history();
    std::vector<std::uint32_t> calls;
    auto selected = resolve_authenticated_session_birth(block(8), epoch(), reader_for(rows, &calls), 2);
    expect_error(selected, "session-birth-budget", "budget_never_falls_back");
    require(calls == std::vector<std::uint32_t>({8, 7}), "budget_never_falls_back");
  });
  add("zero_budget", [] {
    const auto rows = history(0, 0);
    expect_error(resolve_authenticated_session_birth(block(0), epoch(), reader_for(rows), 0), "session-birth-budget",
                 "zero_budget");
  });
  add("hard_budget", [] {
    const auto rows = history(0, 0);
    expect_error(resolve_authenticated_session_birth(block(0), epoch(), reader_for(rows), 65537),
                 "session-birth-budget", "hard_budget");
  });
  add("derive_uses_birth_not_detection_tip", [] {
    auto birth = authenticated();
    std::uint32_t derived_at = 0;
    auto context = derive_session_committee<FakeCommittee>(
        std::move(birth), [&derived_at](const SessionBirthBlock& at) -> Result<FakeCommittee> {
          derived_at = at.seqno;
          return FakeCommittee{{1, 2, 3}};
        });
    require(context.ok() && derived_at == 5, "derive_uses_birth_not_detection_tip");
    require(context.value()->birth().trusted_tip() == block(8), "derive_uses_birth_not_detection_tip");
  });
  add("derive_error_has_no_fallback", [] {
    auto birth = authenticated();
    int calls = 0;
    auto context = derive_session_committee<FakeCommittee>(
        std::move(birth), [&calls](const SessionBirthBlock&) -> Result<FakeCommittee> {
          ++calls;
          return Error{"election-registry-binding"};
        });
    expect_error(context, "election-registry-binding", "derive_error_has_no_fallback");
    require(calls == 1, "derive_error_has_no_fallback");
  });
  add("owned_committee_is_immutable", [] {
    std::vector<int> source{1, 2, 3};
    auto context = derive_session_committee<FakeCommittee>(
        authenticated(), [&source](const SessionBirthBlock&) -> Result<FakeCommittee> { return FakeCommittee{source}; });
    require(context.ok(), "owned_committee_is_immutable");
    source.clear();
    require(context.value()->committee().members == std::vector<int>({1, 2, 3}), "owned_committee_is_immutable");
  });
  add("legacy_key_coordinate_is_normalized", [] {
    auto input = epoch_input();
    input.last_key_block_seqno = 99;
    auto mapped = map_native_session_epoch(input);
    require(mapped.ok() && mapped.value().key_block_seqno == 0, "legacy_key_coordinate_is_normalized");
  });
  add("vertical_coordinate_is_preserved", [] {
    auto input = epoch_input();
    input.maximal_vertical_seqno = 17;
    input.last_key_block_seqno = 99;
    auto mapped = map_native_session_epoch(input);
    require(mapped.ok() && mapped.value().vertical_seqno == 17 && mapped.value().key_block_seqno == 0,
            "vertical_coordinate_is_preserved");
  });
  add("new_id_key_coordinate_is_preserved", [] {
    auto input = epoch_input();
    input.new_catchain_ids = true;
    input.maximal_vertical_seqno = 17;
    input.last_key_block_seqno = 99;
    auto mapped = map_native_session_epoch(input);
    require(mapped.ok() && mapped.value().vertical_seqno == 17 && mapped.value().key_block_seqno == 99,
            "new_id_key_coordinate_is_preserved");
  });
  add("zero_options_are_refused", [] {
    auto input = epoch_input();
    input.native_options_hash = {};
    expect_error(map_native_session_epoch(input), "session-birth-options", "zero_options_are_refused");
  });
  add("split_merge_shards_are_not_aliased", [] {
    const std::uint64_t parent = std::uint64_t{1} << 63;
    const std::uint64_t left = parent | (std::uint64_t{1} << 62);
    const std::uint64_t right = parent | (std::uint64_t{3} << 61);
    auto a = epoch_input(21), b = epoch_input(31), c = epoch_input(41);
    a.shard = parent;
    b.shard = left;
    c.shard = right;
    auto ma = map_native_session_epoch(a), mb = map_native_session_epoch(b), mc = map_native_session_epoch(c);
    require(ma.ok() && mb.ok() && mc.ok(), "split_merge_shards_are_not_aliased");
    require(ma.value().shard == parent && mb.value().shard == left && mc.value().shard == right,
            "split_merge_shards_are_not_aliased");
  });
  add("same_session_reuses_owned_context", [] {
    auto existing = context_for(authenticated());
    int calls = 0;
    auto admitted = admit_session_committee<FakeCommittee>(
        existing, authenticated(), [&calls](const SessionBirthBlock&) -> Result<FakeCommittee> {
          ++calls;
          return FakeCommittee{{9}};
        });
    require(admitted.ok() && admitted.value() == existing && calls == 0, "same_session_reuses_owned_context");
  });
  add("same_id_metadata_conflict_is_refused", [] {
    auto existing = context_for(authenticated());
    auto changed = epoch(21, 24);
    auto candidate = authenticated(8, 5, changed, epoch(31));
    auto admitted = admit_session_committee<FakeCommittee>(
        existing, std::move(candidate), [](const SessionBirthBlock&) -> Result<FakeCommittee> {
          return FakeCommittee{{9}};
        });
    expect_error(admitted, "session-admission-epoch-conflict", "same_id_metadata_conflict_is_refused");
    require(existing->committee().members == std::vector<int>({1, 2, 3}), "same_id_metadata_conflict_is_refused");
  });
  add("same_id_birth_conflict_is_refused", [] {
    auto existing = context_for(authenticated(8, 5));
    auto candidate = authenticated(8, 6);
    auto admitted = admit_session_committee<FakeCommittee>(
        existing, std::move(candidate), [](const SessionBirthBlock&) -> Result<FakeCommittee> {
          return FakeCommittee{{9}};
        });
    expect_error(admitted, "session-admission-birth-conflict", "same_id_birth_conflict_is_refused");
  });
  add("new_native_id_creates_new_context", [] {
    auto existing = context_for(authenticated());
    auto next_epoch = epoch(41);
    auto candidate = authenticated(8, 7, next_epoch, epoch());
    std::uint32_t derived_at = 0;
    auto admitted = admit_session_committee<FakeCommittee>(
        existing, std::move(candidate), [&derived_at](const SessionBirthBlock& at) -> Result<FakeCommittee> {
          derived_at = at.seqno;
          return FakeCommittee{{4, 5, 6}};
        });
    require(admitted.ok() && admitted.value() != existing && derived_at == 7, "new_native_id_creates_new_context");
    require(existing->committee().members == std::vector<int>({1, 2, 3}), "new_native_id_creates_new_context");
  });
  add("failed_new_session_retains_existing", [] {
    auto existing = context_for(authenticated());
    auto next_epoch = epoch(41);
    auto candidate = authenticated(8, 7, next_epoch, epoch());
    auto admitted = admit_session_committee<FakeCommittee>(
        existing, std::move(candidate), [](const SessionBirthBlock&) -> Result<FakeCommittee> {
          return Error{"election-registry-binding"};
        });
    expect_error(admitted, "election-registry-binding", "failed_new_session_retains_existing");
    require(existing->birth().selected().block == block(5), "failed_new_session_retains_existing");
    require(existing->committee().members == std::vector<int>({1, 2, 3}), "failed_new_session_retains_existing");
  });
  return result;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc > 2) {
    std::cerr << "USAGE: test-p0-session-admission [case-name|--list]\n";
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
