#include "validator/auth/native-session-continuity.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include "session-continuity-test-fixture.h"

namespace {
using namespace tos::auth;
using namespace owner_fixture;
using namespace session_continuity_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

void expect_error(const auto& result, std::string_view code,
                  const std::string& assertion) {
  require(!result.ok() && result.error().code == code, assertion);
}

std::filesystem::path store_path(
    const std::filesystem::path& work, const std::string& name) {
  auto path = work / (name + ".commitments");
  std::filesystem::remove(path);
  std::filesystem::remove(path.string() + ".frontier");
  return path;
}

std::unique_ptr<NativeSessionCommitmentStore> initialize_store(
    const std::filesystem::path& path,
    const std::string& assertion) {
  auto opened =
      NativeSessionCommitmentStore::initialize(path.string());
  require(opened.ok(), assertion);
  return std::move(opened.value());
}

std::shared_ptr<const NativeSessionCommitteeContext> context(
    const HistoryFixture& fixture, const NativeSessionIdInput& input,
    const std::string& assertion) {
  auto made = make_context(fixture, input);
  require(made.ok(), assertion);
  return made.value();
}

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests(
    const std::filesystem::path& owner_inputs,
    const std::filesystem::path& committee_fixtures,
    const std::filesystem::path& work) {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("restart_identical_commitment", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "restart_identical_commitment");
    auto path = store_path(work, "restart-identical");
    {
      auto store =
          initialize_store(path, "restart_identical_commitment");
      auto first = CommittedNativeSession::commit_new(
          *store, candidate, fixture.chain);
      require(first.ok() && first.value()->retained(),
              "restart_identical_commitment");
    }

    auto reopened =
        NativeSessionCommitmentStore::open(path.string());
    require(reopened.ok(), "restart_identical_commitment");
    auto rederived =
        context(fixture, identity_input(),
                "restart_identical_commitment");
    auto restarted = CommittedNativeSession::restart(
        *reopened.value(), rederived, fixture.chain);
    require(restarted.ok() && restarted.value()->retained(),
            "restart_identical_commitment");
  });

  add("restart_missing_refused", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "restart_missing_refused");
    auto path = store_path(work, "restart-missing");
    auto store =
        initialize_store(path, "restart_missing_refused");
    auto before = store->size();
    expect_error(
        CommittedNativeSession::restart(
            *store, candidate, fixture.chain),
        "session-commitment-missing",
        "restart_missing_refused");
    require(store->size() == before && store->records() == 0,
            "restart_missing_refused");
  });

  add("restart_commitment_conflict_refused", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "restart_commitment_conflict_refused");
    auto commitment =
        make_native_session_commitment(*candidate, fixture.chain);
    require(commitment.ok(),
            "restart_commitment_conflict_refused");
    auto altered = commitment.value();
    altered.birth.root[0] ^= 1;

    auto path = store_path(work, "restart-conflict");
    auto store = initialize_store(
        path, "restart_commitment_conflict_refused");
    require(store->record_new(altered).ok(),
            "restart_commitment_conflict_refused");
    auto before = store->size();

    expect_error(
        CommittedNativeSession::restart(
            *store, candidate, fixture.chain),
        "session-commitment-conflict",
        "restart_commitment_conflict_refused");
    require(store->size() == before &&
                store->verify(altered).ok(),
            "restart_commitment_conflict_refused");
  });

  add("committee_commitment_checked", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "committee_commitment_checked");
    auto commitment =
        make_native_session_commitment(*candidate, fixture.chain);
    require(commitment.ok(), "committee_commitment_checked");
    auto altered = commitment.value();
    altered.committee_hash[0] ^= 1;

    auto path = store_path(work, "committee-conflict");
    auto store =
        initialize_store(path, "committee_commitment_checked");
    require(store->record_new(altered).ok(),
            "committee_commitment_checked");
    expect_error(
        CommittedNativeSession::restart(
            *store, candidate, fixture.chain),
        "session-commitment-conflict",
        "committee_commitment_checked");
  });

  add("new_session_recorded_before_use", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "new_session_recorded_before_use");
    auto commitment =
        make_native_session_commitment(*candidate, fixture.chain);
    require(commitment.ok(),
            "new_session_recorded_before_use");

    auto path = store_path(work, "record-before-use");
    auto store = initialize_store(
        path, "new_session_recorded_before_use");
    auto committed = CommittedNativeSession::commit_new(
        *store, candidate, fixture.chain);
    require(committed.ok() &&
                store->verify(commitment.value()).ok() &&
                store->records() == 1,
            "new_session_recorded_before_use");
  });

  add("frontier_rollback_refused", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "frontier_rollback_refused");
    auto path = store_path(work, "frontier-rollback");
    {
      auto store =
          initialize_store(path, "frontier_rollback_refused");
      auto committed = CommittedNativeSession::commit_new(
          *store, candidate, fixture.chain);
      require(committed.ok(), "frontier_rollback_refused");
    }

    std::fstream frontier(
        path.string() + ".frontier",
        std::ios::in | std::ios::out | std::ios::binary);
    require(frontier.good(), "frontier_rollback_refused");
    frontier.seekp(16);
    char changed = 0x5a;
    frontier.write(&changed, 1);
    frontier.flush();
    frontier.close();

    expect_error(
        NativeSessionCommitmentStore::open(path.string()),
        "session-commitment-frontier",
        "frontier_rollback_refused");
  });

  add("member_authority_only_for_member", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "member_authority_only_for_member");
    auto path = store_path(work, "member-authority");
    auto store = initialize_store(
        path, "member_authority_only_for_member");
    auto committed = CommittedNativeSession::commit_new(
        *store, candidate, fixture.chain);
    require(committed.ok(),
            "member_authority_only_for_member");

    const auto& members =
        candidate->committee().snapshot().committee().members_;
    require(!members.empty(),
            "member_authority_only_for_member");
    auto member =
        committed.value()->member_authority(
            members.front().identity_);
    require(member.ok(),
            "member_authority_only_for_member");
    // A role-1 duty payload is exactly 40 bytes: the candidate type prefix, the
    // position as a little-endian word, and the candidate hash. Three arbitrary
    // bytes are refused by the duty grammar, so asserting they succeed asserts
    // the grammar is broken rather than that a member can act.
    constexpr std::uint32_t position = 7;
    Bytes payload{0x3f, 0xcd, 0x91, 0xb6};
    for (unsigned i = 0; i < 4; ++i)
      payload.push_back(static_cast<std::uint8_t>(position >> (8 * i)));
    auto candidate_hash = h(4242);
    payload.insert(payload.end(), candidate_hash.begin(), candidate_hash.end());
    require(payload.size() == 40, "member_authority_only_for_member");
    auto duty = member.value().make_duty(1, position, payload);
    require(duty.ok(), "member_authority_only_for_member");
    // The duty a member signs carries the canonical P0 session id H(session, ...),
    // never the native ValidatorSessionId. This is the domain frozen WIRE binds
    // into VAS1; make_member_duty must use p0_session_id_, not native_session_id_.
    const auto& duty_epoch = candidate->birth().selected().epoch;
    auto expected_session =
        session_id(fixture.chain, candidate->committee().snapshot(),
                   SessionOrigin{duty_epoch.native_options_hash,
                                 duty_epoch.vertical_seqno,
                                 duty_epoch.key_block_seqno});
    require(expected_session.ok(), "member_authority_only_for_member");
    require(duty.value().session_ == expected_session.value() &&
                duty.value().session_ != duty_epoch.native_session_id,
            "member_authority_only_for_member");

    Hash absent = h(999999);
    expect_error(
        committed.value()->member_authority(absent),
        "session-member-nonmember",
        "member_authority_only_for_member");
  });

  add("same_session_not_terminated", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "same_session_not_terminated");
    auto path = store_path(work, "same-session-live");
    auto store =
        initialize_store(path, "same_session_not_terminated");
    auto committed = CommittedNativeSession::commit_new(
        *store, candidate, fixture.chain);
    require(committed.ok(), "same_session_not_terminated");

    auto observation =
        committed.value()->release_if_terminated(
            fixture.head_state, fixture.head, identity_input());
    require(observation.ok() &&
                !observation.value().released &&
                observation.value().retained &&
                observation.value().release_count == 0 &&
                committed.value()->retained(),
            "same_session_not_terminated");
  });

  add("authenticated_termination_releases", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "authenticated_termination_releases");
    std::weak_ptr<const NativeSessionCommitteeContext> weak = candidate;

    auto path = store_path(work, "authenticated-release");
    auto store = initialize_store(
        path, "authenticated_termination_releases");
    auto committed = CommittedNativeSession::commit_new(
        *store, candidate, fixture.chain);
    require(committed.ok(),
            "authenticated_termination_releases");
    candidate.reset();

    auto observation =
        committed.value()->release_if_terminated(
            fixture.head_state, fixture.head, identity_input(731));
    require(observation.ok() &&
                observation.value().released &&
                !observation.value().retained &&
                observation.value().release_count == 1 &&
                committed.value()->release_count() == 1 &&
                !committed.value()->retained() &&
                weak.expired(),
            "authenticated_termination_releases");
  });

  add("member_authority_revoked_on_release", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "member_authority_revoked_on_release");
    auto path = store_path(work, "member-release");
    auto store = initialize_store(
        path, "member_authority_revoked_on_release");
    auto committed = CommittedNativeSession::commit_new(
        *store, candidate, fixture.chain);
    require(committed.ok(),
            "member_authority_revoked_on_release");
    const auto identity =
        candidate->committee().snapshot().committee()
            .members_.front().identity_;
    auto authority =
        committed.value()->member_authority(identity);
    require(authority.ok(),
            "member_authority_revoked_on_release");

    auto released =
        committed.value()->release_if_terminated(
            fixture.head_state, fixture.head, identity_input(731));
    require(released.ok() && released.value().released,
            "member_authority_revoked_on_release");
    std::array<std::uint8_t, 1> payload{1};
    expect_error(
        authority.value().make_duty(1, 0, payload),
        "session-context-released",
        "member_authority_revoked_on_release");
  });

  add("termination_before_birth_refused", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "termination_before_birth_refused");
    auto path = store_path(work, "termination-before-birth");
    auto store = initialize_store(
        path, "termination_before_birth_refused");
    auto committed = CommittedNativeSession::commit_new(
        *store, candidate, fixture.chain);
    require(committed.ok(),
            "termination_before_birth_refused");

    expect_error(
        committed.value()->release_if_terminated(
            fixture.predecessor_state, fixture.predecessor,
            identity_input()),
        "session-termination-before-birth",
        "termination_before_birth_refused");
    require(committed.value()->retained(),
            "termination_before_birth_refused");
  });

  add("release_preserves_durable_commitment", [=] {
    auto fixture = make_history(owner_inputs, committee_fixtures);
    auto candidate =
        context(fixture, identity_input(),
                "release_preserves_durable_commitment");
    auto commitment =
        make_native_session_commitment(*candidate, fixture.chain);
    require(commitment.ok(),
            "release_preserves_durable_commitment");

    auto path = store_path(work, "release-keeps-record");
    auto store = initialize_store(
        path, "release_preserves_durable_commitment");
    auto committed = CommittedNativeSession::commit_new(
        *store, candidate, fixture.chain);
    require(committed.ok(),
            "release_preserves_durable_commitment");

    auto released =
        committed.value()->release_if_terminated(
            fixture.head_state, fixture.head, identity_input(731));
    require(released.ok() && released.value().released &&
                store->verify(commitment.value()).ok(),
            "release_preserves_durable_commitment");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4 || argc > 5) {
    std::cerr
        << "USAGE: test-p0-native-session-continuity OWNER_INPUTS "
           "COMMITTEE_FIXTURES WORKDIR [case-name|--list]\n";
    return 2;
  }
  const std::filesystem::path owner_inputs(argv[1]);
  const std::filesystem::path committee_fixtures(argv[2]);
  const std::filesystem::path work(argv[3]);
  std::filesystem::create_directories(work);
  const auto all =
      tests(owner_inputs, committee_fixtures, work);

  if (argc == 5 && std::string_view(argv[4]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }

  std::size_t ran = 0;
  for (const auto& [case_name, fn] : all) {
    if (argc == 5 && case_name != argv[4])
      continue;
    try {
      std::cout << "SETUP_OK " << case_name << '\n';
      fn();
      std::cout << "CASE_PASS " << case_name << '\n';
      ++ran;
    } catch (const AssertionFailure& error) {
      std::cerr << "ASSERTION_FAILED " << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION " << case_name << ": "
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
