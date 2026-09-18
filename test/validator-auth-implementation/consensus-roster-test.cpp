// The committee a validator session seats is the authenticated one, not the
// validator set the manager built beside it.
//
// The manager already confirms that its own session identity equals the one the
// native path derives. That confirmation proves the two agree; it does not make
// either authoritative. These cases exercise the type that does: for a chain
// that has activated the design, the roster consensus runs is the committee the
// session was committed under, and the historical validator set is not read for
// membership at all.
//
// The historical set passed in here is deliberately built from unrelated keys,
// so a positive test that only checked "some roster came back" would pass even
// if the historical one were seated. Every authenticated case asserts the
// members equal the committee's transport order and differ from that set.
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto/block/validator-set.h"
#include "validator/auth/consensus-roster.h"

#include "session-continuity-test-fixture.h"

namespace {
using namespace tos::auth;
using namespace owner_fixture;
using namespace session_continuity_fixture;

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

// A validator set that shares nothing with the committee: different keys,
// different weights, different count. Seating this instead of the committee is
// the failure every authenticated case is built to catch.
td::Ref<block::ValidatorSet> foreign_set() {
  std::vector<tos::ValidatorDescr> nodes;
  for (unsigned i = 0; i < 3; ++i)
    nodes.emplace_back(tos::Ed25519_PublicKey{h(90000 + i)}, static_cast<tos::ValidatorWeight>(7 + i));
  return td::make_ref<block::ValidatorSet>(19u, tos::ShardIdFull(tos::masterchainId, tos::shardIdAll),
                                           std::move(nodes));
}

std::shared_ptr<CommittedNativeSession> commit(const HistoryFixture& fixture,
                                               const std::shared_ptr<const NativeSessionCommitteeContext>& context,
                                               const std::filesystem::path& path, NativeSessionCommitmentStore*& store_out,
                                               std::unique_ptr<NativeSessionCommitmentStore>& store_keep,
                                               const char* name) {
  std::filesystem::remove(path);
  std::filesystem::remove(path.string() + ".frontier");
  auto store = NativeSessionCommitmentStore::initialize(path.string());
  expect(store.ok(), name);
  store_keep = std::move(store.value());
  store_out = store_keep.get();
  auto committed = CommittedNativeSession::commit_new(*store_keep, context, fixture.chain);
  expect(committed.ok(), name);
  return committed.value();
}

std::shared_ptr<const NativeSessionCommitteeContext> context_for(const HistoryFixture& fixture, const char* name) {
  auto made = make_context(fixture, identity_input());
  expect(made.ok(), name);
  return made.value();
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: " << argv[0] << " OWNER_INPUTS COMMITTEE_FIXTURES WORK\n";
    return 2;
  }
  const std::filesystem::path owner(argv[1]), committee(argv[2]), work(argv[3]);
  std::filesystem::create_directories(work);
  try {
    // P0 active: the roster is the committee, and it is exactly the transport
    // order the native selector produced -- same order the historical loop
    // seats, so a member index means the same thing on either path.
    {
      auto fixture = make_history(owner, committee);
      auto context = context_for(fixture, "authenticated_roster_is_the_committee");
      std::unique_ptr<NativeSessionCommitmentStore> keep;
      NativeSessionCommitmentStore* store = nullptr;
      auto session = commit(fixture, context, work / "authenticated.commitments", store, keep,
                            "authenticated_roster_is_the_committee");
      auto set = foreign_set();

      auto roster = seat_consensus_roster(true, session, *set);
      expect(roster.ok(), "authenticated_roster_is_the_committee");
      expect(roster.value().source() == ConsensusRosterSource::authenticated,
             "authenticated_roster_is_the_committee");
      const auto& expected = context->committee().transport_order();
      expect(!expected.empty(), "authenticated_roster_is_the_committee");
      expect(roster.value().members() == expected, "authenticated_roster_is_the_committee");
      // And the historical set it was handed is genuinely not what came back:
      // otherwise the assertion above could hold for the wrong reason.
      expect(roster.value().members() != set->export_vector(), "authenticated_roster_is_the_committee");
      expect(roster.value().catchain() == context->birth().selected().epoch.catchain,
             "authenticated_roster_is_the_committee");
      ok("authenticated_roster_is_the_committee");
    }

    // P0 inactive: unchanged historical behaviour. The owner is null and is not
    // consulted; the historical set is seated exactly as before.
    {
      auto set = foreign_set();
      auto roster = seat_consensus_roster(false, nullptr, *set);
      expect(roster.ok() && roster.value().source() == ConsensusRosterSource::historical,
             "inactive_roster_is_the_historical_set");
      expect(roster.value().members() == set->export_vector(), "inactive_roster_is_the_historical_set");
      expect(roster.value().catchain() == set->get_catchain_seqno(), "inactive_roster_is_the_historical_set");
      ok("inactive_roster_is_the_historical_set");
    }

    // P0 active with no committed session is a refusal to run, never a fallback
    // to the historical set. This is the shape a fallback would have to break.
    {
      auto set = foreign_set();
      auto roster = seat_consensus_roster(true, nullptr, *set);
      expect(!roster.ok() && roster.error().code == "consensus-roster-unauthenticated",
             "active_without_a_session_is_refused");
      ok("active_without_a_session_is_refused");
    }

    // A released session owns no committee to seat, and says so rather than
    // handing back an empty or stale roster.
    {
      auto fixture = make_history(owner, committee);
      auto context = context_for(fixture, "a_released_session_seats_nothing");
      std::unique_ptr<NativeSessionCommitmentStore> keep;
      NativeSessionCommitmentStore* store = nullptr;
      auto session = commit(fixture, context, work / "released.commitments", store, keep,
                            "a_released_session_seats_nothing");
      // Seating works while it is retained.
      expect(seat_consensus_roster(true, session, *foreign_set()).ok(), "a_released_session_seats_nothing");
      // A finalized state that no longer names this session releases it.
      auto observation = session->release_if_terminated(fixture.head_state, fixture.head, identity_input(731));
      expect(observation.ok() && observation.value().released && !session->retained(),
             "a_released_session_seats_nothing");
      auto roster = seat_consensus_roster(true, session, *foreign_set());
      expect(!roster.ok() && roster.error().code == "session-released", "a_released_session_seats_nothing");
      ok("a_released_session_seats_nothing");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
