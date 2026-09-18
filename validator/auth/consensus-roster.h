#pragma once
#include <cstdint>
#include <memory>
#include <vector>

#include "crypto/block/validator-set.h"
#include "tos/tos-types.h"

#include "native-session-continuity.h"
namespace tos::auth {
// The members a validator session seats, and where they came from.
//
// Consensus used to build its member table from the validator set the manager
// handed it, and the authenticated committee -- derived, admitted, committed,
// and carried in beside it -- was compared against that table and then never
// read again. A comparison proves two constructions agree today; it does not
// make either of them the authority. For a chain that has activated validator
// authentication, the committee the session was committed under is the roster,
// and the validator set the manager built is not consulted for membership.
//
// The type has exactly two constructors and no third. One takes the historical
// validator set and is for chains where the design is inactive. One takes a
// committed authenticated session. There is no constructor that takes a
// validator set for an active chain, so "active, but seated from the
// historical set" is not a value this type can hold, and a caller that wanted
// to fall back to it would have to write that constructor first.
enum class ConsensusRosterSource { historical, authenticated };

class ConsensusRoster {
  ConsensusRosterSource source_;
  std::vector<tos::ValidatorDescr> members_;
  std::uint32_t catchain_{};
  ConsensusRoster(ConsensusRosterSource source, std::vector<tos::ValidatorDescr> members, std::uint32_t catchain)
      : source_(source), members_(std::move(members)), catchain_(catchain) {
  }

 public:
  // The historical behaviour, unchanged, for a chain that has not activated
  // the design.
  static ConsensusRoster historical(const block::ValidatorSet&);
  // Exactly the committee the session was committed under, in the order the
  // native selector produced -- the same order the historical loop seats, so
  // member indices mean the same thing on both paths. Refused once the session
  // has been released: a released session owns no committee to seat.
  static Result<ConsensusRoster> authenticated(const CommittedNativeSession&);

  ConsensusRosterSource source() const {
    return source_;
  }
  const std::vector<tos::ValidatorDescr>& members() const {
    return members_;
  }
  std::uint32_t catchain() const {
    return catchain_;
  }
};

// What a bus seats. `required` is the chain's own classification -- validator
// authentication is active for the state this session runs on -- carried from
// the manager, which reads it from the masterchain state. `owner` is the
// committed session the manager admitted for this session id, when there is
// one.
//
//   inactive                    -> the historical set, as before
//   active, committed session   -> that session's committee
//   active, no committed session -> refusal
//
// The last line is the one that matters: an authenticated derivation that did
// not produce a session is a refusal to run, never a reason to seat the
// historical set. That would turn a security refusal into a bypass.
Result<ConsensusRoster> seat_consensus_roster(bool required, const std::shared_ptr<CommittedNativeSession>& owner,
                                              const block::ValidatorSet& historical);
}  // namespace tos::auth
