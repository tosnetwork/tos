#include "consensus-roster.h"

namespace tos::auth {
ConsensusRoster ConsensusRoster::historical(const block::ValidatorSet& set) {
  return ConsensusRoster(ConsensusRosterSource::historical, set.export_vector(), set.get_catchain_seqno());
}

Result<ConsensusRoster> ConsensusRoster::authenticated(const CommittedNativeSession& session) {
  auto context = session.context();
  if (!context.ok())
    return context.error();
  // The transport order is the committee's own separately owned list in native
  // selection order; the sorted member list beside it is for signing context.
  // Copied whole rather than rebuilt from fields, so nothing here decides what a
  // member is.
  return ConsensusRoster(ConsensusRosterSource::authenticated, context.value()->committee().transport_order(),
                         context.value()->birth().selected().epoch.catchain);
}

Result<ConsensusRoster> seat_consensus_roster(bool required, const std::shared_ptr<CommittedNativeSession>& owner,
                                              const block::ValidatorSet& historical) {
  if (!required)
    return ConsensusRoster::historical(historical);
  if (!owner)
    return Error{"consensus-roster-unauthenticated"};
  return ConsensusRoster::authenticated(*owner);
}
}  // namespace tos::auth
