#include <algorithm>

#include "native-witnessed-history.h"
namespace tos::auth {

Result<std::vector<std::uint32_t>> required_finalized_coordinates(const Authorizations& authorizations,
                                                                 std::uint32_t inclusion) {
  std::vector<std::uint32_t> coordinates;
  for (const auto& owner : authorizations.owner_) {
    const auto at = owner.proof_.anchor_.seqno_;
    // The same rule execution will apply, applied here so a caller cannot be
    // asked to fetch a block that could never be accepted.
    if (at >= inclusion)
      return Error{"owner-finality-coordinate"};
    coordinates.push_back(at);
  }
  std::sort(coordinates.begin(), coordinates.end());
  coordinates.erase(std::unique(coordinates.begin(), coordinates.end()), coordinates.end());
  // Bounded for the same reason every other read here is: a transaction that
  // could name unlimited history would make one block's work unbounded.
  if (coordinates.size() > 64)
    return Error{"owner-finality-breadth"};
  return coordinates;
}

Result<Anchor> WitnessedAnchorSource::finalized_anchor(std::uint32_t at) const {
  auto found = anchors_.find(at);
  if (found == anchors_.end())
    return Error{"finalized-anchor-unavailable"};
  // An entry still has to be the coordinate it is filed under, or the map itself
  // becomes a place where a substitution can hide.
  if (found->second.seqno_ != at)
    return Error{"finalized-anchor-binding"};
  return found->second;
}
}  // namespace tos::auth
