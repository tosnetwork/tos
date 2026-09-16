#pragma once
#include <map>
#include <vector>

#include "native-apply.h"
namespace tos::auth {
// The registry library resolves finalized anchors through a synchronous reader,
// so what execution may reach has to be fixed before execution starts. An owner
// approval names the anchor it relies on, which makes every anchor a
// transaction will ask for known from its authorizations alone.
//
// Consensus admission does not fetch those anchors from anywhere: it
// authenticates the witness the message carries and supplies that one
// authenticated anchor, so a producer and a validator holding the same block
// execute against the same history. Nothing is resolved during execution that
// was not established before it.
Result<std::vector<std::uint32_t>> required_finalized_coordinates(const Authorizations&, std::uint32_t inclusion);

// Answers only from what was prefetched. A coordinate that was not fetched is a
// refusal, never a read: the point of prefetching is lost if a miss can still
// reach storage, and an execution that silently read more than it declared
// would be unreproducible from its own inputs.
class PrefetchedAnchorSource final : public FinalizedAnchorSource {
  std::map<std::uint32_t, Anchor> anchors_;

 public:
  explicit PrefetchedAnchorSource(std::map<std::uint32_t, Anchor> anchors) : anchors_(std::move(anchors)) {
  }
  Result<Anchor> finalized_anchor(std::uint32_t at) const override;
};
}  // namespace tos::auth
