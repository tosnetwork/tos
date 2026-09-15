#pragma once
#include <map>
#include <vector>

#include "native-apply.h"
namespace tos::auth {
// The registry library resolves finalized anchors through a synchronous reader;
// a node's archive is asynchronous. Rather than making the library asynchronous
// or blocking the node, the requirement is made explicit before execution: an
// owner approval names the anchor it relies on, so every anchor a transaction
// will ask for is known from its authorizations alone.
//
// The caller enumerates them, fetches them however its storage works, and then
// executes synchronously against what it fetched. Nothing is resolved during
// execution that was not resolved before it.
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
