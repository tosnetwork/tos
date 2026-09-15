#include "native-anchor-cache.h"
namespace tos::auth {

std::vector<std::uint32_t> NativeAnchorCache::missing(std::span<const std::uint32_t> required) const {
  std::vector<std::uint32_t> absent;
  for (auto at : required)
    if (!anchors_.count(at))
      absent.push_back(at);
  return absent;
}

Result<bool> NativeAnchorCache::admit(std::uint32_t at, const Anchor& anchor) {
  if (anchor.seqno_ != at)
    return Error{"anchor-cache-binding"};
  if (anchor.root_ == Hash{} || anchor.file_ == Hash{} || anchor.state_ == Hash{})
    return Error{"anchor-cache-incomplete"};
  auto found = anchors_.find(at);
  // A second answer for one coordinate is a disagreement about finalized
  // history, not a refresh, so it is refused rather than overwritten.
  if (found != anchors_.end())
    return found->second == anchor ? Result<bool>(true) : Result<bool>(Error{"anchor-cache-conflict"});
  anchors_.emplace(at, anchor);
  while (anchors_.size() > limit_)
    anchors_.erase(anchors_.begin());
  return true;
}

Result<PrefetchedAnchorSource> NativeAnchorCache::source(std::span<const std::uint32_t> required) const {
  std::map<std::uint32_t, Anchor> selected;
  for (auto at : required) {
    auto found = anchors_.find(at);
    if (found == anchors_.end())
      return Error{"anchor-cache-incomplete-set"};
    selected.emplace(at, found->second);
  }
  return PrefetchedAnchorSource{std::move(selected)};
}

Result<Resolution> resolve_declared_history(std::span<const std::uint32_t> coordinates, std::int32_t expected_network,
                                            const NativeCoordinateReader& read, NativeAnchorCache& cache,
                                            ResolutionBudget budget) {
  if (!read)
    return Error{"anchor-resolve-reader"};
  // The declaration is already bounded where it is parsed; bounding it again
  // here is what makes that bound this function's own precondition rather than
  // a dependency on a constant somewhere else.
  if (coordinates.size() > budget.coordinates)
    return Error{"anchor-resolve-budget"};

  Resolution resolution;
  for (auto at : coordinates) {
    auto raw = read(at, budget.bytes);
    if (!raw.ok()) {
      resolution.unavailable.push_back(at);
      continue;
    }
    if (raw.value().size() > budget.bytes)
      return Error{"anchor-resolve-size"};
    auto anchor = native_masterchain_block_anchor(raw.value(), expected_network);
    if (!anchor.ok())
      return anchor.error();
    auto admitted = cache.admit(at, anchor.value());
    if (!admitted.ok())
      return admitted.error();
    ++resolution.admitted;
  }
  return resolution;
}
}  // namespace tos::auth
