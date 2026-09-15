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

Result<Resolution> resolve_declared_history(std::span<const std::uint32_t> coordinates,
                                            td::Ref<vm::Cell> masterchain_state, const Anchor& head,
                                            const ChainContext& chain, NativeBlockReader read, NativeAnchorCache& cache,
                                            ResolutionBudget budget) {
  if (!read)
    return Error{"anchor-resolve-reader"};
  // The declaration is already bounded where it is parsed; bounding it again
  // here makes that bound this function's own precondition rather than a
  // dependency on a constant somewhere else.
  if (coordinates.size() > budget.coordinates)
    return Error{"anchor-resolve-budget"};

  // Telling "this node has not fetched it" apart from "what it fetched does not
  // authenticate" is the whole difference between waiting and refusing, and
  // only the reader knows which of the two happened.
  bool served = true;
  auto observed = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
    auto bytes = read(id, limit);
    if (!bytes.ok())
      served = false;
    return bytes;
  };

  auto history = NativeFinalizedHistory::open(std::move(masterchain_state), head, chain, observed, budget.reads);
  if (!history.ok())
    return history.error();

  Resolution resolution;
  for (auto at : coordinates) {
    served = true;
    auto anchor = history.value().finalized_anchor(at);
    if (!anchor.ok()) {
      if (!served) {
        resolution.unavailable.push_back(at);
        continue;
      }
      return anchor.error();
    }
    auto admitted = cache.admit(at, anchor.value());
    if (!admitted.ok())
      return admitted.error();
    ++resolution.admitted;
  }
  return resolution;
}

Result<std::vector<tos::BlockIdExt>> required_finalized_blocks(std::span<const std::uint32_t> coordinates,
                                                               td::Ref<vm::Cell> masterchain_state, const Anchor& head,
                                                               const ChainContext& chain, const NativeAnchorCache& held,
                                                               ResolutionBudget budget) {
  // What is already held needs no read, and the history has no knowledge of
  // this cache, so narrowing has to happen here rather than inside it.
  const auto absent = held.missing(coordinates);

  std::vector<tos::BlockIdExt> wanted;
  // Refusing every read records what would have been read without resolving
  // anything: a coordinate that needs a block is reported unavailable, and one
  // that needs none is answered outright and admitted to a throwaway cache.
  auto enumerate = [&](const tos::BlockIdExt& id, std::size_t) -> Result<Bytes> {
    wanted.push_back(id);
    return Error{"anchor-resolve-enumerating"};
  };
  NativeAnchorCache scratch;
  auto resolved =
      resolve_declared_history(absent, std::move(masterchain_state), head, chain, enumerate, scratch, budget);
  if (!resolved.ok())
    return resolved.error();
  return wanted;
}
}  // namespace tos::auth
