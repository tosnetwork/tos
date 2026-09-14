#pragma once
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "native-prefetch.h"
namespace tos::auth {
// Anchors a node resolved once and keeps across block collations.
//
// A registry update names the history it relies on, but resolving that history
// is an archive read and collation is synchronous. The node therefore refuses
// the update in the block where it first sees it, resolves what that update
// declared, and admits it in a later block. This holds what was resolved.
//
// It is node-lifetime state, so it is bounded and evicts deterministically. An
// unbounded cache of history is the shape that looks free for a week and then
// is not; evicting the lowest coordinates first is correct because an approval
// references recent history and the old entries are the ones nothing will ask
// for again.
class NativeAnchorCache {
  std::map<std::uint32_t, Anchor> anchors_;
  std::size_t limit_;

 public:
  explicit NativeAnchorCache(std::size_t limit = 1024) : limit_(limit < 1 ? 1 : limit) {
  }

  // What still has to be fetched before the requested set can be served.
  std::vector<std::uint32_t> missing(std::span<const std::uint32_t> required) const;

  // Records one resolved anchor. An anchor filed under a coordinate it does not
  // carry is refused: the cache is consulted instead of the archive, so a
  // substitution admitted here would never be checked again.
  Result<bool> admit(std::uint32_t at, const Anchor&);

  // A source for exactly the requested set, or a refusal naming that something
  // is still missing. Building a partial source would let execution proceed
  // with history it never resolved.
  Result<PrefetchedAnchorSource> source(std::span<const std::uint32_t> required) const;

  std::size_t size() const {
    return anchors_.size();
  }
};
}  // namespace tos::auth
