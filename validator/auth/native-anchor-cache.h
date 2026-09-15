#pragma once
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "native-history.h"
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

struct ResolutionBudget {
  std::size_t coordinates = 64;  // the bound a declaration is already held to
  HistoryReadBudget reads{};
};

struct Resolution {
  std::size_t admitted = 0;                // newly held, or already held and agreeing
  std::vector<std::uint32_t> unavailable;  // this node cannot serve these yet
};

// Fills the cache with the anchors a deferred update declared.
//
// What anchor sits at a coordinate is decided by NativeFinalizedHistory and
// nothing else: it binds the coordinate through the parent state's own record
// of previous blocks, and requires the block served to be the one that record
// names. This adds no second opinion. It only carries an already authenticated
// answer across blocks, because collation cannot wait for an archive read.
//
// A coordinate this node cannot serve yet is reported, not refused -- the
// update was deferred precisely for naming history that had not been fetched.
// A block that is served but does not authenticate is refused outright: the
// cache is consulted instead of the archive afterwards, so a substitution
// admitted here would never be looked at again.
Result<Resolution> resolve_declared_history(std::span<const std::uint32_t> coordinates,
                                            td::Ref<vm::Cell> masterchain_state, const Anchor& head,
                                            const ChainContext&, NativeBlockReader, NativeAnchorCache&,
                                            ResolutionBudget = {});

// Which finalized blocks a resolution would have to read.
//
// A node has to fetch these before it can resolve anything, because fetching is
// asynchronous and resolution is not. The set is derived by asking the same
// authority that will later be asked for the anchors, so it cannot drift from
// what resolution actually wants; a separately written derivation would be a
// second reading of the parent state's record with nothing comparing the two.
//
// Coordinates that need no read at all -- the head, and anything already held
// -- are absent from the set rather than named in it.
Result<std::vector<tos::BlockIdExt>> required_finalized_blocks(std::span<const std::uint32_t> coordinates,
                                                               td::Ref<vm::Cell> masterchain_state, const Anchor& head,
                                                               const ChainContext&, const NativeAnchorCache& held,
                                                               ResolutionBudget = {});
}  // namespace tos::auth
