#pragma once

#include <algorithm>
#include <map>
#include <optional>

#include "tos/tos-shard.h"

namespace tos::validator::fullnode {

// Overlay topology follows each workchain's monitoring depth. Selecting a
// transport route does not authorize execution or activate a workchain.
class FullNodeShardRouting {
 public:
  void clear() {
    depths_.clear();
  }
  void set_depth(WorkchainId workchain, int depth) {
    depths_[workchain] = depth;
  }
  int depth(WorkchainId workchain) const {
    auto it = depths_.find(workchain);
    return it == depths_.end() ? 0 : it->second;
  }
  ShardIdFull cut(ShardIdFull shard) const {
    auto limit = depth(shard.workchain);
    return shard.pfx_len() > limit ? shard_prefix(shard, limit) : shard;
  }

  template <typename Exists>
  std::optional<ShardIdFull> select(ShardIdFull shard, int requested_depth, Exists exists) const {
    if (shard.is_masterchain()) {
      return ShardIdFull{masterchainId};
    }
    int limit = std::max(0, std::min(depth(shard.workchain), requested_depth));
    if (shard.pfx_len() > limit) {
      shard = shard_prefix(shard, limit);
    }
    while (true) {
      if (exists(shard)) {
        return shard;
      }
      if (shard.pfx_len() == 0) {
        break;
      }
      shard = shard_parent(shard);
    }
    // Preserve the basechain startup fallback; foreign workchains must have
    // their own known overlay instead of silently using the masterchain.
    if (shard.workchain == basechainId) {
      return ShardIdFull{masterchainId};
    }
    return std::nullopt;
  }

 private:
  std::map<WorkchainId, int> depths_;
};

}  // namespace tos::validator::fullnode
