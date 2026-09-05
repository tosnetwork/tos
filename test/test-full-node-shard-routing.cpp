#include <set>

#include "td/utils/tests.h"
#include "validator/full-node-shard-routing.h"

using namespace tos;
using namespace tos::validator::fullnode;

TEST(FullNodeShardRouting, ForeignWorkchainAndIsolation) {
  FullNodeShardRouting routing;
  routing.set_depth(basechainId, 3);
  routing.set_depth(2, 0);
  std::set<ShardIdFull> overlays{ShardIdFull{masterchainId}, ShardIdFull{basechainId}, ShardIdFull{2}};
  auto exists = [&](ShardIdFull shard) { return overlays.contains(shard); };
  auto selected = routing.select(ShardIdFull{2}, 0, exists);
  ASSERT_TRUE(selected.has_value());
  ASSERT_TRUE(*selected == ShardIdFull{2});
  ASSERT_TRUE(!routing.select(ShardIdFull{3}, 0, exists).has_value());
  overlays.erase(ShardIdFull{2});
  ASSERT_TRUE(!routing.select(ShardIdFull{2}, 0, exists).has_value());
  overlays.clear();
  ASSERT_TRUE(routing.select(ShardIdFull{basechainId}, 0, exists).value() == ShardIdFull{masterchainId});
  ASSERT_TRUE(routing.select(ShardIdFull{masterchainId}, 0, exists).value() == ShardIdFull{masterchainId});
}

TEST(FullNodeShardRouting, IndependentDepthAndHistoricalParents) {
  FullNodeShardRouting routing;
  routing.set_depth(basechainId, 1);
  routing.set_depth(2, 3);
  const ShardIdFull deep{2, 0x0800000000000000ULL};
  ASSERT_EQ(deep.pfx_len(), 4);
  auto cut = routing.cut(deep);
  ASSERT_EQ(cut.pfx_len(), 3);
  ASSERT_EQ(cut.workchain, 2);
  ASSERT_EQ(routing.cut(ShardIdFull{basechainId, deep.shard}).pfx_len(), 1);
  std::set<ShardIdFull> overlays{ShardIdFull{2}, shard_parent(cut), cut};
  auto exists = [&](ShardIdFull shard) { return overlays.contains(shard); };
  ASSERT_TRUE(routing.select(deep, 3, exists).value() == cut);
  ASSERT_TRUE(routing.select(deep, 0, exists).value() == ShardIdFull{2});
  overlays.erase(cut);
  ASSERT_TRUE(routing.select(deep, 3, exists).value() == shard_parent(cut));
  routing.clear();
  routing.set_depth(2, 0);
  ASSERT_EQ(routing.depth(basechainId), 0);
  ASSERT_TRUE(routing.cut(deep) == ShardIdFull{2});
  ASSERT_TRUE(routing.select(deep, 3, exists).value() == ShardIdFull{2});
}
