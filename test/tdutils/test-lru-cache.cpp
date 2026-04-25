#include "td/utils/LRUCache.h"
#include "td/utils/tests.h"

namespace td {
namespace {

TEST(LRUCache, EmptyReflectsContents) {
  LRUCache<int, int> cache(8);
  EXPECT(cache.empty());

  cache.put(1, 10);
  EXPECT(!cache.empty());

  cache.clear();
  EXPECT(cache.empty());

  cache.put(2, 20);
  cache.erase(2);
  EXPECT(cache.empty());
}

}  // namespace
}  // namespace td
