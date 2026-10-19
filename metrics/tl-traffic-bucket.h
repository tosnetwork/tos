#pragma once

#include <algorithm>
#include <map>
#include <optional>
#include <string>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/int_types.h"

#include "metrics-types.h"

namespace tos::metrics {
// Routing envelopes are unwrapped with bounded reads; malformed envelopes keep
// their own constructor. Unknown magics share one cell to prevent label growth.
td::int32 resolve_tl_magic(td::Slice payload);
std::optional<std::string> tl_schema_name(td::int32 magic);

class TlTrafficBucket {
 public:
  void account(td::Slice payload);
  void account(td::int32 magic, td::uint64 size);
  TlTrafficBucket &operator+=(const TlTrafficBucket &other);
  MetricSet collect(const std::string &direction) const;
  std::size_t label_capacity() const {
    std::size_t bound = 72;
    for (const auto &[_, cell] : cells_)
      bound = std::max(bound, cell.name.capacity() + 16);
    return bound;
  }
  std::size_t cells() const {
    return cells_.size();
  }

 private:
  struct Cell {
    std::string name;
    td::uint64 bytes = 0;
    td::uint64 messages = 0;
  };
  std::map<td::int32, Cell> cells_{{0, Cell{.name = "unknown"}}};
  static void add_saturated(td::uint64 &value, td::uint64 delta);
};
struct CollectionBudget;
td::Result<MetricSet> collect_traffic_with_budget(const TlTrafficBucket &in, const TlTrafficBucket &out,
                                                  std::size_t drains, CollectionBudget budget);
}  // namespace tos::metrics
