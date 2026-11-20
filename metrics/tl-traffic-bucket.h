#pragma once

#include <algorithm>
#include <array>
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

// Upper bounds, in seconds, of the delivery delay histogram. A broadcast carries its
// origin time in whole seconds, so nothing finer than one second can be told apart.
inline constexpr std::array<double, 7> kBroadcastDelayBuckets = {1, 2, 4, 8, 15, 30, 60};

class TlTrafficBucket {
 public:
  void account(td::Slice payload);
  void account(td::int32 magic, td::uint64 size);
  // Time from the origin's timestamp on a broadcast to its delivery here. Only
  // broadcasts received from other nodes are observed.
  void account_delay(td::Slice payload, double seconds);
  void account_delay(td::int32 magic, double seconds);
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
  // Cells that carry a delay histogram, each of which renders its own series.
  std::size_t delay_cells() const {
    return static_cast<std::size_t>(
        std::count_if(cells_.begin(), cells_.end(), [](const auto &item) { return item.second.delay_count != 0; }));
  }

 private:
  struct Cell {
    std::string name;
    td::uint64 bytes = 0;
    td::uint64 messages = 0;
    std::array<td::uint64, kBroadcastDelayBuckets.size() + 1> delay_buckets{};
    double delay_sum = 0;
    td::uint64 delay_count = 0;
  };
  std::map<td::int32, Cell> cells_{{0, Cell{.name = "unknown"}}};
  Cell &cell(td::int32 magic);
  static void add_saturated(td::uint64 &value, td::uint64 delta);
};
struct CollectionBudget;
td::Result<MetricSet> collect_traffic_with_budget(const TlTrafficBucket &in, const TlTrafficBucket &out,
                                                  std::size_t drains, CollectionBudget budget);
}  // namespace tos::metrics
