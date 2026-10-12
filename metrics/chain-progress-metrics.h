#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "metrics-types.h"
#include "node-state-snapshot.h"

namespace tos::health {
// Masterchain progress for alerting: how old the last masterchain block and
// the applied state (shard client) are, and how many network attempts to
// fetch block data have failed. The ages are derived here from the block
// times the validator manager publishes, against the collection's own wall
// clock, so they keep growing while the manager is stuck. An age whose block
// time is not known yet is left out rather than reported as zero, and a block
// time ahead of the wall clock reads as age zero.
inline std::vector<metrics::MetricFamily> chain_progress_families(const std::string &prefix, double wall,
                                                                  const NodeStateGauges &gauges = node_state) {
  std::vector<metrics::MetricFamily> families;
  auto age = [&](const std::string &name, std::uint64_t at, const char *help) {
    if (at == 0) {
      return;
    }
    const double value = wall - static_cast<double>(at);
    families.push_back(metrics::MetricFamily::make_scalar(prefix + name, "gauge", value > 0 ? value : 0, help));
  };
  age("_masterchain_head_age_seconds", gauges.masterchain_block_unix_seconds.load(std::memory_order_relaxed),
      "Seconds since the generation time of the last masterchain block this node accepted.");
  age("_shard_client_age_seconds", gauges.shard_client_unix_seconds.load(std::memory_order_relaxed),
      "Seconds since the generation time of the masterchain block whose state this node has applied.");
  families.push_back(metrics::MetricFamily::make_scalar(
      prefix + "_wait_block_data_net_failures_total", "counter",
      static_cast<double>(gauges.block_data_net_failures.load(std::memory_order_relaxed)),
      "Failed network attempts to fetch block data, for any reason."));
  return families;
}
}  // namespace tos::health
