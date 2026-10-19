#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "metrics-types.h"
#include "node-state-snapshot.h"

namespace tos::health {
// Masterchain progress for alerting: how old the last masterchain block and
// the applied state (shard client) are, and how many network attempts to
// fetch block data have failed, and how the full node's refusal-answer budget
// has been spent. The ages are derived here from the block
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
  const auto masterchain_unix = gauges.masterchain_block_unix_seconds.load(std::memory_order_relaxed);
  const auto shard_client_unix = gauges.shard_client_unix_seconds.load(std::memory_order_relaxed);
  age("_masterchain_head_age_seconds", masterchain_unix,
      "Seconds since the generation time of the last masterchain block this node accepted.");
  age("_shard_client_age_seconds", shard_client_unix,
      "Seconds since the generation time of the masterchain block whose state this node has applied.");
  // A node that knows the masterchain head but has no applied state has no
  // shard-client age to alert on; this says so explicitly.
  if (masterchain_unix != 0) {
    families.push_back(metrics::MetricFamily::make_scalar(
        prefix + "_shard_client_state_known", "gauge", shard_client_unix != 0 ? 1 : 0,
        "1 when the applied state (shard client) is known, 0 while the masterchain head is known but it is not."));
  }
  families.push_back(metrics::MetricFamily::make_scalar(
      prefix + "_wait_block_data_net_failures_total", "counter",
      static_cast<double>(gauges.block_data_net_failures.load(std::memory_order_relaxed)),
      "Failed network attempts to fetch block data, for any reason."));
  families.push_back(metrics::MetricFamily::make_scalar(
      prefix + "_full_node_refusal_answers_total", "counter",
      static_cast<double>(gauges.refusal_answers.answered.load(std::memory_order_relaxed)),
      "Queries refused for capacity that the full node decided to answer within its refusal-answer budget; "
      "counted when the answer is handed to the transport, not on delivery."));
  families.push_back(metrics::MetricFamily::make_scalar(
      prefix + "_full_node_refusal_answers_suppressed_total", "counter",
      static_cast<double>(gauges.refusal_answers.suppressed.load(std::memory_order_relaxed)),
      "Queries refused for capacity, of a type that has an answer, left unanswered because the refusal-answer "
      "budget was spent."));
  return families;
}
}  // namespace tos::health
