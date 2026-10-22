#pragma once

#include <array>

#include "metrics-collectors.h"

namespace tos::metrics {

// Fixed label domains from the external-message collation observations.
struct ExtMessageCollationSnapshot {
  std::array<std::array<td::uint64, 4>, 4> outcomes{};
  void add(bool master, bool ok, td::uint32 total, td::uint32 filtered, td::uint32 included,
           td::uint32 skipped_backpressure) {
    auto &cell = outcomes[(master ? 0 : 2) + (ok ? 0 : 1)];
    cell[0] += filtered;
    cell[1] += skipped_backpressure;
    cell[2] += included;
    const auto accounted = static_cast<td::uint64>(filtered) + skipped_backpressure + included;
    cell[3] += total > accounted ? total - accounted : 0;
  }
  MetricSet collect() const {
    MetricFamily family{.name = "collation_ext_messages", .type = "counter", .help = std::nullopt, .metrics = {}};
    constexpr std::array names{"filtered", "skipped_backpressure", "included", "rejected"};
    for (size_t cell = 0; cell < outcomes.size(); ++cell) {
      for (size_t outcome = 0; outcome < names.size(); ++outcome) {
        family.metrics.push_back(
            Metric{.suffix = "total",
                   .label_set = {{{"chain", cell < 2 ? "master" : "shard"},
                                  {"result", cell % 2 == 0 ? "ok" : "error"},
                                  {"outcome", names[outcome]}}},
                   .samples = {{.label_set = {}, .value = static_cast<double>(outcomes[cell][outcome])}}});
      }
    }
    return MetricSet{{std::move(family)}};
  }
};

}  // namespace tos::metrics
