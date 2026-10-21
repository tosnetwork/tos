#pragma once

#include "metrics-collectors.h"

namespace tos::metrics {

struct ExtMessagePoolSnapshot {
  td::uint64 pending_ext_messages{0};
  td::uint64 check_ok{0};
  td::uint64 check_error{0};

  MetricSet collect() const {
    MetricSet result;
    result.families.push_back(MetricFamily::make_scalar("mempool_ext_messages", "gauge", pending_ext_messages));
    auto checks = MetricFamily{.name = "mempool_ext_check", .type = "counter", .help = std::nullopt, .metrics = {}};
    for (const auto &[label, value] : {std::pair{"ok", check_ok}, std::pair{"error", check_error}}) {
      checks.metrics.push_back(Metric{.suffix = "total", .label_set = {{{"result", label}}},
                                     .samples = {{.label_set = {}, .value = static_cast<double>(value)}}});
    }
    result.families.push_back(std::move(checks));
    return result;
  }
};

}  // namespace tos::metrics
