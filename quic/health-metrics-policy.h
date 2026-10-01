#pragma once

namespace tos::quic::health_metrics_policy {

// C01 publishes summary-only QUIC metrics. This compile-time false reaches the
// server before it constructs the per-connection map and reaches the sender
// before it constructs per-path labels. Enabling detail requires a later cost
// gate and a new reviewed profile.
inline constexpr bool build_per_path = false;

}  // namespace tos::quic::health_metrics_policy
