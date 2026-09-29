#pragma once

#include <cmath>
#include <ctime>
#include <optional>
#include <string>

#include "td/utils/Random.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"

namespace tos::health {
inline bool node_alias(const std::string &value) {
  if (value.empty() || value.size() > 64 || value[0] < 'a' || value[0] > 'z')
    return false;
  for (auto c : value) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
      return false;
  }
  return true;
}
inline bool network_hash(const std::string &value) {
  if (value.size() != 64)
    return false;
  for (auto c : value)
    if (!((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')))
      return false;
  return true;
}
inline std::string network_identity(td::Slice root_hash) {
  if (root_hash.size() != 32)
    return {};
  return td::hex_encode(root_hash);
}
inline std::string digest(const std::string &body) {
  return td::hex_encode(td::sha256(body));
}
struct OperationSnapshot {
  std::uint64_t succeeded = 0;
  std::uint64_t failed = 0;
  bool complete = false;
  std::string json() const {
    return std::string("{\"complete\":") + (complete ? "true" : "false") + ",\"failed\":\"" + std::to_string(failed) +
           "\",\"succeeded\":\"" + std::to_string(succeeded) + "\"}";
  }
};
struct NativeCoreSnapshot {
  static constexpr size_t max_bytes = 256 * 1024;
  std::string prefix;
  std::string suffix;
  double sampled_at = 0;
  std::optional<std::string> read(double now) const {
    if (!std::isfinite(now) || now < sampled_at || now - sampled_at > 30)
      return std::nullopt;
    auto result = prefix + std::to_string(static_cast<std::uint64_t>(std::ceil((now - sampled_at) * 1000))) + suffix;
    if (result.size() > max_bytes)
      return std::nullopt;
    return result;
  }
};
class NativeCorePublisher {
 public:
  NativeCorePublisher() {
    std::string bytes(16, '\0');
    td::Random::secure_bytes(td::MutableSlice(bytes));
    epoch_ = td::hex_encode(bytes);
  }
  bool set_node(std::string value) {
    if (!node_alias(value) || (!node_.empty() && node_ != value))
      return false;
    node_ = std::move(value);
    return true;
  }
  bool set_network(std::string value) {
    if (!network_hash(value) || (!network_.empty() && network_ != value))
      return false;
    network_ = std::move(value);
    return true;
  }
  bool configured() const {
    return !node_.empty() && !network_.empty();
  }
  const std::string &epoch() const {
    return epoch_;
  }
  std::optional<NativeCoreSnapshot> prepare(std::uint64_t generation, double sampled_at, double wall,
                                            const std::string &openmetrics, bool pq_enabled,
                                            const OperationSnapshot &sign, const OperationSnapshot &verify) const {
    if (openmetrics.size() > 2097152 || !configured() || generation == 0 || !std::isfinite(sampled_at) ||
        !std::isfinite(wall) || wall < 0 || wall > 4102444800.)
      return std::nullopt;
    std::time_t seconds = static_cast<std::time_t>(wall);
    std::tm utc{};
#ifdef _WIN32
    if (gmtime_s(&utc, &seconds) != 0)
      return std::nullopt;
#else
    if (gmtime_r(&seconds, &utc) == nullptr)
      return std::nullopt;
#endif
    char timestamp[32];
    if (std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0)
      return std::nullopt;
    const auto g = std::to_string(generation);
    // Keys are canonical lexical order; exact integers remain decimal strings.
    const auto payload = "{\"bytes\":" + std::to_string(openmetrics.size()) + ",\"generation\":\"" + g +
                         "\",\"kind\":\"native_core\",\"network_id\":\"" + network_ + "\",\"openmetrics_hash\":\"" +
                         digest(openmetrics) + "\",\"pq_sign\":" + (pq_enabled ? sign.json() : "null") +
                         ",\"pq_verify\":" + (pq_enabled ? verify.json() : "null") + "}";
    const bool complete = pq_enabled && sign.complete && verify.complete;
    NativeCoreSnapshot result;
    result.sampled_at = sampled_at;
    result.prefix = "{\"schema_version\":1,\"source_id\":\"native_core\",\"node_id\":\"" + node_ +
                    "\",\"scope_id\":\"node\",\"process_epoch\":\"" + epoch_ + "\",\"source_epoch\":\"" + epoch_ +
                    "\",\"source_version\":\"native-core-v1\",\"generation\":\"" + g +
                    "\",\"availability\":\"available\",\"observed_at\":\"" + timestamp + "\",\"last_success_at\":\"" +
                    timestamp + "\",\"received_at\":null,\"source_age_ms\":";
    result.suffix = std::string(
                        ",\"clock_quality\":\"valid\",\"coverage\":{\"status\":\"partial\",\"missing_fields\":[\"chain_"
                        "anchors\",\"local_duties\",\"queue_state\",\"storage_state\"],\"gaps\":[],\"sampling_policy\":"
                        "\"native_generation_approximate_pq\"},\"content_hash\":\"") +
                    digest(payload) + "\",\"payload\":" + payload +
                    ",\"quality\":{\"instrumentation_complete\":" + (complete ? "true" : "false") +
                    ",\"producer_dropped\":\"0\",\"relay_dropped\":\"0\",\"parse_errors\":\"0\",\"shed_reason\":" +
                    (pq_enabled ? "null" : "\"pq_instrumentation_disabled\"") + "}}";
    if (!result.read(sampled_at))
      return std::nullopt;
    return result;
  }

 private:
  std::string node_;
  std::string network_;
  std::string epoch_;
};
}  // namespace tos::health
