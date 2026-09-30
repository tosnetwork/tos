#pragma once

#include <cmath>
#include <ctime>
#include <optional>
#include <string>

#include "consensus-snapshot.h"
#include "chain-anchor-snapshot.h"
#include "node-state-snapshot.h"
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
  std::size_t publication_limit = max_bytes;
  std::optional<std::string> read(double now) const {
    if (!std::isfinite(now) || now < sampled_at || now - sampled_at > 30)
      return std::nullopt;
    std::string result;
    result.reserve(publication_limit);
    result.append(prefix);
    result.append(std::to_string(static_cast<std::uint64_t>(std::ceil((now - sampled_at) * 1000))));
    result.append(suffix);
    if (result.size() > publication_limit)
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
  const std::string &network() const { return network_; }
  const std::string &epoch() const {
    return epoch_;
  }
  std::optional<NativeCoreSnapshot> prepare(std::uint64_t generation, double sampled_at, double wall,
                                            const std::string &openmetrics, bool pq_enabled,
                                            const OperationSnapshot &sign, const OperationSnapshot &verify, bool v2 = false,
                                            const ConsensusPublication *consensus = nullptr, bool v3 = false) const {
    if ((v3 && !v2) || (v2 && consensus != nullptr && consensus->json.size() > 32 * 1024) ||
        (v2 && openmetrics.size() > 1048576) || openmetrics.size() > 2097152 || !configured() || generation == 0 || !std::isfinite(sampled_at) ||
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
    auto anchors = v3 ? chain_anchor_state.read() : std::nullopt;
    const auto wall_seconds = static_cast<std::uint64_t>(wall);
    constexpr char network_digits[] = "0123456789abcdef";
    auto network_matches = [&] {
      if (!anchors) return false;
      for (std::size_t i = 0; i < 32; ++i) {
        const auto byte = anchors->network_hash[i];
        if (network_[2 * i] != network_digits[byte >> 4] ||
            network_[2 * i + 1] != network_digits[byte & 15]) return false;
      }
      return true;
    };
    // The anchor stays attached while the publisher keeps refreshing it (the
    // validator manager re-observes it every second). A chain that stopped
    // advancing is still a fact: the sample carries the applied-advance clock,
    // and consumers derive the stall age from it. Dropping the anchor on a
    // stall would blind exactly the checks (fork, isolation, applied/served
    // gap) that must keep working during a halt.
    if (anchors && (anchors->observed_unix_seconds > wall_seconds + 1 ||
                    !network_matches() ||
                    anchors->applied_advanced_unix_seconds == 0 ||
                    anchors->applied_advanced_unix_seconds > anchors->observed_unix_seconds ||
                    anchors->key_block_unix_seconds > anchors->observed_unix_seconds ||
                    (wall_seconds > anchors->observed_unix_seconds &&
                     wall_seconds - anchors->observed_unix_seconds > 30))) anchors.reset();
    auto anchor_json = [&](const ChainAnchorSnapshot::Block &block, const char *point) {
      constexpr char digits[] = "0123456789abcdef";
      auto hex = [&](const std::array<std::uint8_t, 32> &bytes) {
        std::string out;
        out.reserve(64);
        for (auto byte : bytes) { out += digits[byte >> 4]; out += digits[byte & 15]; }
        return out;
      };
      return "{\"file_hash\":\"" + hex(block.file_hash) + "\",\"kind\":\"block\",\"network_id\":\"" + network_ +
             "\",\"point\":\"" + point + "\",\"root_hash\":\"" + hex(block.root_hash) +
             "\",\"scope_id\":\"masterchain\",\"seqno\":" + std::to_string(block.seqno) +
             ",\"shard\":\"9223372036854775808\",\"workchain\":-1}";
    };
    const auto chain = !anchors ? std::string("null") :
        "{\"applied\":" + anchor_json(anchors->applied, "applied") +
        ",\"applied_advanced_unix_seconds\":\"" + std::to_string(anchors->applied_advanced_unix_seconds) +
        "\",\"key_block\":" +
        (anchors->key_block_unix_seconds == 0 ? std::string("null") :
         "{\"seqno\":" + std::to_string(anchors->key_block_seqno) + ",\"unix_seconds\":\"" +
             std::to_string(anchors->key_block_unix_seconds) + "\"}") +
        ",\"observed_unix_seconds\":\"" + std::to_string(anchors->observed_unix_seconds) +
        "\",\"served\":" + (anchors->have_served ? anchor_json(anchors->served, "served") : std::string("null")) + "}";
    // Node state (duties, real queues, storage position) is attached while the
    // manager keeps refreshing it; storage needs a valid statvfs sample.
    std::string node_state_json = "null";
    bool have_node_state = false;
    if (v3) {
      const auto &ns = node_state;
      const auto ns_observed = ns.observed_unix_seconds.load(std::memory_order_acquire);
      if (ns_observed != 0 && ns_observed <= wall_seconds + 1 && wall_seconds - ns_observed <= 30 &&
          ns.storage_valid.load(std::memory_order_relaxed)) {
        have_node_state = true;
        auto u = [](std::uint64_t v) { return "\"" + std::to_string(v) + "\""; };
        auto queue = [&](const char *name, const NodeStateGauges::Queue &q) {
          return "{\"depth\":" + std::to_string(q.depth.load(std::memory_order_relaxed)) + ",\"oldest_age_ms\":" +
                 u(q.oldest_age_ms.load(std::memory_order_relaxed)) + ",\"queue\":\"" + name + "\"}";
        };
        node_state_json =
            "{\"duties\":{\"leader_windows\":{\"assigned\":" + u(ns.leader_windows_assigned.load(std::memory_order_relaxed)) +
            ",\"started\":" + u(consensus_stats.leader_windows_started.load(std::memory_order_relaxed)) +
            ",\"superseded\":" + u(ns.leader_windows_superseded.load(std::memory_order_relaxed)) +
            ",\"suppressed_behind\":" + u(ns.leader_windows_suppressed_behind.load(std::memory_order_relaxed)) +
            "},\"member\":" + (ns.validator_member.load(std::memory_order_relaxed) ? "true" : "false") +
            "},\"observed_unix_seconds\":" + u(ns_observed) +
            ",\"queues\":[" + queue("block_data_waiters", ns.block_data_waiters) + "," + queue("shard_client_waiters", ns.shard_client_waiters) +
            "," + queue("state_waiters", ns.state_waiters) + "]" +
            ",\"storage\":{\"db_free_bytes\":" + u(ns.db_free_bytes.load(std::memory_order_relaxed)) +
            ",\"db_total_bytes\":" + u(ns.db_total_bytes.load(std::memory_order_relaxed)) +
            ",\"gc_seqno\":" + std::to_string(ns.gc_seqno.load(std::memory_order_relaxed)) +
            ",\"persistent_state_seqno\":" + std::to_string(ns.persistent_state_seqno.load(std::memory_order_relaxed)) + "}}";
      }
    }
    // Keys are canonical lexical order; exact integers remain decimal strings.
    const auto payload = "{\"bytes\":" + std::to_string(openmetrics.size()) +
                         (v3 ? ",\"chain\":" + chain : std::string{}) +
                         (v2 ? ",\"consensus\":" + (consensus == nullptr ? std::string("null") : consensus->json) : std::string{}) +
                         ",\"generation\":\"" + g +
                         "\",\"kind\":\"native_core\",\"network_id\":\"" + network_ +
                         (v3 ? "\",\"node_state\":" + node_state_json + ",\"openmetrics_hash\":\"" : std::string("\",\"openmetrics_hash\":\"")) +
                         digest(openmetrics) + "\",\"pq_sign\":" + (pq_enabled ? sign.json() : "null") +
                         ",\"pq_verify\":" + (pq_enabled ? verify.json() : "null") + "}";
    // v3 is complete only while a fresh chain anchor sample is attached; the
    // unsupported duty/queue denominators stay listed as missing coverage.
    const bool complete = pq_enabled && sign.complete && verify.complete &&
                          (!v2 || (consensus != nullptr && consensus->complete)) &&
                          (!v3 || (anchors.has_value() && have_node_state));
    NativeCoreSnapshot result;
    result.sampled_at = sampled_at;
    result.publication_limit = v2 ? 64 * 1024 : NativeCoreSnapshot::max_bytes;
    result.prefix = "{\"schema_version\":1,\"source_id\":\"native_core\",\"node_id\":\"" + node_ +
                    "\",\"scope_id\":\"node\",\"process_epoch\":\"" + epoch_ + "\",\"source_epoch\":\"" + epoch_ +
                    "\",\"source_version\":\"" + (v3 ? "native-core-v3" : v2 ? "native-core-v2" : "native-core-v1") + "\",\"generation\":\"" + g +
                    "\",\"availability\":\"available\",\"observed_at\":\"" + timestamp + "\",\"last_success_at\":\"" +
                    timestamp + "\",\"received_at\":null,\"source_age_ms\":";
    // Coverage names exactly what this sample cannot speak about.
    std::string missing;
    if (!(v3 && anchors)) missing += "\"chain_anchors\",";
    if (!have_node_state) missing += "\"local_duties\",\"queue_state\",\"storage_state\",";
    if (!missing.empty()) missing.pop_back();
    result.suffix = std::string(",\"clock_quality\":\"valid\",\"coverage\":{\"status\":\"") +
                    (missing.empty() ? "complete" : "partial") + "\",\"missing_fields\":[" + missing +
                    "],\"gaps\":[],\"sampling_policy\":\"" +
                    (v3 ? "native-core-v3-chain-partial" : v2 ? "native-core-v2-concurrent-bounded" : "native_generation_approximate_pq") + "\"},\"content_hash\":\"" +
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
