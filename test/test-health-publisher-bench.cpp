#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>

#include "metrics/core-registry.h"
#include "metrics/native-core-snapshot.h"
#include "td/utils/check.h"

int main() {
  using Clock = std::chrono::steady_clock;
  using Registry = tos::health::CoreRegistry;
  Registry registry(Registry::RegistrationProfile::TestOnly);
  for (std::size_t slot = 0; slot < Registry::max_slots; ++slot) {
    auto handle = registry.register_metric("tos_health_bench_counter_" + std::to_string(slot), Registry::Kind::Counter);
    CHECK(handle.valid() && registry.add(handle, slot));
  }

  tos::health::NativeCorePublisher publisher;
  CHECK(publisher.set_node("bench"));
  CHECK(publisher.set_network(std::string(64, 'b')));
  const tos::health::OperationSnapshot operations{1, 0, true};
  // The v3 anchor is an independent manager-produced event. A new exporter
  // generation must carry its full immutable identity without changing v1/v2.
  tos::health::ChainAnchorSnapshot anchors;
  anchors.network_hash.fill(0xbb);
  anchors.applied.file_hash.fill(0x12);
  anchors.applied.root_hash.fill(0x34);
  anchors.applied.seqno = 17;
  anchors.served.file_hash.fill(0x56);
  anchors.served.root_hash.fill(0x78);
  anchors.served.seqno = 16;
  anchors.have_served = true;
  anchors.applied_advanced_unix_seconds = 1699999999;
  anchors.observed_unix_seconds = 1700000000;
  tos::health::chain_anchor_state.publish(anchors);
  auto captured = tos::health::chain_anchor_state.read();
  CHECK(captured && captured->applied.seqno == 17 && captured->served.seqno == 16);
  tos::health::ConsensusPublication consensus{"{}", false};
  auto v3 = publisher.prepare(1, 1, 1700000000, "# EOF\n", true, operations, operations, true, &consensus, true);
  CHECK(v3);
  const auto v3_body = v3->read(1);
  CHECK(v3_body && v3_body->find("\"source_version\":\"native-core-v3\"") != std::string::npos);
  CHECK(v3_body->find("\"seqno\":17") != std::string::npos);
  CHECK(v3_body->find("\"seqno\":16") != std::string::npos);
  CHECK(v3_body->find("\"chain_anchors\"") == std::string::npos);
  CHECK(v3_body->find("\"instrumentation_complete\":false") != std::string::npos);
  auto stale_v3 = publisher.prepare(2, 2, 1700000032, "# EOF\n", true, operations, operations, true, &consensus, true);
  CHECK(stale_v3);
  const auto stale_body = stale_v3->read(2);
  CHECK(stale_body && stale_body->find("\"chain\":null") != std::string::npos);
  CHECK(stale_body->find("\"chain_anchors\"") != std::string::npos);
  tos::health::NativeCorePublisher other_network;
  CHECK(other_network.set_node("other"));
  CHECK(other_network.set_network(std::string(64, 'c')));
  auto mismatched = other_network.prepare(1, 1, 1700000000, "# EOF\n", true, operations, operations, true, &consensus, true);
  CHECK(mismatched);
  const auto mismatch_body = mismatched->read(1);
  CHECK(mismatch_body && mismatch_body->find("\"chain\":null") != std::string::npos);
  constexpr std::uint64_t iterations = 2000;
  std::uint64_t total_ns = 0;
  std::uint64_t max_ns = 0;
  std::size_t published_bytes = 0;
  for (std::uint64_t iteration = 1; iteration <= iterations; ++iteration) {
    const auto begin = Clock::now();
    auto body = registry.collect().render();
    body += "# EOF\n";
    auto snapshot =
        publisher.prepare(iteration, static_cast<double>(iteration), static_cast<double>(1700000000ULL + iteration),
                          body, true, operations, operations);
    const auto elapsed =
        static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - begin).count());
    CHECK(snapshot.has_value());
    total_ns += elapsed;
    max_ns = std::max(max_ns, elapsed);
    published_bytes = body.size();
  }
  std::cout << "{\"profile\":\"isolated_synthetic_c01\",\"iterations\":" << iterations
            << ",\"published_bytes\":" << published_bytes
            << ",\"mean_contiguous_work_us\":" << static_cast<double>(total_ns) / iterations / 1000.0
            << ",\"max_contiguous_work_us\":" << static_cast<double>(max_ns) / 1000.0
            << ",\"production_acceptance\":false}" << std::endl;
}
