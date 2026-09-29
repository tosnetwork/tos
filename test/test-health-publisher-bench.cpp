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
