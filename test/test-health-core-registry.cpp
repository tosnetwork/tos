#include <atomic>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include "metrics/core-registry.h"
#include "td/utils/check.h"

int main() {
  using Registry = tos::health::CoreRegistry;
  CHECK(Registry::max_update_attempts == 8);
  Registry production;
  CHECK(!production.register_metric("tos_health_unapproved_total", Registry::Kind::Counter).valid());
  CHECK(!production.complete() && production.dropped_updates() == 1);
  Registry registry(Registry::RegistrationProfile::TestOnly);
  auto counter = registry.register_metric("tos_health_test_operations_total", Registry::Kind::Counter);
  auto gauge = registry.register_metric("tos_health_test_active", Registry::Kind::Gauge);
  CHECK(counter.valid() && gauge.valid());
  CHECK(registry.add(counter, 7));
  {
    auto owner = registry.acquire_gauge(gauge);
    CHECK(owner.valid());
    CHECK(owner.set(3));
    CHECK(!registry.acquire_gauge(gauge).valid());
    auto live = registry.collect().render();
    CHECK(live.find("tos_health_test_operations_total 7.000000\n") != std::string::npos);
    CHECK(live.find("tos_health_test_active 3.000000\n") != std::string::npos);
  }
  auto cleared = registry.collect().render();
  CHECK(cleared.find("tos_health_test_operations_total 7.000000\n") != std::string::npos);
  CHECK(cleared.find("tos_health_test_active 0.000000\n") != std::string::npos);

  CHECK(registry.add(counter, std::numeric_limits<std::uint64_t>::max() - 7));
  CHECK(!registry.add(counter));
  CHECK(!registry.complete());
  CHECK(registry.dropped_updates() >= 2);  // active gauge collision plus saturation

  Registry full(Registry::RegistrationProfile::TestOnly);
  for (std::size_t i = 0; i < Registry::max_slots; ++i) {
    CHECK(full.register_metric("tos_health_slot_" + std::to_string(i), Registry::Kind::Counter).valid());
  }
  CHECK(full.registered() == Registry::max_slots);
  CHECK(!full.register_metric("tos_health_overflow", Registry::Kind::Counter).valid());
  CHECK(!full.add({}));  // no sink is visible but never blocks business work
  CHECK(!full.complete());
  CHECK(full.dropped_updates() == 2);
  CHECK(full.collect().render().find("tos_health_core_registry_instrumentation_complete 0.000000\n") !=
        std::string::npos);

  Registry contended(Registry::RegistrationProfile::TestOnly);
  auto contested = contended.register_metric("tos_health_contended_total", Registry::Kind::Counter);
  constexpr std::size_t threads = 32;
  constexpr std::size_t updates = 20000;
  std::atomic<std::uint64_t> successful{0};
  std::atomic<bool> start{false};
  std::vector<std::thread> workers;
  workers.reserve(threads);
  for (std::size_t thread = 0; thread < threads; ++thread) {
    workers.emplace_back([&] {
      while (!start.load(std::memory_order_acquire)) {
      }
      for (std::size_t update = 0; update < updates; ++update) {
        if (contended.add(contested))
          successful.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  start.store(true, std::memory_order_release);
  for (auto &worker : workers)
    worker.join();
  const auto failed = threads * updates - successful.load();
  CHECK(contended.dropped_updates() == failed ||
        contended.dropped_updates() == std::numeric_limits<std::uint64_t>::max());
  CHECK(contended.complete() == (failed == 0));
  const auto body = contended.collect().render();
  const auto key = std::string("\ntos_health_contended_total ");
  const auto position = body.find(key);
  CHECK(position != std::string::npos);
  CHECK(std::stod(body.substr(position + key.size())) == static_cast<double>(successful.load()));
}
