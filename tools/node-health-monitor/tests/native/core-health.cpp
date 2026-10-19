#include <cassert>
#include <thread>

#include "metrics/core-health.h"
int main() {
  tos::health::OperationStats stats;
  stats.observe(1000, true);
  stats.observe(1001, false);
  assert(stats.completed.load() == 1 && stats.failed.load() == 1);
  assert(stats.buckets[0][0].load() == 1);
  assert(stats.buckets[1][1].load() == 1);
  assert(stats.sum_us[0].load() == 1000);
  stats.observe(6000000, true);
  assert(stats.buckets[0][12].load() == 1);
  tos::health::enabled.store(false);
  {
    tos::health::OperationTimer timer(stats);
    timer.finish(true);
  }
  assert(stats.completed.load() == 2);
  tos::health::enabled.store(true);
  {
    tos::health::OperationTimer timer(stats);
    timer.finish(true);
    timer.finish(true);
  }
  assert(stats.completed.load() == 3);
  {
    tos::health::OperationTimer timer(stats);
  }
  assert(stats.failed.load() == 2);
  std::thread a([&] {
    for (int i = 0; i < 10000; ++i)
      stats.observe(5, true);
  });
  std::thread b([&] {
    for (int i = 0; i < 10000; ++i)
      stats.observe(5, true);
  });
  a.join();
  b.join();
  assert(stats.completed.load() == 20003);
  stats.completed.store(UINT64_MAX);
  stats.observe(1, true);
  assert(!stats.complete.load());
}
