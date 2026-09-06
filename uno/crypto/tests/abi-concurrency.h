#pragma once

#include <array>
#include <condition_variable>
#include <mutex>
#include <thread>

// Release real ABI callers together. Each worker owns its request/output while
// immutable proof buffers may be shared. Distinct bool elements are not packed.
template <class F>
bool concurrent_abi_calls(F&& operation) {
  constexpr std::size_t workers = 8;
  std::mutex mutex;
  std::condition_variable ready;
  std::size_t arrived = 0;
  std::array<bool, workers> results{};
  std::array<std::thread, workers> threads;
  for (std::size_t index = 0; index < workers; ++index) {
    threads[index] = std::thread([&, index] {
      {
        std::unique_lock<std::mutex> lock(mutex);
        ++arrived;
        if (arrived == workers) ready.notify_all();
        ready.wait(lock, [&] { return arrived == workers; });
      }
      results[index] = operation(index);
    });
  }
  for (auto& thread : threads) thread.join();
  for (bool result : results) if (!result) return false;
  return true;
}
