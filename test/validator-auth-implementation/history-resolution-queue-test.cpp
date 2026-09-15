#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "validator/auth/native-anchor-cache.h"

namespace {
using tos::auth::NativeHistoryResolutionQueue;

struct Case {
  const char* name;
  std::function<void()> run;
};

void expect(bool condition) {
  if (!condition) {
    throw std::runtime_error("assertion");
  }
}

std::optional<std::vector<std::uint32_t>> submit(NativeHistoryResolutionQueue& queue,
                                                 std::initializer_list<std::uint32_t> coordinates) {
  std::vector<std::uint32_t> values(coordinates);
  return queue.submit(values);
}

std::vector<Case> cases() {
  return {
      {"idle-request-starts-resolution", [] {
         NativeHistoryResolutionQueue queue;
         auto batch = submit(queue, {40, 30, 40});
         expect(batch.has_value());
         expect(batch.value() == std::vector<std::uint32_t>({30, 40}));
         expect(queue.active());
         expect(queue.pending_size() == 0);
       }},
      {"busy-request-is-retained", [] {
         NativeHistoryResolutionQueue queue;
         expect(submit(queue, {10}).has_value());
         expect(!submit(queue, {20}).has_value());
         expect(queue.active());
         expect(queue.pending_size() == 1);
       }},
      {"active-duplicates-do-not-requeue", [] {
         NativeHistoryResolutionQueue queue;
         expect(submit(queue, {10, 20}).has_value());
         expect(!submit(queue, {20, 20}).has_value());
         expect(queue.pending_size() == 0);
       }},
      {"pending-duplicates-coalesce", [] {
         NativeHistoryResolutionQueue queue;
         expect(submit(queue, {10}).has_value());
         expect(!submit(queue, {30, 20, 30, 20}).has_value());
         expect(queue.pending_size() == 2);
         auto next = queue.complete();
         expect(next.has_value());
         expect(next.value() == std::vector<std::uint32_t>({20, 30}));
       }},
      {"completion-drains-pending", [] {
         NativeHistoryResolutionQueue queue;
         expect(submit(queue, {10}).has_value());
         expect(!submit(queue, {30, 20}).has_value());
         auto next = queue.complete();
         expect(next.has_value());
         expect(next.value() == std::vector<std::uint32_t>({20, 30}));
       }},
      {"drained-batch-starts-next-resolution", [] {
         NativeHistoryResolutionQueue queue;
         expect(submit(queue, {10}).has_value());
         expect(!submit(queue, {20}).has_value());
         auto next = queue.complete();
         expect(next.has_value());
         auto started = queue.submit(next.value());
         expect(started.has_value());
         expect(started.value() == std::vector<std::uint32_t>({20}));
         expect(queue.active());
         expect(queue.pending_size() == 0);
       }},
      {"completion-clears-inflight", [] {
         NativeHistoryResolutionQueue queue;
         expect(submit(queue, {10}).has_value());
         expect(!queue.complete().has_value());
         expect(!queue.active());
         expect(submit(queue, {20}).has_value());
       }},
      {"empty-completion-does-not-loop", [] {
         NativeHistoryResolutionQueue queue;
         expect(submit(queue, {10}).has_value());
         expect(!queue.complete().has_value());
         expect(!queue.complete().has_value());
         expect(!queue.active());
         expect(queue.pending_size() == 0);
       }},
  };
}
}  // namespace

int main(int argc, char** argv) {
  const auto inventory = cases();
  if (argc == 2 && std::string(argv[1]) == "--list") {
    for (const auto& item : inventory) {
      std::cout << item.name << '\n';
    }
    return 0;
  }

  const std::string selected = argc == 2 ? argv[1] : "";
  std::size_t passed = 0;
  for (const auto& item : inventory) {
    if (!selected.empty() && selected != item.name) {
      continue;
    }
    std::cout << "SETUP_OK " << item.name << '\n' << std::flush;
    try {
      item.run();
    } catch (...) {
      std::cerr << "ASSERTION_FAILED " << item.name << '\n';
      return 1;
    }
    ++passed;
    std::cout << "CASE_PASS " << item.name << '\n';
  }
  if (!selected.empty() && passed != 1) {
    std::cerr << "UNKNOWN_CASE " << selected << '\n';
    return 2;
  }
  std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
  return 0;
}
