#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "validator/auth/native-anchor-cache.h"

namespace {
using tos::auth::NativeHistoryResolutionQueue;
using tos::auth::ResolutionBudget;

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
      {"pending-over-bound-drains-without-loss", [] {
         constexpr std::size_t limit = 3;
         NativeHistoryResolutionQueue queue(limit);
         expect(submit(queue, {100}).value() == std::vector<std::uint32_t>({100}));

         std::vector<std::uint32_t> submitted{1, 2, 3, 4, 5, 6, 7, 8};
         expect(!queue.submit(submitted).has_value());
         std::vector<std::uint32_t> returned;
         for (;;) {
           auto preview = queue.complete();
           if (!preview.has_value()) {
             break;
           }
           expect(!preview->empty());
           expect(preview->size() <= limit);
           returned.insert(returned.end(), preview->begin(), preview->end());

           auto started = queue.submit(preview.value());
           expect(started.has_value());
           expect(started->size() <= limit);
           expect(started.value() == preview.value());
         }
         std::sort(returned.begin(), returned.end());
         expect(returned == submitted);
         expect(queue.pending_size() == 0);
       }},
      {"active-batch-respects-bound", [] {
         constexpr std::size_t limit = 2;
         NativeHistoryResolutionQueue queue(limit);
         auto first = submit(queue, {1, 2, 3});
         expect(first.has_value());
         expect(first.value() == std::vector<std::uint32_t>({1, 2}));
         expect(first->size() <= limit);
         expect(queue.pending_size() == 1);

         // 2 is already in flight. It must not be queued again while 4 is new.
         expect(!submit(queue, {2, 4}).has_value());
         expect(queue.pending_size() == 2);
         auto preview = queue.complete();
         expect(preview.has_value());
         expect(preview.value() == std::vector<std::uint32_t>({3, 4}));
         expect(preview->size() <= limit);
       }},
      {"completion-preview-remains-pending", [] {
         NativeHistoryResolutionQueue queue(3);
         expect(submit(queue, {10}).has_value());
         expect(!submit(queue, {20, 30}).has_value());

         auto preview = queue.complete();
         expect(preview.has_value());
         expect(preview.value() == std::vector<std::uint32_t>({20, 30}));
         expect(queue.pending_size() == 2);

         // The caller deliberately drops the preview. An empty later submission
         // must still restart the work that complete() only previewed.
         const std::vector<std::uint32_t> empty;
         auto restarted = queue.submit(empty);
         expect(restarted.has_value());
         expect(restarted.value() == std::vector<std::uint32_t>({20, 30}));
         expect(queue.pending_size() == 0);
         expect(queue.active());
       }},
      {"default-bound-matches-resolver-budget", [] {
         NativeHistoryResolutionQueue queue;
         std::vector<std::uint32_t> coordinates;
         for (std::uint32_t value = 1; value <= 65; ++value) {
           coordinates.push_back(value);
         }
         auto first = queue.submit(coordinates);
         expect(first.has_value());
         expect(first->size() == 64);
         expect(queue.pending_size() == 1);

         ResolutionBudget budget;
         expect(budget.coordinates == 64);
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
