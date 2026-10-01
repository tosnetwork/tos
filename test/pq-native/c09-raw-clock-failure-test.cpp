/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <iostream>
#include <time.h>

#include "validator/measurement/c09-raw-monotonic.h"

using tos::validator::measurement::c09::Capture;
using tos::validator::measurement::c09::Counters;
using tos::validator::measurement::c09::Outcome;
using tos::validator::measurement::c09::Point;
using tos::validator::measurement::c09::Record;
using tos::validator::measurement::c09::Stage;

namespace {
std::atomic<bool> fail_next_clock{false};
}

extern "C" int __real_clock_gettime(clockid_t, timespec*);
extern "C" int __wrap_clock_gettime(clockid_t domain, timespec* result) {
  if (fail_next_clock.exchange(false)) {
    errno = EIO;
    return -1;
  }
  return __real_clock_gettime(domain, result);
}

int main() {
  Capture<1> start_failure;
  if (!start_failure.ready())
    return 1;
  Point point;
  fail_next_clock.store(true);
  if (start_failure.start(Stage::vote_sign, point))
    return 2;
  std::array<Record, 1> records{};
  std::size_t count = 0;
  Counters start_counts{};
  if (!start_failure.snapshot(records, count, start_counts) || count != 0 || start_counts.clock_error != 1 ||
      start_counts.complete)
    return 3;

  Capture<1> finish_failure;
  if (!finish_failure.ready() || !finish_failure.start(Stage::vote_sign, point))
    return 4;
  fail_next_clock.store(true);
  if (finish_failure.finish(point, Outcome::ok))
    return 5;
  Counters finish_counts{};
  if (!finish_failure.snapshot(records, count, finish_counts) || count != 0 || finish_counts.started != 1 ||
      finish_counts.clock_error != 1 || finish_counts.complete)
    return 6;
  std::cout << "C09_NATIVE_CLOCK_FAILURE_OK start_error=" << start_counts.clock_error
            << " finish_error=" << finish_counts.clock_error << " complete=" << finish_counts.complete << '\n';
  return 0;
}
