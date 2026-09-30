/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <sys/wait.h>
#include <unistd.h>

#include "validator/measurement/c09-raw-monotonic.h"

using tos::validator::measurement::c09::Capture;
using tos::validator::measurement::c09::Counters;
using tos::validator::measurement::c09::Outcome;
using tos::validator::measurement::c09::Point;
using tos::validator::measurement::c09::Record;
using tos::validator::measurement::c09::Stage;
using tos::validator::measurement::c09::clock_domain;
using tos::validator::measurement::c09::max_duration_ns;
using tos::validator::measurement::c09::detail::checked_raw_ns;

int main() {
  constexpr auto max = std::numeric_limits<std::int64_t>::max();
  constexpr auto billion = 1000000000LL;
  std::int64_t converted = 0;
  const timespec limit{static_cast<time_t>(max / billion), static_cast<long>(max % billion)};
  if (!checked_raw_ns(limit, converted) || converted != max) return 14;
  const timespec overflow{limit.tv_sec, limit.tv_nsec + 1};
  if (checked_raw_ns(overflow, converted)) return 15;
  const timespec next_second{limit.tv_sec + 1, 0};
  if (checked_raw_ns(next_second, converted)) return 16;

  Capture<1> clean;
  Point clean_start;
  std::array<Record, 1> clean_rows{};
  Counters clean_counts{};
  std::size_t clean_size = 0;
  if (!clean.ready() || !clean.start(Stage::vote_sign, clean_start) ||
      !clean.finish(clean_start, Outcome::ok) ||
      !clean.snapshot(clean_rows, clean_size, clean_counts) || clean_size != 1 ||
      !clean_counts.complete || clean_counts.dropped_full != 0 || clean_counts.dropped_contention != 0) return 17;

  Capture<2> capture;
  if (!capture.ready() || sizeof(Capture<1024>) > 128 * 1024) return 1;
  Point first;
  if (!capture.start(Stage::vote_sign, first)) return 2;
  if (!capture.finish(first, Outcome::ok)) return 3;

  // All four refusals must reach the actual native finish path.
  Point wrong_process = first;
  wrong_process.pid += 1;
  if (capture.finish(wrong_process, Outcome::ok)) return 4;
  Point wrong_nonce = first;
  wrong_nonce.process_nonce ^= 1;
  if (capture.finish(wrong_nonce, Outcome::ok)) return 5;
  Point wrong_domain = first;
  wrong_domain.domain = clock_domain + 1;
  if (capture.finish(wrong_domain, Outcome::ok)) return 6;
  Point future = first;
  future.monotonic_ns += static_cast<std::int64_t>(max_duration_ns + 1);
  if (capture.finish(future, Outcome::ok)) return 7;

  // A child inherits memory but is a different process even with the same
  // nonce, start point and clock name.
  const pid_t child = fork();
  if (child < 0) return 8;
  if (child == 0) _exit(capture.finish(first, Outcome::ok) ? 1 : 0);
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 9;

  Point second;
  Point third;
  if (!capture.start(Stage::vote_intent_commit, second) || !capture.start(Stage::storage_ack, third)) return 10;
  if (!capture.finish(second, Outcome::error)) return 11;
  if (capture.finish(third, Outcome::ok)) return 12;
  std::array<Record, 2> rows{};
  Counters counts{};
  std::size_t size = 0;
  if (!capture.snapshot(rows, size, counts) || size != 2 || counts.retained != 2 ||
      counts.dropped_full != 1 || counts.rejected_identity != 3 || counts.rejected_time != 1 ||
      counts.complete || rows[0].start.pid != getpid() || rows[0].start.domain != clock_domain ||
      rows[0].duration_ns > max_duration_ns) return 13;
  std::cout << "C09_NATIVE_RAW_OK retained=" << counts.retained << " full=" << counts.dropped_full
            << " identity=" << counts.rejected_identity << " time=" << counts.rejected_time
            << " complete=" << counts.complete << " resident_bytes=" << sizeof(Capture<1024>) << '\n';
  return 0;
}
