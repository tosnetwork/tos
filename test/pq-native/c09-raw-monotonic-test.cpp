/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cstdint>
#include <iostream>
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

int main() {
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
      !counts.complete || rows[0].start.pid != getpid() || rows[0].start.domain != clock_domain ||
      rows[0].duration_ns > max_duration_ns) return 13;
  std::cout << "C09_NATIVE_RAW_OK retained=" << counts.retained << " full=" << counts.dropped_full
            << " identity=" << counts.rejected_identity << " time=" << counts.rejected_time
            << " resident_bytes=" << sizeof(Capture<1024>) << '\n';
  return 0;
}
