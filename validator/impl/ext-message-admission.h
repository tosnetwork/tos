/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once
#include <cstddef>
#include <cstdint>

namespace tos::validator {

// How long a message may wait in front of the expensive admission check, and
// the most that may ever be waiting at once. Kept beside the rule that uses
// them so the bound and the arithmetic expressing it cannot drift apart.
inline constexpr double max_admission_queue_delay = 5.0;
inline constexpr std::size_t max_admission_waiters_ceiling = 50000;

// The queue a pool completing `completions_per_second` checks may admit.
//
// The length is the delay's own statement: however many checks finish in
// `max_admission_queue_delay` at the rate this pool is actually achieving.
// There is deliberately no lower bound in entries. A constant floor is a count
// under a cap derived from a delay, and a count cannot honour a delay: it
// departs from it exactly as the node slows, which is the condition the bound
// exists for. A floor of 512 made a queue nominally sized for five seconds
// imply ten seconds at fifty completions a second, and over eight minutes at
// one.
//
// Nothing is lost at start-up, which is the only thing such a floor could have
// been for. The rate this is called with begins at an optimistic estimate
// rather than at zero, so the first window is bounded by that estimate and not
// by having measured nothing yet.
//
// A pool completing nothing admits no queue. That is the honest reading of the
// same rule rather than a new refusal: the checks already in flight still run
// and still release their slots, and a sender told "not ready" at once is
// better served than one left waiting for a delay nobody bounded.
// The completion rate after a measurement window closes.
//
// A window with nothing in it means two different things, and only the caller
// knows which. A pool nobody is sending to completes nothing because there is
// no work: that window has measured nothing, and folding it in as zero would
// shrink the queue it can offer the next burst for want of traffic rather than
// for want of capacity. A pool that is saturated -- every check slot occupied
// for the whole window -- and still completes nothing has measured its
// throughput, and the throughput is zero.
//
// The second case is the one that matters, and it is the one production is in:
// the cap is consulted only while the pool is full. Keeping an older, higher
// estimate there means promising five seconds of a throughput that is no longer
// being observed, and promising it to a queue in front of checks that are not
// finishing. So a saturated empty window is not smoothed: there is nothing to
// smooth, the measurement is zero, and one window with work in it brings the
// estimate straight back.
//
// The idle branch is not reached from production today. It is here so the
// answer stays right if that ever changes rather than depending on a call site
// nobody restated, and it is exercised directly.
//
// A window far shorter or longer than one is not a measurement either way: too
// short to have measured anything, or long enough that the pool was idle for
// most of it.
inline double updated_completion_rate(double previous, std::uint64_t completions, double window_seconds,
                                      bool saturated) {
  if (!(window_seconds >= 1.0) || window_seconds > 10.0) {
    return previous;
  }
  if (completions == 0) {
    return saturated ? 0.0 : previous;
  }
  return 0.5 * previous + 0.5 * static_cast<double>(completions) / window_seconds;
}

inline std::size_t admission_cap(double completions_per_second) {
  // Written as a refusal of everything that is not a positive rate, so that a
  // rate which is zero, negative or not a number all answer the same way
  // rather than one of them multiplying into a ceiling-sized queue.
  if (!(completions_per_second > 0)) {
    return 0;
  }
  const double cap = completions_per_second * max_admission_queue_delay;
  if (!(cap < static_cast<double>(max_admission_waiters_ceiling))) {
    return max_admission_waiters_ceiling;
  }
  return static_cast<std::size_t>(cap);
}

}  // namespace tos::validator
