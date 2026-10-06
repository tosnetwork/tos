/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "validator/consensus/validator-cleanup.h"

// Driver of validator consensus-DB cleanup. The durable store is the only backlog:
// every retired session's record stays there until its directory is confirmed gone,
// and cleanup reads it with a cursor scan driven by a fixed-period tick. In memory
// there is only
//   (a) runtime retirements whose close is not yet confirmed (bounded by the groups
//       the node runs; empty after a restart, since nothing is open then),
//   (b) operations in flight -- reserved, deleting or erasing -- at most kMaxInFlight,
//   (c) the live sessions' incarnation tokens, the scan cursor and the running pass.
// It has NO actor/DB dependencies, so it is unit-testable and can be driven through
// every ordering deterministically; it must be confined to the owner's actor thread.
//
// Every tick (begin_tick) runs at most one pass, and none while a pass is still
// running or kMaxInFlight operations are in flight. A pass reads one page of at most
// kPageSize records strictly after the cursor (on_page), runs the deletion gate on
// each record whose session is in neither (a), (b) nor live, and picks up to
// kDispatchBudget eligible records. Each pick is re-read by its key
// (on_point_read_result) and reserved only if the durable record still equals the page
// copy, so a copy that a later retirement or an erase made stale is never acted on.
// The cursor moves past the last record examined; if the dispatch budget stopped the
// pass, the next tick starts at the first record it did not examine. A page that
// reaches the end of the store wraps the cursor, and the scan cycles forever: nothing
// pauses it and no event schedules it. Errors need no special handling: a failed page
// read leaves the cursor where it was for the next tick; a failed point read skips its
// candidate, which the next cycle sees again; a failed delete releases its
// reservation, and the next cycle sees the record again. The tick period is the only
// retry pacing.
//
// Invariants (each covered by a test):
//   - No durable record is lost: this class never erases a record itself; a record is
//     erased only after its directory was confirmed gone (on_delete_completed).
//   - A live or not-yet-close-confirmed session is never reserved.
//   - An erased record is never re-admitted: the point read finds it gone.
//   - Progress: the cursor only moves forward within a cycle. A record that becomes
//     eligible is examined within ceil(N / kPageSize) ticks, plus one tick per
//     kDispatchBudget eligible records reserved ahead of it, plus every tick skipped at
//     the in-flight cap, where N is the number of keys the cycle reads -- the store at
//     the start of the cycle plus every key inserted ahead of the cursor during it.
//     This assumes page reads eventually succeed, passes finish, and in-flight
//     capacity frees: unlimited insertion ahead of the cursor can extend a cycle
//     without limit, and a permanently unreadable page blocks progress through it.
//   - Memory is O(open retirements + live groups + kMaxInFlight), independent of the
//     size of the backlog.
namespace tos::validator::consensus {

// A record reserved for deletion. The caller threads BOTH tokens back through
// completion: `generation` and `attempt_id` identify this specific delete attempt, so
// a stale or duplicate completion from an earlier attempt is rejected.
struct ReservedValidatorDelete {
  PendingValidatorConsensusDbCleanup record;
  uint64_t generation = 0;
  uint64_t attempt_id = 0;
};

// A request for the next page of durable records: read at most `max_keys` keys
// strictly after `after_key` and hand the result back with the same `token`.
struct ValidatorCleanupPageRequest {
  std::string after_key;
  size_t max_keys = 0;
  uint64_t token = 0;
};

// The deletion-gate inputs for one pass, all bound to one durable GC snapshot.
struct ValidatorCleanupOracles {
  BlockIdExt gc;
  CleanupAncestorOfGcFn ancestor_or_equal_of_gc;
  GcShardCatchainSeqnoFn gc_shard_catchain_seqno;
  CleanupSessionIsLiveFn is_live;
};

struct ValidatorCleanupPassSummary {
  size_t examined = 0;
  size_t reserved = 0;
  bool wrapped = false;
  bool page_failed = false;   // the page read failed: nothing examined, cursor unchanged
  bool point_failed = false;  // a point read failed: that candidate waits for the next cycle
};

class ValidatorCleanupManager {
 public:
  static constexpr size_t kPageSize = 256;
  static constexpr size_t kDispatchBudget = 16;
  static constexpr size_t kMaxInFlight = 64;
  // The tick period: one pass at most per tick, and the pacing of every retry.
  static constexpr double kTickSeconds = 10.0;
  using CleanupExaminedFn = std::function<void(const ValidatorSessionId&, bool /*eligible*/)>;

  // A group (initial creation or reopen) for `session` is about to be created. The
  // caller MUST first check !is_delete_in_flight(session) and defer creation while a
  // delete is in flight. Assigns a process-wide strictly increasing incarnation token,
  // retained only while the session is live. A retirement still awaiting its close
  // is superseded by the new incarnation.
  void on_group_created(const ValidatorSessionId& session) {
    live_generation_[session] = ++next_generation_;
    open_retirements_.erase(session);
  }

  // The current incarnation of `session` retired; its durable record is persisted
  // before the actor is allowed to close. Releases the live token and returns it so
  // the caller can tag the close callback; until that close is confirmed the session
  // is never reserved. A session whose delete is in flight cannot be retired (creation
  // is fenced), so that case keeps the operation intact and reports its generation.
  uint64_t on_group_retired(const PendingValidatorConsensusDbCleanup& record) {
    auto session = record.session_id;
    if (auto it = in_flight_.find(session); it != in_flight_.end()) {
      return it->second.generation;
    }
    uint64_t gen;
    if (auto it = live_generation_.find(session); it != live_generation_.end()) {
      gen = it->second;
      live_generation_.erase(it);
    } else {
      gen = ++next_generation_;
    }
    open_retirements_[session] = gen;
    return gen;
  }

  // The retiring actor confirmed its bus stopped and DB closed. Accepted only for the
  // generation it was retired at, so a stale ack from an older incarnation is ignored.
  void on_close_confirmed(const ValidatorSessionId& session, uint64_t generation) {
    auto it = open_retirements_.find(session);
    if (it != open_retirements_.end() && it->second == generation) {
      open_retirements_.erase(it);
    }
  }

  // True from reservation until the durable erase is acknowledged; the group-creation
  // path must defer creating a group for the session that whole time.
  bool is_delete_in_flight(const ValidatorSessionId& session) const {
    return in_flight_.count(session) > 0;
  }

  // A tick at the durable GC block `gc`: the page to read, or nothing when this tick is
  // skipped because a pass is still running or in-flight capacity is exhausted.
  std::optional<ValidatorCleanupPageRequest> begin_tick(const BlockIdExt& gc) {
    if (pass_.active || in_flight_.size() >= kMaxInFlight) {
      return std::nullopt;
    }
    pass_ = Pass{};
    pass_.active = true;
    pass_.token = ++next_token_;
    pass_.gc = gc;
    return ValidatorCleanupPageRequest{cursor_, kPageSize, pass_.token};
  }

  // Whether `token` is the running pass. A page result for any other token -- success
  // or failure -- must be dropped before it is looked at.
  bool is_current_pass(uint64_t token) const {
    return pass_.active && token == pass_.token && !pass_.page_examined;
  }

  // The page read of the running pass `token` failed: the pass ends having examined
  // nothing, with the cursor unchanged. A stale token changes nothing.
  std::optional<ValidatorCleanupPassSummary> abort_pass(uint64_t token) {
    if (!is_current_pass(token)) {
      return std::nullopt;
    }
    pass_ = Pass{};
    ValidatorCleanupPassSummary summary;
    summary.page_failed = true;
    return summary;
  }

  // The page read for `request`. Runs the deletion gate on every record not held by
  // (a), (b) or a live group and returns up to kDispatchBudget eligible records (fewer
  // when in-flight capacity is short) to confirm with a point read each. The cursor
  // moves past every record examined; an eligible record beyond the budget is not
  // examined, so the next tick starts there.
  std::vector<PendingValidatorConsensusDbCleanup> on_page(const ValidatorCleanupPageRequest& request,
                                                          const ValidatorCleanupPage& page,
                                                          const ValidatorCleanupOracles& oracles,
                                                          const CleanupExaminedFn& on_examined = {}) {
    std::vector<PendingValidatorConsensusDbCleanup> candidates;
    if (!is_current_pass(request.token)) {
      return candidates;
    }
    size_t capacity = kMaxInFlight > in_flight_.size() ? kMaxInFlight - in_flight_.size() : 0;
    size_t room = std::min(kDispatchBudget, capacity);
    auto closed = [](const ValidatorSessionId&) { return true; };  // open retirements are held below
    bool stopped = false;
    for (const auto& record : page.records) {
      auto session = record.session_id;
      bool held = held_in_memory(session);
      bool eligible = !held && validator_cleanup_eligible(record, oracles.gc, oracles.ancestor_or_equal_of_gc,
                                                          oracles.gc_shard_catchain_seqno, oracles.is_live, closed);
      if (eligible && candidates.size() == room) {
        stopped = true;
        break;
      }
      cursor_ = validator_cleanup_key(session);
      ++pass_.examined;
      if (on_examined) {
        on_examined(session, eligible);
      }
      if (eligible) {
        candidates.push_back(record);
      }
    }
    if (!stopped) {
      if (!page.last_key.empty()) {
        cursor_ = std::max(cursor_, page.last_key);  // also past trailing malformed keys
      }
      pass_.wrapped = page.reached_end;
    }
    pass_.unverified = candidates.size();
    pass_.page_examined = true;
    return candidates;
  }

  // The point read of one candidate of the pass `token`: its durable record now
  // (nothing if gone), or a read error. A callback for another pass changes nothing.
  // Reserves the delete only if the record is unchanged since the page read and the
  // session is still not held. A read error is not absence: the candidate is not
  // reserved, and the next cycle examines it again.
  std::optional<ReservedValidatorDelete> on_point_read_result(
      uint64_t token, const PendingValidatorConsensusDbCleanup& candidate,
      const td::Result<std::optional<PendingValidatorConsensusDbCleanup>>& current,
      const CleanupSessionIsLiveFn& is_live) {
    if (!pass_.active || token != pass_.token || !pass_.page_examined || pass_.unverified == 0) {
      return std::nullopt;
    }
    --pass_.unverified;
    if (current.is_error()) {
      pass_.point_failed = true;
      return std::nullopt;
    }
    auto session = candidate.session_id;
    const auto& record = current.ok();
    if (!record || !(*record == candidate)) {
      return std::nullopt;  // erased or superseded since the page read; the next cycle sees the new value
    }
    if (held_in_memory(session) || is_live(session) || in_flight_.size() >= kMaxInFlight) {
      return std::nullopt;
    }
    auto attempt = ++next_attempt_;
    in_flight_[session] = InFlight{candidate, 0, attempt, InFlightState::Deleting};
    ++pass_.reserved;
    return ReservedValidatorDelete{candidate, 0, attempt};
  }

  // The running pass has examined its page and every candidate has had its point read.
  bool pass_verified() const {
    return pass_.active && pass_.page_examined && pass_.unverified == 0;
  }

  // Finish the running pass (once pass_verified) and return its outcome; a pass that
  // reached the end of the store wraps the cursor.
  ValidatorCleanupPassSummary end_pass() {
    ValidatorCleanupPassSummary summary{pass_.examined, pass_.reserved, pass_.wrapped, false, pass_.point_failed};
    if (pass_.active && pass_.wrapped) {
      cursor_.clear();
      ++completed_cycles_;
    }
    pass_ = Pass{};
    return summary;
  }

  // A dispatched delete ATTEMPT finished. Must be called only when the attempt truly
  // finished, never on a timeout. Rejected unless it matches the in-flight attempt.
  // On confirmed removal the entry moves to Erasing and the durable erase is
  // dispatched; the reservation is held until the erase is acknowledged. On failure
  // the reservation is released and the record, still durable, is seen again by the
  // next cycle.
  void on_delete_completed(const ValidatorSessionId& session, uint64_t generation, uint64_t attempt_id,
                           bool confirmed_gone,
                           const std::function<void(const ValidatorSessionId&, uint64_t, uint64_t)>&
                               dispatch_durable_erase) {
    auto it = in_flight_.find(session);
    if (it == in_flight_.end() || it->second.generation != generation || it->second.attempt_id != attempt_id ||
        it->second.state != InFlightState::Deleting) {
      return;
    }
    if (confirmed_gone) {
      it->second.state = InFlightState::Erasing;
      dispatch_durable_erase(session, generation, attempt_id);
    } else {
      in_flight_.erase(it);
    }
  }

  // The durable erase for the attempt committed: release the reservation.
  void on_erase_acknowledged(const ValidatorSessionId& session, uint64_t generation, uint64_t attempt_id) {
    auto it = in_flight_.find(session);
    if (it == in_flight_.end() || it->second.generation != generation || it->second.attempt_id != attempt_id ||
        it->second.state != InFlightState::Erasing) {
      return;
    }
    in_flight_.erase(it);
  }

  // No full cycle has completed yet in this process.
  bool in_first_scan() const {
    return completed_cycles_ == 0;
  }
  uint64_t completed_cycles() const {
    return completed_cycles_;
  }
  bool pass_running() const {
    return pass_.active;
  }
  size_t in_flight_count() const {
    return in_flight_.size();
  }
  size_t open_retirement_count() const {
    return open_retirements_.size();
  }
  size_t live_session_count() const {
    return live_generation_.size();
  }
  const std::string& cursor() const {
    return cursor_;
  }

 private:
  bool held_in_memory(const ValidatorSessionId& session) const {
    return in_flight_.count(session) > 0 || open_retirements_.count(session) > 0 || live_generation_.count(session) > 0;
  }

  enum class InFlightState { Deleting, Erasing };
  struct InFlight {
    PendingValidatorConsensusDbCleanup record;
    uint64_t generation = 0;
    uint64_t attempt_id = 0;
    InFlightState state = InFlightState::Deleting;
  };
  struct Pass {
    bool active = false;
    uint64_t token = 0;
    BlockIdExt gc;
    bool page_examined = false;
    size_t unverified = 0;
    size_t examined = 0;
    size_t reserved = 0;
    bool wrapped = false;
    bool point_failed = false;
  };

  // (a) runtime retirements awaiting their close: session -> retired generation.
  std::map<ValidatorSessionId, uint64_t> open_retirements_;
  // (b) reserved, deleting or erasing.
  std::map<ValidatorSessionId, InFlight> in_flight_;
  // Incarnation token of each currently-live session.
  std::map<ValidatorSessionId, uint64_t> live_generation_;
  uint64_t next_generation_ = 0;
  uint64_t next_attempt_ = 0;
  uint64_t next_token_ = 0;

  // (c) the cursor is the last key examined; empty means the start.
  std::string cursor_;
  Pass pass_;
  uint64_t completed_cycles_ = 0;
};

}  // namespace tos::validator::consensus
