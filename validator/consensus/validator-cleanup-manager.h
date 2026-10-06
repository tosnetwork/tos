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

// Stateful driver of validator consensus-DB cleanup. The durable store is the only
// backlog: every retired session's record stays there until its directory is
// confirmed gone, and cleanup reads it with a stateless cursor scan. In memory there
// is only
//   (a) runtime retirements whose close is not yet confirmed (bounded by the groups
//       the node runs; empty after a restart, since nothing is open then),
//   (b) operations in flight -- reserved, deleting or erasing -- at most kMaxInFlight,
//   (c) the live sessions' incarnation tokens, the scan cursor, and the scheduler.
// It has NO actor/DB dependencies, so it is unit-testable and can be driven through
// every ordering deterministically; it must be confined to the owner's actor thread.
//
// A pass reads one page of at most kPageSize records strictly after the cursor
// (begin_pass / on_page), runs the deletion gate on each record whose session is in
// neither (a), (b) nor live, and picks up to kDispatchBudget eligible records. Each
// pick is re-read by its key (on_point_read_result) and reserved only if the durable
// record still equals the page copy, so a copy that a later retirement or an erase
// made stale is never acted on. The cursor moves past the last record examined; if
// the dispatch budget stopped the pass, the next pass starts at the first record it
// did not examine. A page that reaches the end of the store wraps the cursor.
//
// Scheduling has one authority, this class, and one state:
//   Idle     nothing scheduled; a trigger (kick) may schedule a pass.
//   Queued   exactly one continuation message is pending.
//   Running  a pass is in flight.
//   Backoff  exactly one retry timer is pending; triggers do not shorten it.
//   Paused   a clean sweep finished at the recorded GC block; a trigger resumes only
//            when the GC block or the event count changed, or a failed delete is due.
// Every scheduled callback carries the scheduler generation and is accepted only if
// that generation is current and the state still expects it; disabling and every
// transition that schedules something bump the generation, so a stale callback
// changes nothing. After a pass (schedule_after_pass):
//   - a failed page read (or no GC snapshot) backs off with the cursor unchanged and
//     retries at the same cursor;
//   - a sweep still mid-way continues at once if there is in-flight capacity, and
//     otherwise waits Idle for a delete completion to free some;
//   - a wrapped sweep with a failed point read, or with a failed delete since it began,
//     backs off and then rescans from the start (the failed records are behind it);
//   - a wrapped clean sweep starts another at once if a retirement, close or reopen
//     happened since it began (a record behind the cursor may have become eligible),
//     and otherwise pauses. Deletions still in flight never cause another sweep.
// The backoff is 1, 2, 4 ... 64 seconds over consecutive failures and resets only
// after an entirely error-free sweep: no failed page or point read, and every delete it
// reserved completed without failure.
//
// Invariants (each covered by a test):
//   - No durable record is lost: this class never erases a record itself; a record is
//     erased only after its directory was confirmed gone (on_delete_completed).
//   - A live or not-yet-close-confirmed session is never reserved.
//   - An erased record is never re-admitted: the point read finds it gone.
//   - Progress: retirements never move the cursor back, so with the GC block fixed a
//     full sweep takes at most ceil(N / kPageSize) passes (one more when N is a
//     multiple of it) plus one pass per kDispatchBudget eligible records it reserves,
//     where N is the number of keys the sweep reads: the backlog at the start of the
//     sweep PLUS every key inserted ahead of the cursor while it runs. It is therefore
//     not a bound in the backlog size alone: unlimited churn ahead of the cursor can
//     lengthen a sweep without limit. Passes of an unfinished sweep follow each other
//     without waiting for an external trigger.
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
  bool page_failed = false;   // the page read failed (or no GC snapshot): nothing examined
  bool point_failed = false;  // a point read failed: that candidate is left for a later sweep
};

// What the owner must schedule: nothing, one continuation message, or one timer. The
// callback must hand `generation` back to accept_scheduled.
struct ValidatorCleanupScheduleAction {
  enum class Kind { None, Queue, Timer };
  Kind kind = Kind::None;
  uint64_t generation = 0;
  double delay_seconds = 0;
};

class ValidatorCleanupManager {
 public:
  static constexpr size_t kPageSize = 256;
  static constexpr size_t kDispatchBudget = 16;
  static constexpr size_t kMaxInFlight = 64;
  static constexpr uint64_t kMaxBackoffShift = 6;  // 2^6 = 64 seconds
  using CleanupExaminedFn = std::function<void(const ValidatorSessionId&, bool /*eligible*/)>;
  enum class SchedState { Idle, Queued, Running, Backoff, Paused };

  // A group (initial creation or reopen) for `session` is about to be created. The
  // caller MUST first check !is_delete_in_flight(session) and defer creation while a
  // delete is in flight. Assigns a process-wide strictly increasing incarnation token,
  // retained only while the session is live. A retirement still awaiting its close
  // is superseded by the new incarnation.
  void on_group_created(const ValidatorSessionId& session) {
    live_generation_[session] = ++next_generation_;
    open_retirements_.erase(session);
    ++event_seq_;
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
    ++event_seq_;
    return gen;
  }

  // The retiring actor confirmed its bus stopped and DB closed. Accepted only for the
  // generation it was retired at, so a stale ack from an older incarnation is ignored.
  void on_close_confirmed(const ValidatorSessionId& session, uint64_t generation) {
    auto it = open_retirements_.find(session);
    if (it != open_retirements_.end() && it->second == generation) {
      open_retirements_.erase(it);
      ++event_seq_;
    }
  }

  // True from reservation until the durable erase is acknowledged; the group-creation
  // path must defer creating a group for the session that whole time.
  bool is_delete_in_flight(const ValidatorSessionId& session) const {
    return in_flight_.count(session) > 0;
  }

  // ---- scheduler -------------------------------------------------------------------

  // A trigger (GC advance, close, erase ack, delete completion, start-up) at the
  // durable GC block `gc`. Returns what to schedule, if anything.
  ValidatorCleanupScheduleAction kick(const BlockIdExt& gc) {
    switch (sched_) {
      case SchedState::Queued:
      case SchedState::Running:
      case SchedState::Backoff:
        return {};  // already decided; the demand is seen when the pass ends
      case SchedState::Paused:
        if (error_pending_) {
          return enter_backoff();  // a failed delete after the pause: retry after a backoff
        }
        if (paused_gc_ && *paused_gc_ == gc && paused_event_seq_ == event_seq_) {
          return {};
        }
        sched_ = SchedState::Idle;
        return from_idle();
      case SchedState::Idle:
        return from_idle();
    }
    return {};
  }

  // A scheduled callback (continuation message or timer) with its generation. Accepted
  // only if the generation is current and the state still expects it; then the owner
  // must run a pass (begin_pass) and the state is Running.
  bool accept_scheduled(uint64_t generation) {
    if (generation != sched_gen_ || (sched_ != SchedState::Queued && sched_ != SchedState::Backoff)) {
      return false;
    }
    sched_ = SchedState::Running;
    return true;
  }

  // Cleanup was disabled: supersede every scheduled callback and any running pass.
  void disable() {
    ++sched_gen_;
    sched_ = SchedState::Idle;
    pass_ = Pass{};
  }

  // ---- one pass ----------------------------------------------------------------------

  // Start a pass at the durable GC block `gc`: the page to read, or nothing when a pass
  // is already running. A pass at an empty cursor starts a new sweep.
  std::optional<ValidatorCleanupPageRequest> begin_pass(const BlockIdExt& gc) {
    if (pass_.active) {
      return std::nullopt;
    }
    if (cursor_.empty()) {
      ++sweep_id_;
      sweep_start_event_seq_ = event_seq_;
      sweep_error_ = false;
      error_pending_ = false;  // this sweep retries everything a failure left behind
    }
    pass_ = Pass{};
    pass_.active = true;
    pass_.token = ++next_token_;
    pass_.gc = gc;
    return ValidatorCleanupPageRequest{cursor_, kPageSize, pass_.token};
  }

  // The page read for `request`. Runs the deletion gate on every record not held by
  // (a), (b) or a live group and returns up to kDispatchBudget eligible records (fewer
  // when in-flight capacity is short) to confirm with a point read each. The cursor
  // moves past every record examined; an eligible record beyond the budget is not
  // examined, so the next pass starts there.
  std::vector<PendingValidatorConsensusDbCleanup> on_page(const ValidatorCleanupPageRequest& request,
                                                          const ValidatorCleanupPage& page,
                                                          const ValidatorCleanupOracles& oracles,
                                                          const CleanupExaminedFn& on_examined = {}) {
    std::vector<PendingValidatorConsensusDbCleanup> candidates;
    if (!pass_.active || request.token != pass_.token || pass_.page_examined) {
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
  // session is still not held. A read error is not absence: the candidate is left for
  // a later sweep, which this sweep's error outcome forces.
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
      return std::nullopt;  // erased or superseded since the page read; the next sweep sees the new value
    }
    if (held_in_memory(session) || is_live(session) || in_flight_.size() >= kMaxInFlight) {
      return std::nullopt;
    }
    auto attempt = ++next_attempt_;
    in_flight_[session] = InFlight{candidate, 0, attempt, InFlightState::Deleting, sweep_id_};
    ++pass_.reserved;
    return ReservedValidatorDelete{candidate, 0, attempt};
  }

  // The running pass has examined its page and every candidate has had its point read.
  bool pass_verified() const {
    return pass_.active && pass_.page_examined && pass_.unverified == 0;
  }

  // Finish the running pass and return its outcome; a pass that reached the end of the
  // store wraps the cursor. Must be followed by schedule_after_pass.
  ValidatorCleanupPassSummary end_pass() {
    ValidatorCleanupPassSummary summary{pass_.examined, pass_.reserved, pass_.wrapped, false, pass_.point_failed};
    if (pass_.active && pass_.wrapped) {
      cursor_.clear();
      ++completed_sweeps_;
    }
    pass_ = Pass{};
    return summary;
  }

  // The page read failed, or there was no GC snapshot: the pass ends having examined
  // nothing, with the cursor unchanged. Must be followed by schedule_after_pass.
  ValidatorCleanupPassSummary abort_pass() {
    pass_ = Pass{};
    ValidatorCleanupPassSummary summary;
    summary.page_failed = true;
    return summary;
  }

  // Decide what follows a pass (see the class comment).
  ValidatorCleanupScheduleAction schedule_after_pass(const ValidatorCleanupPassSummary& summary, const BlockIdExt& gc) {
    if (sched_ != SchedState::Running) {
      return {};  // superseded (disabled) while the pass ran
    }
    if (summary.page_failed) {
      return enter_backoff();  // retry at the same cursor
    }
    if (summary.point_failed) {
      sweep_error_ = true;
    }
    if (!summary.wrapped) {
      sched_ = SchedState::Idle;
      return from_idle();  // continue the sweep if there is capacity
    }
    if (sweep_error_ || error_pending_) {
      sweep_error_ = false;
      error_pending_ = true;  // rescan from the start once the backoff ends
      return enter_backoff();
    }
    // An error-free sweep resets the backoff -- once its own deletions have all
    // completed without failure (a failure of one of them makes it not error-free).
    reset_candidate_sweep_ = sweep_id_;
    try_reset_backoff();
    if (event_seq_ != sweep_start_event_seq_) {
      sched_ = SchedState::Idle;
      return from_idle();  // something happened during the sweep: sweep again
    }
    sched_ = SchedState::Paused;
    paused_gc_ = gc;
    paused_event_seq_ = event_seq_;
    return {};
  }

  // ---- delete completion -------------------------------------------------------------

  // A dispatched delete ATTEMPT finished. Must be called only when the attempt truly
  // finished, never on a timeout. Rejected unless it matches the in-flight attempt.
  // On confirmed removal the entry moves to Erasing and the durable erase is
  // dispatched; the reservation is held until the erase is acknowledged. On failure
  // the reservation is released and the record, still durable, is retried by a sweep
  // after a backoff (it is behind the cursor). The caller then kicks: the freed
  // capacity may resume an unfinished sweep.
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
      if (reset_candidate_sweep_ && *reset_candidate_sweep_ == it->second.sweep) {
        reset_candidate_sweep_.reset();  // that sweep was not error-free after all
      }
      in_flight_.erase(it);
      error_pending_ = true;
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
    try_reset_backoff();
  }

  // ---- observers ---------------------------------------------------------------------

  // No full sweep has completed yet in this process.
  bool in_first_scan() const {
    return completed_sweeps_ == 0;
  }
  SchedState schedule_state() const {
    return sched_;
  }
  bool paused() const {
    return sched_ == SchedState::Paused;
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

  // From Idle: at capacity stay Idle (a delete completion kicks again); an unresolved
  // error at an empty cursor backs off; otherwise run a pass (continuing the sweep, or
  // starting one).
  ValidatorCleanupScheduleAction from_idle() {
    if (in_flight_.size() >= kMaxInFlight) {
      return {};
    }
    if (cursor_.empty() && error_pending_) {
      return enter_backoff();
    }
    ++sched_gen_;
    sched_ = SchedState::Queued;
    return ValidatorCleanupScheduleAction{ValidatorCleanupScheduleAction::Kind::Queue, sched_gen_, 0};
  }

  // Reset the backoff once the candidate error-free sweep has no deletion in flight.
  void try_reset_backoff() {
    if (!reset_candidate_sweep_) {
      return;
    }
    for (const auto& [session, op] : in_flight_) {
      if (op.sweep == *reset_candidate_sweep_) {
        return;
      }
    }
    consecutive_failures_ = 0;
    reset_candidate_sweep_.reset();
  }

  ValidatorCleanupScheduleAction enter_backoff() {
    auto shift = std::min<uint64_t>(consecutive_failures_, kMaxBackoffShift);
    ++consecutive_failures_;
    ++sched_gen_;
    sched_ = SchedState::Backoff;
    return ValidatorCleanupScheduleAction{ValidatorCleanupScheduleAction::Kind::Timer, sched_gen_,
                                          static_cast<double>(uint64_t{1} << shift)};
  }

  enum class InFlightState { Deleting, Erasing };
  struct InFlight {
    PendingValidatorConsensusDbCleanup record;
    uint64_t generation = 0;
    uint64_t attempt_id = 0;
    InFlightState state = InFlightState::Deleting;
    uint64_t sweep = 0;  // the sweep that reserved it
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

  // (c) scan: the cursor is the last key examined; empty means the start.
  std::string cursor_;
  Pass pass_;
  uint64_t completed_sweeps_ = 0;
  // Retirements, closes and reopens so far, and the count when the sweep began.
  uint64_t event_seq_ = 0;
  uint64_t sweep_start_event_seq_ = 0;
  // A point read failed in the current sweep.
  bool sweep_error_ = false;
  // A failed point read or delete left records that need a rescan after a backoff.
  bool error_pending_ = false;

  // Scheduler.
  SchedState sched_ = SchedState::Idle;
  uint64_t sched_gen_ = 0;
  uint64_t consecutive_failures_ = 0;
  // Sweeps started so far, and the error-free sweep whose deletions must all succeed
  // before the backoff resets.
  uint64_t sweep_id_ = 0;
  std::optional<uint64_t> reset_candidate_sweep_;
  std::optional<BlockIdExt> paused_gc_;
  uint64_t paused_event_seq_ = 0;
};

}  // namespace tos::validator::consensus
