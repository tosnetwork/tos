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

#include "validator/consensus/validator-cleanup.h"

// Stateful driver of validator consensus-DB cleanup. The durable store is the only
// backlog: every retired session's record stays there until its directory is
// confirmed gone, and cleanup reads it with a stateless cursor scan. In memory there
// is only
//   (a) runtime retirements whose close is not yet confirmed (bounded by the groups
//       the node runs; empty after a restart, since nothing is open then),
//   (b) operations in flight -- reserved, deleting or erasing -- at most kMaxInFlight,
//   (c) the live sessions' incarnation tokens, and the scan cursor and its bookkeeping.
// It has NO actor/DB dependencies, so it is unit-testable and can be driven through
// every ordering deterministically; it must be confined to the owner's actor thread.
//
// A pass reads one page of at most kPageSize records strictly after the cursor
// (begin_pass / on_page), runs the deletion gate on each record whose session is in
// neither (a), (b) nor live, and picks up to kDispatchBudget eligible records. Each
// pick is re-read by its key (on_point_read) and reserved only if the durable record
// still equals the page copy, so a copy that a later retirement or an erase made stale
// is never acted on. The cursor moves past the last record examined; if the dispatch
// budget stopped the pass, the next pass starts at the first record it did not
// examine. A page that reaches the end of the store wraps the cursor to the start.
// A full scan that reserved nothing, with nothing in flight and no retirement, close,
// failed delete or GC move since it began, pauses scanning until the GC block moves
// or one of those events happens.
//
// Invariants (each covered by a test):
//   - No durable record is lost: this class never erases a record itself; a record is
//     erased only after its directory was confirmed gone (on_delete_completed).
//   - A live or not-yet-close-confirmed session is never reserved.
//   - An erased record is never re-admitted: the point read finds it gone.
//   - Progress: retirements never move the cursor back, so with the GC block fixed a
//     full scan of N records takes at most ceil(N / kPageSize) passes (one more when N
//     is a multiple of it) plus one pass per kDispatchBudget eligible records it
//     reserves. N counts the records the scan reads, including ones retired meanwhile
//     ahead of the cursor.
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
};

class ValidatorCleanupManager {
 public:
  static constexpr size_t kPageSize = 256;
  static constexpr size_t kDispatchBudget = 16;
  static constexpr size_t kMaxInFlight = 64;
  using CleanupExaminedFn = std::function<void(const ValidatorSessionId&, bool /*eligible*/)>;

  // A group (initial creation or reopen) for `session` is about to be created. The
  // caller MUST first check !is_delete_in_flight(session) and defer creation while a
  // delete is in flight. Assigns a process-wide strictly increasing incarnation token,
  // retained only while the session is live. A retirement still awaiting its close
  // is superseded by the new incarnation.
  void on_group_created(const ValidatorSessionId& session) {
    live_generation_[session] = ++next_generation_;
    open_retirements_.erase(session);
    note_event();
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
    note_event();
    return gen;
  }

  // The retiring actor confirmed its bus stopped and DB closed. Accepted only for the
  // generation it was retired at, so a stale ack from an older incarnation is ignored.
  void on_close_confirmed(const ValidatorSessionId& session, uint64_t generation) {
    auto it = open_retirements_.find(session);
    if (it != open_retirements_.end() && it->second == generation) {
      open_retirements_.erase(it);
      note_event();
    }
  }

  // True from reservation until the durable erase is acknowledged; the group-creation
  // path must defer creating a group for the session that whole time.
  bool is_delete_in_flight(const ValidatorSessionId& session) const {
    return in_flight_.count(session) > 0;
  }

  // Start a pass at the durable GC block `gc`: the page to read, or nothing when a
  // pass is already running or scanning is paused at this GC block.
  std::optional<ValidatorCleanupPageRequest> begin_pass(const BlockIdExt& gc) {
    if (pass_.active) {
      return std::nullopt;
    }
    if (paused_at_) {
      if (*paused_at_ == gc) {
        return std::nullopt;
      }
      paused_at_.reset();
    }
    if (!scan_start_gc_) {
      scan_start_gc_ = gc;
    } else if (!(*scan_start_gc_ == gc)) {
      event_since_scan_start_ = true;  // the GC block moved during this scan
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

  // The point read of one candidate: `current` is its durable record now, or nothing
  // if it is gone. Reserves the delete only if the record is unchanged since the page
  // read and the session is still not held. Returns the reservation, if any.
  std::optional<ReservedValidatorDelete> on_point_read(const PendingValidatorConsensusDbCleanup& candidate,
                                                       const std::optional<PendingValidatorConsensusDbCleanup>& current,
                                                       const CleanupSessionIsLiveFn& is_live) {
    if (!pass_.active || !pass_.page_examined || pass_.unverified == 0) {
      return std::nullopt;
    }
    --pass_.unverified;
    auto session = candidate.session_id;
    if (!current || !(*current == candidate)) {
      return std::nullopt;  // erased or superseded since the page read; the next scan sees the new value
    }
    if (held_in_memory(session) || is_live(session) || in_flight_.size() >= kMaxInFlight) {
      return std::nullopt;
    }
    auto attempt = ++next_attempt_;
    in_flight_[session] = InFlight{candidate, 0, attempt, InFlightState::Deleting};
    ++pass_.reserved;
    reserved_this_scan_ = true;
    return ReservedValidatorDelete{candidate, 0, attempt};
  }

  // The running pass has examined its page and every candidate has had its point read.
  bool pass_verified() const {
    return pass_.active && pass_.page_examined && pass_.unverified == 0;
  }

  // Finish the running pass. A pass whose page reached the end of the store completes
  // the scan: the cursor wraps, and the scanner pauses if the scan changed nothing.
  ValidatorCleanupPassSummary end_pass() {
    ValidatorCleanupPassSummary summary{pass_.examined, pass_.reserved, pass_.wrapped};
    if (!pass_.active) {
      return summary;
    }
    if (pass_.wrapped) {
      cursor_.clear();
      if (!reserved_this_scan_ && in_flight_.empty() && !event_since_scan_start_) {
        paused_at_ = pass_.gc;
      }
      scan_start_gc_ = pass_.gc;
      reserved_this_scan_ = false;
      event_since_scan_start_ = false;
      ++completed_scans_;
    }
    pass_ = Pass{};
    return summary;
  }

  // The page read failed: the pass ends and the cursor stays where it was.
  void abort_pass() {
    pass_ = Pass{};
  }

  // A dispatched delete ATTEMPT finished. Must be called only when the attempt truly
  // finished, never on a timeout. Rejected unless it matches the in-flight attempt.
  // On confirmed removal the entry moves to Erasing and the durable erase is
  // dispatched; the reservation is held until the erase is acknowledged. On failure
  // the reservation is released and the record, still durable, is retried by a later
  // scan.
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
      note_event();
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

  // No full scan has completed yet in this process.
  bool in_first_scan() const {
    return completed_scans_ == 0;
  }
  bool paused() const {
    return paused_at_.has_value();
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

  // Something that can change a decision happened: resume a paused scanner, and do
  // not let the current scan pause when it completes.
  void note_event() {
    paused_at_.reset();
    event_since_scan_start_ = true;
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

  // (c) scan state. The cursor is the last key examined; empty means the start.
  std::string cursor_;
  Pass pass_;
  std::optional<BlockIdExt> scan_start_gc_;
  bool reserved_this_scan_ = false;
  bool event_since_scan_start_ = false;
  std::optional<BlockIdExt> paused_at_;
  uint64_t completed_scans_ = 0;
};

}  // namespace tos::validator::consensus
