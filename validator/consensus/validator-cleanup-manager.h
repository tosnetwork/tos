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

#include <cstdint>
#include <limits>
#include <map>
#include <vector>

#include "validator/consensus/validator-cleanup.h"

// Stateful adapter (B2-8a) that drives validator consensus-DB cleanup while
// enforcing the safety invariants the pure coordinator cannot: generation-scoped
// closure, an in-flight-delete reservation that fences reopen, and erase bound to
// the retiring incarnation. It has NO actor/DB dependencies so it is unit-testable
// and can be driven through every crash/reopen ordering deterministically; the
// ValidatorManager forwards group lifecycle events here and supplies the GC
// oracles, a live-query, an (async) deleter, and a durable erase. Must be confined
// to the manager's actor thread. Deletion is not enabled until the manager is
// wired to call this and the gate is flipped (B2-8b/B2-8c).
namespace tos::validator::consensus {

// A record reserved for deletion. The caller threads BOTH tokens back through
// completion: `generation` identifies the incarnation (rejects a completion from
// an older incarnation), and `attempt_id` identifies this specific delete attempt
// (rejects a stale/duplicate completion from an EARLIER attempt of the SAME
// incarnation, e.g. a worker that finished late after a retry was dispatched).
struct ReservedValidatorDelete {
  PendingValidatorConsensusDbCleanup record;
  uint64_t generation = 0;
  uint64_t attempt_id = 0;
};

class ValidatorCleanupManager {
 public:
  // Records loaded from durable storage at a fresh startup. Before any group is
  // created in this process nothing owns the directory, so the retiring actor is
  // effectively closed -- closure is established by the fresh process + exclusive
  // ownership, not an invented ack. Generation 0 is the pre-any-creation baseline.
  //
  // A late load must NEVER overwrite knowledge of a RUNTIME incarnation: block
  // application can create/retire a group before this load's callback returns (the
  // startup load is not the only path to update_shards), and overwriting a live or
  // already-retired session with generation 0 / closed=true would corrupt the
  // state the deletion decision relies on. So this is insert-if-absent: if the
  // session is already tracked (live or pending), the runtime state wins and the
  // stale durable record is dropped here (it is superseded by the runtime
  // incarnation and replaced or cleaned when that incarnation next retires). This
  // makes correctness independent of whether the load races ahead of group
  // creation, rather than relying on an ordering barrier alone.
  void on_loaded_at_startup(PendingValidatorConsensusDbCleanup record) {
    auto session = record.session_id;
    if (live_generation_.count(session) > 0 || pending_.count(session) > 0) {
      return;
    }
    pending_[session] = Entry{std::move(record), /*retired_generation=*/0, /*closed=*/true, EntryState::Pending};
  }

  // A group (initial creation or reopen) for `session` is about to be created. The
  // caller MUST first check !is_delete_in_flight(session) and defer creation while
  // a delete is in flight. Assigns a PROCESS-WIDE monotonically increasing
  // incarnation token (never per-session and never reset), so a later incarnation
  // of a session always has a strictly greater generation than any earlier one --
  // a stale close/delete callback carrying an older generation can therefore never
  // match a newer incarnation. The token is retained only while the session is
  // live (released at retirement), so this map is bounded by the number of
  // concurrently-live sessions, not by all sessions ever created. Also drops any
  // pending cleanup entry -- the directory is being reused by a live group.
  void on_group_created(const ValidatorSessionId& session) {
    live_generation_[session] = ++next_generation_;
    auto it = pending_.find(session);
    if (it != pending_.end()) {
      if (it->second.state != EntryState::Pending) {
        // Defensive: the caller must fence creation while a delete is in flight, so
        // reaching here means the fence was bypassed; keep outstanding_ consistent.
        --outstanding_;
      }
      pending_.erase(it);
    }
  }

  // The current incarnation of `session` retired; `record` is its durable cleanup
  // record (persisted before the actor is allowed to close). Consumes and RELEASES
  // the live incarnation token (the session is no longer live), returning it so the
  // manager can tag the close callback. A retiring group must have been created; if
  // its token is somehow absent, mint a fresh unique one rather than reuse a stale
  // value. A re-retirement overwrites the prior pending entry.
  uint64_t on_group_retired(PendingValidatorConsensusDbCleanup record) {
    auto session = record.session_id;
    // Defensive: never overwrite an entry whose delete is already in flight
    // (Deleting/Erasing). This cannot happen in production -- creation is fenced
    // while in flight, so a session cannot be re-created and re-retired mid-delete
    // -- but overwriting it would abandon the running worker and permanently
    // elevate outstanding_. Keep the in-flight operation intact and report its
    // generation.
    auto existing = pending_.find(session);
    if (existing != pending_.end() && existing->second.state != EntryState::Pending) {
      return existing->second.retired_generation;
    }
    uint64_t gen;
    auto it = live_generation_.find(session);
    if (it != live_generation_.end()) {
      gen = it->second;
      live_generation_.erase(it);
    } else {
      gen = ++next_generation_;
    }
    pending_[session] = Entry{std::move(record), gen, /*closed=*/false, EntryState::Pending};
    return gen;
  }

  // The retiring actor confirmed its bus stopped and DB closed, tagged with the
  // generation it was retired at. Accepted ONLY if it matches the pending entry's
  // generation: a stale ack from an older incarnation (after a reopen/re-retire)
  // is ignored, so it can never mark a newer incarnation closed.
  void on_close_confirmed(const ValidatorSessionId& session, uint64_t generation) {
    auto it = pending_.find(session);
    if (it != pending_.end() && it->second.retired_generation == generation) {
      it->second.closed = true;
    }
  }

  // True while a delete (or its durable erase) is in progress for `session`. The
  // reservation is held from delete dispatch through the durable-erase ack, so the
  // group-creation path MUST refuse/defer creating a group for it that whole time
  // -- a reopen can never race an in-flight delete of the same directory.
  bool is_delete_in_flight(const ValidatorSessionId& session) const {
    auto it = pending_.find(session);
    return it != pending_.end() && it->second.state != EntryState::Pending;
  }

  // Select up to `delete_budget` eligible records, RESERVE them (Pending ->
  // Deleting), and return each with its incarnation generation as an operation
  // token. The caller deletes each directory asynchronously and MUST thread the
  // (session, generation) back through on_delete_completed / on_erase_acknowledged,
  // so a stale completion cannot act on a replacement entry. Eligibility is the
  // four-condition gate with is_closed taken from this adapter's per-incarnation
  // closure.
  // `dispatch_budget` caps reservations made THIS pass; `scan_budget` caps entries
  // EXAMINED this pass (so a large backlog of ineligible records cannot make one
  // pass walk the whole table); `max_outstanding` caps total concurrent
  // Deleting+Erasing reservations ACROSS passes (so a slow async worker cannot let
  // in-flight work grow unbounded). scan_budget / max_outstanding default to
  // unbounded for callers that only want the dispatch cap.
  // `on_examined`, if set, is called for EVERY Pending record this pass actually examined,
  // with (session, eligible). It lets an acceptance harness prove -- per session -- that a
  // record was evaluated and what the decision was, rather than inferring examination from
  // budget arithmetic (the scan can stop early on dispatch_budget / max_outstanding).
  using CleanupExaminedFn = std::function<void(const ValidatorSessionId&, bool /*eligible*/)>;
  std::vector<ReservedValidatorDelete> begin_eligible_deletes(
      const BlockIdExt& gc_checkpoint, const CleanupAncestorOfGcFn& ancestor_or_equal_of_gc,
      const GcShardCatchainSeqnoFn& gc_shard_catchain_seqno, const CleanupSessionIsLiveFn& is_live,
      size_t dispatch_budget, size_t scan_budget = std::numeric_limits<size_t>::max(),
      size_t max_outstanding = std::numeric_limits<size_t>::max(), const CleanupExaminedFn& on_examined = {}) {
    std::vector<ReservedValidatorDelete> reserved;
    if (pending_.empty() || dispatch_budget == 0) {
      return reserved;
    }
    // Round-robin: resume scanning at the cursor and wrap once, examining each entry
    // at most once this pass, so a prefix of persistently-failing records cannot
    // monopolize the budget every pass and starve later ones. The cursor advances
    // even on scan-budget exhaustion. The cursor is a session-id value, so a removed
    // cursor session simply resolves to the next.
    size_t scan_limit = std::min(scan_budget, pending_.size());
    auto it = pending_.lower_bound(retry_cursor_);
    for (size_t examined = 0;
         examined < scan_limit && reserved.size() < dispatch_budget && outstanding_ < max_outstanding; ++examined) {
      if (it == pending_.end()) {
        it = pending_.begin();
      }
      auto& entry = it->second;
      if (entry.state == EntryState::Pending) {
        auto is_closed = [&entry](const ValidatorSessionId&) { return entry.closed; };
        bool eligible = validator_cleanup_eligible(entry.record, gc_checkpoint, ancestor_or_equal_of_gc,
                                                   gc_shard_catchain_seqno, is_live, is_closed);
        if (on_examined) {
          on_examined(it->first, eligible);
        }
        if (eligible) {
          entry.state = EntryState::Deleting;
          entry.attempt_id = ++next_attempt_;  // fresh per-attempt token
          ++outstanding_;
          reserved.push_back(ReservedValidatorDelete{entry.record, entry.retired_generation, entry.attempt_id});
        }
      }
      ++it;
    }
    // Resume the next pass after the last entry examined.
    retry_cursor_ = (it == pending_.end()) ? ValidatorSessionId{} : it->first;
    return reserved;
  }

  // Report the result of a dispatched delete for the operation identified by
  // (session, generation). Rejected unless the entry still exists, its incarnation
  // matches `generation`, and it is in the Deleting state -- so a stale completion
  // (e.g. for an incarnation replaced despite the fence) cannot act on a newer
  // entry. On confirmed removal, DISPATCH the durable erase (via the injected
  // callback) and move to Erasing; the reservation is NOT released and the record
  // is NOT dropped until on_erase_acknowledged. On unconfirmed removal, return to
  // Pending for a later retry.
  // Must be called ONLY when a dispatched delete ATTEMPT truly finishes (the worker
  // reports success or failure), never speculatively on a timeout -- a timeout does
  // not prove the worker stopped, so the caller must keep the ownership fence and
  // not re-dispatch until the outstanding attempt is confirmed done or cancelled.
  // Rejected unless the entry exists, matches the incarnation `generation` AND the
  // `attempt_id`, and is in Deleting -- so a stale/duplicate completion from an
  // earlier attempt (of this or an older incarnation) cannot act. On confirmed
  // removal, move to Erasing (keeping the same attempt token) and dispatch the
  // durable erase; the record is NOT dropped and the reservation NOT released yet.
  // On reported failure, return to Pending for a fresh attempt on a later pass.
  void on_delete_completed(const ValidatorSessionId& session, uint64_t generation, uint64_t attempt_id,
                           bool confirmed_gone,
                           const std::function<void(const ValidatorSessionId&, uint64_t, uint64_t)>&
                               dispatch_durable_erase) {
    auto it = pending_.find(session);
    if (it == pending_.end() || it->second.retired_generation != generation || it->second.attempt_id != attempt_id ||
        it->second.state != EntryState::Deleting) {
      return;  // stale / replaced / wrong attempt / not in flight -> ignore
    }
    if (confirmed_gone) {
      it->second.state = EntryState::Erasing;  // still outstanding until the erase is acked
      dispatch_durable_erase(session, generation, attempt_id);
    } else {
      it->second.state = EntryState::Pending;  // retry with a fresh attempt on a later pass
      --outstanding_;
    }
  }

  // The durable erase for the operation (session, generation, attempt_id) has been
  // acknowledged as committed. Only now is the record dropped and the reservation
  // released. Rejected unless the entry still matches that incarnation AND attempt
  // and is in Erasing, so a late erase ack cannot remove a replacement record.
  void on_erase_acknowledged(const ValidatorSessionId& session, uint64_t generation, uint64_t attempt_id) {
    auto it = pending_.find(session);
    if (it == pending_.end() || it->second.retired_generation != generation || it->second.attempt_id != attempt_id ||
        it->second.state != EntryState::Erasing) {
      return;
    }
    pending_.erase(it);
    --outstanding_;
  }

  size_t pending_count() const {
    return pending_.size();
  }

  // Number of currently-live sessions whose incarnation token is retained. Bounded
  // by concurrently-live sessions (released at retirement); exposed so a test can
  // prove the bookkeeping does not grow with historical session churn.
  size_t live_session_count() const {
    return live_generation_.size();
  }

 private:
  // Pending: retired, not yet being reclaimed. Deleting: a filesystem delete is in
  // flight. Erasing: the directory is confirmed gone and the durable record erase
  // is in flight. The reservation (is_delete_in_flight) is held in Deleting and
  // Erasing; the entry is dropped only after the erase is acknowledged.
  enum class EntryState { Pending, Deleting, Erasing };
  struct Entry {
    PendingValidatorConsensusDbCleanup record;
    uint64_t retired_generation = 0;
    bool closed = false;
    EntryState state = EntryState::Pending;
    uint64_t attempt_id = 0;  // token of the current Deleting/Erasing attempt
  };
  std::map<ValidatorSessionId, Entry> pending_;
  // Incarnation token of each currently-live session (created, not yet retired).
  std::map<ValidatorSessionId, uint64_t> live_generation_;
  // Process-wide monotonically increasing incarnation token source. Never reset, so
  // no two incarnations (across the whole process lifetime) ever share a token.
  uint64_t next_generation_ = 0;
  // Process-wide monotonically increasing per-delete-attempt token source, so no
  // two delete attempts (even of the same incarnation) ever share a token.
  uint64_t next_attempt_ = 0;
  // Round-robin resume point for begin_eligible_deletes, so retries are fair and a
  // failing prefix cannot starve later records. Default-constructed sorts first.
  ValidatorSessionId retry_cursor_{};
  // Count of entries currently Deleting or Erasing (reserved). Caps concurrent
  // in-flight cleanup work via max_outstanding.
  size_t outstanding_ = 0;
};

}  // namespace tos::validator::consensus
