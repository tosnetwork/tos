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

class ValidatorCleanupManager {
 public:
  // Records loaded from durable storage at a fresh startup. Before any group is
  // created in this process nothing owns the directory, so the retiring actor is
  // effectively closed -- closure is established by the fresh process + exclusive
  // ownership, not an invented ack. Generation 0 is the pre-any-creation baseline;
  // a later on_group_created bumps it and drops the record.
  void on_loaded_at_startup(PendingValidatorConsensusDbCleanup record) {
    auto session = record.session_id;
    pending_[session] = Entry{std::move(record), /*retired_generation=*/0, /*closed=*/true, /*in_flight=*/false};
  }

  // A group (initial creation or reopen) for `session` is about to be created. The
  // caller MUST first check !is_delete_in_flight(session) and defer creation while
  // a delete is in flight. Bumps the live incarnation and drops any pending
  // cleanup entry -- the directory is being reused by a live group, so its record
  // is no longer a deletion target (the durable record is replaced when the
  // session next retires; until then is_live also vetoes it).
  void on_group_created(const ValidatorSessionId& session) {
    live_generation_[session]++;
    pending_.erase(session);
  }

  // The current incarnation of `session` retired; `record` is its durable cleanup
  // record (persisted before the actor is allowed to close). Captures the
  // incarnation generation and returns it so the manager can tag the close
  // callback. A re-retirement overwrites the prior entry.
  uint64_t on_group_retired(PendingValidatorConsensusDbCleanup record) {
    auto session = record.session_id;
    auto gen = live_generation_[session];
    pending_[session] = Entry{std::move(record), gen, /*closed=*/false, /*in_flight=*/false};
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

  // True while a delete has been dispatched but not completed for `session`. The
  // group-creation path MUST refuse/defer creating a group for it until the delete
  // completes, so a reopen can never race an in-flight delete of the same
  // directory.
  bool is_delete_in_flight(const ValidatorSessionId& session) const {
    auto it = pending_.find(session);
    return it != pending_.end() && it->second.in_flight;
  }

  // Select up to `delete_budget` eligible records, RESERVE them (mark in-flight),
  // and return them for the caller to delete asynchronously. Eligibility is the
  // four-condition gate with is_closed taken from this adapter's per-incarnation
  // closure. A reserved session is fenced against reopen until on_delete_completed.
  std::vector<PendingValidatorConsensusDbCleanup> begin_eligible_deletes(
      const BlockIdExt& gc_checkpoint, const CleanupAncestorOfGcFn& ancestor_or_equal_of_gc,
      const GcShardCatchainSeqnoFn& gc_shard_catchain_seqno, const CleanupSessionIsLiveFn& is_live,
      size_t delete_budget) {
    std::vector<PendingValidatorConsensusDbCleanup> reserved;
    for (auto& [session, entry] : pending_) {
      if (reserved.size() >= delete_budget) {
        break;
      }
      if (entry.in_flight) {
        continue;  // already being deleted
      }
      auto is_closed = [&entry](const ValidatorSessionId&) { return entry.closed; };
      if (!validator_cleanup_eligible(entry.record, gc_checkpoint, ancestor_or_equal_of_gc, gc_shard_catchain_seqno,
                                      is_live, is_closed)) {
        continue;
      }
      entry.in_flight = true;
      reserved.push_back(entry.record);
    }
    return reserved;
  }

  // Report the result of a dispatched delete. Clears the in-flight reservation.
  // On confirmed removal, durably erases (via the injected callback) and drops the
  // entry; otherwise the entry is retained for a later retry. Because reopen is
  // fenced while in-flight, the entry's incarnation cannot have changed, so the
  // erase is bound to the retiring record. An unknown session (already dropped) is
  // a no-op.
  void on_delete_completed(const ValidatorSessionId& session, bool confirmed_gone,
                           const std::function<void(const ValidatorSessionId&)>& erase_record) {
    auto it = pending_.find(session);
    if (it == pending_.end()) {
      return;
    }
    it->second.in_flight = false;
    if (confirmed_gone) {
      erase_record(session);
      pending_.erase(it);
    }
  }

  size_t pending_count() const {
    return pending_.size();
  }

 private:
  struct Entry {
    PendingValidatorConsensusDbCleanup record;
    uint64_t retired_generation = 0;
    bool closed = false;
    bool in_flight = false;
  };
  std::map<ValidatorSessionId, Entry> pending_;
  std::map<ValidatorSessionId, uint64_t> live_generation_;
};

}  // namespace tos::validator::consensus
