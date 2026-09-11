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

#include "td/actor/actor.h"
#include "validator/consensus/validator-cleanup-manager.h"
#include "validator/consensus/validator-cleanup-worker.h"
#include "validator/interfaces/db.h"

// The async dispatch/continuation glue that ties the pure cleanup adapter
// (ValidatorCleanupManager), the blocking delete worker
// (ValidatorConsensusCleanupWorker), and the durable record store (Db) together.
//
// These are template free functions parameterized by the owner actor `Self`, so the
// production manager (ValidatorManagerImpl) and the integration-test harness
// instantiate the SAME code. That is deliberate: the completion token threading and
// the retry-pacing decision (which path re-triggers the next pass) are exactly the
// parts that a per-component test cannot exercise and that must be proven against the
// real actor/worker/RocksDB composition, not a hand-rolled copy. A bug here is caught
// by whichever caller's tests run -- there is only one copy.
//
// `Self` must expose, as actor-reachable methods with these exact signatures:
//   void validator_cleanup_delete_done(ValidatorSessionId, td::uint64 generation,
//                                      td::uint64 attempt_id, bool confirmed_gone);
//   void validator_cleanup_erase_acked(ValidatorSessionId, td::uint64 generation,
//                                      td::uint64 attempt_id);
//   void try_validator_consensus_db_cleanup();
// The gate check, the GC-snapshot oracles, and begin_eligible_deletes stay in the
// owner's try_validator_consensus_db_cleanup (they are environment-specific: the
// production gate is compile-time false and the oracles come from a MasterchainState;
// a test supplies its own gate and injected oracles). Everything after the reserved
// batch is produced -- worker creation, dispatch, completion, durable erase, and the
// re-trigger placement -- is shared here.
namespace tos::validator::consensus {

// Dispatch each already-reserved delete to the worker, OFF the owner's message stack.
// The worker is created lazily on first use (so a caller that never reserves anything
// -- e.g. production with the gate off -- never allocates it). The completion promise
// carries the confirmed-gone result plus the (session, generation, attempt_id) token
// back to Self::validator_cleanup_delete_done, so the adapter can reject a stale or
// duplicate completion. The reservation and the worker-creation fence stay held until
// that real completion; nothing here releases them on a timeout.
template <class Self>
void dispatch_reserved_validator_deletes(td::actor::ActorId<Self> self_id,
                                         td::actor::ActorOwn<ValidatorConsensusCleanupWorker>& worker,
                                         const std::string& db_root,
                                         const std::vector<ReservedValidatorDelete>& reserved) {
  if (reserved.empty()) {
    return;
  }
  if (worker.empty()) {
    worker = td::actor::create_actor<ValidatorConsensusCleanupWorker>("valcleanupworker");
  }
  for (const auto& item : reserved) {
    auto session = item.record.session_id;
    auto generation = item.generation;
    auto attempt = item.attempt_id;
    auto promise = td::PromiseCreator::lambda([self_id, session, generation, attempt](td::Result<bool> R) {
      R.ensure();
      td::actor::send_closure(self_id, &Self::validator_cleanup_delete_done, session, generation, attempt,
                              R.move_as_ok());
    });
    td::actor::send_closure(worker.get(), &ValidatorConsensusCleanupWorker::run_delete, db_root, session,
                            item.record.dir_name, std::move(promise));
  }
}

// Feed a completed delete ATTEMPT to the adapter. On a confirmed delete the adapter
// invokes the durable-erase dispatch, which erases the record via the Db and, only
// when that erase COMMITS, calls Self::validator_cleanup_erase_acked -- so a crash
// between delete and erase leaves a record a later pass reconciles. A stale completion
// (wrong generation/attempt/state) is ignored inside on_delete_completed.
//
// Deliberately NOT re-triggering a pass here. A not-gone result returns the entry to
// Pending; an unconditional re-trigger would spin a backoff-free retry loop against an
// undeletable directory with no successes and no external trigger. This path buys
// exactly: absent any successful erase-ack and any external trigger, a failing delete
// does not re-dispatch itself (no infinite self-excitation). A per-record minimum
// retry interval is intentionally NOT provided here (see acknowledge_validator_erase).
template <class Self>
void complete_validator_delete(td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                               td::actor::ActorId<Db> db, const ValidatorSessionId& session, td::uint64 generation,
                               td::uint64 attempt_id, bool confirmed_gone) {
  adapter.on_delete_completed(
      session, generation, attempt_id, confirmed_gone,
      [self_id, db](const ValidatorSessionId& s, td::uint64 g, td::uint64 a) {
        td::actor::send_closure(db, &Db::erase_pending_validator_consensus_db_cleanup, s,
                                [self_id, s, g, a](td::Result<td::Unit> R) {
                                  R.ensure();
                                  td::actor::send_closure(self_id, &Self::validator_cleanup_erase_acked, s, g, a);
                                });
      });
}

// A record was actually removed (durable erase committed): outstanding capacity is
// freed and the backlog shrank by one. Re-triggering a pass here is loop-safe because
// each re-trigger is paid for by a completed removal -- the backlog is monotonically
// decreasing -- so it cannot spin. This is the ONLY completion-path re-trigger.
//
// The re-trigger is a DIRECT, synchronous call on the owner (not a deferred
// send_closure): it runs within the same actor turn as the erase-ack, before the next
// mailbox message. That ordering matters -- e.g. an erase-ack immediately followed by a
// group-creation request must reserve the freed session's next delete BEFORE the
// creation runs, so creation hits the in-flight fence. `self` is the owner actor, on
// whose thread this executes.
template <class Self>
void acknowledge_validator_erase(Self* self, ValidatorCleanupManager& adapter, const ValidatorSessionId& session,
                                 td::uint64 generation, td::uint64 attempt_id) {
  adapter.on_erase_acknowledged(session, generation, attempt_id);
  self->try_validator_consensus_db_cleanup();
}

}  // namespace tos::validator::consensus
