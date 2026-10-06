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

#include <optional>
#include <string>
#include <vector>

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
//   void try_validator_consensus_db_cleanup();
//   void validator_cleanup_page_loaded(ValidatorCleanupPageRequest request,
//                                      td::Result<ValidatorCleanupPage> page);
//   void validator_cleanup_point_read(PendingValidatorConsensusDbCleanup candidate,
//                                     td::Result<std::optional<PendingValidatorConsensusDbCleanup>> current);
//   void validator_cleanup_delete_done(ValidatorSessionId, td::uint64 generation,
//                                      td::uint64 attempt_id, bool confirmed_gone);
//   void validator_cleanup_erase_acked(ValidatorSessionId, td::uint64 generation,
//                                      td::uint64 attempt_id);
// and, as plain methods called on the owner's thread:
//   bool validator_cleanup_reserved(const ReservedValidatorDelete& reserved);
//     (returns whether to dispatch the delete now; the manager always does, a test
//     harness may hold it to model a worker that has not run yet)
//   void validator_cleanup_pass_finished(ValidatorCleanupPassSummary summary, td::Status status);
// The gate check and the GC-snapshot oracles stay with the owner (they are
// environment-specific: the production gate is the validator option and the oracles
// come from a MasterchainState; a test supplies its own). Everything else -- the page
// read, the point reads, worker creation, dispatch, completion, durable erase, and the
// re-trigger placement -- is shared here.
namespace tos::validator::consensus {

// Dispatch each already-reserved delete to the worker, OFF the owner's message stack.
// The worker is created lazily on first use (so a caller that never reserves anything
// -- e.g. a node started with --disable-validator-consensus-cleanup -- never allocates it). The completion promise
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

// A record was actually removed (durable erase committed): in-flight capacity is
// freed and the backlog shrank by one. Re-triggering a pass here is loop-safe because
// each re-trigger is paid for by a completed removal -- the backlog is monotonically
// decreasing -- so it cannot spin. This is the ONLY completion-path re-trigger. A
// group created for a session before its delete is reserved is safe regardless of
// ordering: the reservation itself (on_point_read) refuses a live session.
template <class Self>
void acknowledge_validator_erase(Self* self, ValidatorCleanupManager& adapter, const ValidatorSessionId& session,
                                 td::uint64 generation, td::uint64 attempt_id) {
  adapter.on_erase_acknowledged(session, generation, attempt_id);
  self->try_validator_consensus_db_cleanup();
}

// Start a pass at the durable GC block `gc`: read the next page of records after the
// adapter's cursor. Returns false when the adapter declines (a pass is running, or
// scanning is paused at this GC block).
template <class Self>
bool start_validator_cleanup_pass(td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                  td::actor::ActorId<Db> db, const BlockIdExt& gc) {
  auto request = adapter.begin_pass(gc);
  if (!request) {
    return false;
  }
  auto after_key = request->after_key;
  auto max_keys = request->max_keys;
  td::actor::send_closure(db, &Db::get_pending_validator_consensus_db_cleanup_page, std::move(after_key), max_keys,
                          [self_id, request = std::move(*request)](td::Result<ValidatorCleanupPage> R) mutable {
                            td::actor::send_closure(self_id, &Self::validator_cleanup_page_loaded, std::move(request),
                                                    std::move(R));
                          });
  return true;
}

// The page of a running pass arrived. Examine it against `oracles` (nothing when the
// durable GC snapshot is unavailable, which ends the pass with the cursor unchanged)
// and point-read each candidate.
template <class Self>
void handle_validator_cleanup_page(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                   td::actor::ActorId<Db> db, const ValidatorCleanupPageRequest& request,
                                   td::Result<ValidatorCleanupPage> R,
                                   const std::optional<ValidatorCleanupOracles>& oracles,
                                   const ValidatorCleanupManager::CleanupExaminedFn& on_examined) {
  if (R.is_error() || !oracles) {
    adapter.abort_pass();
    self->validator_cleanup_pass_finished(
        ValidatorCleanupPassSummary{},
        R.is_error() ? R.move_as_error() : td::Status::Error("no durable GC snapshot for the pass"));
    return;
  }
  auto candidates = adapter.on_page(request, R.ok(), *oracles, on_examined);
  for (auto& candidate : candidates) {
    auto session = candidate.session_id;
    td::actor::send_closure(db, &Db::get_pending_validator_consensus_db_cleanup_record, session,
                            [self_id, candidate = std::move(candidate)](
                                td::Result<std::optional<PendingValidatorConsensusDbCleanup>> current) mutable {
                              td::actor::send_closure(self_id, &Self::validator_cleanup_point_read,
                                                      std::move(candidate), std::move(current));
                            });
  }
  if (adapter.pass_verified()) {
    self->validator_cleanup_pass_finished(adapter.end_pass(), td::Status::OK());
  }
}

// The point read of one candidate arrived. A failed read counts as "not there": the
// candidate is skipped and the next scan sees it again.
template <class Self>
void handle_validator_cleanup_point_read(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                         td::actor::ActorOwn<ValidatorConsensusCleanupWorker>& worker,
                                         const std::string& db_root,
                                         const PendingValidatorConsensusDbCleanup& candidate,
                                         td::Result<std::optional<PendingValidatorConsensusDbCleanup>> R,
                                         const CleanupSessionIsLiveFn& is_live) {
  std::optional<PendingValidatorConsensusDbCleanup> current;
  if (R.is_ok()) {
    current = R.move_as_ok();
  }
  if (auto reserved = adapter.on_point_read(candidate, current, is_live)) {
    if (self->validator_cleanup_reserved(*reserved)) {
      dispatch_reserved_validator_deletes(self_id, worker, db_root, std::vector<ReservedValidatorDelete>{*reserved});
    }
  }
  if (adapter.pass_verified()) {
    self->validator_cleanup_pass_finished(adapter.end_pass(), td::Status::OK());
  }
}

}  // namespace tos::validator::consensus
