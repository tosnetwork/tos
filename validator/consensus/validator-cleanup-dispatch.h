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

#include "common/delay.h"
#include "td/actor/actor.h"
#include "validator/consensus/validator-cleanup-manager.h"
#include "validator/consensus/validator-cleanup-worker.h"
#include "validator/interfaces/db.h"

// The async glue that ties the pure cleanup driver (ValidatorCleanupManager), the
// blocking delete worker (ValidatorConsensusCleanupWorker), and the durable record
// store (Db) together.
//
// These are template free functions parameterized by the owner actor `Self`, so the
// production manager (ValidatorManagerImpl) and the integration-test harness
// instantiate the SAME code. The driver decides every scheduling question; this glue
// only carries its decisions out (one continuation message or one timer, each tagged
// with the driver's scheduler generation) and threads the reads and completions back.
//
// `Self` must expose, as actor-reachable methods with these exact signatures:
//   void try_validator_consensus_db_cleanup();               // a trigger: kick
//   void validator_cleanup_scheduled(td::uint64 generation); // a scheduled callback
//   void validator_cleanup_page_loaded(ValidatorCleanupPageRequest request,
//                                      td::Result<ValidatorCleanupPage> page);
//   void validator_cleanup_point_read(td::uint64 pass_token, PendingValidatorConsensusDbCleanup candidate,
//                                     td::Result<std::optional<PendingValidatorConsensusDbCleanup>> current);
//   void validator_cleanup_delete_done(ValidatorSessionId, td::uint64 generation,
//                                      td::uint64 attempt_id, bool confirmed_gone);
//   void validator_cleanup_erase_acked(ValidatorSessionId, td::uint64 generation,
//                                      td::uint64 attempt_id);
// and, as plain methods called on the owner's thread:
//   bool validator_cleanup_enabled();
//   std::optional<ValidatorCleanupOracles> validator_cleanup_oracles();
//   bool validator_cleanup_reserved(const ReservedValidatorDelete& reserved);
//     (returns whether to dispatch the delete now; the manager always does, a test
//     harness may hold it to model a worker that has not run yet)
//   void validator_cleanup_pass_finished(ValidatorCleanupPassSummary summary, td::Status status);
//     (reporting only: it must not start a pass)
namespace tos::validator::consensus {

// Carry out a scheduling decision of the driver.
template <class Self>
void apply_validator_cleanup_action(td::actor::ActorId<Self> self_id, const ValidatorCleanupScheduleAction& action) {
  auto generation = action.generation;
  switch (action.kind) {
    case ValidatorCleanupScheduleAction::Kind::None:
      return;
    case ValidatorCleanupScheduleAction::Kind::Queue:
      td::actor::send_closure(self_id, &Self::validator_cleanup_scheduled, generation);
      return;
    case ValidatorCleanupScheduleAction::Kind::Timer:
      tos::delay_action(
          [self_id, generation]() { td::actor::send_closure(self_id, &Self::validator_cleanup_scheduled, generation); },
          td::Timestamp::in(action.delay_seconds));
      return;
  }
}

// A trigger: GC advance, close, erase ack, delete completion, start-up. With cleanup
// disabled every scheduled callback is superseded and nothing runs. Without a durable
// GC snapshot there is nothing to decide against; the next GC advance kicks again.
template <class Self>
void kick_validator_cleanup(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter) {
  if (!self->validator_cleanup_enabled()) {
    adapter.disable();
    return;
  }
  auto oracles = self->validator_cleanup_oracles();
  if (!oracles) {
    return;
  }
  apply_validator_cleanup_action(self_id, adapter.kick(oracles->gc));
}

// End the running pass and schedule what follows. The owner hook only reports.
template <class Self>
void end_validator_cleanup_pass(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                ValidatorCleanupPassSummary summary, const BlockIdExt& gc, td::Status status) {
  auto action = adapter.schedule_after_pass(summary, gc);
  self->validator_cleanup_pass_finished(summary, std::move(status));
  apply_validator_cleanup_action(self_id, action);
}

// A continuation message or retry timer fired. A stale one (superseded generation or
// unexpected state) changes nothing. Otherwise run a pass: read the next page. Without
// a GC snapshot the pass fails like a page read, keeping the cursor.
template <class Self>
void run_scheduled_validator_cleanup(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                     td::actor::ActorId<Db> db, td::uint64 generation) {
  if (!self->validator_cleanup_enabled()) {
    adapter.disable();
    return;
  }
  if (!adapter.accept_scheduled(generation)) {
    return;
  }
  auto oracles = self->validator_cleanup_oracles();
  if (!oracles) {
    end_validator_cleanup_pass(self, self_id, adapter, adapter.abort_pass(), BlockIdExt{},
                               td::Status::Error("no durable GC snapshot for the pass"));
    return;
  }
  auto request = adapter.begin_pass(oracles->gc);
  if (!request) {
    return;  // cannot happen: a Running scheduler has no other pass
  }
  auto after_key = request->after_key;
  auto max_keys = request->max_keys;
  td::actor::send_closure(db, &Db::get_pending_validator_consensus_db_cleanup_page, std::move(after_key), max_keys,
                          [self_id, request = std::move(*request)](td::Result<ValidatorCleanupPage> R) mutable {
                            td::actor::send_closure(self_id, &Self::validator_cleanup_page_loaded, std::move(request),
                                                    std::move(R));
                          });
}

// Dispatch each already-reserved delete to the worker, OFF the owner's message stack.
// The worker is created lazily on first use (so a caller that never reserves anything
// -- e.g. a node started with --disable-validator-consensus-cleanup -- never allocates
// it). The completion promise carries the confirmed-gone result plus the (session,
// generation, attempt_id) token back to Self::validator_cleanup_delete_done, so the
// driver can reject a stale or duplicate completion. The reservation and the
// worker-creation fence stay held until that real completion; nothing here releases
// them on a timeout.
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

// The page of a running pass arrived. A failed read (or no GC snapshot now) ends the
// pass with the cursor unchanged and a backoff. Otherwise examine the page and
// point-read each candidate; the pass ends when every point read has returned.
template <class Self>
void handle_validator_cleanup_page(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                   td::actor::ActorId<Db> db, const ValidatorCleanupPageRequest& request,
                                   td::Result<ValidatorCleanupPage> R,
                                   const std::optional<ValidatorCleanupOracles>& oracles,
                                   const ValidatorCleanupManager::CleanupExaminedFn& on_examined) {
  if (R.is_error() || !oracles) {
    auto status = R.is_error() ? R.move_as_error() : td::Status::Error("no durable GC snapshot for the pass");
    end_validator_cleanup_pass(self, self_id, adapter, adapter.abort_pass(), oracles ? oracles->gc : BlockIdExt{},
                               std::move(status));
    return;
  }
  auto candidates = adapter.on_page(request, R.ok(), *oracles, on_examined);
  auto token = request.token;
  for (auto& candidate : candidates) {
    auto session = candidate.session_id;
    td::actor::send_closure(db, &Db::get_pending_validator_consensus_db_cleanup_record, session,
                            [self_id, token, candidate = std::move(candidate)](
                                td::Result<std::optional<PendingValidatorConsensusDbCleanup>> current) mutable {
                              td::actor::send_closure(self_id, &Self::validator_cleanup_point_read, token,
                                                      std::move(candidate), std::move(current));
                            });
  }
  if (adapter.pass_verified()) {
    end_validator_cleanup_pass(self, self_id, adapter, adapter.end_pass(), oracles->gc, td::Status::OK());
  }
}

// The point read of one candidate of the pass `token` arrived. A read error is not
// absence: the candidate is left for a later sweep, which the pass's error outcome
// forces after a backoff. The pass ends once every point read has returned.
template <class Self>
void handle_validator_cleanup_point_read(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                         td::actor::ActorOwn<ValidatorConsensusCleanupWorker>& worker,
                                         const std::string& db_root, td::uint64 token,
                                         const PendingValidatorConsensusDbCleanup& candidate,
                                         td::Result<std::optional<PendingValidatorConsensusDbCleanup>> R,
                                         const std::optional<ValidatorCleanupOracles>& oracles) {
  auto is_live = oracles ? oracles->is_live : CleanupSessionIsLiveFn([](const ValidatorSessionId&) { return true; });
  if (auto reserved = adapter.on_point_read_result(token, candidate, R, is_live)) {
    if (self->validator_cleanup_reserved(*reserved)) {
      dispatch_reserved_validator_deletes(self_id, worker, db_root, std::vector<ReservedValidatorDelete>{*reserved});
    }
  }
  if (adapter.pass_verified()) {
    end_validator_cleanup_pass(self, self_id, adapter, adapter.end_pass(), oracles ? oracles->gc : BlockIdExt{},
                               td::Status::OK());
  }
}

// Feed a completed delete ATTEMPT to the driver. On a confirmed delete the driver
// invokes the durable-erase dispatch, which erases the record via the Db and, only
// when that erase COMMITS, calls Self::validator_cleanup_erase_acked -- so a crash
// between delete and erase leaves a record a later sweep reconciles. A stale
// completion (wrong generation/attempt/state) is ignored inside on_delete_completed.
// A failed delete releases its capacity and kicks: that may resume an unfinished
// sweep. The failed record itself is retried only by a sweep after a backoff, so a
// persistently failing delete cannot spin.
template <class Self>
void complete_validator_delete(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                               td::actor::ActorId<Db> db, const ValidatorSessionId& session, td::uint64 generation,
                               td::uint64 attempt_id, bool confirmed_gone) {
  adapter.on_delete_completed(session, generation, attempt_id, confirmed_gone,
                              [self_id, db](const ValidatorSessionId& s, td::uint64 g, td::uint64 a) {
                                td::actor::send_closure(db, &Db::erase_pending_validator_consensus_db_cleanup, s,
                                                        [self_id, s, g, a](td::Result<td::Unit> R) {
                                                          R.ensure();
                                                          td::actor::send_closure(
                                                              self_id, &Self::validator_cleanup_erase_acked, s, g, a);
                                                        });
                              });
  if (!confirmed_gone) {
    kick_validator_cleanup(self, self_id, adapter);
  }
}

// A record was actually removed (durable erase committed): in-flight capacity is
// freed, so kick -- the driver decides whether that resumes anything. A group created
// for a session before its delete is reserved is safe regardless of ordering: the
// reservation itself (on_point_read_result) refuses a live session.
template <class Self>
void acknowledge_validator_erase(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                 const ValidatorSessionId& session, td::uint64 generation, td::uint64 attempt_id) {
  adapter.on_erase_acknowledged(session, generation, attempt_id);
  kick_validator_cleanup(self, self_id, adapter);
}

}  // namespace tos::validator::consensus
