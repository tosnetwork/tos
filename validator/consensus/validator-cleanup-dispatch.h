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

// The async glue that ties the cleanup driver (ValidatorCleanupManager), the blocking
// delete worker (ValidatorConsensusCleanupWorker), and the durable record store (Db)
// together.
//
// These are template free functions parameterized by the owner actor `Self`, so the
// production manager (ValidatorManagerImpl) and the integration-test harness
// instantiate the SAME code.
//
// Scheduling is one fixed-period timer chain per owner, started once at start-up and
// only if cleanup is enabled (enabling or disabling cleanup is a start-up decision;
// there is no runtime toggle). Each timer callback checks that cleanup is enabled,
// then re-arms the next timer, then runs one tick. The callbacks capture only the
// owner's actor id, never a pointer to it: once the owner stops, a pending callback is
// dropped with its message, so it neither ticks nor re-arms. Nothing else schedules a
// pass -- not retirements, closes, GC advances, erase acks nor failures.
//
// `Self` must expose, as actor-reachable methods with these exact signatures:
//   void validator_cleanup_timer();
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
namespace tos::validator::consensus {

template <class Self>
void arm_validator_cleanup_timer(td::actor::ActorId<Self> self_id, double interval_seconds) {
  tos::delay_action([self_id]() { td::actor::send_closure(self_id, &Self::validator_cleanup_timer); },
                    td::Timestamp::in(interval_seconds));
}

// Start the owner's one timer chain. Call exactly once, at start-up.
template <class Self>
void start_validator_cleanup_ticks(Self* self, td::actor::ActorId<Self> self_id, double interval_seconds) {
  if (!self->validator_cleanup_enabled()) {
    return;
  }
  arm_validator_cleanup_timer(self_id, interval_seconds);
}

// One tick: at most one pass, skipped while a pass is running, at the in-flight cap,
// or without a durable GC snapshot.
template <class Self>
void run_validator_cleanup_tick(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                td::actor::ActorId<Db> db) {
  auto oracles = self->validator_cleanup_oracles();
  if (!oracles) {
    return;
  }
  auto request = adapter.begin_tick(oracles->gc);
  if (!request) {
    return;
  }
  auto after_key = request->after_key;
  auto max_keys = request->max_keys;
  td::actor::send_closure(db, &Db::get_pending_validator_consensus_db_cleanup_page, std::move(after_key), max_keys,
                          [self_id, request = std::move(*request)](td::Result<ValidatorCleanupPage> R) mutable {
                            td::actor::send_closure(self_id, &Self::validator_cleanup_page_loaded, std::move(request),
                                                    std::move(R));
                          });
}

// The timer fired: check, re-arm, tick -- in that order.
template <class Self>
void on_validator_cleanup_timer(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                td::actor::ActorId<Db> db, double interval_seconds) {
  if (!self->validator_cleanup_enabled()) {
    return;
  }
  arm_validator_cleanup_timer(self_id, interval_seconds);
  run_validator_cleanup_tick(self, self_id, adapter, db);
}

// Dispatch each already-reserved delete to the worker, OFF the owner's message stack.
// The worker is created lazily on first use. The completion promise carries the
// confirmed-gone result plus the (session, generation, attempt_id) token back to
// Self::validator_cleanup_delete_done, so the driver can reject a stale or duplicate
// completion. The reservation and the worker-creation fence stay held until that real
// completion; nothing here releases them on a timeout.
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

// The page of a pass arrived. A result for any pass but the running one -- success or
// failure -- is dropped before it is looked at. A failed read (or no GC snapshot now)
// ends the pass with the cursor unchanged; the next tick reads the same page again.
// Otherwise examine the page and point-read each candidate; the pass ends when every
// point read has returned.
template <class Self>
void handle_validator_cleanup_page(Self* self, td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
                                   td::actor::ActorId<Db> db, const ValidatorCleanupPageRequest& request,
                                   td::Result<ValidatorCleanupPage> R,
                                   const std::optional<ValidatorCleanupOracles>& oracles,
                                   const ValidatorCleanupManager::CleanupExaminedFn& on_examined) {
  if (!adapter.is_current_pass(request.token)) {
    return;
  }
  if (R.is_error() || !oracles) {
    auto status = R.is_error() ? R.move_as_error() : td::Status::Error("no durable GC snapshot for the pass");
    if (auto summary = adapter.abort_pass(request.token)) {
      self->validator_cleanup_pass_finished(*summary, std::move(status));
    }
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
    self->validator_cleanup_pass_finished(adapter.end_pass(), td::Status::OK());
  }
}

// The point read of one candidate of the pass `token` arrived. A read error is not
// absence: the candidate is not reserved and the next cycle examines it again. The
// pass ends once every point read has returned.
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
    self->validator_cleanup_pass_finished(adapter.end_pass(), td::Status::OK());
  }
}

// Feed a completed delete ATTEMPT to the driver. On a confirmed delete the driver
// invokes the durable-erase dispatch, which erases the record via the Db and, only
// when that erase COMMITS, calls Self::validator_cleanup_erase_acked -- so a crash
// between delete and erase leaves a record a later cycle reconciles. A stale
// completion (wrong generation/attempt/state) is ignored inside on_delete_completed.
template <class Self>
void complete_validator_delete(td::actor::ActorId<Self> self_id, ValidatorCleanupManager& adapter,
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
}

// A record was actually removed (durable erase committed): release its reservation.
inline void acknowledge_validator_erase(ValidatorCleanupManager& adapter, const ValidatorSessionId& session,
                                        td::uint64 generation, td::uint64 attempt_id) {
  adapter.on_erase_acknowledged(session, generation, attempt_id);
}

}  // namespace tos::validator::consensus
