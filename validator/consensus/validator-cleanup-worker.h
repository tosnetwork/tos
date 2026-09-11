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
#include "tos/tos-types.h"
#include "validator/consensus/validator-cleanup-store.h"

// A separate actor that performs the blocking validator consensus-DB deletion
// (RocksDb::destroy + rmrf + confirmed-absent stat) OUTSIDE the manager's own message
// handling, so the delete does not run inline on the manager actor between its other
// messages. (Both actors draw from the shared scheduler thread pool -- this is a
// separate actor context, not a dedicated OS thread, so it does not guarantee full
// CPU isolation from every manager message, only that the blocking call is not a
// manager message itself.) It holds no cleanup state and makes no eligibility
// decision -- the manager has already reserved the operation under the four-condition
// gate and fenced the directory; this worker is only the blocking filesystem step.
//
// Completion is reported exactly once, via the supplied promise, ONLY after the
// delete attempt truly finishes (the promise carries the confirmed-gone result).
// The manager threads its (session, generation, attempt_id) token through the
// promise continuation, so the adapter can reject a stale/duplicate completion.
// The worker never reports a speculative/timeout completion -- it has no timer; a
// timeout is the manager's concern and must keep the ownership fence until this
// real completion arrives.
namespace tos::validator::consensus {

class ValidatorConsensusCleanupWorker : public td::actor::Actor {
 public:
  // Delete the (already-reserved, already-fenced) validator consensus directory and
  // report whether it is confirmed gone. `dir_name` is re-validated as the canonical
  // validator directory for `session_id` inside delete_validator_consensus_db, so a
  // corrupt request can never target an arbitrary path.
  void run_delete(std::string db_root, ValidatorSessionId session_id, std::string dir_name,
                  td::Promise<bool> promise) {
    promise.set_value(delete_validator_consensus_db(td::Slice{db_root}, session_id, dir_name));
  }
};

}  // namespace tos::validator::consensus
