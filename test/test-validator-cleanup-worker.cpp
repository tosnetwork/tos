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
// Drives the async delete worker (ValidatorConsensusCleanupWorker) through a real
// actor Scheduler, exactly as the manager does: the blocking filesystem delete runs
// on the worker actor, OFF the caller, and completion is reported exactly once via
// the supplied promise. This exercises the actor boundary and the promise
// continuation that the pure store-level test (test-validator-cleanup-statedb) does
// not: that one calls delete_validator_consensus_db() synchronously in-line.
//
// Each assertion is falsifiable:
//   * happy path   — if the worker did not actually remove the tree, the dir would
//                    still stat OK, or the promise would carry false: red.
//   * non-canonical — if the worker skipped the canonical revalidation and deleted
//                    anyway, the unrelated dir would vanish and the promise would
//                    carry true: red.
#include "validator/consensus/validator-cleanup-worker.h"

#include "validator/consensus/db-path.h"

#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Slice.h"
#include "td/utils/Timer.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"

#include <atomic>

using namespace tos::validator::consensus;

namespace {

void wait_flag(td::actor::Scheduler &scheduler, std::atomic<bool> &flag, const char *what) {
  auto deadline = td::Timestamp::in(10.0);
  while (!flag.load(std::memory_order_acquire)) {
    scheduler.run(0.1);
    LOG_CHECK(!deadline.is_in_past()) << "timed out: " << what;
  }
}

tos::ValidatorSessionId make_session_id(unsigned char seed) {
  tos::ValidatorSessionId id;
  for (size_t i = 0; i < id.as_slice().size(); i++) {
    id.as_slice()[i] = static_cast<char>(seed + i * 7);
  }
  return id;
}

const tos::ShardId kMasterShard = static_cast<tos::ShardId>(0x8000000000000000ULL);
const tos::ShardIdFull kShard{0, kMasterShard};

// Create <root>/consensus/<dir_name>/db/ with a real file inside, so there is a
// non-empty directory tree for the worker to remove.
void create_consensus_dir(const std::string &root, const std::string &dir_name) {
  auto db_dir = consensus_db_root(td::Slice{root}) + dir_name + "/db/";
  td::mkpath(db_dir).ensure();
  td::write_file(db_dir + "CURRENT", td::Slice{"x"}).ensure();
}

bool consensus_dir_exists(const std::string &root, const std::string &dir_name) {
  return td::stat(consensus_db_root(td::Slice{root}) + dir_name).is_ok();
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_INFO);

  std::string db_root = PSTRING() << "tmp-test-validator-cleanup-worker-" << td::Random::fast_uint32();
  td::rmrf(db_root).ignore();
  td::mkpath(db_root + "/").ensure();

  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<ValidatorConsensusCleanupWorker> worker;
  scheduler.run_in_context([&] { worker = td::actor::create_actor<ValidatorConsensusCleanupWorker>("worker"); });

  // Phase 1: happy path. A real canonical validator consensus dir is removed by the
  // worker and reported confirmed-gone via the promise.
  {
    auto sid = make_session_id(11);
    auto dir_name = consensus_db_dir_name(kShard, 7, sid, td::Slice(""));
    create_consensus_dir(db_root, dir_name);
    LOG_CHECK(consensus_dir_exists(db_root, dir_name)) << "fixture dir was not created";

    std::atomic<bool> done{false};
    std::atomic<bool> gone{false};
    scheduler.run_in_context([&] {
      auto promise = td::PromiseCreator::lambda([&](td::Result<bool> R) {
        R.ensure();
        gone.store(R.move_as_ok(), std::memory_order_relaxed);
        done.store(true, std::memory_order_release);
      });
      td::actor::send_closure(worker, &ValidatorConsensusCleanupWorker::run_delete, db_root, sid, dir_name,
                              std::move(promise));
    });
    wait_flag(scheduler, done, "worker delete of canonical dir");
    LOG_CHECK(gone.load(std::memory_order_relaxed)) << "worker reported the dir NOT gone after a real delete";
    if (consensus_dir_exists(db_root, dir_name)) {
      LOG(FATAL) << "worker returned confirmed-gone but the consensus dir is still on disk";
    }
  }

  // Phase 2: non-canonical refusal. A directory whose name is NOT the canonical name
  // for the requested session must be left untouched, and the promise must carry
  // false. This guards the worker's reliance on delete_validator_consensus_db's
  // canonical revalidation, so a corrupt request can never target an arbitrary path.
  {
    auto sid = make_session_id(22);
    const std::string bogus_dir = "not-a-canonical-validator-dir";
    create_consensus_dir(db_root, bogus_dir);
    LOG_CHECK(consensus_dir_exists(db_root, bogus_dir)) << "fixture dir was not created";

    std::atomic<bool> done{false};
    std::atomic<bool> gone{true};  // starts true so a missing callback cannot pass as "refused"
    scheduler.run_in_context([&] {
      auto promise = td::PromiseCreator::lambda([&](td::Result<bool> R) {
        R.ensure();
        gone.store(R.move_as_ok(), std::memory_order_relaxed);
        done.store(true, std::memory_order_release);
      });
      td::actor::send_closure(worker, &ValidatorConsensusCleanupWorker::run_delete, db_root, sid, bogus_dir,
                              std::move(promise));
    });
    wait_flag(scheduler, done, "worker refusal of non-canonical dir");
    LOG_CHECK(!gone.load(std::memory_order_relaxed)) << "worker claimed a non-canonical dir was deleted";
    if (!consensus_dir_exists(db_root, bogus_dir)) {
      LOG(FATAL) << "worker removed a non-canonical directory instead of refusing it";
    }
  }

  scheduler.run_in_context([&] {
    worker.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }

  td::rmrf(db_root).ignore();
  LOG(INFO) << "test-validator-cleanup-worker: all phases passed";
  return 0;
}
