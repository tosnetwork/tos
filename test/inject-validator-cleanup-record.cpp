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
// ACCEPTANCE-ONLY test-fixture injector for the validator consensus-DB cleanup negative
// matrix. Writes ONE validator cleanup record (with a caller-chosen retirement checkpoint,
// directory workchain, and directory catchain seqno) into a STOPPED node's StateDb and
// creates its canonical consensus directory. By choosing those fields, a driver builds a
// DIFFERENTIAL set that isolates each veto of the four-condition gate:
//   * eligible CONTROL   (ancestor retirement + obsolete cc + real shard) -> gets deleted;
//   * poison "ancestry"  (FUTURE non-ancestor retirement, else eligible)  -> refused by B;
//   * poison "obsolete"  (ancestor retirement + FUTURE cc)                -> refused by C;
//   * poison "unknown-gc"(ancestor retirement + nonexistent workchain)    -> refused (sentinel).
// The record is always read back through the production decoder (POISON_LOADABLE) so a
// PASS cannot be vacuous.
//
// A trailing "predelete" arg RECONSTRUCTS the mid-flight state {dir gone, record present}:
// after writing the record and creating the dir, it runs the REAL deleter
// (delete_validator_consensus_db -- the exact function the cleanup worker calls), so on
// disk the durable record outlives its directory. That is the state left AFTER the
// directory is physically removed but BEFORE the durable record erase commits. A restarted
// engine must reconcile it (an already-absent dir counts as a confirmed delete, so the pass
// completes the erase and drops the orphan record) rather than loop or fault. This is a
// reconstruction; crash_boundary_recovery.py drives the real dispatch path and interrupts
// it at that exact point.
//
// Usage:
//   inject-validator-cleanup-record write <db_root> <seed> <retire_seqno> <retire_root_b64> \
//       <retire_file_b64> <dir_wc> <dir_cc> [predelete]
//   inject-validator-cleanup-record check <db_root> <seed>
// Retirement is always a masterchain block id (wc -1, shard 0x8000000000000000); the
// directory shard is 0x8000000000000000 with the given workchain. Session id is derived
// deterministically from <seed>.
#include "validator/consensus/db-path.h"
#include "validator/consensus/validator-cleanup-store.h"

#include "td/db/RocksDb.h"
#include "td/utils/base64.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace tos::validator::consensus;

namespace {
tos::ValidatorSessionId session_from_seed(int seed) {
  tos::ValidatorSessionId sid;
  for (size_t i = 0; i < sid.as_slice().size(); i++) {
    sid.as_slice()[i] = static_cast<char>((seed + static_cast<int>(i) * 7) & 0xFF);
  }
  return sid;
}

bool decode_hash(const std::string& b64, tos::Bits256& out) {
  auto r = td::base64_decode(b64);
  if (r.is_error() || r.ok().size() != 32) {
    return false;
  }
  out.as_slice().copy_from(td::Slice{r.ok()});
  return true;
}
}  // namespace

int main(int argc, char** argv) {
  const tos::ShardId mc_shard = static_cast<tos::ShardId>(0x8000000000000000ULL);

  if (argc >= 4 && std::string(argv[1]) == "check") {
    std::string db_root = argv[2];
    auto sid = session_from_seed(std::atoi(argv[3]));
    auto kv_res = td::RocksDb::open(db_root + "/state");
    if (kv_res.is_error()) {
      std::fprintf(stderr, "ERROR: cannot open StateDb: %s\n", kv_res.error().message().c_str());
      return 1;
    }
    auto kv = kv_res.move_as_ok();
    bool present = false;
    int dir_present = -1;  // -1 = record absent so undefined; 0/1 when the record is present
    for (const auto& r : load_validator_cleanup_records(kv)) {
      if (r.session_id == sid) {
        present = true;
        auto full = consensus_db_root(td::Slice{db_root}) + r.dir_name;
        dir_present = path_is_confirmed_absent(full) ? 0 : 1;
      }
    }
    std::printf("POISON_PRESENT=%d DIR_PRESENT=%d session=%s\n", present ? 1 : 0, dir_present, sid.to_hex().c_str());
    return 0;
  }

  // reset: erase EVERY durable cleanup record so a following injection is the only eligible
  // record (a deterministic slate for the crash-boundary driver). Leftover directories
  // without a record are inert -- the deleter only ever acts on a record.
  if (argc == 3 && std::string(argv[1]) == "reset") {
    std::string db_root = argv[2];
    auto kv_res = td::RocksDb::open(db_root + "/state");
    if (kv_res.is_error()) {
      std::fprintf(stderr, "ERROR: cannot open StateDb: %s\n", kv_res.error().message().c_str());
      return 1;
    }
    auto kv = kv_res.move_as_ok();
    int erased = 0;
    for (const auto& r : load_validator_cleanup_records(kv)) {
      erase_validator_cleanup_record(kv, r.session_id);
      erased++;
    }
    std::printf("RESET erased=%d\n", erased);
    return 0;
  }

  bool predelete = (argc == 10 && std::string(argv[9]) == "predelete");
  if (!((argc == 9 || argc == 10) && std::string(argv[1]) == "write")) {
    std::fprintf(stderr,
                 "usage: %s write <db_root> <seed> <retire_seqno> <retire_root_b64> <retire_file_b64> <dir_wc> "
                 "<dir_cc> [predelete]\n       %s check <db_root> <seed>\n",
                 argv[0], argv[0]);
    return 2;
  }
  std::string db_root = argv[2];
  int seed = std::atoi(argv[3]);
  auto retire_seqno = static_cast<tos::BlockSeqno>(std::strtoul(argv[4], nullptr, 10));
  std::string retire_root_b64 = argv[5];
  std::string retire_file_b64 = argv[6];
  auto dir_wc = static_cast<tos::WorkchainId>(std::atoi(argv[7]));
  auto dir_cc = static_cast<tos::CatchainSeqno>(std::strtoul(argv[8], nullptr, 10));

  tos::Bits256 root_hash, file_hash;
  if (!decode_hash(retire_root_b64, root_hash) || !decode_hash(retire_file_b64, file_hash)) {
    std::fprintf(stderr, "ERROR: retire root/file hash must be base64 of 32 bytes\n");
    return 2;
  }

  auto sid = session_from_seed(seed);
  PendingValidatorConsensusDbCleanup record;
  record.session_id = sid;
  record.retirement_checkpoint = tos::BlockIdExt{tos::masterchainId, mc_shard, retire_seqno, root_hash, file_hash};
  record.dir_name = consensus_db_dir_name(tos::ShardIdFull{dir_wc, mc_shard}, dir_cc, sid, td::Slice(""));

  auto kv_res = td::RocksDb::open(db_root + "/state");
  if (kv_res.is_error()) {
    std::fprintf(stderr, "ERROR: cannot open StateDb at %s/state: %s (is the engine stopped?)\n", db_root.c_str(),
                 kv_res.error().message().c_str());
    return 1;
  }
  auto kv = kv_res.move_as_ok();
  store_validator_cleanup_record(kv, record);

  auto db_dir = consensus_db_root(td::Slice{db_root}) + record.dir_name + "/db/";
  td::mkpath(db_dir).ensure();
  td::write_file(db_dir + "CURRENT", td::Slice{"fixture"}).ensure();

  bool loadable = false;
  for (const auto& r : load_validator_cleanup_records(kv)) {
    if (r.session_id == sid) {
      loadable = true;
    }
  }

  // Crash-boundary-2 reconstruction: run the REAL deleter (the exact function the cleanup
  // worker calls) so the directory is removed while the durable record still stands. This
  // reconstructs the on-disk state left AFTER the directory is physically removed but
  // BEFORE the durable record erase commits -- {dir gone, record present} -- with the
  // production delete function, not a simulated rm. The engine must reconcile it on
  // restart. (The real dispatch-path interruption is exercised by crash_boundary_recovery.py.)
  int dir_gone = 0;
  int loadable_post = loadable ? 1 : 0;  // record readability AFTER the delete (the state that matters)
  if (predelete) {
    // Returns true only on stat-confirmed removal (see delete_validator_consensus_db).
    dir_gone = delete_validator_consensus_db(td::Slice{db_root}, sid, record.dir_name) ? 1 : 0;
    if (!dir_gone) {
      auto full = consensus_db_root(td::Slice{db_root}) + record.dir_name;
      std::fprintf(stderr, "ERROR: predelete did not confirm removal of dir %s\n", full.c_str());
      return 1;
    }
    // Re-read the record AFTER the delete: the reconstructed post-state is only meaningful
    // if the durable record actually survives the directory removal. POISON_LOADABLE alone
    // is a pre-delete read, so prove the post-delete state here.
    loadable_post = 0;
    for (const auto& r : load_validator_cleanup_records(kv)) {
      if (r.session_id == sid) {
        loadable_post = 1;
      }
    }
    if (!loadable_post) {
      std::fprintf(stderr, "ERROR: predelete removed the durable record too (expected record to survive)\n");
      return 1;
    }
  }
  std::printf(
      "INJECTED seed=%d session=%s dir=%s retire_seqno=%u dir_wc=%d dir_cc=%u POISON_LOADABLE=%d PREDELETE_DIR_GONE=%d "
      "POISON_LOADABLE_POST=%d\n",
      seed, sid.to_hex().c_str(), record.dir_name.c_str(), retire_seqno, dir_wc, dir_cc, loadable ? 1 : 0, dir_gone,
      loadable_post);
  return loadable ? 0 : 1;
}
