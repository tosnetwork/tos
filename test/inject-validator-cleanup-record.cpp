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
// ACCEPTANCE-ONLY negative-test injector. Writes ONE deliberately INELIGIBLE validator
// consensus-DB cleanup record into a (stopped) node's StateDb and creates its canonical
// consensus directory, so a subsequent armed run can prove the four-condition safety gate
// REFUSES to delete it (no VALCLEANUP reserve for it; the directory is retained).
//
// The injected record is ineligible on two independent conditions:
//   * retirement_checkpoint is a FUTURE masterchain block (huge seqno) -> can never be an
//     ancestor-or-equal of any GC floor the node reaches (fails condition B);
//   * the directory's catchain seqno is FUTURE (huge) -> r < g is false, i.e. not on-chain
//     obsolete (fails condition C).
//
// Usage:  inject-validator-cleanup-record <node_db_root>
// Writes to <node_db_root>/state (StateDb RocksDB) and creates
// <node_db_root>/consensus/consensus.0.<mcshard>.<cc>.<session_hex>/db/CURRENT.
// The node engine MUST be stopped (RocksDB holds a single-process lock). Prints the
// injected session hex and dir so a harness/analyzer can assert on exactly them.
#include "validator/consensus/db-path.h"
#include "validator/consensus/validator-cleanup-store.h"

#include "td/db/RocksDb.h"
#include "td/utils/Slice.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"

#include <cstdio>
#include <string>

using namespace tos::validator::consensus;

int main(int argc, char** argv) {
  // Modes:
  //   inject-validator-cleanup-record <node_db_root>            write poison + create dir + readback
  //   inject-validator-cleanup-record --check <node_db_root>    readback only (post-run: is poison still present?)
  bool check_only = false;
  std::string db_root;
  if (argc == 2) {
    db_root = argv[1];
  } else if (argc == 3 && std::string(argv[1]) == "--check") {
    check_only = true;
    db_root = argv[2];
  } else {
    std::fprintf(stderr, "usage: %s [--check] <node_db_root>\n", argv[0]);
    return 2;
  }

  // Deterministic "poison" session id (all 0xEE) so a harness/analyzer knows exactly
  // what to look for.
  tos::ValidatorSessionId sid;
  for (size_t i = 0; i < sid.as_slice().size(); i++) {
    sid.as_slice()[i] = static_cast<char>(0xEE);
  }
  const tos::ShardId mc_shard = static_cast<tos::ShardId>(0x8000000000000000ULL);
  const tos::ShardIdFull shard{0, mc_shard};
  const tos::CatchainSeqno future_cc = 9000000;  // future cc -> r < g is false

  // Future masterchain retirement block, valid-full (non-zero hashes) but non-ancestor.
  tos::Bits256 root_hash, file_hash;
  for (size_t i = 0; i < root_hash.as_slice().size(); i++) {
    root_hash.as_slice()[i] = static_cast<char>(0xA0 + (i % 16));
    file_hash.as_slice()[i] = static_cast<char>(0x0B + (i % 16));
  }
  const tos::BlockIdExt retire{tos::masterchainId, mc_shard, 9000000u, root_hash, file_hash};

  PendingValidatorConsensusDbCleanup record;
  record.session_id = sid;
  record.retirement_checkpoint = retire;
  record.dir_name = consensus_db_dir_name(shard, future_cc, sid, td::Slice(""));

  auto kv_res = td::RocksDb::open(db_root + "/state");
  if (kv_res.is_error()) {
    std::fprintf(stderr, "ERROR: cannot open StateDb at %s/state: %s (is the engine stopped?)\n", db_root.c_str(),
                 kv_res.error().message().c_str());
    return 1;
  }
  auto kv = kv_res.move_as_ok();

  auto poison_is_loadable = [&]() {
    // Load via the SAME production decode path the engine uses at startup; the poison
    // counts only if it decodes AND its session matches (i.e. the engine WILL load it).
    for (const auto& r : load_validator_cleanup_records(kv)) {
      if (r.session_id == sid) {
        return true;
      }
    }
    return false;
  };

  if (check_only) {
    // Post-run: a wrongful cleanup would have erased the durable record. Its survival
    // (plus the surviving dir, checked by the caller) is session-specific refusal evidence.
    bool present = poison_is_loadable();
    std::printf("POISON_PRESENT=%d session=%s\n", present ? 1 : 0, sid.to_hex().c_str());
    return 0;
  }

  store_validator_cleanup_record(kv, record);

  auto db_dir = consensus_db_root(td::Slice{db_root}) + record.dir_name + "/db/";
  td::mkpath(db_dir).ensure();
  td::write_file(db_dir + "CURRENT", td::Slice{"poison"}).ensure();

  // Read back through the production decoder so a PASS cannot be vacuous: if this is 0 the
  // engine would never load the record and "not reserved" would prove nothing.
  int loadable = poison_is_loadable() ? 1 : 0;
  std::printf("INJECTED session=%s dir=%s retirement_seqno=9000000 cc=9000000 POISON_LOADABLE=%d\n", sid.to_hex().c_str(),
              record.dir_name.c_str(), loadable);
  return loadable ? 0 : 1;
}
