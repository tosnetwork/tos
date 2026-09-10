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

#include <functional>
#include <optional>
#include <set>
#include <string>

#include "td/utils/PathView.h"
#include "td/utils/Slice.h"
#include "td/utils/misc.h"
#include "td/utils/port/path.h"
#include "tos/tos-types.h"

namespace tos::validator::consensus {

// Directory holding the per-group consensus databases.
inline std::string consensus_db_root(td::Slice db_root) {
  return PSTRING() << db_root << "/consensus/";
}

// One directory per validator group, named so the session it belongs to can
// be recovered from the name alone. That recovery is what lets a sweep at
// startup tell an abandoned directory from a live one, so the two sides are
// kept together here rather than each spelling out the format.
inline std::string consensus_db_dir_name(ShardIdFull shard, CatchainSeqno catchain_seqno,
                                         ValidatorSessionId session_id, td::Slice db_suffix) {
  return PSTRING() << "consensus." << shard.workchain << "." << shard.shard << "." << catchain_seqno << "."
                   << session_id.to_hex() << db_suffix;
}

// Recovers the session id from a directory name produced above, or nothing
// when the name did not come from there. A name this cannot parse is left
// alone: an unrecognised directory is not ours to delete.
inline std::optional<ValidatorSessionId> consensus_db_session_id(td::Slice dir_name) {
  std::string name = dir_name.str();
  if (name.rfind("consensus.", 0) != 0) {
    return std::nullopt;
  }
  // The hex session id is the fourth dot-separated field; anything after it
  // is the optional suffix, which may itself contain dots.
  size_t start = std::string::npos;
  int dots = 0;
  for (size_t i = 0; i < name.size(); i++) {
    if (name[i] == '.') {
      dots++;
      if (dots == 4) {
        start = i + 1;
        break;
      }
    }
  }
  if (start == std::string::npos) {
    return std::nullopt;
  }
  constexpr size_t kHexLength = 64;
  if (name.size() < start + kHexLength) {
    return std::nullopt;
  }
  auto hex = name.substr(start, kHexLength);
  ValidatorSessionId session_id;
  if (session_id.as_slice().size() * 2 != hex.size()) {
    return std::nullopt;
  }
  auto decoded = td::hex_decode(td::Slice(hex));
  if (decoded.is_error()) {
    return std::nullopt;
  }
  auto bytes = decoded.move_as_ok();
  if (bytes.size() != session_id.as_slice().size()) {
    return std::nullopt;
  }
  session_id.as_slice().copy_from(td::Slice(bytes));
  return session_id;
}

struct ConsensusDbSweepStats {
  size_t reclaimed = 0;  // directories confirmed deleted this pass
  size_t failed = 0;     // deletions attempted but not confirmed gone (kept queued)
  bool walk_succeeded = false;
};

// Reclaim per-group consensus directories under `db_root`/consensus. A directory
// is deleted if its name is in `pending` (the durable cleanup queue) or, as a
// legacy fallback for databases written before the queue existed, if its parsed
// session id is in `destroyed`. `delete_dir(full_path)` must attempt the removal
// and return true only when the directory is confirmed gone (e.g. via stat).
//
// `pending` is updated in place: a confirmed-deleted name is removed; a name
// whose deletion was not confirmed but was already queued stays queued (a legacy
// destroyed-session name is deliberately NOT added to the queue on failure, so
// validator directories never gain queue-based deletion authority); and -- only
// if the walk fully succeeded -- a queued name not present on disk is dropped (it
// was deleted before a crash lost the dequeue). An incomplete/failed walk proves
// nothing about absence, so no reconciliation is done then. A name this cannot
// parse is left alone.
inline ConsensusDbSweepStats sweep_orphaned_consensus_dbs(
    td::Slice db_root, std::set<std::string>& pending, const std::set<ValidatorSessionId>& destroyed,
    const std::function<bool(td::CSlice full_path)>& delete_dir) {
  ConsensusDbSweepStats stats;
  auto root = consensus_db_root(db_root);
  std::set<std::string> seen;
  auto walk_status = td::WalkPath::run(root, [&](td::CSlice path, td::WalkPath::Type type) {
    if (type != td::WalkPath::Type::EnterDir) {
      return td::WalkPath::Action::Continue;
    }
    auto name = td::PathView(path).file_name().str();
    if (name.empty() || path.str() == root || path.str() + "/" == root) {
      return td::WalkPath::Action::Continue;
    }
    seen.insert(name);
    auto session_id = consensus_db_session_id(name);
    bool queued = pending.count(name) > 0;
    bool legacy = session_id && destroyed.count(session_id.value()) > 0;
    if (!queued && !legacy) {
      // Not ours, or still live: do not descend into a database we may open.
      return td::WalkPath::Action::SkipDir;
    }
    if (delete_dir(path)) {
      stats.reclaimed++;
      pending.erase(name);
    } else {
      stats.failed++;
      // Do NOT newly queue a directory that is here only via the legacy
      // destroyed-session gate (a validator directory). Its retry stays gated on
      // the tombstone, exactly as before this change, so it can never be deleted
      // through the queue after the tombstone is pruned -- which could otherwise
      // destroy the consensus state of a session that is recreated. An
      // already-queued directory (an observer) simply stays queued (it was not
      // erased above), so a failed observer deletion is retried next sweep.
    }
    return td::WalkPath::Action::SkipDir;
  });
  stats.walk_succeeded = walk_status.is_ok();
  if (stats.walk_succeeded) {
    for (auto it = pending.begin(); it != pending.end();) {
      if (seen.count(*it) == 0) {
        it = pending.erase(it);
      } else {
        ++it;
      }
    }
  }
  return stats;
}

}  // namespace tos::validator::consensus
