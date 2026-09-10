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

#include <cerrno>
#include <vector>

#include "td/db/KeyValue.h"
#include "td/db/RocksDb.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "validator/consensus/validator-cleanup.h"

// Key-value persistence for validator cleanup records (Finding 1), kept separate
// from validator-cleanup.h so the pure record/predicate core has no dependency on
// the KeyValue layer. StateDb's methods are thin wrappers over these functions,
// and tests exercise the SAME functions against a real RocksDb -- so disabling a
// write, erase, or scan here fails both production and the tests.
namespace tos::validator::consensus {

// Persist one record under its per-session key (single-key synced write batch).
inline void store_validator_cleanup_record(td::KeyValue& kv, const PendingValidatorConsensusDbCleanup& record) {
  auto key = validator_cleanup_key(record.session_id);
  auto value = encode_validator_cleanup_record(record);
  kv.begin_write_batch().ensure();
  kv.set(td::Slice{key}, td::Slice{value}).ensure();
  kv.commit_write_batch().ensure();
}

// Atomically persist a validator retirement: the destroyed-session fence (already
// encoded by the caller as a single key/value) together with every newly-retiring
// cleanup record, in ONE synced write batch. This is the durable precondition for
// PR B's "persist intent before the actor is allowed to close" flow: if the actor
// may begin retiring, the fence and the cleanup intents are already on disk
// together. The record keys are written directly here (not via
// store_validator_cleanup_record) because that helper opens its own batch and
// RocksDb::begin_write_batch does not nest.
inline void store_validator_retirement(td::KeyValue& kv, td::Slice destroyed_sessions_key,
                                        td::Slice destroyed_sessions_value,
                                        const std::vector<PendingValidatorConsensusDbCleanup>& records) {
  kv.begin_write_batch().ensure();
  kv.set(destroyed_sessions_key, destroyed_sessions_value).ensure();
  for (const auto& record : records) {
    kv.set(td::Slice{validator_cleanup_key(record.session_id)},
           td::Slice{encode_validator_cleanup_record(record)})
        .ensure();
  }
  kv.commit_write_batch().ensure();
}

// Remove one record by session id. Erasing an absent key is a no-op.
inline void erase_validator_cleanup_record(td::KeyValue& kv, const ValidatorSessionId& session_id) {
  auto key = validator_cleanup_key(session_id);
  kv.begin_write_batch().ensure();
  kv.erase(td::Slice{key}).ensure();
  kv.commit_write_batch().ensure();
}

// Load every record via a bracketed prefix range scan. A value that fails the
// strict decode is dropped (a lost record can at worst leak an orphan directory,
// never authorize deleting the wrong one); one bad record does not abort the scan.
inline std::vector<PendingValidatorConsensusDbCleanup> load_validator_cleanup_records(td::KeyValueReader& kv) {
  std::vector<PendingValidatorConsensusDbCleanup> records;
  auto end = validator_cleanup_key_range_end();
  kv.for_each_in_range(validator_cleanup_key_prefix(), td::Slice{end}, [&records](td::Slice key, td::Slice value) {
      auto decoded = decode_validator_cleanup_record(value);
      if (!decoded) {
        return td::Status::OK();
      }
      // The value's session id is checked against its directory name by decode,
      // but the record must ALSO sit under its own key. A record found under a
      // different session's key is inconsistent persistence: drop it, so an
      // erase-by-session (which targets validator_cleanup_key(session_id)) can
      // never leave a mismatched record behind to reappear on the next load.
      if (key != td::Slice{validator_cleanup_key(decoded.value().session_id)}) {
        return td::Status::OK();
      }
      records.push_back(std::move(decoded.value()));
      return td::Status::OK();
    }).ensure();
  return records;
}

// True only when a stat of `full` confirms it is absent (POSIX ENOENT / Windows
// file-or-path-not-found). rmrf ignores unlink/rmdir errors, so its own status is
// not proof of removal -- only a confirmed-absent stat is. Any other stat error
// (e.g. permission) is NOT treated as absent, so an unconfirmed removal reports
// false and the orchestrator retries.
inline bool path_is_confirmed_absent(const std::string& full) {
  auto probe = td::stat(full);
  if (probe.is_ok()) {
    return false;
  }
#if TD_PORT_WINDOWS
  auto code = probe.error().code();
  return code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND;
#else
  return probe.error().code() == ENOENT;
#endif
}

// True only when `resolved` (a realpath result) lies strictly inside `root_real`
// (also a realpath). Any trailing slash on root_real is normalized away first, and
// a boundary '/' is then required so "/a/consensusX" is not treated as inside
// "/a/consensus".
inline bool resolved_path_is_inside(std::string root_real, const std::string& resolved) {
  while (!root_real.empty() && root_real.back() == '/') {
    root_real.pop_back();
  }
  return resolved.size() > root_real.size() + 1 && resolved.compare(0, root_real.size(), root_real) == 0 &&
         resolved[root_real.size()] == '/';
}

// Physically delete a validator group's consensus directory. Does ONLY:
//  - revalidate that dir_name is the exact canonical validator directory for
//    session_id (never trust a persisted path -- reject an observer name, a
//    mismatched session, a non-canonical name, a separator, or a NUL);
//  - CONTAIN the target: the resolved real path of the directory (and of its `db`
//    subdirectory, which DestroyDB opens) must lie strictly inside the resolved
//    consensus root, so a symlink planted in the data dir cannot make DestroyDB or
//    rmrf follow it and delete something outside the root;
//  - destroy the RocksDB and remove the directory, and confirm removal by stat.
// Returns true ONLY on confirmed removal (an already-absent directory counts as
// gone). Performs NO eligibility check: the caller (the cleanup orchestrator,
// B2-6) must have already established -- under the checkpoint-bound four-condition
// rule -- that deleting this session's directory is safe. This is the last step,
// not the decision. It also assumes the consensus root itself is a node-owned,
// trusted directory.
inline bool delete_validator_consensus_db(td::Slice db_root, const ValidatorSessionId& session_id,
                                          const std::string& dir_name) {
  if (!is_canonical_validator_dir_name(dir_name, session_id)) {
    return false;
  }
  auto root = consensus_db_root(db_root);
  auto full = root + dir_name;

  auto r_full = td::realpath(full);
  if (r_full.is_error()) {
    // Cannot resolve: if that is because it is absent, it is already gone;
    // otherwise do not claim removal.
    return path_is_confirmed_absent(full);
  }
  auto r_root = td::realpath(root);
  if (r_root.is_error()) {
    return false;
  }
  auto root_real = r_root.move_as_ok();
  if (!resolved_path_is_inside(root_real, r_full.move_as_ok())) {
    return false;  // the directory resolves outside the consensus root (symlink escape)
  }
  auto r_db = td::realpath(full + "/db");
  if (r_db.is_ok() && !resolved_path_is_inside(root_real, r_db.move_as_ok())) {
    return false;  // the db subdirectory resolves outside the consensus root
  }

  td::RocksDb::destroy(full + "/db/").ignore();
  td::rmrf(full).ignore();
  return path_is_confirmed_absent(full);
}

}  // namespace tos::validator::consensus
