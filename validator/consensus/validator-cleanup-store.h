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

#include <vector>

#include "td/db/KeyValue.h"
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

}  // namespace tos::validator::consensus
