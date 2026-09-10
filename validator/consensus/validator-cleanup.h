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

#include <array>
#include <charconv>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "td/utils/Slice.h"
#include "tos/tos-types.h"
#include "validator/consensus/db-path.h"

// Validator-group consensus-DB cleanup (Finding 1).
//
// Unlike the observer cleanup queue (db-path.h), a validator consensus DB holds
// own-votes and leader-window recovery state, so deleting one for a session that
// can still be legally recreated would destroy live consensus state. Deletion
// authority therefore cannot be "this directory name was queued"; it must be
// bound to a checkpoint that proves the session is permanently retired.
//
// This header is the observational core (PR A): the durable record, its strict
// encoding, and the *pure* deletion predicate. It is consulted by nothing in the
// retirement/sweep paths yet -- enabling deletion is PR B. Keeping the predicate
// pure and header-only lets the safety logic be proven with falsifiable tests,
// independent of the actor/DB stack.
namespace tos::validator::consensus {

// One durable cleanup intent: a validator session, the masterchain checkpoint at
// which it was retired, and the exact directory to reclaim once that retirement
// is proven permanent.
struct PendingValidatorConsensusDbCleanup {
  ValidatorSessionId session_id;
  BlockIdExt retirement_checkpoint;  // full BlockIdExt, not a bare seqno
  std::string dir_name;

  bool operator==(const PendingValidatorConsensusDbCleanup& o) const {
    return session_id == o.session_id && retirement_checkpoint == o.retirement_checkpoint && dir_name == o.dir_name;
  }
};

namespace detail {
constexpr uint8_t kValidatorCleanupRecordVersion = 1;
// version(1) + session_id(32) + workchain(4) + shard(8) + seqno(4) + root(32) + file(32)
constexpr size_t kValidatorCleanupFixedPrefix = 1 + 32 + 4 + 8 + 4 + 32 + 32;

inline void put_u32_le(std::string& out, uint32_t v) {
  for (int i = 0; i < 4; i++) {
    out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
  }
}
inline void put_u64_le(std::string& out, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
  }
}
inline uint32_t get_u32_le(const unsigned char* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t get_u64_le(const unsigned char* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) {
    v |= static_cast<uint64_t>(p[i]) << (8 * i);
  }
  return v;
}

// Parse an entire field as an integer, rejecting empty input, stray characters,
// leading '+', and anything std::from_chars cannot fully consume. Non-canonical
// forms (e.g. leading zeros) survive parsing here but are rejected by the
// canonical re-render comparison in is_canonical_validator_dir_name.
template <typename Int>
inline bool parse_full_int(const std::string& s, Int& out) {
  if (s.empty()) {
    return false;
  }
  const char* begin = s.data();
  const char* end = s.data() + s.size();
  auto [ptr, ec] = std::from_chars(begin, end, out);
  return ec == std::errc() && ptr == end;
}
}  // namespace detail

// True only for a canonical validator (non-observer) consensus directory basename
// whose session id is exactly `sid`. The authority is: parse the three numeric
// fields, then require that re-rendering the canonical name equals the input.
// That single equality rejects any trailing suffix or garbage, any separator or
// NUL, any non-canonical numeric form, and any session-hex mismatch -- none of
// which a directory we may later delete can contain.
inline bool is_canonical_validator_dir_name(const std::string& name, const ValidatorSessionId& sid) {
  std::array<size_t, 4> dot{};
  size_t found = 0;
  size_t pos = 0;
  while (found < 4) {
    pos = name.find('.', pos);
    if (pos == std::string::npos) {
      return false;
    }
    dot[found++] = pos;
    pos++;
  }
  if (name.compare(0, dot[0], "consensus") != 0) {
    return false;
  }
  std::string f_wc = name.substr(dot[0] + 1, dot[1] - dot[0] - 1);
  std::string f_shard = name.substr(dot[1] + 1, dot[2] - dot[1] - 1);
  std::string f_cc = name.substr(dot[2] + 1, dot[3] - dot[2] - 1);
  int32_t wc = 0;
  uint64_t shard = 0;
  uint32_t cc = 0;
  if (!detail::parse_full_int(f_wc, wc) || !detail::parse_full_int(f_shard, shard) ||
      !detail::parse_full_int(f_cc, cc)) {
    return false;
  }
  auto canonical = consensus_db_dir_name(ShardIdFull{wc, static_cast<ShardId>(shard)},
                                         static_cast<CatchainSeqno>(cc), sid, td::Slice(""));
  return canonical == name;
}

// A cleanup checkpoint must be a fully specified MASTERCHAIN block. is_valid_full
// alone also accepts shardchain blocks, which are not a retirement/replay anchor.
inline bool is_full_masterchain_checkpoint(const BlockIdExt& b) {
  return b.is_masterchain() && b.is_valid_full();
}

// Persistence keys. Each record lives under its own key (prefix + session hex) so
// one retirement or one completed deletion is a single-key write/erase, never a
// whole-table rewrite. The prefix ends in '.'; the 64-char lowercase session hex
// that follows is always > '.', so incrementing the prefix's last byte gives an
// exclusive upper bound that brackets exactly these records for a range scan.
inline td::Slice validator_cleanup_key_prefix() {
  return td::Slice{"tos.state.pending_validator_consensus_db_cleanup."};
}
inline std::string validator_cleanup_key(const ValidatorSessionId& session_id) {
  return PSTRING() << validator_cleanup_key_prefix() << session_id.to_hex();
}
inline std::string validator_cleanup_key_range_end() {
  std::string end = validator_cleanup_key_prefix().str();
  end.back() = static_cast<char>(static_cast<unsigned char>(end.back()) + 1);
  return end;
}

// Deterministic, architecture-independent (little-endian) encoding of one record.
// The format is versioned so a future reader can reject or migrate old records
// rather than silently misread them.
inline std::string encode_validator_cleanup_record(const PendingValidatorConsensusDbCleanup& r) {
  std::string out;
  out.reserve(detail::kValidatorCleanupFixedPrefix + r.dir_name.size());
  out.push_back(static_cast<char>(detail::kValidatorCleanupRecordVersion));
  auto sid = r.session_id.as_slice();
  out.append(sid.data(), sid.size());
  detail::put_u32_le(out, static_cast<uint32_t>(r.retirement_checkpoint.id.workchain));
  detail::put_u64_le(out, static_cast<uint64_t>(r.retirement_checkpoint.id.shard));
  detail::put_u32_le(out, r.retirement_checkpoint.id.seqno);
  auto rh = r.retirement_checkpoint.root_hash.as_slice();
  auto fh = r.retirement_checkpoint.file_hash.as_slice();
  out.append(rh.data(), rh.size());
  out.append(fh.data(), fh.size());
  out += r.dir_name;
  return out;
}

// Strict decode. Returns nothing on any inconsistency -- a malformed safety
// record must never be trusted. For a cleanup-authority record the safe failure
// is to DROP it (at worst an orphan directory leaks, which is recoverable),
// never to fabricate authority to delete. The decoded dir_name must be a
// parseable validator (non-observer) consensus directory whose session id
// matches the record, or the record is rejected.
inline std::optional<PendingValidatorConsensusDbCleanup> decode_validator_cleanup_record(td::Slice value) {
  if (value.size() < detail::kValidatorCleanupFixedPrefix) {
    return std::nullopt;
  }
  const auto* p = reinterpret_cast<const unsigned char*>(value.data());
  if (p[0] != detail::kValidatorCleanupRecordVersion) {
    return std::nullopt;
  }
  PendingValidatorConsensusDbCleanup r;
  size_t off = 1;
  if (r.session_id.as_slice().size() != 32) {
    return std::nullopt;
  }
  r.session_id.as_slice().copy_from(td::Slice(reinterpret_cast<const char*>(p + off), 32));
  off += 32;
  auto workchain = static_cast<int32_t>(detail::get_u32_le(p + off));
  off += 4;
  auto shard = detail::get_u64_le(p + off);
  off += 8;
  auto seqno = detail::get_u32_le(p + off);
  off += 4;
  RootHash root_hash;
  FileHash file_hash;
  root_hash.as_slice().copy_from(td::Slice(reinterpret_cast<const char*>(p + off), 32));
  off += 32;
  file_hash.as_slice().copy_from(td::Slice(reinterpret_cast<const char*>(p + off), 32));
  off += 32;
  r.retirement_checkpoint = BlockIdExt{workchain, static_cast<ShardId>(shard), seqno, root_hash, file_hash};
  r.dir_name = value.substr(off).str();

  // The checkpoint must be a fully specified masterchain block, and the directory
  // must be the exact canonical validator directory for this session id. Anything
  // else is not a record we could ever safely act on, so drop it.
  if (!is_full_masterchain_checkpoint(r.retirement_checkpoint)) {
    return std::nullopt;
  }
  if (!is_canonical_validator_dir_name(r.dir_name, r.session_id)) {
    return std::nullopt;
  }
  return r;
}

// Build the cleanup record for a retiring validator group. The directory name is
// the canonical VALIDATOR name (empty suffix) for this session, matching exactly
// what the bridge's db_path() produces for a validator group, so a later cleanup
// acts on the real directory. `catchain_seqno` must be the group's catchain seqno
// (the same value the bridge derives from its validator set). The result always
// satisfies the decode contract (canonical name, masterchain checkpoint) when the
// checkpoint is a full masterchain block.
inline PendingValidatorConsensusDbCleanup make_validator_cleanup_record(const ValidatorSessionId& session_id,
                                                                        ShardIdFull shard,
                                                                        CatchainSeqno catchain_seqno,
                                                                        const BlockIdExt& retirement_checkpoint) {
  PendingValidatorConsensusDbCleanup record;
  record.session_id = session_id;
  record.retirement_checkpoint = retirement_checkpoint;
  record.dir_name = consensus_db_dir_name(shard, catchain_seqno, session_id, td::Slice(""));
  return record;
}

// Ancestry of the retirement checkpoint relative to the safe checkpoint on the
// accepted masterchain. Unknown is distinct from NotAncestor: an oracle that
// cannot resolve the relation (handle gone, foreign branch) must report Unknown,
// and the predicate below fails closed on it.
enum class CleanupAncestry { Ancestor, NotAncestor, Unknown };

using CleanupAncestryOracle =
    std::function<CleanupAncestry(const BlockIdExt& retirement, const BlockIdExt& safe_checkpoint)>;

// The pure deletion predicate. A validator consensus DB may be deleted only when
// the session is not currently live/recreatable AND its retirement checkpoint is
// the safe checkpoint or a verified ancestor of it. Every uncertain case -- an
// invalid checkpoint, unknown ancestry, a different branch -- returns false
// (retain). This is the single place the safety decision is made.
inline bool can_delete_validator_db(const PendingValidatorConsensusDbCleanup& record,
                                    const BlockIdExt& safe_checkpoint, bool session_is_live,
                                    const CleanupAncestryOracle& ancestry_of) {
  if (session_is_live) {
    return false;
  }
  if (!is_full_masterchain_checkpoint(record.retirement_checkpoint) ||
      !is_full_masterchain_checkpoint(safe_checkpoint)) {
    return false;
  }
  if (record.retirement_checkpoint == safe_checkpoint) {
    return true;
  }
  return ancestry_of(record.retirement_checkpoint, safe_checkpoint) == CleanupAncestry::Ancestor;
}

// Monotonic adoption of a new safe checkpoint. The safe checkpoint must never
// regress (a later-loaded older init block must not lower it), so a candidate is
// adopted only when there is no current checkpoint or the candidate is a verified
// strict descendant of the current one. Unknown ancestry or a non-descendant
// candidate is refused -- the safe checkpoint holds.
inline bool should_adopt_safe_checkpoint(const BlockIdExt& current, const BlockIdExt& candidate,
                                         const CleanupAncestryOracle& ancestry_of) {
  if (!is_full_masterchain_checkpoint(candidate)) {
    return false;
  }
  if (!is_full_masterchain_checkpoint(current)) {
    return true;
  }
  if (current == candidate) {
    return false;
  }
  // candidate adopted only if current is an ancestor of candidate (candidate is
  // strictly ahead on the same accepted chain).
  return ancestry_of(current, candidate) == CleanupAncestry::Ancestor;
}

}  // namespace tos::validator::consensus
