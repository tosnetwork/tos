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

#include "td/utils/Slice.h"
#include "td/utils/misc.h"
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

}  // namespace tos::validator::consensus
