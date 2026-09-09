/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <string>

#include "td/utils/JsonBuilder.h"
#include "td/utils/Slice.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/int_types.h"

namespace tos {

// Builders for the getSigningPayload response JSON.
//
// The embedded `payload` is the base64 of the serialized external message,
// whose size is bounded only by the per-component BOC limits — several
// independently checked components (body, init_code, init_data) can combine
// into a message well past 128 KiB. These builders use a growable
// td::StringBuilder rather than PSTRING(), whose fixed 128 KiB Logger buffer
// would silently truncate a large response into invalid JSON / a corrupt
// signing payload (the truncation sets an error flag that Stringify does not
// surface, and an outer growable builder cannot repair an already-truncated
// string). td::StringBuilder cannot truncate.

// Delegation branch: carries the delegation reference, no chain id.
inline std::string build_delegation_signing_payload_json(td::Slice payload_b64, td::Slice delegation_ref) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"transaction.signingPayload\""
     << ",\"payload_version\":1"
     << ",\"payload_encoding\":\"boc_base64\""
     << ",\"payload\":" << td::JsonString(payload_b64) << ",\"delegation_ref\":" << td::JsonString(delegation_ref)
     << ",\"replay_protection\":{\"@type\":\"transaction.replayProtection\""
     << ",\"mode\":\"contract_defined\"}"
     << "}";
  return sb.as_cslice().str();
}

// Normal branch: carries the resolved chain id, no delegation reference.
inline std::string build_signing_payload_json(td::Slice payload_b64, td::int64 chain_id) {
  td::StringBuilder sb;
  sb << "{\"@type\":\"transaction.signingPayload\""
     << ",\"payload_version\":1"
     << ",\"payload_encoding\":\"boc_base64\""
     << ",\"payload\":" << td::JsonString(payload_b64) << ",\"chain_id\":" << chain_id
     << ",\"replay_protection\":{\"@type\":\"transaction.replayProtection\""
     << ",\"mode\":\"contract_defined\"}"
     << "}";
  return sb.as_cslice().str();
}

}  // namespace tos
