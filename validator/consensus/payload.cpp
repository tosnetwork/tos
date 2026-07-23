/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "validator-session/candidate-serializer.h"

#include "payload.h"

namespace tos::validator::consensus {

td::Result<td::BufferSlice> serialize_payload(const tl_object_ptr<tl::payload>& payload) {
  return validatorsession::serialize_candidate(payload, true);
}

td::Result<tl_object_ptr<tl::payload>> deserialize_payload(td::Slice data, int max_decompressed_data_size) {
  return validatorsession::deserialize_candidate(data, true, max_decompressed_data_size);
}

}  // namespace tos::validator::consensus
