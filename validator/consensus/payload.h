/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "auto/tl/tos_api.h"
#include "td/utils/Status.h"

namespace tos::validator::consensus {

namespace tl {

using payload = tos_api::validatorSession_candidate;

}  // namespace tl

td::Result<td::BufferSlice> serialize_payload(const tl_object_ptr<tl::payload>& payload);
td::Result<tl_object_ptr<tl::payload>> deserialize_payload(td::Slice data, int max_decompressed_data_size);

}  // namespace tos::validator::consensus
