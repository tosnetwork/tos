/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
// Canonical bounded-bytes -> cell tree for PQ objects that do not fit one cell
// (ML-DSA-44 public key 1312 B, signature 2420 B, > the 127-byte cell payload).
// A given byte string encodes to exactly one tree; unpack rejects any non-canonical
// tree, oversize (> max_bytes), or trailing bits/refs. The root cell holds the u32
// byte length; data is a greedy 127-byte snake (each cell full except the last).
#include <cstddef>

#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "vm/cells/Cell.h"

namespace tos::pq {
inline constexpr std::size_t pq_bytes_chunk = 127;  // max whole bytes in one cell payload

// Absolute structural ceiling, enforced independently of the caller's max_bytes and
// before any allocation or traversal. A caller limit can only ever be more strict:
// the effective bound is min(max_bytes, pq_bytes_hard_max). This exists so a wrong or
// hostile caller limit cannot turn the u32 length field into a 4 GiB allocation or an
// unbounded snake walk. The largest PQ object today is the ML-DSA-44 signature
// (2420 B); this ceiling bounds a value to 8 KiB and its snake to 65 cells.
inline constexpr std::size_t pq_bytes_hard_max = 8192;

td::Result<td::Ref<vm::Cell>> pack_pq_bytes(td::Slice data, std::size_t max_bytes);
td::Result<td::BufferSlice> unpack_pq_bytes(td::Ref<vm::Cell> root, std::size_t max_bytes);
}  // namespace tos::pq
