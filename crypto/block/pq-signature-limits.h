/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstddef>

#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-consensus.h"

namespace block::pq {

inline constexpr std::size_t pq_block_signatures_max_signers = tos::pq::PQConsensusLimits{}.max_certificate_signers;
inline constexpr std::size_t pq_block_signature_bytes = tos::pq::mldsa44_signature_bytes;

// The canonical 400-signer block_signatures_simplex_pq#13 BOC is 1,020,996
// bytes, and its measured BlockProof is 1,021,088 bytes: the proof root adds 92
// bytes. The next clean binary boundary is one MiB, leaving 27,488 bytes above
// the measured proof, about 10.8 signer-equivalents at the measured ~2,552 bytes
// per additional signer. One MiB remains below FullNode's 4 MiB proof ceiling
// and the overlay's 16 MiB FEC-broadcast ceiling.
inline constexpr std::size_t pq_block_signatures_hard_max_bytes = 1U << 20;
inline constexpr std::size_t pq_candidate_data_max_bytes = 1024;

// Exact generated-TL size of the frozen 400-signer
// tosNode.blockFinalityBroadcast carrier. The carrier-capacity gate serializes
// the real object and compares it with this value; pending unverified evidence
// budgets use the same measurement instead of a rounded MiB share.
inline constexpr std::size_t pq_block_finality_broadcast_max_bytes = 984260;

static_assert(pq_block_signatures_max_signers == 400);
static_assert(pq_block_signature_bytes == 2420);

inline constexpr bool pq_block_signatures_accepts_signer_count(std::size_t count) {
  return count <= pq_block_signatures_max_signers;
}

// No production #13 decoder exists yet, so this predicate currently has no
// production consumer. The parsing unit must call it at the external byte
// boundary before parsing or verification and re-point the ordering test there.
inline constexpr bool pq_block_signatures_accepts_serialized_size(std::size_t bytes) {
  return bytes <= pq_block_signatures_hard_max_bytes;
}

}  // namespace block::pq
