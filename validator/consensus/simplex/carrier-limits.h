/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

// The hard structural size a post-quantum Simplex protocol message may reach, and the
// per-peer transport allowance that must carry it once framed.
//
// A single ML-DSA-44 signature is 2420 bytes, so one signed vote (~2472 B) already
// exceeds the current direct-message carrier: `Overlays::max_message_size() ==
// adnl::Adnl::get_mtu() - 36`, and `adnl::Adnl::get_mtu()` is 1024 (adnl/adnl.h), so the
// limit is 988 bytes. (This is not `AdnlNetworkManager::get_mtu()`, a different 1440-byte
// network-datagram constant.) The post-quantum conversion raises the consensus peer stream allowance to carry
// these; this header is the one place the ceiling is written, so the transport guard, the
// inbound size check and the tests cannot silently disagree.
//
// This is a HARD STRUCTURAL bound, not the launch policy. Launch policy may choose a smaller
// `max_certificate_bytes` / validator count inside it, but nothing may exceed this
// envelope without a protocol change. Measured exactly by
// `test/pq-native/simplex-carrier-measure.cpp` (cert400 = 972856 B) and derived below from
// the structural signer ceiling so it cannot drift from the encoding.

#include <cstddef>

#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-consensus.h"

namespace tos::validator::consensus::simplex {

// The exact serialized worst case, derived from the TL encoding so a change to either
// side is caught by the static_assert rather than by a validator in production:
//   - a boxed `consensus.simplex.voteSignature` = constructor id (4) + who:int (4) +
//     signature:bytes (4-byte length prefix + 2420, no padding since 2420 % 4 == 0) =
//     2432 bytes; the vote-signature vector is bare, writing only a 32-bit element count.
//   - the enclosing `consensus.simplex.certificate` frame = certificate ctor id (4) +
//     one boxed UnsignedVote (notarize/finalize is the largest at 44) + voteSignatureSet
//     ctor id (4) + vector length (4) = 56 bytes.
inline constexpr std::size_t kVoteSignatureMaxBytes = 4 + 4 + 4 + tos::pq::mldsa44_signature_bytes;  // 2432
inline constexpr std::size_t kCertificateFrameBytes = 4 + 44 + 4 + 4;                                // 56

// The structural signer ceiling, taken directly from the frozen limits so the two cannot
// drift: raising that field raises this, and once the raised value no longer fits the
// frozen envelope the static_assert below fails and forces a deliberate re-measure and
// peer-MTU resize. (A rise that still fits the envelope is carried without change; the
// first ceiling that fails the assert against a 1,000,000-byte envelope is 412 signers.)
inline constexpr std::size_t kMaxCertificateSigners = tos::pq::PQConsensusLimits{}.max_certificate_signers;

// The frozen hard maximum for one inner Simplex protocol message. A clean ceiling above
// the exact worst-case certificate, with headroom for the small per-vote header. An
// inbound message larger than this is refused before it is parsed.
inline constexpr std::size_t simplex_protocol_hard_max_bytes = 1'000'000;

static_assert(kCertificateFrameBytes + kMaxCertificateSigners * kVoteSignatureMaxBytes <=
                  simplex_protocol_hard_max_bytes,
              "the frozen Simplex carrier hard max no longer covers a certificate at the structural signer ceiling; "
              "re-measure and raise it deliberately, and re-size the peer-MTU allowance");

// Framing added below the inner message on the direct path, each layer read from source
// so the peer allowance covers what the transport actually checks its limit against:
//   - `overlay.message` prepends a 4-byte ctor id + 32-byte overlay id = 36 bytes (this
//     is the 36 `Overlays::max_message_size()` already subtracts).
//   - the selected AdnlSenderEx then wraps that whole buffer once more, and its inbound
//     stream/transfer limit is checked against the wrapped size:
//       QUIC  `quic.message data:bytes`        = 4 ctor + 4 length             =  8 B
//       RLDP2 `rldp.message id:int256 data`    = 4 ctor + 32 id + 4 length     = 40 B
//     The consensus path uses the QUIC sender, but the allowance covers the larger RLDP
//     wrapper so either transport fits; a 4-byte alignment margin absorbs padding.
inline constexpr std::size_t kOverlayMessagePrefixBytes = 36;
inline constexpr std::size_t kTransportWrapperMaxBytes = 40;  // max(quic.message 8, rldp.message 40)
inline constexpr std::size_t kTransportAlignmentBytes = 4;

// The bounded per-peer transport allowance the QUIC/ADNL guard installs for consensus
// peers. It is checked against the fully wrapped stream (inner + overlay + transport
// wrapper), so it must cover all of them, not just the inner message.
inline constexpr std::size_t simplex_carrier_peer_mtu_bytes =
    simplex_protocol_hard_max_bytes + kOverlayMessagePrefixBytes + kTransportWrapperMaxBytes + kTransportAlignmentBytes;

// The inbound gate: an inner Simplex protocol message above the hard max is rejected
// before parsing, independently of the transport stream cap.
inline constexpr bool simplex_carrier_accepts(std::size_t inner_message_bytes) {
  return inner_message_bytes <= simplex_protocol_hard_max_bytes;
}

}  // namespace tos::validator::consensus::simplex
