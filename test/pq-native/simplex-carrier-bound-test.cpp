/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The frozen Simplex carrier hard bound, held by a test that fails if the bound
// stops covering a real certificate at the structural signer ceiling.
//
// The measurement program prints the numbers; this pins them. It builds the exact
// 400-signer certificate the node will send (a 2420-byte buffer per signer serializes to
// the same bytes as a real signature, since TL length depends only on size) and requires
// it to fit under `simplex_protocol_hard_max_bytes`. Lower the bound below the real
// certificate and this goes red.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include "auto/tl/tos_api.h"
#include "crypto/pq/mldsa44.h"
#include "tl-utils/tl-utils.hpp"
#include "validator/consensus/simplex/carrier-limits.h"

namespace {

namespace carrier = tos::validator::consensus::simplex;

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

tos::tl_object_ptr<tos::tos_api::consensus_simplex_notarizeVote> a_notarize_vote() {
  return tos::create_tl_object<tos::tos_api::consensus_simplex_notarizeVote>(
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(1789434, fill(0x5a)));
}

td::BufferSlice serialized_certificate(std::size_t signers) {
  // A signature-shaped buffer: the serialized size depends only on its length, so this is
  // the exact wire size a real ML-DSA-44 certificate of this many signers reaches.
  td::BufferSlice signature(tos::pq::mldsa44_signature_bytes);
  std::memset(signature.data(), 0x7c, signature.size());
  std::vector<tos::tl_object_ptr<tos::tos_api::consensus_simplex_voteSignature>> votes;
  votes.reserve(signers);
  for (std::size_t who = 0; who < signers; ++who) {
    votes.push_back(tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignature>(static_cast<std::int32_t>(who),
                                                                                         signature.clone()));
  }
  auto cert = tos::create_tl_object<tos::tos_api::consensus_simplex_certificate>(
      a_notarize_vote(), tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignatureSet>(std::move(votes)));
  return tos::serialize_tl_object(cert, true);
}

std::size_t certificate_bytes(std::size_t signers) {
  return serialized_certificate(signers).size();
}

}  // namespace

int main() {
  // max / max+1: the gate accepts exactly the hard max and refuses one byte more.
  assert(carrier::simplex_carrier_accepts(carrier::simplex_protocol_hard_max_bytes) &&
         "the carrier must accept a message of exactly the hard max");
  assert(!carrier::simplex_carrier_accepts(carrier::simplex_protocol_hard_max_bytes + 1) &&
         "the carrier must refuse a message one byte over the hard max");
  assert(!carrier::simplex_carrier_accepts(carrier::simplex_protocol_hard_max_bytes + 1000) &&
         "the carrier must refuse a message well over the hard max");

  // The real certificate at the structural signer ceiling fits, and does so with the exact size
  // the derivation in carrier-limits.h predicts (a drift on either side fails here).
  const std::size_t cert_ceiling = certificate_bytes(carrier::kMaxCertificateSigners);
  const std::size_t derived =
      carrier::kCertificateFrameBytes + carrier::kMaxCertificateSigners * carrier::kVoteSignatureMaxBytes;
  assert(cert_ceiling == derived &&
         "the serialized certificate size disagrees with the derivation in carrier-limits.h");
  assert(carrier::simplex_carrier_accepts(cert_ceiling) &&
         "a certificate at the structural signer ceiling must fit the carrier");

  // Producer and parser agree: the serialized certificate parses back to the same signer
  // count and re-serializes to the same bytes. A codec drift would surface here, not in a
  // validator refusing a real block.
  auto wire = serialized_certificate(carrier::kMaxCertificateSigners);
  auto parsed = tos::fetch_tl_object<tos::tos_api::consensus_simplex_certificate>(wire.clone(), true);
  assert(parsed.is_ok() && "a well-formed certificate must parse");
  assert(parsed.ok()->signatures_->votes_.size() == carrier::kMaxCertificateSigners &&
         "the parsed certificate must carry every signer the producer wrote");
  assert(tos::serialize_tl_object(parsed.ok(), true).size() == wire.size() &&
         "re-serializing a parsed certificate must reproduce its byte size");

  // A smaller certificate fits too; a single vote is far under the bound.
  assert(carrier::simplex_carrier_accepts(certificate_bytes(21)));
  assert(carrier::simplex_carrier_accepts(certificate_bytes(100)));

  // The peer-MTU allowance carries the fully wrapped hard max: inner + overlay.message +
  // the transport wrapper the sender's limit is actually checked against. The worst case
  // is the RLDP wrapper (inner + 36 + 40); the allowance must cover it.
  const std::size_t rldp_framed_hard_max = carrier::simplex_protocol_hard_max_bytes +
                                           carrier::kOverlayMessagePrefixBytes + carrier::kTransportWrapperMaxBytes;
  assert(carrier::simplex_carrier_peer_mtu_bytes >= rldp_framed_hard_max &&
         "the peer-MTU allowance must cover the inner hard max wrapped in overlay + transport framing");

  std::printf("SIMPLEX_CARRIER_BOUND_OK hard_max=%zu cert400=%zu peer_mtu=%zu\n",
              carrier::simplex_protocol_hard_max_bytes, cert_ceiling, carrier::simplex_carrier_peer_mtu_bytes);
  return 0;
}
