/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Measure what a post-quantum Simplex round actually costs on the wire and on
// the CPU, on the real signer and the real consensus TL objects, before any consensus
// authentication is converted.
//
// It answers the questions the plan freezes into its measurement record:
//   - how large is one signed vote, and one 21 / 100 / 400-signer certificate, once
//     serialized exactly as the node will send them;
//   - how that compares to the current direct-message carrier (Adnl::get_mtu() minus the
//     overlay header), which is what makes a 2420-byte signature not fit today;
//   - how long a single ML-DSA-44 sign and verify take on this host.
//
// It measures; it decides nothing. The frozen hard carrier bound and its max/max+1 test
// live in validator/consensus/simplex/carrier-limits.h, and this program prints the
// number that bound must cover so the two cannot silently disagree.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/mldsa44.h"
#include "tl-utils/tl-utils.hpp"

namespace {

// The current transport carrier, read from source (constexpr there, cited here so a drift
// is visible). adnl/adnl.h: adnl::Adnl::get_mtu() == 1024 (NOT AdnlNetworkManager's 1440).
// overlay/overlays.h: Overlays::max_message_size() == adnl::Adnl::get_mtu() - 36, the 36
// being the overlay.message header (ctor id 4 + overlay:int256 32) prepended to a direct
// message. Below the overlay, the AdnlSenderEx wraps the whole buffer once more and checks
// its per-peer limit against the wrapped size: QUIC `quic.message` adds 8 B, RLDP2
// `rldp.message` adds 40 B.
constexpr std::uint32_t kAdnlMtu = 1024;
constexpr std::uint32_t kOverlayMessageHeader = 36;
constexpr std::uint32_t kDirectMessageMax = kAdnlMtu - kOverlayMessageHeader;  // 988
constexpr std::uint32_t kQuicMessageWrapper = 8;
constexpr std::uint32_t kRldpMessageWrapper = 40;

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

// The PQ signer and verifier take string_view; a BufferSlice's as_slice() is a td::Slice.
std::string_view sv(td::Slice s) {
  return std::string_view(s.data(), s.size());
}

// One real ML-DSA-44 signature, produced by the production signer over a representative
// consensus message. Its length is the suite's fixed 2420; its bytes stand in for every
// signer's in a certificate, since only the length drives the size.
td::BufferSlice real_signature(const tos::pq::ValidatorPQKeyStore& store, std::string_view signed_message) {
  auto sig = store.sign_consensus(signed_message);
  if (!sig.has_value()) {
    std::fprintf(stderr, "FATAL: the consensus signer produced no signature\n");
    std::abort();
  }
  return td::BufferSlice(sig->signature);
}

tos::tl_object_ptr<tos::tos_api::consensus_simplex_notarizeVote> a_notarize_vote() {
  return tos::create_tl_object<tos::tos_api::consensus_simplex_notarizeVote>(
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(/*slot=*/1789434, fill(0x5a)));
}

// An empty candidate's authentication: consensus.empty carries the same 2420-byte
// signature. A full candidate (consensus.block) additionally carries the block as a
// `candidate:bytes` and rides the FEC broadcast path (max 16 MiB), not the direct
// message carrier, so its size is not a carrier constraint; this is the signature-
// carrying part measured for completeness.
std::size_t empty_candidate_bytes(const td::BufferSlice& signature) {
  auto empty = tos::create_tl_object<tos::tos_api::consensus_empty>(
      /*slot=*/1789434, tos::create_tl_object<tos::tos_api::consensus_candidateId>(1789433, fill(0x5b)),
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(-1, 0x8000000000000000LL, 42, fill(0x01), fill(0x02)),
      signature.clone());
  return tos::serialize_tl_object(empty, true).size();
}

std::size_t signed_vote_bytes(const td::BufferSlice& signature) {
  return tos::serialize_tl_object(
             tos::create_tl_object<tos::tos_api::consensus_simplex_vote>(a_notarize_vote(), signature.clone()), true)
      .size();
}

std::size_t certificate_bytes(std::size_t signers, const td::BufferSlice& signature) {
  std::vector<tos::tl_object_ptr<tos::tos_api::consensus_simplex_voteSignature>> votes;
  votes.reserve(signers);
  for (std::size_t who = 0; who < signers; ++who) {
    votes.push_back(tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignature>(static_cast<std::int32_t>(who),
                                                                                         signature.clone()));
  }
  auto cert = tos::create_tl_object<tos::tos_api::consensus_simplex_certificate>(
      a_notarize_vote(), tos::create_tl_object<tos::tos_api::consensus_simplex_voteSignatureSet>(std::move(votes)));
  return tos::serialize_tl_object(cert, true).size();
}

double median_micros(std::vector<double>& samples) {
  std::sort(samples.begin(), samples.end());
  return samples[samples.size() / 2];
}

}  // namespace

int main() {
  std::string seed(32, '\0');
  for (int i = 0; i < 32; ++i) {
    seed[i] = static_cast<char>(i * 5 + 3);
  }
  auto maybe_store = tos::pq::ValidatorPQKeyStore::from_seed(seed);
  if (!maybe_store.has_value()) {
    std::fprintf(stderr, "FATAL: could not derive a consensus key from the seed\n");
    return 1;
  }
  const auto& store = *maybe_store;
  const std::string public_key = store.consensus_key().public_key;

  // The exact bytes a vote signs: dataToSign(session_id, serialize(unsigned vote)).
  auto unsigned_vote_bytes = tos::serialize_tl_object(a_notarize_vote(), true);
  auto signed_message =
      tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(fill(0x11), unsigned_vote_bytes.clone());

  const auto signature = real_signature(store, sv(signed_message.as_slice()));
  if (signature.size() != tos::pq::mldsa44_signature_bytes) {
    std::fprintf(stderr, "FATAL: signature is %zu bytes, expected %zu\n", signature.size(),
                 tos::pq::mldsa44_signature_bytes);
    return 1;
  }

  // Latencies. Sign includes fresh randomness on every call (hedged), which is the real
  // per-vote cost; verify is what the certificate loop pays per signer.
  constexpr int kSignIters = 400;
  constexpr int kVerifyIters = 400;
  std::vector<double> sign_us, verify_us;
  sign_us.reserve(kSignIters);
  verify_us.reserve(kVerifyIters);
  for (int i = 0; i < kSignIters; ++i) {
    auto t0 = std::chrono::steady_clock::now();
    auto s = store.sign_consensus(sv(signed_message.as_slice()));
    auto t1 = std::chrono::steady_clock::now();
    if (!s.has_value()) {
      std::fprintf(stderr, "FATAL: sign failed mid-measurement\n");
      return 1;
    }
    sign_us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
  }
  for (int i = 0; i < kVerifyIters; ++i) {
    auto t0 = std::chrono::steady_clock::now();
    auto v = tos::pq::verify_mldsa44(sv(signed_message.as_slice()), tos::pq::simplex_sign_context,
                                     sv(signature.as_slice()), public_key);
    auto t1 = std::chrono::steady_clock::now();
    if (v != tos::pq::VerifyResult::valid) {
      std::fprintf(stderr, "FATAL: verify failed mid-measurement\n");
      return 1;
    }
    verify_us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
  }

  // Sizes, exact.
  const std::size_t vote_sz = signed_vote_bytes(signature);
  const std::size_t empty_candidate_sz = empty_candidate_bytes(signature);
  const std::size_t cert21 = certificate_bytes(21, signature);
  const std::size_t cert100 = certificate_bytes(100, signature);
  const std::size_t cert400 = certificate_bytes(400, signature);

  std::printf("=== Simplex carrier & latency measurement (ML-DSA-44) ===\n");
  std::printf("suite               public_key=%zu  signature=%zu bytes\n", public_key.size(),
              tos::pq::mldsa44_signature_bytes);
  std::printf("sign_consensus      median=%.1f us over %d samples\n", median_micros(sign_us), kSignIters);
  std::printf("verify_mldsa44      median=%.1f us over %d samples\n", median_micros(verify_us), kVerifyIters);
  std::printf("\n");
  std::printf("signed vote         %zu bytes\n", vote_sz);
  std::printf("empty candidate     %zu bytes  (auth only; full candidate rides FEC, not this carrier)\n",
              empty_candidate_sz);
  std::printf("certificate  21     %zu bytes\n", cert21);
  std::printf("certificate 100     %zu bytes\n", cert100);
  std::printf("certificate 400     %zu bytes\n", cert400);
  std::printf("\n");
  std::printf("current carrier     adnl::Adnl::get_mtu()=%u, overlay header=%u, direct-message max=%u bytes\n",
              kAdnlMtu, kOverlayMessageHeader, kDirectMessageMax);
  std::printf("a single vote %s in one direct message today (%zu vs %u)\n",
              vote_sz <= kDirectMessageMax ? "FITS" : "DOES NOT FIT", vote_sz, kDirectMessageMax);
  std::printf("\n");
  // The peer-MTU allowance is checked against the fully wrapped stream, so the 400-signer
  // certificate must be covered together with the overlay header and the transport wrapper
  // the sender's limit sees (RLDP is the larger at +40).
  std::printf("cert400 framed QUIC     %zu bytes  (cert400 + overlay %u + quic.message %u)\n",
              cert400 + kOverlayMessageHeader + kQuicMessageWrapper, kOverlayMessageHeader, kQuicMessageWrapper);
  std::printf("cert400 framed RLDP     %zu bytes  (cert400 + overlay %u + rldp.message %u)\n",
              cert400 + kOverlayMessageHeader + kRldpMessageWrapper, kOverlayMessageHeader, kRldpMessageWrapper);
  std::printf("PEER_MTU_MUST_COVER     %zu bytes  (the larger, RLDP-framed)\n",
              cert400 + kOverlayMessageHeader + kRldpMessageWrapper);
  return 0;
}
