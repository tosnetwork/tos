/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// A Simplex consensus message signed by a node's post-quantum consensus key
// verifies through PeerValidator::check_signature, and nothing else does. This pins the
// live sign->verify round: the node signs the exact dataToSign the verifier rebuilds, under
// the frozen simplex_sign_context, and a tamper, a wrong session, other data, another
// validator's key, a classical 64-byte signature, or an empty key are each refused. It also
// pins the other half of the identity split: a genuine Ed25519 signature made with the
// transport key that routes to this validator is not consensus authority, and a failed
// post-quantum check is never retried as a classical one.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

#include "crypto/Ed25519.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "tl-utils/tl-utils.hpp"
#include "validator/consensus/types.h"

using tos::validator::consensus::PeerValidator;

namespace {

// A concept, because a requires-expression over a concrete type is a hard error rather
// than a false requirement, and the point here is to ask the question, not to assume it.
template <typename T>
concept HasClassicalConsensusKey = requires(T peer) { peer.key; } || requires(T peer) { peer.short_id; };

td::Bits256 fill(unsigned char b) {
  td::Bits256 x;
  std::memset(x.data(), b, 32);
  return x;
}

std::string_view sv(td::Slice s) {
  return std::string_view(s.data(), s.size());
}

// Sign the dataToSign(session, inner) bytes with the store, exactly as the node's vote and
// candidate sign sites do, so check_signature (which rebuilds the same dataToSign) verifies.
td::BufferSlice sign_consensus_message(const tos::pq::ValidatorPQKeyStore& store, td::Bits256 session,
                                       td::Slice inner) {
  auto signed_bytes =
      tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(session, td::BufferSlice(inner));
  auto sig = store.sign_consensus(sv(signed_bytes.as_slice()));
  assert(sig.has_value() && "the consensus signer must sign");
  return td::BufferSlice(sig->signature);
}

}  // namespace

int main() {
  auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x07')).value();
  auto other = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x09')).value();

  const td::Bits256 session = fill(0x11);
  const std::string inner = "a-notarize-vote";  // stands in for a serialized unsigned vote

  PeerValidator peer{};
  peer.consensus_key = store.consensus_key();

  auto sig = sign_consensus_message(store, session, td::Slice(inner));

  // Positive: a message signed by the key the set records for this validator verifies.
  assert(peer.check_signature(session, td::Slice(inner), sig.as_slice()) && "a valid PQ consensus message must verify");

  // A tampered signature is refused.
  auto tampered = sig.clone();
  tampered.as_slice()[0] = static_cast<char>(tampered.as_slice()[0] ^ 0x01);
  assert(!peer.check_signature(session, td::Slice(inner), tampered.as_slice()) &&
         "a tampered signature must be refused");

  // A signature made under another session must not verify: the session binds the set.
  assert(!peer.check_signature(fill(0x22), td::Slice(inner), sig.as_slice()) &&
         "a signature under another session must be refused");

  // A signature over other data must not verify.
  const std::string other_inner = "a-finalize-vote";
  assert(!peer.check_signature(session, td::Slice(other_inner), sig.as_slice()) &&
         "a signature over other data must be refused");

  // Another validator's key must not verify this signature.
  PeerValidator other_peer{};
  other_peer.consensus_key = other.consensus_key();
  assert(!other_peer.check_signature(session, td::Slice(inner), sig.as_slice()) &&
         "another validator's key must not verify this signature");

  // A classical 64-byte signature is refused, not reinterpreted as post-quantum.
  const std::string classical_shaped(64, '\x00');
  assert(!peer.check_signature(session, td::Slice(inner), td::Slice(classical_shaped)) &&
         "a 64-byte classical signature must be refused");

  // An empty consensus key verifies nothing and does not crash (fail-closed).
  PeerValidator empty_peer{};
  assert(!empty_peer.check_signature(session, td::Slice(inner), sig.as_slice()) &&
         "an empty consensus key must fail closed");

  // Holding the transport key is not consensus authority. This peer owns the Ed25519
  // identity the overlay routes to and signs the exact message with it; the signature is
  // genuine, and it still must not verify, because the only key that decides a Simplex
  // signature is the post-quantum one the validator set records.
  auto transport_secret = td::Ed25519::generate_private_key().move_as_ok();
  tos::PublicKey transport_key{tos::pubkeys::Ed25519{transport_secret.get_public_key().move_as_ok()}};
  auto transport_public = transport_secret.get_public_key().move_as_ok();
  auto envelope = tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(session, td::BufferSlice(inner));
  auto transport_signature = transport_secret.sign(envelope.as_slice()).move_as_ok();

  // Positive control: that signature really is valid Ed25519 over the exact envelope, so
  // the refusals below are about authority rather than about a malformed input.
  assert(transport_public.verify_signature(envelope.as_slice(), td::Slice(transport_signature)).is_ok() &&
         "the transport signature must itself be valid, or the refusal proves nothing");

  PeerValidator transport_only{};
  transport_only.transport_key_id = transport_key.compute_short_id();
  transport_only.adnl_id = tos::adnl::AdnlNodeIdShort{transport_key.compute_short_id()};
  assert(!transport_only.check_signature(session, td::Slice(inner), td::Slice(transport_signature)) &&
         "owning the transport key must not authorize a consensus signature");

  // And a peer that also holds a real post-quantum key still refuses that Ed25519
  // signature: there is no path that retries a failed post-quantum check as classical.
  PeerValidator both{};
  both.consensus_key = store.consensus_key();
  both.transport_key_id = transport_key.compute_short_id();
  assert(!both.check_signature(session, td::Slice(inner), td::Slice(transport_signature)) &&
         "a failed post-quantum check must not be retried as Ed25519");

  // There is no classical consensus key left to remove, which is why removing one cannot
  // cause a fallback: the field does not exist. Re-adding one under its historical name
  // fails to compile here; re-adding one under a new name is caught by check-no-fallback.py,
  // which forbids a classical key type anywhere under validator/consensus. Neither catches
  // a raw byte array pressed into that service, and nothing short of reflection would.
  static_assert(!HasClassicalConsensusKey<PeerValidator>, "PeerValidator must carry no classical consensus key");

  std::printf(
      "CONSENSUS_VERIFY_OK a PQ consensus message verifies; tamper/session/data/key/64-byte/empty and a "
      "genuine transport-key signature all refused\n");
  return 0;
}
