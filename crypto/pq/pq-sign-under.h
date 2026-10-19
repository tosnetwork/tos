/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// ML-DSA "pure" signing, and the one place its message prefix is built.
//
// Every post-quantum authority in this system differs from every other in its context
// string and in nothing else. That makes the prefix -- domain octet, context length,
// context -- a single routine shared by every signer, rather than a few lines each
// signer writes for itself. A second copy would be a second chance to get it wrong, and
// a signature made under a malformed prefix is one nobody can verify and everybody
// blames on the key.

#include <array>
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <optional>
#include <string_view>
#include <vector>

#include "mldsa_native.h"
#include "pq-consensus.h"

namespace tos::pq::detail {

inline std::optional<ConsensusPQSignature> sign_under(const ConsensusPQKey& key, const std::uint8_t* sk,
                                                      std::string_view context, std::string_view message) noexcept {
  if (sk == nullptr || key.algorithm_id != PQAlgorithmId::mldsa44 || message.size() > mldsa44_max_message_bytes ||
      context.size() > mldsa44_max_context_bytes) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> prefix;
  prefix.reserve(2 + context.size());
  prefix.push_back(0);
  prefix.push_back(static_cast<std::uint8_t>(context.size()));
  prefix.insert(prefix.end(), context.begin(), context.end());

  std::array<std::uint8_t, MLDSA_RNDBYTES> rnd{};
  if (RAND_priv_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
    OPENSSL_cleanse(rnd.data(), rnd.size());  // wipe on every exit, including RNG failure
    return std::nullopt;
  }
  std::array<std::uint8_t, MLDSA44_BYTES> sig{};
  const int rc = tos_pq_cs_native_signature_internal(sig.data(), reinterpret_cast<const std::uint8_t*>(message.data()),
                                                     message.size(), prefix.data(), prefix.size(), rnd.data(), sk, 0);
  OPENSSL_cleanse(rnd.data(), rnd.size());
  if (rc != 0) {
    return std::nullopt;
  }
  ConsensusPQSignature out;
  out.algorithm_id = PQAlgorithmId::mldsa44;
  out.signature.assign(reinterpret_cast<const char*>(sig.data()), sig.size());
  return out;
}

// Derive an ML-DSA-44 keypair from a caller-owned 32-byte seed, leaving the expanded
// secret in `sk` and the identity in `key`. Shared for the same reason: one place decides
// what a key's identity is, so two stores cannot disagree about it.
inline bool derive_from_seed(std::string_view seed, ConsensusPQKey& key, std::uint8_t* sk) noexcept {
  if (seed.size() != MLDSA_SEEDBYTES || sk == nullptr) {
    return false;
  }
  std::array<std::uint8_t, MLDSA44_PUBLICKEYBYTES> pk{};
  if (tos_pq_cs_native_keypair_internal(pk.data(), sk, reinterpret_cast<const std::uint8_t*>(seed.data())) != 0) {
    OPENSSL_cleanse(pk.data(), pk.size());  // wipe on every exit, not just the success path
    return false;
  }
  key.algorithm_id = PQAlgorithmId::mldsa44;
  key.public_key.assign(reinterpret_cast<const char*>(pk.data()), pk.size());
  OPENSSL_cleanse(pk.data(), pk.size());
  auto key_id = derive_key_id(PQAlgorithmId::mldsa44, key.public_key);
  if (!key_id) {  // fail closed: no usable identity means no key store
    return false;
  }
  key.key_id = *key_id;
  return true;
}

}  // namespace tos::pq::detail
