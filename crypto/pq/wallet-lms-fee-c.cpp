/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "lms-fee.h"

// Wallet fee intents sign exactly a 32-byte digest. The reserved leaf must be
// checked separately from cryptographic validity under the enrolled public key.
extern "C" int tos_wallet_lms_fee_verify(std::uint32_t leaf, const unsigned char* digest, std::size_t digest_size,
                                         const unsigned char* signature, std::size_t signature_size,
                                         const unsigned char* public_key, std::size_t key_size) noexcept {
  if (!digest || !signature || !public_key || digest_size != 32 ||
      signature_size != tos::pq::lms_fee_max_signature_bytes || key_size != tos::pq::lms_fee_public_key_bytes ||
      leaf >= (1u << 20)) {
    return 0;
  }
  const auto encoded_leaf = (std::uint32_t{signature[4]} << 24) | (std::uint32_t{signature[5]} << 16) |
                            (std::uint32_t{signature[6]} << 8) | signature[7];
  if (encoded_leaf != leaf) {
    return 0;
  }
  const auto view = [](const unsigned char* data, std::size_t size) {
    return std::string_view(reinterpret_cast<const char*>(data), size);
  };
  return tos::pq::verify_lms_fee(view(digest, digest_size), view(signature, signature_size),
                                 view(public_key, key_size)) == tos::pq::VerifyResult::valid;
}
