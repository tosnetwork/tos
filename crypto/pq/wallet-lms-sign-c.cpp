/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "lms-fee.h"
#include <cstring>
#include <openssl/crypto.h>
extern "C" {
#include "hss_derive.h"
#include "lm_ots.h"
}

// Internal primitive only. Callers must durably reserve the leaf before calling;
// this function neither owns nor persists signer state. No Rust public signer API
// exposes this entry point until journal/custody integration is complete.
extern "C" int tos_wallet_lms_fee_sign_reserved(
    const unsigned char* seed, std::size_t seed_size, std::uint32_t leaf,
    const unsigned char* digest, std::size_t digest_size,
    const unsigned char* path, std::size_t path_size,
    const unsigned char* public_key, std::size_t key_size,
    unsigned char* output, std::size_t output_size) noexcept {
  if (!output || output_size != tos::pq::lms_fee_max_signature_bytes) {
    return 0;
  }
  OPENSSL_cleanse(output, output_size);
  if (!seed || seed_size != 48 || !digest || digest_size != 32 || !path || path_size != 640 ||
      !public_key || key_size != 60 || leaf >= (1u << 20) ||
      !tos::pq::lms_fee_worst_compressions(
          std::string_view(reinterpret_cast<const char*>(public_key), key_size), digest_size) ||
      std::memcmp(seed + 32, public_key + 12, 16) != 0) {
    return 0;
  }
  struct seed_derive derive{};
  if (!hss_seed_derive_init(&derive, 8, 3, seed + 32, seed)) {
    OPENSSL_cleanse(&derive, sizeof derive);
    return 0;
  }
  hss_seed_derive_set_q(&derive, leaf);
  output[4] = static_cast<unsigned char>(leaf >> 24);
  output[5] = static_cast<unsigned char>(leaf >> 16);
  output[6] = static_cast<unsigned char>(leaf >> 8);
  output[7] = static_cast<unsigned char>(leaf);
  const bool signed_ok = lm_ots_generate_signature(3, seed + 32, leaf, &derive, digest,
                                                  digest_size, false, output + 8, 2180);
  hss_seed_derive_done(&derive);
  OPENSSL_cleanse(&derive, sizeof derive);
  output[2191] = 8;
  std::memcpy(output + 2192, path, path_size);
  const auto view = [](const unsigned char* data, std::size_t size) {
    return std::string_view(reinterpret_cast<const char*>(data), size);
  };
  if (!signed_ok || tos::pq::verify_lms_fee(view(digest, digest_size), view(output, output_size),
                                          view(public_key, key_size)) != tos::pq::VerifyResult::valid) {
    OPENSSL_cleanse(output, output_size);
    return 0;
  }
  return 1;
}
