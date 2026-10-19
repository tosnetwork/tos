/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/sha.h>
extern "C" {
#include "hss_derive.h"
#include "lm_ots.h"
}

// All output nodes are public. Index zero is unused, index one is the root.
// This fixed-profile operation derives public chains only; it never signs.
extern "C" int tos_wallet_lms_fee_generate_tree(const unsigned char* seed, std::size_t seed_size, unsigned char* output,
                                                std::size_t output_size) noexcept {
  constexpr std::uint32_t leaves = 1u << 20;
  constexpr std::size_t bytes = std::size_t{leaves} * 2 * 32;
  if (!seed || seed_size != 48 || !output || output_size != bytes) {
    return 0;
  }
  std::memset(output, 0, bytes);
  struct seed_derive derive{};
  if (!hss_seed_derive_init(&derive, 8, 3, seed + 32, seed)) {
    OPENSSL_cleanse(&derive, sizeof derive);
    return 0;
  }
  unsigned char input[86]{};
  std::memcpy(input, seed + 32, 16);
  const auto index = [&input](std::uint32_t r) {
    input[16] = static_cast<unsigned char>(r >> 24);
    input[17] = static_cast<unsigned char>(r >> 16);
    input[18] = static_cast<unsigned char>(r >> 8);
    input[19] = static_cast<unsigned char>(r);
  };
  const auto hash = [](const unsigned char* data, std::size_t length, unsigned char* result) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, length);
    SHA256_Final(result, &ctx);
  };
  input[20] = input[21] = 0x82;
  for (std::uint32_t q = 0; q < leaves; ++q) {
    hss_seed_derive_set_q(&derive, q);
    if (!lm_ots_generate_public_key(3, seed + 32, q, &derive, input + 22, 32)) {
      hss_seed_derive_done(&derive);
      OPENSSL_cleanse(&derive, sizeof derive);
      return 0;
    }
    const std::uint32_t r = leaves | q;
    index(r);
    hash(input, 54, output + std::size_t{r} * 32);
  }
  hss_seed_derive_done(&derive);
  OPENSSL_cleanse(&derive, sizeof derive);
  input[20] = input[21] = 0x83;
  for (std::uint32_t r = leaves - 1; r != 0; --r) {
    index(r);
    std::memcpy(input + 22, output + std::size_t{r} * 64, 64);
    hash(input, sizeof input, output + std::size_t{r} * 32);
  }
  return 1;
}
