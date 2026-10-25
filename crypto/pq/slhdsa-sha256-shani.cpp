/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
/* Connects the SLH-DSA SHA-256 state layout to the vendored SHA-NI transform in
 * third-party/bitcoin-sha256 (see its PROVENANCE.md), which is compiled unchanged with the
 * instruction-set flags it requires. This file needs no such flags.
 *
 * The SLH code keeps the chaining value as eight big-endian 32-bit words in memory followed by
 * the 64-byte block; the transform takes host-order words and does its own byte swapping of the
 * block and its own feed-forward, so the adapter only converts the chaining value. */
#include <cstddef>
#include <cstdint>

#include "slhdsa-sha256.h"

namespace sha256_x86_shani {
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}

namespace {
uint32_t load_be32(const unsigned char* p) {
  return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | uint32_t{p[3]};
}

void store_be32(unsigned char* p, uint32_t v) {
  p[0] = static_cast<unsigned char>(v >> 24);
  p[1] = static_cast<unsigned char>(v >> 16);
  p[2] = static_cast<unsigned char>(v >> 8);
  p[3] = static_cast<unsigned char>(v);
}
}  // namespace

extern "C" void tos_slhdsa_sha_ni_compress(uint32_t* sp) {
  auto* bytes = reinterpret_cast<unsigned char*>(sp);
  uint32_t words[8];
  for (int i = 0; i < 8; i++) {
    words[i] = load_be32(bytes + 4 * i);
  }
  sha256_x86_shani::Transform(words, bytes + 32, 1);
  for (int i = 0; i < 8; i++) {
    store_be32(bytes + 4 * i, words[i]);
  }
}
