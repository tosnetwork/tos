/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "falcon512-native.h"
#include "inner.h"

int tos_falcon512_public_key_valid(const uint8_t *key, size_t key_len) {
  uint16_t h[512];
  return key && key_len == 897 && key[0] == 0x09 &&
      Zf(modq_decode)(h, 9, key + 1, 896) == 896;
}

int tos_falcon512_padded_verify(const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len, const uint8_t *key, size_t key_len) {
  uint16_t h[512], hm[512];
  int16_t sv[512];
  /* Alignment is part of verify_raw's temporary-buffer contract. */
  union { uint64_t align; uint8_t bytes[1024]; } tmp;
  inner_shake256_context hash;
  size_t used, i;
  if (message_len > 8192 || signature_len != 666 || key_len != 897 ||
      !signature || !key || (message_len && !message)) return -1;
  /* Only logn=9 compressed coefficients WITH fixed padded length are accepted.
     CT and other parameters never pass an auto-detect API. */
  if (key[0] != 0x09 || signature[0] != 0x39) return 0;
  if (Zf(modq_decode)(h, 9, key + 1, 896) != 896) return 0;
  used = Zf(comp_decode)(sv, 9, signature + 41, 625);
  if (!used) return 0;
  for (i = 41 + used; i < 666; ++i) if (signature[i] != 0) return 0;
  inner_shake256_init(&hash);
  inner_shake256_inject(&hash, signature + 1, 40);
  if (message_len) inner_shake256_inject(&hash, message, message_len);
  inner_shake256_flip(&hash);
  Zf(hash_to_point_vartime)(&hash, hm, 9);
  Zf(to_ntt_monty)(h, 9);
  return Zf(verify_raw)(hm, sv, h, 9, tmp.bytes) ? 1 : 0;
}
