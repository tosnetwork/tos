/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/* Offline-only API; callers MUST supply fresh checked OS CSPRNG bytes. */
#include "falcon.h"
#include "falcon512-native.h"
#include <stdint.h>
#include <string.h>

static void clear(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
}

int tos_falcon_offline_keygen(const uint8_t *entropy, size_t entropy_len,
                             uint8_t *sk, uint8_t *pk) {
  shake256_context rng;
  union { uint64_t align; uint8_t bytes[FALCON_TMPSIZE_KEYGEN(9)]; } tmp;
  int result;
  if (!entropy || entropy_len != 48 || !sk || !pk) return -1;
  shake256_init_prng_from_seed(&rng, entropy, entropy_len);
  result = falcon_keygen_make(&rng, 9, sk, 1281, pk, 897, tmp.bytes, sizeof tmp.bytes);
  clear(&rng, sizeof rng); clear(&tmp, sizeof tmp);
  if (result || !tos_falcon512_public_key_valid(pk, 897)) {
    clear(sk, 1281); clear(pk, 897); return -1;
  }
  return 0;
}

int tos_falcon_offline_sign(const uint8_t *entropy, size_t entropy_len,
    const uint8_t *sk, const uint8_t *pk, const uint8_t *message, size_t message_len,
    uint8_t *signature) {
  shake256_context rng;
  union { uint64_t align; uint8_t bytes[FALCON_TMPSIZE_SIGNDYN(9)]; } tmp;
  size_t size = 666;
  int result;
  if (!entropy || entropy_len != 48 || !sk || !pk || !signature ||
      message_len > 8192 || (message_len && !message)) return -1;
  shake256_init_prng_from_seed(&rng, entropy, entropy_len);
  result = falcon_sign_dyn(&rng, signature, &size, FALCON_SIG_PADDED,
                          sk, 1281, message, message_len, tmp.bytes, sizeof tmp.bytes);
  clear(&rng, sizeof rng); clear(&tmp, sizeof tmp);
  /* Fail closed on a wrong key pairing, signer fault or unrecognized encoding. */
  if (result || size != 666 ||
      tos_falcon512_padded_verify(message, message_len, signature, size, pk, 897) != 1) {
    clear(signature, 666); return -1;
  }
  return 0;
}
