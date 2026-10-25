/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
/* SHA-224/256 for the SLH-DSA verifier, with an SHA-NI compression path.
 *
 * Built in place of third-party/slhdsa-c/sha2_256.c when TOS_SLHDSA_SHA_NI is on; that file
 * is not modified. Its portable compression function is compiled here under a private name
 * and stays the fallback. The SHA-NI compression is the vendored, unmodified transform in
 * third-party/bitcoin-sha256, reached through slhdsa-sha256-shani.cpp. The buffering and
 * padding routines below are copied from the imported file unchanged (hence its license on
 * this file): the SLH code reaches the compression function through them as well as directly,
 * so replacing only the compression symbol would leave most hashing on the portable path.
 * State layout is the imported one: s[0..7] hold the chaining value as big-endian words,
 * s[8..23] the 64-byte block. */
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
#error "the SHA-NI SHA-256 backend needs x86-64 and GCC or Clang"
#endif

#include <cpuid.h>
#include <string.h>
#include "slhdsa-sha256.h"
#include "sha2_api.h"

/* The imported implementation under private names; only its compression function is used. */
void tos_slhdsa_portable_sha2_256_compress(void *v);
void tos_slhdsa_portable_sha2_256_init(sha2_256_t *sha);
void tos_slhdsa_portable_sha2_224_init(sha2_256_t *sha);
void tos_slhdsa_portable_sha2_256_copy(sha2_256_t *dst, const sha2_256_t *src);
void tos_slhdsa_portable_sha2_256_update(sha2_256_t *sha, const uint8_t *m, size_t m_sz);
void tos_slhdsa_portable_sha2_256_final_pad(sha2_256_t *sha);
void tos_slhdsa_portable_sha2_256_final_len(sha2_256_t *sha, uint8_t *h, size_t h_sz);
void tos_slhdsa_portable_sha2_256(uint8_t *h, const void *m, size_t m_sz);
void tos_slhdsa_portable_sha2_224(uint8_t *h, const void *m, size_t m_sz);

#define sha2_256_compress tos_slhdsa_portable_sha2_256_compress
#define sha2_256_init_h0 tos_slhdsa_portable_sha2_256_init_h0
#define sha2_256_init tos_slhdsa_portable_sha2_256_init
#define sha2_224_init tos_slhdsa_portable_sha2_224_init
#define sha2_256_copy tos_slhdsa_portable_sha2_256_copy
#define sha2_256_update tos_slhdsa_portable_sha2_256_update
#define sha2_256_final_pad tos_slhdsa_portable_sha2_256_final_pad
#define sha2_256_final_len tos_slhdsa_portable_sha2_256_final_len
#define sha2_256 tos_slhdsa_portable_sha2_256
#define sha2_224 tos_slhdsa_portable_sha2_224
#include "sha2_256.c"
#undef sha2_256_compress
#undef sha2_256_init_h0
#undef sha2_256_init
#undef sha2_224_init
#undef sha2_256_copy
#undef sha2_256_update
#undef sha2_256_final_pad
#undef sha2_256_final_len
#undef sha2_256
#undef sha2_224

/* === Backend selection. The value depends only on the CPU, so concurrent first calls may both
 * probe and store the same result; relaxed atomics keep that free of data races. */

enum { backend_unknown = 0, backend_portable = 1, backend_sha_ni = 2 };
static int backend_state = backend_unknown;

/* The vendored transform is compiled with -msse4.1 -msse4 -msha, so every one of those
 * extensions must be present, not only SHA. */
static int accepts_cpu(unsigned leaf1_ecx, unsigned leaf7_ebx)
{
  const unsigned leaf1_needed = bit_SSSE3 | bit_SSE4_1 | bit_SSE4_2;
  return (leaf1_ecx & leaf1_needed) == leaf1_needed && (leaf7_ebx & bit_SHA) != 0;
}

static int cpu_has_sha_ni(void)
{
  unsigned a, b1, c1, d;
  unsigned b7, c7;
  if (!__get_cpuid(1, &a, &b1, &c1, &d) || !__get_cpuid_count(7, 0, &a, &b7, &c7, &d))
  {
    return 0;
  }
  return accepts_cpu(c1, b7);
}

static int backend(void)
{
  int s = __atomic_load_n(&backend_state, __ATOMIC_RELAXED);
  if (s == backend_unknown)
  {
    s = cpu_has_sha_ni() ? backend_sha_ni : backend_portable;
    __atomic_store_n(&backend_state, s, __ATOMIC_RELAXED);
  }
  return s;
}

const char *tos_slhdsa_sha256_backend(void)
{
  return backend() == backend_sha_ni ? "sha-ni" : "portable";
}

#ifdef TOS_SLHDSA_SHA256_TESTING
void tos_slhdsa_sha256_force_portable(int on)
{
  __atomic_store_n(&backend_state, on ? backend_portable : backend_unknown, __ATOMIC_RELAXED);
}

int tos_slhdsa_sha256_accepts_cpu(unsigned leaf1_ecx, unsigned leaf7_ebx)
{
  return accepts_cpu(leaf1_ecx, leaf7_ebx);
}
#endif

/* === Compression: the vendored SHA-NI transform when the probe accepts the CPU, otherwise the
 * imported portable function. */

void sha2_256_compress(void *v)
{
  if (backend() == backend_sha_ni)
  {
    tos_slhdsa_sha_ni_compress((uint32_t *)v);
    return;
  }
  tos_slhdsa_portable_sha2_256_compress(v);
}

/* === Copied unchanged from third-party/slhdsa-c/sha2_256.c. */

/* initialize */

static void sha2_256_init_h0(sha2_256_t *sha, const uint8_t h0[32])
__contract__(
  requires(memory_no_alias(sha, sizeof(sha2_256_t)))
  requires(memory_no_alias(h0, 32))
  assigns(object_whole(sha))
)
{
  memcpy(sha->s, h0, 32);
  sha->i = 0;
  sha->len = 0;
}

void sha2_256_init(sha2_256_t *sha)
{
  /* SHA-256 initial values H0, Sect 5.3.3. */
  const uint8_t sha2_256_h0[32] = {
      0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85, 0x3C, 0x6E, 0xF3,
      0x72, 0xA5, 0x4F, 0xF5, 0x3A, 0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05,
      0x68, 0x8C, 0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19};

  sha2_256_init_h0(sha, sha2_256_h0);
}

void sha2_224_init(sha2_256_t *sha)
{
  /* SHA-224 initial values H0, Sect 5.3.2. */
  const uint8_t sha2_224_h0[32] = {
      0xC1, 0x05, 0x9E, 0xD8, 0x36, 0x7C, 0xD5, 0x07, 0x30, 0x70, 0xDD,
      0x17, 0xF7, 0x0E, 0x59, 0x39, 0xFF, 0xC0, 0x0B, 0x31, 0x68, 0x58,
      0x15, 0x11, 0x64, 0xF9, 0x8F, 0xA7, 0xBE, 0xFA, 0x4F, 0xA4};

  sha2_256_init_h0(sha, sha2_224_h0);
}

void sha2_256_copy(sha2_256_t *dst, const sha2_256_t *src)
{
  dst->i = src->i;
  dst->len = src->len;
  memcpy(dst->s, src->s, 32 + src->i);
}

/* SHA2-256 process input */

void sha2_256_update(sha2_256_t *sha, const uint8_t *m, size_t m_sz)
{
  size_t l;
  uint8_t *mp = (uint8_t *)&sha->s[8];

  sha->len += m_sz;
  l = 64 - sha->i;

  if (m_sz < l)
  {
    memcpy(mp + sha->i, m, m_sz);
    sha->i += m_sz;
    return;
  }
  if (sha->i > 0)
  {
    memcpy(mp + sha->i, m, l);
    sha2_256_compress(sha->s);
    m_sz -= l;
    m += l;
    sha->i = 0;
  }
  while (m_sz >= 64)
  {
    memcpy(mp, m, 64);
    sha2_256_compress(sha->s);
    m_sz -= 64;
    m += 64;
  }
  memcpy(mp, m, m_sz);
  sha->i = m_sz;
}

/* perform final padding */

void sha2_256_final_pad(sha2_256_t *sha)
{
  uint8_t *mp = (uint8_t *)&sha->s[8];
  uint64_t x;
  size_t i;

  i = sha->i; /* last data block */
  mp[i++] = 0x80;
  if (i > 56)
  {
    memset(mp + i, 0x00, 64 - i);
    sha2_256_compress(sha->s);
    i = 0;
  }
  memset(mp + i, 0x00, 64 - i); /* clear rest */

  x = ((uint64_t)sha->len) << 3; /* process length */
  i = 64;
  while (x > 0)
  {
    mp[--i] = x & 0xFF;
    x >>= 8;
  }
}

/* produce h_sz byte hash */

void sha2_256_final_len(sha2_256_t *sha, uint8_t *h, size_t h_sz)
{
  sha2_256_final_pad(sha);
  sha2_256_compress(sha->s);

  memcpy(h, sha->s, h_sz);
}

/* SHA-224/256 public single-call interfaces */

void sha2_256(uint8_t *h, const void *m, size_t m_sz)
{
  sha2_256_t sha;

  sha2_256_init(&sha);
  sha2_256_update(&sha, m, m_sz);
  sha2_256_final(&sha, h);
}

void sha2_224(uint8_t *h, const void *m, size_t m_sz)
{
  sha2_256_t sha;

  sha2_224_init(&sha);
  sha2_224_update(&sha, m, m_sz);
  sha2_224_final(&sha, h);
}
