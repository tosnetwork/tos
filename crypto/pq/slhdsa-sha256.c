/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
/* SHA-224/256 for the SLH-DSA verifier, with an SHA-NI compression path.
 *
 * Built in place of third-party/slhdsa-c/sha2_256.c when TOS_SLHDSA_SHA_NI is on; that file
 * is not modified. Its portable compression function is compiled here under a private name
 * and stays the fallback. The buffering and padding routines below are copied from it
 * unchanged (hence its license on this file): the SLH code reaches the compression function
 * through them as well as directly, so replacing only the compression symbol would leave most
 * hashing on the portable path. State layout is the imported one: s[0..7] hold the chaining
 * value as big-endian words, s[8..23] the 64-byte block. */
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
#error "the SHA-NI SHA-256 backend needs x86-64 and GCC or Clang"
#endif

#include <cpuid.h>
#include <immintrin.h>
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

static int cpu_has_sha_ni(void)
{
  unsigned a, b, c, d;
  if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_SSSE3) || !(c & bit_SSE4_1))
  {
    return 0;
  }
  if (!__get_cpuid_count(7, 0, &a, &b, &c, &d))
  {
    return 0;
  }
  return (b & bit_SHA) != 0;
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
#endif

/* === SHA-NI compression (FIPS 180-4 round function in hardware). */

static const uint32_t sha_ni_k[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

__attribute__((target("sha,sse4.1,ssse3"))) static void sha_ni_compress(uint32_t *sp)
{
  /* Byte-swaps each 32-bit lane: big-endian words in memory to host order and back. */
  const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
  const uint8_t *block = (const uint8_t *)(sp + 8);

  __m128i abcd = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)&sp[0]), bswap);
  __m128i efgh = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)&sp[4]), bswap);
  /* The instructions take the state as ABEF and CDGH. */
  __m128i tmp = _mm_shuffle_epi32(abcd, 0xB1);
  __m128i st1 = _mm_shuffle_epi32(efgh, 0x1B);
  __m128i st0 = _mm_alignr_epi8(tmp, st1, 8);
  st1 = _mm_blend_epi16(st1, tmp, 0xF0);
  const __m128i abef = st0;
  const __m128i cdgh = st1;

  __m128i w[4];
  for (int i = 0; i < 4; i++)
  {
    w[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 16 * i)), bswap);
  }
  for (int i = 0; i < 16; i++)
  {
    __m128i msg = _mm_add_epi32(w[i & 3], _mm_loadu_si128((const __m128i *)&sha_ni_k[4 * i]));
    st1 = _mm_sha256rnds2_epu32(st1, st0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    st0 = _mm_sha256rnds2_epu32(st0, st1, msg);
    if (i < 12)
    {
      /* Schedule words 4i+16..4i+19 from words 4i..4i+15. */
      __m128i t = _mm_sha256msg1_epu32(w[i & 3], w[(i + 1) & 3]);
      t = _mm_add_epi32(t, _mm_alignr_epi8(w[(i + 3) & 3], w[(i + 2) & 3], 4));
      w[i & 3] = _mm_sha256msg2_epu32(t, w[(i + 3) & 3]);
    }
  }
  st0 = _mm_add_epi32(st0, abef);
  st1 = _mm_add_epi32(st1, cdgh);

  tmp = _mm_shuffle_epi32(st0, 0x1B);
  st1 = _mm_shuffle_epi32(st1, 0xB1);
  abcd = _mm_blend_epi16(tmp, st1, 0xF0);
  efgh = _mm_alignr_epi8(st1, tmp, 8);
  _mm_storeu_si128((__m128i *)&sp[0], _mm_shuffle_epi8(abcd, bswap));
  _mm_storeu_si128((__m128i *)&sp[4], _mm_shuffle_epi8(efgh, bswap));
}

void sha2_256_compress(void *v)
{
  if (backend() == backend_sha_ni)
  {
    sha_ni_compress((uint32_t *)v);
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
