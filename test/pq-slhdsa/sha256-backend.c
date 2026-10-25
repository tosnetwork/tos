/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/* crypto/pq/slhdsa-sha256.c against the unmodified imported sha2_256.c, on the CPU-selected path
 * and again with the portable path forced. Covers every entry point the SLH code uses, including
 * final_pad followed by a direct compression of the padded state (the WOTS chain loop), and the
 * CPU probe's decision for each missing required extension.
 * Checks stay on under NDEBUG. TOS_REQUIRE_SHA_NI=1 fails the run unless the SHA-NI path is
 * the one selected on this CPU. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256-reference.h"
#include "slhdsa-sha256.h"

#define CHECK(cond)                                                          \
  do                                                                         \
  {                                                                          \
    if (!(cond))                                                             \
    {                                                                        \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
      exit(1);                                                               \
    }                                                                        \
  } while (0)

static uint64_t rng = 0x9E3779B97F4A7C15ULL;

static uint32_t next(void)
{
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return (uint32_t)(rng >> 16);
}

static void fill(uint8_t *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
  {
    p[i] = (uint8_t)next();
  }
}

static void from_hex(uint8_t *out, const char *hex)
{
  size_t n = strlen(hex) / 2;
  for (size_t i = 0; i < n; i++)
  {
    unsigned v = 0;
    CHECK(sscanf(hex + 2 * i, "%2x", &v) == 1);
    out[i] = (uint8_t)v;
  }
}

/* Chaining value plus the buffered bytes; the rest of the block buffer is never initialized. */
static int same_state(const sha2_256_t *a, const sha2_256_t *b)
{
  return a->i == b->i && a->len == b->len && memcmp(a->s, b->s, 32 + a->i) == 0;
}

/* After final_pad the whole block is defined: chaining value and all 64 block bytes. */
static int same_padded(const sha2_256_t *a, const sha2_256_t *b)
{
  return memcmp(a->s, b->s, 32 + 64) == 0;
}

static void known_answers(void)
{
  static const struct
  {
    const char *msg;
    size_t repeat;
    const char *digest;
  } kat[] = {
      {"", 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {"a", 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
  };
  for (size_t k = 0; k < sizeof kat / sizeof kat[0]; k++)
  {
    sha2_256_t sha;
    uint8_t got[32], want[32];
    sha2_256_init(&sha);
    for (size_t r = 0; r < kat[k].repeat; r++)
    {
      sha2_256_update(&sha, (const uint8_t *)kat[k].msg, strlen(kat[k].msg));
    }
    sha2_256_final(&sha, got);
    from_hex(want, kat[k].digest);
    CHECK(memcmp(got, want, 32) == 0);
  }
  uint8_t got224[28], want224[28];
  sha2_224(got224, "abc", 3);
  from_hex(want224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
  CHECK(memcmp(got224, want224, 28) == 0);
}

static void against_reference(void)
{
  uint8_t data[512];
  uint8_t got[32], want[32];

  /* One-shot hashes across every padding boundary up to four blocks. */
  for (size_t len = 0; len <= 300; len++)
  {
    fill(data, len);
    sha2_256(got, data, len);
    ref_sha2_256(want, data, len);
    CHECK(memcmp(got, want, 32) == 0);
    sha2_224(got, data, len);
    ref_sha2_224(want, data, len);
    CHECK(memcmp(got, want, 28) == 0);
  }

  /* Random chunking, copy mid-stream with divergent continuations, truncated outputs. */
  for (int round = 0; round < 2000; round++)
  {
    size_t len = next() % sizeof data;
    fill(data, len);
    sha2_256_t a, b;
    sha2_256_init(&a);
    ref_sha2_256_init(&b);
    size_t at = 0;
    while (at < len)
    {
      size_t step = 1 + next() % 80;
      if (step > len - at)
      {
        step = len - at;
      }
      sha2_256_update(&a, data + at, step);
      ref_sha2_256_update(&b, data + at, step);
      CHECK(same_state(&a, &b));
      at += step;
    }
    sha2_256_t a2, b2;
    sha2_256_copy(&a2, &a);
    ref_sha2_256_copy(&b2, &b);
    uint8_t tail[70];
    size_t tail_len = next() % sizeof tail;
    fill(tail, tail_len);
    sha2_256_update(&a2, tail, tail_len);
    ref_sha2_256_update(&b2, tail, tail_len);
    CHECK(same_state(&a2, &b2));

    size_t out_len = (size_t[]){16, 28, 32}[round % 3];
    sha2_256_final_len(&a, got, out_len);
    ref_sha2_256_final_len(&b, want, out_len);
    CHECK(memcmp(got, want, out_len) == 0);
    CHECK(same_state(&a, &b));

    /* final_pad, then the caller compresses the padded state itself. */
    sha2_256_final_pad(&a2);
    ref_sha2_256_final_pad(&b2);
    CHECK(same_padded(&a2, &b2));
    sha2_256_compress(a2.s);
    ref_sha2_256_compress(b2.s);
    CHECK(same_padded(&a2, &b2));
  }

  /* Raw compressions of arbitrary states and blocks. */
  for (int round = 0; round < 100000; round++)
  {
    uint32_t a[8 + 24], b[8 + 24];
    fill((uint8_t *)a, sizeof a);
    memcpy(b, a, sizeof a);
    sha2_256_compress(a);
    ref_sha2_256_compress(b);
    CHECK(memcmp(a, b, sizeof a) == 0);
  }
}

/* The probe accepts SHA-NI only with every extension the vendored transform is compiled for:
 * SSSE3, SSE4.1, SSE4.2 (CPUID leaf 1 ECX bits 9, 19, 20) and SHA (leaf 7 EBX bit 29). */
static void cpu_probe(void)
{
  const unsigned ssse3 = 1u << 9, sse41 = 1u << 19, sse42 = 1u << 20, sha = 1u << 29;
  const unsigned all1 = ssse3 | sse41 | sse42;
  CHECK(tos_slhdsa_sha256_accepts_cpu(all1, sha) == 1);
  CHECK(tos_slhdsa_sha256_accepts_cpu(0xFFFFFFFFu, 0xFFFFFFFFu) == 1);
  CHECK(tos_slhdsa_sha256_accepts_cpu(all1 & ~ssse3, sha) == 0);
  CHECK(tos_slhdsa_sha256_accepts_cpu(all1 & ~sse41, sha) == 0);
  CHECK(tos_slhdsa_sha256_accepts_cpu(all1 & ~sse42, sha) == 0);
  CHECK(tos_slhdsa_sha256_accepts_cpu(all1, 0) == 0);
  CHECK(tos_slhdsa_sha256_accepts_cpu(0xFFFFFFFFu & ~sse42, 0xFFFFFFFFu) == 0);
  CHECK(tos_slhdsa_sha256_accepts_cpu(0xFFFFFFFFu, 0xFFFFFFFFu & ~sha) == 0);
}

int main(void)
{
  cpu_probe();
  const char *selected = tos_slhdsa_sha256_backend();
  printf("CPU-selected backend: %s\n", selected);
  const char *require = getenv("TOS_REQUIRE_SHA_NI");
  if (require != NULL && strcmp(require, "1") == 0)
  {
    CHECK(strcmp(selected, "sha-ni") == 0);
  }
  if (strcmp(selected, "sha-ni") != 0)
  {
    printf("NOTE: this CPU has no SHA-NI; only the portable path is exercised\n");
  }

  known_answers();
  against_reference();
  printf("OK: %s path matches the imported implementation\n", selected);

  tos_slhdsa_sha256_force_portable(1);
  CHECK(strcmp(tos_slhdsa_sha256_backend(), "portable") == 0);
  known_answers();
  against_reference();
  printf("OK: forced portable path matches the imported implementation\n");

  tos_slhdsa_sha256_force_portable(0);
  CHECK(strcmp(tos_slhdsa_sha256_backend(), selected) == 0);
  return 0;
}
