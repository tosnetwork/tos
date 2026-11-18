/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/* Timing of Pure SLH-DSA-SHA2-128s verification on the SHA-256 backend this build selected and,
 * in a build with a hardware backend, again with the portable path forced. It prints the
 * minimum, median and maximum time of one verification and the time of one SHA-256 compression.
 * It measures; it has no time threshold. It does fail when a vector's result changes between
 * calls or between backends, because the result must not depend on the backend.
 *
 * Usage: bench-pq-slhdsa-verify <vectors.txt> [rounds]
 * The vector file has the format of slh-verify-vectors.txt. Signatures need not be valid: an
 * invalid one is verified in full as well, and the counts of valid and invalid ones are printed.
 * The signatures in slh-verify-vectors.txt are honestly generated. slh-worst-case-vectors.txt
 * holds one chosen to maximise the hash chain steps; its time is the one the gas price must
 * cover. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sha2_api.h"
#include "slh_dsa.h"
#ifdef TOS_SLHDSA_SHA256_TESTING
#include "slhdsa-sha256.h"
#endif

#define CHECK(cond)                                                          \
  do                                                                         \
  {                                                                          \
    if (!(cond))                                                             \
    {                                                                        \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
      exit(1);                                                               \
    }                                                                        \
  } while (0)

enum
{
  public_key_bytes = 32,
  signature_bytes = 7856,
  max_field_bytes = 255,
  max_vectors = 64,
  max_rounds = 100000,
  default_rounds = 200,
  compress_blocks = 2000000,
  /* Four hex fields, three separators, line end. */
  max_line = 2 * (public_key_bytes + 2 * max_field_bytes + signature_bytes) + 8
};

struct vector
{
  uint8_t pk[public_key_bytes];
  uint8_t ctx[max_field_bytes];
  size_t ctx_len;
  uint8_t msg[max_field_bytes];
  size_t msg_len;
  uint8_t sig[signature_bytes];
  int result;
};

static struct vector vectors[max_vectors];
static size_t vector_count;
/* The chaining value the compression loop ends with; it must not depend on the backend. */
static uint32_t compress_result[8];

static int hex_digit(char c)
{
  if (c >= '0' && c <= '9')
  {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f')
  {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F')
  {
    return c - 'A' + 10;
  }
  return -1;
}

/* Decodes one whitespace-delimited hex field of at most `cap` bytes and returns its length. */
static size_t hex_field(char **cursor, uint8_t *out, size_t cap)
{
  char *p = *cursor;
  while (*p == ' ' || *p == '\t')
  {
    p++;
  }
  size_t n = 0;
  while (hex_digit(p[0]) >= 0)
  {
    CHECK(hex_digit(p[1]) >= 0);
    CHECK(n < cap);
    out[n++] = (uint8_t)(hex_digit(p[0]) * 16 + hex_digit(p[1]));
    p += 2;
  }
  CHECK(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\0');
  *cursor = p;
  return n;
}

static void load_vectors(const char *path)
{
  static char line[max_line];
  FILE *in = fopen(path, "r");
  CHECK(in != NULL);
  while (fgets(line, sizeof line, in) != NULL)
  {
    size_t len = strlen(line);
    CHECK(len > 0 && (len + 1 < sizeof line || line[len - 1] == '\n'));
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
    {
      continue;
    }
    CHECK(vector_count < max_vectors);
    struct vector *v = &vectors[vector_count];
    char *cursor = line;
    CHECK(hex_field(&cursor, v->pk, sizeof v->pk) == sizeof v->pk);
    v->ctx_len = hex_field(&cursor, v->ctx, sizeof v->ctx);
    v->msg_len = hex_field(&cursor, v->msg, sizeof v->msg);
    CHECK(hex_field(&cursor, v->sig, sizeof v->sig) == sizeof v->sig);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r')
    {
      cursor++;
    }
    CHECK(*cursor == '\0');
    vector_count++;
  }
  CHECK(ferror(in) == 0);
  CHECK(fclose(in) == 0);
  CHECK(vector_count > 0);
}

static uint64_t now_ns(void)
{
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
  return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static int verify(const struct vector *v)
{
  return slh_verify(v->msg, v->msg_len, v->sig, sizeof v->sig, v->ctx, v->ctx_len, v->pk,
                    &slh_dsa_sha2_128s);
}

static int by_value(const void *a, const void *b)
{
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return x < y ? -1 : x > y;
}

static const char *backend_name(void)
{
#ifdef TOS_SLHDSA_SHA256_TESTING
  return tos_slhdsa_sha256_backend();
#else
  return "portable";
#endif
}

/* `first` records each vector's result and the compression loop's final chaining value; later
 * passes must reproduce both. */
static void measure(const char *name, uint64_t *samples, size_t rounds, int first)
{
  size_t valid = 0;
  for (size_t i = 0; i < vector_count; i++)
  {
    int result = verify(&vectors[i]);
    CHECK(result == 0 || result == 1);
    if (first)
    {
      vectors[i].result = result;
    }
    CHECK(result == vectors[i].result);
    valid += (size_t)result;
  }
  size_t n = 0;
  for (size_t r = 0; r < rounds; r++)
  {
    for (size_t i = 0; i < vector_count; i++)
    {
      uint64_t start = now_ns();
      int result = verify(&vectors[i]);
      samples[n++] = now_ns() - start;
      CHECK(result == vectors[i].result);
    }
  }
  qsort(samples, n, sizeof samples[0], by_value);
  printf("verify %s: vectors=%zu valid=%zu invalid=%zu rounds=%zu min=%.1f median=%.1f max=%.1f us\n",
         name, vector_count, valid, vector_count - valid, rounds, (double)samples[0] / 1e3,
         (double)samples[n / 2] / 1e3, (double)samples[n - 1] / 1e3);

  uint32_t state[8 + 24];
  memset(state, 0x5a, sizeof state);
  uint64_t start = now_ns();
  for (size_t i = 0; i < compress_blocks; i++)
  {
    sha2_256_compress(state);
  }
  uint64_t spent = now_ns() - start;
  if (first)
  {
    memcpy(compress_result, state, sizeof compress_result);
  }
  CHECK(memcmp(compress_result, state, sizeof compress_result) == 0);
  printf("compress %s: %.1f ns per block over %d chained blocks\n", name,
         (double)spent / (double)compress_blocks, (int)compress_blocks);
}

int main(int argc, char **argv)
{
  CHECK(argc == 2 || argc == 3);
  size_t rounds = default_rounds;
  if (argc == 3)
  {
    char *end = NULL;
    unsigned long value = strtoul(argv[2], &end, 10);
    CHECK(end != argv[2] && *end == '\0' && value >= 1 && value <= max_rounds);
    rounds = (size_t)value;
  }
  load_vectors(argv[1]);
  uint64_t *samples = malloc(rounds * vector_count * sizeof samples[0]);
  CHECK(samples != NULL);

  const char *selected = backend_name();
  printf("SLH-DSA SHA-256 backend: %s\n", selected);
  measure(selected, samples, rounds, 1);
#ifdef TOS_SLHDSA_SHA256_TESTING
  if (strcmp(selected, "portable") != 0)
  {
    tos_slhdsa_sha256_force_portable(1);
    CHECK(strcmp(tos_slhdsa_sha256_backend(), "portable") == 0);
    measure("portable", samples, rounds, 0);
    tos_slhdsa_sha256_force_portable(0);
    CHECK(strcmp(tos_slhdsa_sha256_backend(), selected) == 0);
  }
#endif
  free(samples);
  printf("NOTE: timing of this host only, for the signatures in the file; not a pass/fail result\n");
  return 0;
}
