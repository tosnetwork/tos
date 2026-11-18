/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/* The work one Pure SLH-DSA-SHA2-128s verification costs, counted, not timed: the number of
 * SHA-256 compressions the imported verifier performs for each input of a vector file, with the
 * imported implementation's own counter (SLH_EXPERIMENTAL). The count does not depend on the
 * host, the compiler or the SHA-256 backend, so it is a pass/fail check where a time is not.
 *
 * Usage: test-pq-slhdsa-work <vectors.txt> <result> <compressions>
 * Every input of the file must give that verification result (0 or 1) and cost exactly that
 * many compressions. slh-worst-case-vectors.txt is kept as the input the gas price has to cover
 * by this check: a change to it that makes it cheaper, or makes it verify, fails here. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2_api.h"
#include "slh_dsa.h"

extern uint64_t sha2_256_compress_count;
extern uint64_t sha2_512_compress_count;

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
  /* The bound for this parameter set is 3,894; nothing legitimate is asked for above it. */
  max_compressions = 3894,
  /* Four hex fields, three separators, line end. */
  max_line = 2 * (public_key_bytes + 2 * max_field_bytes + signature_bytes) + 8
};

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

static unsigned long parse_number(const char *text, unsigned long max)
{
  char *end = NULL;
  CHECK(text[0] >= '0' && text[0] <= '9');
  unsigned long value = strtoul(text, &end, 10);
  CHECK(end != text && *end == '\0' && value <= max);
  return value;
}

int main(int argc, char **argv)
{
  static char line[max_line];
  static uint8_t pk[public_key_bytes], ctx[max_field_bytes], msg[max_field_bytes];
  static uint8_t sig[signature_bytes];
  CHECK(argc == 4);
  const int want_result = (int)parse_number(argv[2], 1);
  const uint64_t want_compressions = parse_number(argv[3], max_compressions);

  FILE *in = fopen(argv[1], "r");
  CHECK(in != NULL);
  size_t vectors = 0;
  while (fgets(line, sizeof line, in) != NULL)
  {
    size_t len = strlen(line);
    CHECK(len > 0 && (len + 1 < sizeof line || line[len - 1] == '\n'));
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
    {
      continue;
    }
    CHECK(vectors < max_vectors);
    char *cursor = line;
    CHECK(hex_field(&cursor, pk, sizeof pk) == sizeof pk);
    size_t ctx_len = hex_field(&cursor, ctx, sizeof ctx);
    size_t msg_len = hex_field(&cursor, msg, sizeof msg);
    CHECK(hex_field(&cursor, sig, sizeof sig) == sizeof sig);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r')
    {
      cursor++;
    }
    CHECK(*cursor == '\0');

    sha2_256_compress_count = 0;
    sha2_512_compress_count = 0;
    int result = slh_verify(msg, msg_len, sig, sizeof sig, ctx, ctx_len, pk, &slh_dsa_sha2_128s);
    uint64_t compressions = sha2_256_compress_count;
    vectors++;
    printf("input %zu: result=%d sha256_compressions=%llu\n", vectors, result,
           (unsigned long long)compressions);
    /* This parameter set hashes with SHA-256 only. */
    CHECK(sha2_512_compress_count == 0);
    if (result != want_result || compressions != want_compressions)
    {
      fprintf(stderr, "input %zu: expected result=%d sha256_compressions=%llu\n", vectors,
              want_result, (unsigned long long)want_compressions);
      return 1;
    }
  }
  CHECK(ferror(in) == 0);
  CHECK(fclose(in) == 0);
  CHECK(vectors > 0);
  printf("OK: %zu input(s), each result=%d at %llu SHA-256 compressions\n", vectors, want_result,
         (unsigned long long)want_compressions);
  return 0;
}
