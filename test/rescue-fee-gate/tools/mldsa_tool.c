/* Test-only ML-DSA-44 tool (public test data, deterministic Pure signing).
 *   mldsa_tool keygen <seed32hex> <pkfile> <skfile>
 *   mldsa_tool sign <skfile> <ctxhex|-> <msgfile> <sigfile>
 */
#include <stdio.h>
#include <string.h>
#include "mldsa_native.h"

static int unhex(const char *s, uint8_t *out, size_t max) {
  size_t n = strlen(s);
  if (n % 2 || n / 2 > max) return -1;
  for (size_t i = 0; i < n / 2; i++) {
    unsigned v;
    if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
    out[i] = (uint8_t)v;
  }
  return (int)(n / 2);
}

static int put(const char *path, const uint8_t *b, size_t n) {
  FILE *f = fopen(path, "wb");
  if (!f || fwrite(b, 1, n, f) != n) return -1;
  return fclose(f);
}

int main(int argc, char **argv) {
  static uint8_t pk[1312], sk[2560], sig[2420], msg[8192], pre[257];
  if (argc == 5 && !strcmp(argv[1], "keygen")) {
    uint8_t seed[32];
    if (unhex(argv[2], seed, 32) != 32) return 2;
    if (mldtest_keypair_internal(pk, sk, seed) != 0) return 3;
    return put(argv[3], pk, sizeof pk) || put(argv[4], sk, sizeof sk);
  }
  if (argc == 6 && !strcmp(argv[1], "sign")) {
    FILE *f = fopen(argv[2], "rb");
    if (!f || fread(sk, 1, sizeof sk, f) != sizeof sk) return 2;
    fclose(f);
    int ctx_len = strcmp(argv[3], "-") ? unhex(argv[3], pre + 2, 255) : 0;
    if (ctx_len < 0) return 2;
    pre[0] = 0;
    pre[1] = (uint8_t)ctx_len;
    f = fopen(argv[4], "rb");
    if (!f) return 2;
    size_t m = fread(msg, 1, sizeof msg, f);
    fclose(f);
    uint8_t rnd[32] = {0};
    if (mldtest_signature_internal(sig, msg, m, pre, (size_t)ctx_len + 2, rnd, sk, 0) != 0) return 4;
    return put(argv[5], sig, sizeof sig);
  }
  return 1;
}
