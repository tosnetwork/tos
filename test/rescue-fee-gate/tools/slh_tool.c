/* Test-only SLH-DSA-SHA2-128s tool (public test data, deterministic signing).
 *   slh_tool keygen <seed48hex>              -> prints pk_hex sk_hex
 *   slh_tool sign <sk64hex> <ctxhex|-> <msgfile> <sigfile>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "slh_dsa.h"

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

int main(int argc, char **argv) {
  const slh_param_t *p = &slh_dsa_sha2_128s;
  if (argc == 3 && !strcmp(argv[1], "keygen")) {
    uint8_t seed[48], pk[32], sk[64];
    if (unhex(argv[2], seed, 48) != 48) return 2;
    if (slh_keygen_internal(sk, pk, seed, seed + 16, seed + 32, p) != 0) return 3;
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf(" ");
    for (int i = 0; i < 64; i++) printf("%02x", sk[i]);
    printf("\n");
    return 0;
  }
  if (argc == 6 && !strcmp(argv[1], "sign")) {
    uint8_t sk[64], ctx[255], msg[8192], sig[7856];
    if (unhex(argv[2], sk, 64) != 64) return 2;
    int ctx_len = strcmp(argv[3], "-") ? unhex(argv[3], ctx, 255) : 0;
    if (ctx_len < 0) return 2;
    FILE *f = fopen(argv[4], "rb");
    if (!f) return 2;
    size_t m = fread(msg, 1, sizeof msg, f);
    fclose(f);
    size_t n = slh_sign(sig, msg, m, ctx, (size_t)ctx_len, sk, NULL, p);
    if (n != 7856) return 4;
    f = fopen(argv[5], "wb");
    if (!f || fwrite(sig, 1, n, f) != n) return 5;
    fclose(f);
    return 0;
  }
  return 1;
}
