#ifdef NDEBUG
#undef NDEBUG
#endif
#include "tos_v5r2.h"
#include "mldsa_native.h"
#include "slh_dsa.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifndef TOS_V5R2_ML_PREFIX
#define TOS_V5R2_ML_PREFIX tos_v5r2_mldsa44
#endif
#define JOIN_INNER(a,b) a##b
#define JOIN(a,b) JOIN_INNER(a,b)

static int zero(const uint8_t *p, size_t n) {
  while (n--) if (*p++) return 0;
  return 1;
}
int main(void) {
  uint8_t seed[48], entropy[32], digest[32], pk[1312], same[1312], sig[7856];
  memset(seed, 0x11, sizeof(seed)); memset(entropy, 0x22, sizeof(entropy)); memset(digest, 0x33, sizeof(digest));
  assert(tos_v5r2_seed_size(0) == 0 && tos_v5r2_signature_size(3) == 0);
  for (int role = 1; role <= 2; ++role) {
    size_t ns = tos_v5r2_seed_size(role), np = tos_v5r2_public_key_size(role);
    size_t ne = tos_v5r2_entropy_size(role), nz = tos_v5r2_signature_size(role);
    assert(tos_v5r2_public_key(role, seed, ns, pk, np) == 0);
    assert(tos_v5r2_public_key(role, seed, ns, same, np) == 0 && !memcmp(pk, same, np));
    memset(same, 0xff, np);
    assert(tos_v5r2_public_key(role, seed, ns - 1, same, np) == -1 && zero(same, np));
    for (int purpose = 1; purpose <= 3; ++purpose) {
      memset(sig, 0xff, nz);
      int rc = tos_v5r2_sign(role, purpose, seed, ns, entropy, ne, digest, 32, sig, nz);
      if (role == 1 && purpose == 3) { assert(rc == -1 && zero(sig, nz)); continue; }
      assert(rc == 0 && tos_v5r2_verify(role, purpose, pk, np, digest, 32, sig, nz) == 1);
      const char *expected = purpose == 2 ? "TOS-RESCUE-POP-v1" : purpose == 3 ? "TOS-RESCUE-FEE-PREP-v1" :
                             role == 1 ? "TOS-AUTH-V2-ML-DSA-44-v1" : "TOS-AUTH-SLH-DSA-SHA2-128S-v1";
      if (role == 1) assert(JOIN(TOS_V5R2_ML_PREFIX, _verify)(sig, digest, 32, (const uint8_t *)expected, strlen(expected), pk) == 0);
      else assert(slh_verify(digest, 32, sig, nz, (const uint8_t *)expected, strlen(expected), pk, &slh_dsa_sha2_128s) == 1);
      assert(tos_v5r2_verify(role, purpose == 1 ? 2 : 1, pk, np, digest, 32, sig, nz) == 0);
      assert(tos_v5r2_verify(role, purpose, pk, np, digest, 31, sig, nz) == 0);
      assert(tos_v5r2_verify(role, purpose, pk, np, digest, 32, sig, nz - 1) == 0);
      digest[0] ^= 1; assert(!tos_v5r2_verify(role, purpose, pk, np, digest, 32, sig, nz)); digest[0] ^= 1;
      sig[0] ^= 1; assert(!tos_v5r2_verify(role, purpose, pk, np, digest, 32, sig, nz));
    }
    memset(sig, 0xff, nz);
    assert(tos_v5r2_sign(role, 99, seed, ns, entropy, ne, digest, 32, sig, nz) == -1 && zero(sig, nz));
    memset(sig, 0xff, nz);
    assert(tos_v5r2_sign(role, 1, seed, ns, entropy, ne - 1, digest, 32, sig, nz) == -1 && zero(sig, nz));
    memset(sig, 0xff, nz);
    assert(tos_v5r2_sign(role, 1, seed, ns, entropy, ne, digest, 33, sig, nz) == -1 && zero(sig, nz));
    assert(tos_v5r2_verify(role, 0, pk, np, digest, 32, sig, nz) == 0);
  }
  puts("mobile V5R2: both roles, five contexts, malformed inputs and cleared failure outputs pass");
  return 0;
}
