#include "tos_quantum.h"
#include "mldsa_native.h"
#include "slh_dsa.h"
#include <string.h>

#ifndef TOS_Quantum_ML_PREFIX
#define TOS_Quantum_ML_PREFIX tos_mobile_mldsa44
#endif
#define JOIN_INNER(a,b) a##b
#define JOIN(a,b) JOIN_INNER(a,b)
#define M(sym) JOIN(TOS_Quantum_ML_PREFIX, _##sym)

static void wipe(void *data, size_t size) {
  volatile uint8_t *p = (volatile uint8_t *)data;
  while (size--) *p++ = 0;
}
static const char *context(int role, int purpose) {
  if (role != 1 && role != 2) return NULL;
  if (purpose == 1) return role == 1 ? "TOS-AUTH-V2-ML-DSA-44-v1" : "TOS-AUTH-SLH-DSA-SHA2-128S-v1";
  if (purpose == 2) return "TOS-RESCUE-POP-v1";
  if (purpose == 3 && role == 2) return "TOS-RESCUE-FEE-PREP-v1";
  return NULL;
}
size_t tos_quantum_seed_size(int role) { return role == 1 ? 32 : role == 2 ? 48 : 0; }
size_t tos_quantum_public_key_size(int role) { return role == 1 ? 1312 : role == 2 ? 32 : 0; }
size_t tos_quantum_signature_size(int role) { return role == 1 ? 2420 : role == 2 ? 7856 : 0; }
size_t tos_quantum_entropy_size(int role) { return role == 1 ? 32 : role == 2 ? 16 : 0; }
static int keygen(int role, const uint8_t *seed, uint8_t *sk, uint8_t *pk) {
  if (role == 1) return M(keypair_internal)(pk, sk, seed);
  return slh_keygen_internal(sk, pk, seed, seed + 16, seed + 32, &slh_dsa_sha2_128s);
}
int tos_quantum_public_key(int role, const uint8_t *seed, size_t seed_size, uint8_t *pk, size_t pk_size) {
  uint8_t sk[2560] = {0};
  int rc = -1;
  if (!pk || !pk_size || pk_size != tos_quantum_public_key_size(role)) return -1;
  if (seed && seed_size == tos_quantum_seed_size(role)) rc = keygen(role, seed, sk, pk);
  wipe(sk, sizeof(sk));
  if (rc) wipe(pk, pk_size);
  return rc ? -1 : 0;
}
int tos_quantum_verify(int role, int purpose, const uint8_t *pk, size_t pk_size,
                   const uint8_t *digest, size_t digest_size, const uint8_t *sig, size_t sig_size) {
  const char *ctx = context(role, purpose);
  if (!ctx || !pk || !digest || !sig || digest_size != 32 ||
      pk_size != tos_quantum_public_key_size(role) || sig_size != tos_quantum_signature_size(role)) return 0;
  if (role == 1) return M(verify)(sig, digest, digest_size, (const uint8_t *)ctx, strlen(ctx), pk) == 0;
  return slh_verify(digest, digest_size, sig, sig_size, (const uint8_t *)ctx, strlen(ctx), pk, &slh_dsa_sha2_128s) == 1;
}
int tos_quantum_sign(int role, int purpose, const uint8_t *seed, size_t seed_size,
                 const uint8_t *entropy, size_t entropy_size, const uint8_t *digest, size_t digest_size,
                 uint8_t *sig, size_t sig_size) {
  uint8_t sk[2560] = {0}, pk[1312] = {0}, prefix[64] = {0};
  const char *ctx = context(role, purpose);
  int rc = -1;
  if (!sig || !sig_size || sig_size != tos_quantum_signature_size(role)) return -1;
  if (!ctx || !seed || seed_size != tos_quantum_seed_size(role) || !entropy ||
      entropy_size != tos_quantum_entropy_size(role) || !digest || digest_size != 32) goto done;
  if (keygen(role, seed, sk, pk)) goto done;
  if (role == 1) {
    size_t n = strlen(ctx);
    prefix[0] = 0; prefix[1] = (uint8_t)n; memcpy(prefix + 2, ctx, n);
    rc = M(signature_internal)(sig, digest, digest_size, prefix, n + 2, entropy, sk, 0);
  } else {
    rc = slh_sign(sig, digest, digest_size, (const uint8_t *)ctx, strlen(ctx), sk, entropy,
                  &slh_dsa_sha2_128s) == sig_size ? 0 : -1;
  }
  if (rc || !tos_quantum_verify(role, purpose, pk, tos_quantum_public_key_size(role), digest, digest_size, sig, sig_size)) rc = -1;
done:
  wipe(sk, sizeof(sk)); wipe(pk, sizeof(pk)); wipe(prefix, sizeof(prefix));
  if (rc) wipe(sig, sig_size);
  return rc ? -1 : 0;
}
