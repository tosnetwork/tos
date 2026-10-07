#ifndef TOS_Quantum_NATIVE_H
#define TOS_Quantum_NATIVE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Roles: 1 ML-DSA-44 PRIMARY; 2 SLH-SHA2-128s rescue.
 * Purposes: 1 AUTH; 2 POP; 3 preparation (rescue only).
 * Seed sizes: 32/48; entropy sizes: 32/16. Caller supplies checked OS entropy.
 * Digest is exactly 32 bytes. No expanded secret leaves the native call.
 * This stateless API never signs LMS or grants a fee-state reservation. */
size_t tos_quantum_seed_size(int role);
size_t tos_quantum_public_key_size(int role);
size_t tos_quantum_signature_size(int role);
size_t tos_quantum_entropy_size(int role);
int tos_quantum_public_key(int role, const uint8_t *seed, size_t seed_size,
                      uint8_t *public_key, size_t public_key_size);
int tos_quantum_sign(int role, int purpose, const uint8_t *seed, size_t seed_size,
                 const uint8_t *entropy, size_t entropy_size,
                 const uint8_t *digest, size_t digest_size,
                 uint8_t *signature, size_t signature_size);
int tos_quantum_verify(int role, int purpose, const uint8_t *public_key, size_t public_key_size,
                   const uint8_t *digest, size_t digest_size,
                   const uint8_t *signature, size_t signature_size);
#ifdef __cplusplus
}
#endif
#endif
