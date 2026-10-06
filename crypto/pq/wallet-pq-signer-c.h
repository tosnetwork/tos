/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tos_wallet_pq_signer tos_wallet_pq_signer;
enum { TOS_WALLET_PQ_PRIMARY = 1, TOS_WALLET_PQ_RESCUE = 2 };
enum { TOS_WALLET_PQ_AUTH = 1, TOS_WALLET_PQ_POP = 2, TOS_WALLET_PQ_PREPARATION = 3 };

/* Owned, non-copyable handle. NULL means failure. No exception crosses this ABI.
 * Import consumes no ownership: caller must wipe its seed (32 primary / 48 rescue).
 * This interface supplies no persistence, approval UI or chain-proof validation. */
tos_wallet_pq_signer* tos_wallet_pq_generate(int role);
tos_wallet_pq_signer* tos_wallet_pq_import(int role, const uint8_t* seed, size_t seed_size);
void tos_wallet_pq_destroy(tos_wallet_pq_signer* signer);

/* Return 1 on success, 0 on failure. Output buffers are untouched on failure.
 * Exact sizes only: public key 1312 primary / 32 rescue; signature 2420 / 7856.
 * All non-NULL pointers must designate valid memory of the stated size, and a
 * live handle must not be destroyed concurrently with any operation. */
int tos_wallet_pq_public_key(const tos_wallet_pq_signer* signer, uint8_t* output, size_t output_size);

/* Caller obtains expected role/key from its authenticated enrollment. Matching
 * these fields prevents accidental use of another signer; it does not authenticate
 * enrollment or approve the digest. Only protocol-defined purposes are admitted.
 * The native backend verifies the randomized signature before it is copied out. */
int tos_wallet_pq_sign(const tos_wallet_pq_signer* signer, int expected_role, int purpose, const uint8_t* expected_key,
                       size_t key_size, const uint8_t* digest, size_t digest_size, uint8_t* signature,
                       size_t signature_size);

#ifdef __cplusplus
}
#endif
