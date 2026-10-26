/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Pointer ranges must be valid for their lengths and mutually disjoint.
 * Output capacities are bounded (result 64 MiB, state 1 MiB). Invalid output
 * pointers/capacities cannot be cleared and are refused before reading inputs.
 * All inputs are borrowed for this call. Anchor, clock and persisted live state
 * are locally trusted. Proof material is untrusted. No transport, filesystem or
 * state commit is performed. Live next_state must be durably committed before
 * using a successful result; omission of prior live state is not a restore API.
 * kind: 1 masterchain_info, 2 chain, 3 descent, 4 config, 5 account,
 *       6 exec_config, 7 libraries. Repeated singleton kinds are rejected. */
typedef struct tos_proof_material {
  uint32_t kind;
  const uint8_t *data;
  size_t size;
} tos_proof_material;
/* Return 0 verified, -1 invalid interface input, -2 verification refused,
 * -3 insufficient output capacity, -4 internal failure. Outputs are cleared on
 * every failure after validating output buffers. Returned lengths exclude NUL; outputs are byte strings.
 * Caller must serialize live reads and independently bind result to the wallet.
 */
int tos_proof_verify_embedded(const char *anchor, size_t anchor_size, const char *request, size_t request_size,
                              const char *state, size_t state_size, int64_t local_now,
                              const tos_proof_material *material, size_t material_count, char *result,
                              size_t result_capacity, size_t *result_size, char *next_state, size_t state_capacity,
                              size_t *next_state_size);
/* Bounded local transaction codec and hash binding, not chain authentication,
 * execution, fee estimation or a claim of payment. The caller must obtain the
 * expected transaction hash/lt from an authenticated account head or predecessor.
 * Only basechain (workchain 0) is supported. Hash inputs are exactly 32 borrowed
 * bytes each. BOC and result capacity are bounded to 1 MiB; input cell count to
 * 16384, graph depth to 1023 and output messages to 256. Opaque message bodies
 * are hashed without executing them. No I/O or persistent state is used.
 * Pointer ranges must be valid and mutually disjoint, including result_size.
 * Return codes and output clearing follow tos_proof_verify_embedded above.
 */
int tos_proof_verify_wallet_transaction(int32_t workchain, const uint8_t *account_hash, uint64_t logical_time,
                                        const uint8_t *transaction_hash, const uint8_t *boc, size_t boc_size,
                                        char *result, size_t result_capacity, size_t *result_size);
#ifdef __cplusplus
}
#endif
