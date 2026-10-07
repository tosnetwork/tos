#ifndef TOS_FEE_STATE_H
#define TOS_FEE_STATE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* All array arguments are exactly 32 readable bytes. Outputs must be writable.
 * Handles are process-local integers, never pointers. Calls serialize internally
 * and return BUSY on contention; close must succeed before discarding a handle.
 * 0 success; -1 invalid; -2 state/IO/wait; -3 busy; -4 internal; -5 capacity.
 * These operations neither authenticate proofs nor sign or approve broadcast. */
int32_t tos_fee_state_open(const uint8_t *path, size_t path_size, int32_t global_id,
    const uint8_t *network, const uint8_t *vault, const uint8_t *tree_id,
    uint32_t epoch0, uint32_t proven_time, uint64_t *output);
int32_t tos_fee_state_preview(uint64_t handle, uint32_t time, uint32_t chain_next, uint32_t *leaf);
int32_t tos_fee_state_reserve(uint64_t handle, uint32_t time, uint32_t chain_next,
    uint32_t expected_leaf, const uint8_t *digest, uint64_t *reservation);
int32_t tos_fee_state_close(uint64_t handle);
/* Trusted native verification callback: exactly 1 means valid. It must not
 * unwind or trust network verdicts. Reentrant state calls return BUSY.
 * public_key is 60 bytes, digest 32, signature 2832. No signer is called here. */
typedef int32_t (*tos_fee_state_verify)(void *context, const uint8_t *public_key,
    uint32_t leaf, const uint8_t *digest, const uint8_t *signature, size_t signature_size);
int32_t tos_fee_state_cache_verified(uint64_t handle, uint64_t reservation,
    const uint8_t *public_key, const uint8_t *signature, size_t signature_size,
    tos_fee_state_verify verify, void *context);
int32_t tos_fee_state_cached_verified(uint64_t handle, uint32_t leaf,
    const uint8_t *digest, const uint8_t *public_key, tos_fee_state_verify verify,
    void *context, uint8_t *output, size_t output_size);
#ifdef __cplusplus
}
#endif
#endif
