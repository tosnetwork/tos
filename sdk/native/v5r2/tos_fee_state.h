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
#ifdef __cplusplus
}
#endif
#endif
