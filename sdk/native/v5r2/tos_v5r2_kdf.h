#ifndef TOS_V5R2_KDF_H
#define TOS_V5R2_KDF_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Material: 1 primary (32 bytes), 2 rescue (48), 3 fee (48).
 * master is exactly 32 mutable bytes and wiped on every return path.
 * network is 32 readable bytes; tree_id is 32 bytes for fee and NULL otherwise.
 * All buffers must be valid and nonoverlapping. Output is wiped on failure.
 * Domain separation does not establish independent custody or restore fee state. */
int tos_v5r2_derive_and_wipe(int material, uint8_t *master, size_t master_size,
    const uint8_t *network, int32_t global_id, uint32_t account_index,
    uint32_t key_generation, const uint8_t *tree_id, uint8_t *output, size_t output_size);
#ifdef __cplusplus
}
#endif
#endif
