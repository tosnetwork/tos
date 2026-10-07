/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Callbacks are trusted local code. Query must enforce capacity while receiving
 * endpoint-controlled bytes and set size only on success. Buffers are borrowed
 * for the callback duration; callbacks must not re-enter this acquisition.
 * Emit receives unverified material (same kinds as embedded.h). Collectors must
 * discard all emitted data if the whole call fails. No state is committed and
 * no signing authority follows from acquisition success.
 */
typedef int (*tos_proof_query_callback)(void *context, const uint8_t *query, size_t query_size,
    uint8_t *response, size_t response_capacity, size_t *response_size);
typedef int (*tos_proof_emit_callback)(void *context, uint32_t kind, const uint8_t *data, size_t size);
int tos_proof_acquire(const char *anchor, size_t anchor_size, const char *request, size_t request_size,
    const char *state, size_t state_size, tos_proof_query_callback query, void *query_context,
    tos_proof_emit_callback emit, void *emit_context);
#ifdef __cplusplus
}
#endif
