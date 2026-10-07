/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "embedded.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Trusted caller-owned private directory, never supplied by an endpoint.
 * Only live requests are allowed. initialize=1 is explicit first enrollment,
 * never a missing-state repair. Existing enrollment with missing state refuses.
 * State is committed (file + directory fsync) before any result is returned.
 * The caller must exclude this directory from backup and protect it from edits.
 * Errors include -5 busy and -6 persistence refused; outputs remain empty.
 */
int tos_proof_verify_live_persisted(const char *directory, int initialize,
    const char *anchor, size_t anchor_size, const char *request, size_t request_size,
    int64_t local_now, const tos_proof_material *material, size_t material_count,
    char *result, size_t result_capacity, size_t *result_size);
#ifdef __cplusplus
}
#endif
