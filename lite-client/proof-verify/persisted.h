/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "acquisition.h"
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
int tos_proof_verify_live_persisted(const char *directory, int initialize, const char *anchor, size_t anchor_size,
                                    const char *request, size_t request_size, int64_t local_now,
                                    const tos_proof_material *material, size_t material_count, char *result,
                                    size_t result_capacity, size_t *result_size);
/* Holds the same checkpoint lock across acquisition, verification and commit.
 * Query callback must apply network timeout/cancellation and receive-size bounds.
 */
int tos_proof_acquire_verify_live_persisted(const char *directory, int initialize, const char *anchor,
                                            size_t anchor_size, const char *request, size_t request_size,
                                            int64_t local_now, tos_proof_query_callback query, void *query_context,
                                            char *result, size_t result_capacity, size_t *result_size);
/* Same lock and durable commit as live reads, but acquires full simulation
 * inputs and locally executes the exact signed message. Requires an existing
 * enrollment/checkpoint; never initializes or restores missing state. Message
 * <=1 MiB, result capacity <=2 MiB; other bounds follow the simulation/acquisition
 * ABI. The message is never passed to the query callback. A successful result
 * is only local_estimate, never a receipt, balance cache update or outbox release.
 * Return codes -1..-6 are the simulation ABI's errors; -7 persistence refused,
 * -8 busy. Acquisition failure is -2. Valid outputs are cleared on every failure.
 * Pointer ranges are valid and disjoint as in the embedded ABI. The trusted
 * directory and callback lifetime/timeout rules above still apply.
 */
int tos_proof_acquire_simulate_self_pay_persisted(
    const char *directory, const char *anchor, size_t anchor_size, const char *request, size_t request_size,
    int64_t local_now, tos_proof_query_callback query, void *query_context, const uint8_t *message, size_t message_size,
    char *result, size_t result_capacity, size_t *result_size);
#ifdef __cplusplus
}
#endif
