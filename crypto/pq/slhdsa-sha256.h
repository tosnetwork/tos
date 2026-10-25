/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

/* SHA-256 backend of the SLH-DSA verifier when it is built with TOS_SLHDSA_SHA_NI.
 * The hashes are identical on either path; only CPU time differs. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* "sha-ni" when the running CPU executes the SHA-NI compression path, otherwise "portable". */
const char *tos_slhdsa_sha256_backend(void);

/* One SHA-256 compression of the SLH state layout (chaining value as big-endian words in
 * sp[0..7], block in sp[8..23]) by the vendored SHA-NI transform. Only called after the CPU
 * probe has accepted SHA-NI. */
void tos_slhdsa_sha_ni_compress(uint32_t *sp);

#ifdef TOS_SLHDSA_SHA256_TESTING
/* Test builds only: nonzero pins the portable path, zero returns to CPU detection. */
void tos_slhdsa_sha256_force_portable(int on);
/* Test builds only: the probe's decision for given CPUID leaf 1 ECX and leaf 7 EBX values. */
int tos_slhdsa_sha256_accepts_cpu(unsigned leaf1_ecx, unsigned leaf7_ebx);
#endif

#ifdef __cplusplus
}
#endif
