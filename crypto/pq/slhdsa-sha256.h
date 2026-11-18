/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

/* SHA-256 backend of the SLH-DSA verifier when it is built with TOS_SLHDSA_SHA_NI (x86-64) or
 * TOS_SLHDSA_ARMV8_SHA2 (Linux aarch64). The hashes are identical on every path; only CPU
 * time differs. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The compression path the running CPU executes: "sha-ni" (x86-64 builds) or "armv8-sha2"
 * (aarch64 builds) when the probe accepts the CPU, otherwise "portable". */
const char *tos_slhdsa_sha256_backend(void);

/* One SHA-256 compression of the SLH state layout (chaining value as big-endian words in
 * sp[0..7], block in sp[8..23]) by the vendored SHA-NI transform. x86-64 builds only; only
 * called after the CPU probe has accepted SHA-NI. */
void tos_slhdsa_sha_ni_compress(uint32_t *sp);

/* The same by the vendored ARMv8 SHA2 transform. aarch64 builds only; only called after the
 * kernel has reported the SHA2 extension. */
void tos_slhdsa_armv8_sha2_compress(uint32_t *sp);

#ifdef TOS_SLHDSA_SHA256_TESTING
/* Test builds only: nonzero pins the portable path, zero returns to CPU detection. */
void tos_slhdsa_sha256_force_portable(int on);
#if defined(__x86_64__)
/* Test builds only: the probe's decision for given CPUID leaf 1 ECX and leaf 7 EBX values. */
int tos_slhdsa_sha256_accepts_cpu(unsigned leaf1_ecx, unsigned leaf7_ebx);
#elif defined(__aarch64__)
/* Test builds only: the probe's decision for a given AT_HWCAP value. */
int tos_slhdsa_sha256_accepts_hwcap(unsigned long hwcap);
#endif
#endif

#ifdef __cplusplus
}
#endif
