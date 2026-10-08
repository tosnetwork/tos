/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only */
/* PROTOTYPE. The single SLH-DSA profile the Rust VM admits (suite 3): Pure
 * SLH-DSA-SHA2-128s verification with an explicit context. The parameter table
 * stays in C, so Rust never restates its layout. Returns 1 valid, 0 invalid. */
#include "slh_dsa.h"

int tos_rust_slhdsa128s_verify(const uint8_t *m, size_t m_sz, const uint8_t *sig, size_t sig_sz,
                               const uint8_t *ctx, size_t ctx_sz, const uint8_t *pk) {
  return slh_verify(m, m_sz, sig, sig_sz, ctx, ctx_sz, pk, &slh_dsa_sha2_128s);
}
