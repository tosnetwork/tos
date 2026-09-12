/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only */
/* The verifier distinguishes "this signature is invalid" from "the backend
 * failed", and the two are told apart by a constant the vendored header owns.
 * Exporting it from the one translation unit where that header is in scope
 * keeps the value out of Rust, where it could only ever be a stale copy. */
#include "mldsa_native.h"

const int tos_rust_mldsa44_invalid_signature = MLD_ERR_INVALID_SIGNATURE;
