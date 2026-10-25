/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/* The imported third-party/slhdsa-c/sha2_256.c, unmodified, under ref_ names: the reference the
 * SHA-NI backend is compared against. Every public name is renamed, so the original buffering
 * code calls the original compression function. */
#include "sha256-reference.h"

#define sha2_256_compress ref_sha2_256_compress
#define sha2_256_init_h0 ref_sha2_256_init_h0
#define sha2_256_init ref_sha2_256_init
#define sha2_224_init ref_sha2_224_init
#define sha2_256_copy ref_sha2_256_copy
#define sha2_256_update ref_sha2_256_update
#define sha2_256_final_pad ref_sha2_256_final_pad
#define sha2_256_final_len ref_sha2_256_final_len
#define sha2_256 ref_sha2_256
#define sha2_224 ref_sha2_224
#include "sha2_256.c"
