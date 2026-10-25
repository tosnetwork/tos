/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "sha2_api.h"

void ref_sha2_256_compress(void *v);
void ref_sha2_256_init(sha2_256_t *sha);
void ref_sha2_224_init(sha2_256_t *sha);
void ref_sha2_256_copy(sha2_256_t *dst, const sha2_256_t *src);
void ref_sha2_256_update(sha2_256_t *sha, const uint8_t *m, size_t m_sz);
void ref_sha2_256_final_pad(sha2_256_t *sha);
void ref_sha2_256_final_len(sha2_256_t *sha, uint8_t *h, size_t h_sz);
void ref_sha2_256(uint8_t *h, const void *m, size_t m_sz);
void ref_sha2_224(uint8_t *h, const void *m, size_t m_sz);
