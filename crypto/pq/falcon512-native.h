/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* 1 valid, 0 invalid encoding/proof, -1 wrong lengths, other: backend failure. */
int tos_falcon512_padded_verify(const uint8_t *message, size_t message_len, const uint8_t *signature,
                                size_t signature_len, const uint8_t *key, size_t key_len);
/* Canonical public-key validation, without treating an invalid proof as a key test. */
int tos_falcon512_public_key_valid(const uint8_t *key, size_t key_len);
#ifdef __cplusplus
}
#endif
