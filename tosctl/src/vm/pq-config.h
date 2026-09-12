/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only */
/* Share the exact parameter set and verify-only portable implementation. Only
 * the symbol prefix differs, avoiding interposition with a loaded native VM. */
#include "../../../crypto/pq/mldsa44-config.h"
#undef MLD_CONFIG_NAMESPACE_PREFIX
#define MLD_CONFIG_NAMESPACE_PREFIX tos_rust_mldsa44_native
