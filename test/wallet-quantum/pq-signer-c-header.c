/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "wallet-pq-signer-c.h"

/* Compile and link the public header as C, not just through a C++ consumer. */
int wallet_pq_c_header_test(void) {
  tos_wallet_pq_destroy(NULL);
  return tos_wallet_pq_generate(0) == NULL && tos_wallet_pq_import(TOS_WALLET_PQ_PRIMARY, NULL, 32) == NULL &&
         tos_wallet_pq_public_key(NULL, NULL, 0) == 0;
}
