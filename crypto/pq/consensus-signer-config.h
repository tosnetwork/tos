/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
/* Sign+keygen-enabled ML-DSA-44 backend for the validator CONSENSUS signer only.
   Distinct namespace from the node's verify-only backend (tos_mldsa44_native) and
   the key-tool (tos_pq_tool), so this signer is never linked into the consensus
   verify path or the ADNL keyring. */
#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX tos_pq_cs_native
#define MLD_CONFIG_NO_RANDOMIZED_API
