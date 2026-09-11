/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifndef TOS_MLDSA44_CONFIG_H
#define TOS_MLDSA44_CONFIG_H
#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX tos_mldsa44_native
#define MLD_CONFIG_NO_KEYPAIR_API
#define MLD_CONFIG_NO_SIGN_API
#define MLD_CONFIG_NO_RANDOMIZED_API
/* Keep arithmetic and FIPS202 on the portable C backend. Do not enable native
 * backend selection or a runtime provider in this consensus build. */
#endif
