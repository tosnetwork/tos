#ifndef HEADER_at_runtime_at_runtime_const_h
#define HEADER_at_runtime_at_runtime_const_h

/* Runtime constants for Avatar
   This provides protocol-level constants for the runtime. */

#include "at/infra/at_util_base.h"

/* Account data size limits */
#define AT_ACC_MAX_DATA_LEN              (10UL * 1024UL * 1024UL) /* 10 MiB */
#define AT_ACC_MIN_DATA_LEN              (0UL)
#define AT_ACC_INITIAL_DATA_LEN          (0UL)

/* Compute budget constants */
#define AT_COMPUTE_UNIT_LIMIT_DEFAULT    (200000UL)
#define AT_COMPUTE_UNIT_LIMIT_MAX        (10000000UL)
#define AT_HEAP_SIZE_DEFAULT             (32UL * 1024UL)   /* 32 KiB */
#define AT_HEAP_SIZE_MAX                 (256UL * 1024UL)  /* 256 KiB */

/* CPI limits */
#define AT_CPI_DEPTH_MAX                 (5UL)
#define AT_CPI_INSTRUCTION_SIZE_MAX      (1280UL)
#define AT_CPI_ACCOUNT_INFO_MAX          (128UL)

/* Secp256k1 limits */
#define AT_SECP256K1_INSTRUCTION_SIZE_MAX (12UL + 85UL * 20UL) /* header + max signatures */

/* Transaction limits */
#define AT_TXN_ACCOUNTS_MAX              (256UL)
#define AT_TXN_INSTRUCTIONS_MAX          (256UL)

/* Stack limits for BPF programs */
#define AT_BPF_STACK_FRAME_SIZE          (4096UL)
#define AT_BPF_MAX_CALL_DEPTH            (64UL)

/* System program IDs (placeholders, should match actual protocol) */

#endif /* HEADER_at_runtime_at_runtime_const_h */