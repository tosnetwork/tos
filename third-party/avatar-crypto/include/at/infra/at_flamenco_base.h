#ifndef HEADER_at_at_flamenco_base_h
#define HEADER_at_at_flamenco_base_h

/* Flamenco base definitions for Avatar VM
   This provides common types and utilities used across the VM subsystem. */

#include "at/infra/at_util_base.h"
#include "at/infra/bits/at_bits.h"
#include "at/infra/bits/at_sat.h"
#include "at/infra/cstr/at_cstr.h"

#include <stdarg.h>
#include <stdio.h>

struct at_alloc;
typedef struct at_alloc at_alloc_t;

/* Common error handling and logging are provided by at_util_base.h */

/* Transaction context limits */
#define AT_INSTR_ACCT_MAX (256UL) /* Maximum instruction accounts */
#define AT_BPF_INSTR_ACCT_MAX AT_INSTR_ACCT_MAX /* Alias for BPF loader */

/* Note: AT_MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION is defined in vm/at_vm_private.h
   using AT_ACC_MAX_DATA_LEN from runtime/at_runtime_const.h */

/* Executor error kinds - used for error logging */
#define AT_EXECUTOR_ERR_KIND_EBPF    (1)
#define AT_EXECUTOR_ERR_KIND_SYSCALL (2)
#define AT_EXECUTOR_ERR_KIND_INSTR   (3)

/* Public key type - 32 bytes */
#ifndef AT_PUBKEY_T_DEFINED
#define AT_PUBKEY_T_DEFINED
struct at_pubkey {
  uchar key[32];
};
typedef struct at_pubkey at_pubkey_t;
#endif

/* Account metadata - represents account state */
struct at_account_meta {
  at_pubkey_t pubkey;       /* Account public key */
  at_pubkey_t owner;        /* Owner program ID */
  ulong       lamports;     /* Balance in lamports */
  ulong       dlen;         /* Data length */
  uchar *     data;         /* Account data pointer */
  uchar       executable;   /* Is this account executable? */
  ulong       rent_epoch;   /* Rent epoch */
  uchar       writable;     /* Is this account writable in current tx? */
};
typedef struct at_account_meta at_account_meta_t;

/* Borrowed account - handle to account during execution */
struct at_borrowed_account {
  at_account_meta_t * meta;            /* Account metadata */
  void *              orig_data;       /* Original data snapshot (for rollback) */
  ulong               orig_dlen;       /* Original data length */
  ulong               orig_lamports;   /* Original lamport balance */
  uchar               orig_executable; /* Original executable flag */
  int                 is_modified;     /* Has account been modified? */
};
typedef struct at_borrowed_account at_borrowed_account_t;

/* Forward declaration for invoke context (full definition in runtime module) */
struct at_instr_info;
typedef struct at_instr_info at_instr_info_t;

struct at_exec_slot_ctx;
typedef struct at_exec_slot_ctx at_exec_slot_ctx_t;

struct at_exec_txn_ctx;
typedef struct at_exec_txn_ctx at_exec_txn_ctx_t;

struct at_features;
typedef struct at_features at_features_t;

/* CPI call flags (EVM-style) */
#define AT_CPI_FLAG_CALL         (0x00)  /* Normal call */
#define AT_CPI_FLAG_STATICCALL   (0x01)  /* Read-only call (no state changes) */
#define AT_CPI_FLAG_DELEGATECALL (0x02)  /* Use caller's context */

/* Maximum CPI depth (matches TOS Rust config.max_call_depth) */
#define AT_CPI_MAX_DEPTH         (64UL)

/* Maximum return data size */
#define AT_CPI_MAX_RETURN_DATA   (1024UL)

/* ============================================================================
   Transient Storage (EIP-1153)
   ============================================================================
   Transient storage provides transaction-scoped key-value storage that is
   automatically cleared at the end of the transaction. Unlike persistent
   storage, transient storage:
   - Is NOT committed to the blockchain
   - Is cleared at transaction end
   - Is much cheaper (100 gas vs 20000 for SSTORE)
   - Is useful for reentrancy guards, temporary data, callback data
   ============================================================================ */

#define AT_TRANSIENT_MAX_SLOTS   (256UL)   /* Max slots per contract */
#define AT_TRANSIENT_KEY_SIZE    (32UL)    /* Key size in bytes */
#define AT_TRANSIENT_VALUE_SIZE  (32UL)    /* Value size in bytes */

/* Transient storage slot */
struct at_transient_slot {
  uchar key[AT_TRANSIENT_KEY_SIZE];
  uchar value[AT_TRANSIENT_VALUE_SIZE];
  uchar in_use;  /* 1 if slot is occupied, 0 if empty */
};
typedef struct at_transient_slot at_transient_slot_t;

/* Transient storage for a single contract */
struct at_transient_storage {
  uchar               contract[32];       /* Contract address */
  at_transient_slot_t slots[AT_TRANSIENT_MAX_SLOTS];
  ulong               slot_cnt;           /* Number of slots in use */
};
typedef struct at_transient_storage at_transient_storage_t;

/* ============================================================================
   VRF (Verifiable Random Function)
   ============================================================================
   TOS uses VRF for secure random number generation in contracts.
   The VRF output is derived from the block producer's VRF proof.
   ============================================================================ */

#define AT_VRF_OUTPUT_SIZE       (32UL)   /* VRF output hash size */
#define AT_VRF_PROOF_SIZE        (80UL)   /* VRF proof size (schnorrkel) */
#define AT_VRF_PUBLIC_KEY_SIZE   (32UL)   /* VRF public key size */

/* VRF context in execution */
struct at_vrf_ctx {
  uchar instant_random[AT_VRF_OUTPUT_SIZE];  /* Block-level instant random */
  uchar vrf_output[AT_VRF_OUTPUT_SIZE];      /* VRF output for this block */
  uchar vrf_proof[AT_VRF_PROOF_SIZE];        /* VRF proof */
  uchar vrf_public_key[AT_VRF_PUBLIC_KEY_SIZE]; /* Block producer's VRF key */
  uchar has_vrf;                              /* 1 if VRF data is available */
};
typedef struct at_vrf_ctx at_vrf_ctx_t;

struct at_vm_exec_trace;
typedef struct at_vm_exec_trace at_vm_exec_trace_t;

/* ============================================================================
   Native System Providers
   ============================================================================
   TOS has native systems that are accessed via syscalls:
   - Asset: Native asset (token) operations
   ============================================================================ */

/* Asset (token) info */
struct at_asset_info {
  uchar  asset_id[32];     /* Asset identifier */
  uchar  issuer[32];       /* Asset issuer */
  ulong  total_supply;     /* Total supply */
  ulong  circulating;      /* Circulating supply */
  uchar  decimals;         /* Decimal places (0-18) */
  uchar  is_frozen;        /* 1 if asset is frozen */
  uchar  is_mintable;      /* 1 if more can be minted */
  uchar  is_burnable;      /* 1 if tokens can be burned */
};
typedef struct at_asset_info at_asset_info_t;

/* CPI call stack entry - tracks nested calls for reentrancy detection */
struct at_cpi_stack_entry {
  uchar program_hash[32];  /* Program being executed */
  uchar caller[32];        /* Caller of this program */
  ulong call_value;        /* Value sent with call */
  uchar flags;             /* Call flags (CALL/STATICCALL/DELEGATECALL) */
};
typedef struct at_cpi_stack_entry at_cpi_stack_entry_t;

/* Instruction execution context */
struct at_exec_instr_ctx {
  at_instr_info_t *       instr;         /* Current instruction info */
  at_exec_txn_ctx_t *     txn_ctx;       /* Transaction context */
  at_exec_slot_ctx_t *    slot_ctx;      /* Slot context */
  ulong                   depth;         /* CPI call depth */
  uchar                   instruction_accounts_cnt; /* Number of instruction accounts */
  at_borrowed_account_t * accounts;      /* Borrowed accounts array */
  at_features_t *         features;      /* Active feature flags */

  /* TOS-specific execution context */
  uchar                   block_hash[32];    /* Current block hash */
  ulong                   block_height;      /* Current block height */
  uchar                   tx_hash[32];       /* Current transaction hash */
  uchar                   tx_sender[32];     /* Transaction sender pubkey */
  uchar                   contract_hash[32]; /* Current contract program hash */
  ulong                   block_timestamp;   /* Block timestamp (Unix seconds) */
  ulong                   chain_id;          /* Chain ID for replay protection */

  /* Additional EVM-compatible environment fields */
  uchar *                 difficulty;        /* Block difficulty (32 bytes), NULL if not set */
  ulong                   gas_limit;         /* Block gas/compute limit (GASLIMIT) */
  ulong                   base_fee;          /* EIP-1559 base fee (BASEFEE) */
  uchar *                 coinbase;          /* Block producer address (32 bytes), NULL if not set */
  ulong                   gas_price;         /* Transaction gas price (GASPRICE) */

  /* CPI (Cross-Program Invocation) state */
  at_cpi_stack_entry_t    cpi_stack[AT_CPI_MAX_DEPTH]; /* CPI call stack */
  ulong                   cpi_depth;         /* Current CPI depth */
  uchar                   return_data[AT_CPI_MAX_RETURN_DATA]; /* Return data buffer */
  ulong                   return_data_len;   /* Return data length */
  uchar                   return_program[32];/* Program that set return data */
  uchar                   is_static;         /* In static call context (no writes) */

  /* Transient Storage (EIP-1153) - Phase 8.4 */
  at_alloc_t *            alloc;            /* Allocator for transient/VRF */
  at_transient_storage_t * transient;        /* Transient storage for this contract */

  /* VRF Context - Phase 8.4 */
  at_vrf_ctx_t *          vrf_ctx;           /* VRF data from block header */
  at_alloc_t *            vrf_ctx_alloc;     /* Allocator used for vrf_ctx (optional) */

  /* Native System Provider Callbacks - Phase 8.4
     These are function pointers set by the runtime to access native systems.
     NULL if the system is not available. */
  void *                  asset_provider;    /* Asset system provider */

  /* CPI-critical providers (storage, accounts, contract loader) */
  void *                  storage_provider;  /* at_vm_storage_provider_t* for SLOAD/SSTORE */
  void *                  account_provider;  /* at_vm_account_provider_t* for balance/transfer */
  void *                  contract_loader;   /* at_vm_contract_loader_t* for CPI bytecode loading */
  void const *            contract_environment; /* at_contract_environment_t* registered env schema */
  at_vm_exec_trace_t *    exec_trace;        /* Optional collector for logs/events/transfers */

  /* Scheduled Execution Provider - CU Tracking Phase 3
     Provides access to scheduled execution storage operations.
     Points to at_store_t when set by executor. */
  void *                  sched_exec_store;  /* at_store_t* for scheduled exec */
  ulong                   current_topoheight; /* Current topoheight for validation */

  /* Optional fee accumulators owned by executor.
     When set, syscalls can account deferred miner fees and burns consistently. */
  ulong *                 total_fees_accum;
  ulong *                 burned_fees_accum;
};
typedef struct at_exec_instr_ctx at_exec_instr_ctx_t;

AT_PROTOTYPES_BEGIN

/* Note: at_pchash_inverse is defined in ballet/murmur3/at_murmur3.h */

AT_PROTOTYPES_END

#endif /* HEADER_at_at_flamenco_base_h */
