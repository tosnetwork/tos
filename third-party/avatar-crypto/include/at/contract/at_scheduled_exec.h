#ifndef HEADER_at_contract_at_scheduled_exec_h
#define HEADER_at_contract_at_scheduled_exec_h

/* at_scheduled_exec.h - Scheduled execution (OFFERCALL) data structures

   This module provides data structures and constants for scheduled contract
   execution, inspired by EIP-7833. Contracts can schedule future execution
   with offer-based priority.

   TOS Alignment: All constants match TOS Rust exactly.
   See: tos/common/src/contract/scheduled_execution/constants.rs */

#include "at/infra/at_util_base.h"
#include "at/vm/at_vm_exec_trace.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Block Execution Limits
   ============================================================================ */

/* Maximum scheduled executions that can be processed per block.
   Prevents block bloat (~5ms overhead per execution). */
#define AT_MAX_SCHEDULED_EXECUTIONS_PER_BLOCK  (100UL)

/* Maximum total gas that can be consumed by scheduled executions per block.
   ~100ms VM execution time, fits within 3s block with overhead. */
#define AT_MAX_SCHEDULED_EXECUTION_GAS_PER_BLOCK (100000000UL)  /* 100M CU */

/* Maximum topoheights into the future an execution can be scheduled.
   ~7 days at 6-second blocks (100800 = 7 * 24 * 60 * 60 / 6). */
#define AT_MAX_SCHEDULING_HORIZON              (100800UL)

/* Maximum number of times an execution can be deferred before expiring. */
#define AT_MAX_DEFER_COUNT                     (10U)

/* Minimum blocks before target topoheight that cancellation is allowed.
   Prevents MEV attacks. */
#define AT_MIN_CANCELLATION_WINDOW             (1UL)

/* ============================================================================
   Gas Requirements
   ============================================================================ */

/* Minimum gas required when scheduling an execution.
   Covers worst-case failure penalties. */
#define AT_MIN_SCHEDULED_EXECUTION_GAS         (20000UL)

/* Base compute cost for offer_call syscall. */
#define AT_OFFER_CALL_BASE_COST                (5000UL)

/* Per-byte compute cost for input data in offer_call. */
#define AT_OFFER_CALL_BYTE_COST                (16UL)

/* Cost charged when scheduled execution fails to find module. */
#define AT_BASE_SCHEDULED_EXECUTION_COST       (10000UL)

/* Cost when module exists but bytecode loading fails. */
#define AT_MODULE_LOAD_COST                    (5000UL)

/* Cost when bytecode itself fails to load. */
#define AT_BYTECODE_LOAD_COST                  (5000UL)

/* ============================================================================
   Offer Handling (EIP-7833 Inspired)
   ============================================================================ */

/* Percentage of offer burned on registration (prevents manipulation). */
#define AT_OFFER_BURN_PERCENT                  (30UL)

/* Percentage of offer paid to miner when execution is processed. */
#define AT_OFFER_MINER_PERCENT                 (70UL)

/* Minimum offer amount (0 = pure FIFO fallback allowed). */
#define AT_MIN_OFFER_AMOUNT                    (0UL)

/* Maximum offer amount (prevents overflow, ~10,000 TOS at 8 decimals). */
#define AT_MAX_OFFER_AMOUNT                    (1000000000000UL)

/* ============================================================================
   Input Data Limits
   ============================================================================ */

/* Maximum input data size for scheduled execution (64KB). */
#define AT_MAX_INPUT_DATA_SIZE                 (65536UL)

/* ============================================================================
   Rate Limiting
   ============================================================================ */

/* Maximum schedules per contract within the rate limit window. */
#define AT_MAX_SCHEDULES_PER_CONTRACT_PER_WINDOW (100UL)

/* Rate limit window in topoheights (~10 minutes at 6s blocks). */
#define AT_SCHEDULE_RATE_LIMIT_WINDOW          (100UL)

/* High-value offers bypass rate limiting (~1 TOS). */
#define AT_RATE_LIMIT_BYPASS_OFFER             (100000000UL)

/* ============================================================================
   Syscall Error Codes
   ============================================================================ */

#define AT_SCHED_ERR_SUCCESS                   (0UL)
#define AT_SCHED_ERR_INSUFFICIENT_BALANCE      (1UL)
#define AT_SCHED_ERR_TOPOHEIGHT_IN_PAST        (2UL)
#define AT_SCHED_ERR_TOPOHEIGHT_TOO_FAR        (3UL)
#define AT_SCHED_ERR_ALREADY_SCHEDULED         (4UL)
#define AT_SCHED_ERR_GAS_TOO_LOW               (5UL)
#define AT_SCHED_ERR_INVALID_PARAMS            (6UL)
#define AT_SCHED_ERR_OFFER_TOO_LOW             (7UL)
#define AT_SCHED_ERR_RATE_LIMIT_EXCEEDED       (8UL)
#define AT_SCHED_ERR_NOT_FOUND                 (9UL)
#define AT_SCHED_ERR_NOT_AUTHORIZED            (10UL)
#define AT_SCHED_ERR_CANNOT_CANCEL             (11UL)
#define AT_SCHED_ERR_STATIC_CALL               (12UL)
#define AT_SCHED_ERR_INPUT_TOO_LARGE           (13UL)
#define AT_SCHED_ERR_OFFER_TOO_HIGH            (14UL)

/* ============================================================================
   Syscall Flags for offer_call
   ============================================================================ */

/* Schedule at block end instead of specific topoheight. */
#define AT_OFFER_CALL_FLAG_BLOCK_END           (0x01U)

/* Schedule at next topoheight (current + 1). */
#define AT_OFFER_CALL_FLAG_NEXT_TOPO           (0x02U)

/* ============================================================================
   Scheduled Execution Status
   ============================================================================ */

typedef enum {
  AT_SCHED_STATUS_PENDING   = 0,  /* Waiting to execute */
  AT_SCHED_STATUS_EXECUTED  = 1,  /* Successfully executed */
  AT_SCHED_STATUS_FAILED    = 2,  /* Execution failed */
  AT_SCHED_STATUS_EXPIRED   = 3,  /* Max deferrals reached */
  AT_SCHED_STATUS_CANCELLED = 4   /* Cancelled by scheduler */
} at_scheduled_exec_status_t;

/* ============================================================================
   Scheduled Execution Kind
   ============================================================================ */

typedef enum {
  AT_SCHED_KIND_TOPOHEIGHT = 0,  /* Execute at specific topoheight */
  AT_SCHED_KIND_BLOCK_END  = 1   /* Execute at block boundary */
} at_scheduled_exec_kind_t;

/* ============================================================================
   Scheduled Execution Error Kind (for result categorization)
   ============================================================================ */

typedef enum {
  AT_SCHED_ERROR_KIND_NONE            = 0,  /* Success */
  AT_SCHED_ERROR_KIND_CONTRACT_NOT_FOUND = 1,  /* Contract bytecode missing */
  AT_SCHED_ERROR_KIND_OUT_OF_GAS      = 2,  /* Execution ran out of gas */
  AT_SCHED_ERROR_KIND_CONTRACT_ERROR  = 3,  /* Non-zero exit code */
  AT_SCHED_ERROR_KIND_EXPIRED         = 4,  /* Max deferrals reached */
  AT_SCHED_ERROR_KIND_INTERNAL_ERROR  = 5,  /* Storage/I/O errors */
  AT_SCHED_ERROR_KIND_UNKNOWN         = 6   /* Uncategorized */
} at_scheduled_exec_error_kind_t;

/* ============================================================================
   Scheduled Execution Record (Full)

   Note: at_rocks_contract.h defines a simpler at_scheduled_exec_t for basic
   queries. This "full" version includes all fields needed for scheduling,
   execution processing, and result tracking.
   ============================================================================ */

typedef struct at_scheduled_exec_full {
  uchar  hash[32];                  /* Unique execution identifier (BLAKE3) */
  uchar  contract[32];              /* Target contract address */
  uchar  scheduler_contract[32];    /* Contract that scheduled this */
  ulong  chunk_id;                  /* Scheduling slot */
  ulong  target_topoheight;         /* When to execute */
  ulong  registration_topoheight;   /* When it was scheduled */
  ulong  max_gas;                   /* Maximum CU allocated */
  ulong  offer_amount;              /* Priority offer (atomic units) */
  uchar  input_data[AT_MAX_INPUT_DATA_SIZE]; /* Input data for execution */
  ulong  input_len;                 /* Actual input length */
  uchar  defer_count;               /* Number of deferrals (0-10) */
  at_scheduled_exec_status_t status;
  at_scheduled_exec_kind_t   kind;
} at_scheduled_exec_full_t;

/* ============================================================================
   Scheduled Execution Result (Single Execution)
   ============================================================================ */

typedef struct at_scheduled_exec_result {
  at_scheduled_exec_full_t     execution;          /* The execution processed */
  int                          success;            /* Whether execution succeeded */
  ulong                        compute_units_used; /* CU consumed */
  ulong                        miner_reward;       /* Reward from offer */
  at_scheduled_exec_error_kind_t error_kind;       /* Categorized error */
  int                          error_code;         /* Detailed error code */
  char                         error_msg[256];     /* Error message */
  at_vm_exec_trace_t           exec_trace;         /* VM return/log/event/transfer trace */
} at_scheduled_exec_result_t;

/* ============================================================================
   Block Scheduled Execution Results (Aggregate)
   ============================================================================ */

typedef struct at_block_sched_exec_results {
  at_scheduled_exec_result_t * results;            /* Array of execution results */
  ulong                        result_count;       /* Number of results */
  ulong                        result_capacity;    /* Allocated capacity */
  ulong                        total_gas_used;     /* Total gas consumed */
  ulong                        total_miner_rewards; /* Total rewards from offers */
  ulong                        success_count;      /* Number of successful executions */
  ulong                        failure_count;      /* Number of failed executions */
  ulong                        deferred_count;     /* Number of deferred executions */
  at_vm_exec_transfer_t *      aggregated_transfers;      /* Sum of successful transfer outputs */
  ulong                        aggregated_transfer_count; /* Number of unique transfer entries */
  ulong                        aggregated_transfer_capacity;
} at_block_sched_exec_results_t;

/* ============================================================================
   Iterator for Scheduled Executions at a Topoheight
   ============================================================================ */

typedef struct at_scheduled_exec_iter {
  void * opaque;           /* Internal iterator state */
  ulong  topoheight;       /* Target topoheight */
  int    valid;            /* 1 if iterator has more items */
} at_scheduled_exec_iter_t;

/* ============================================================================
   Helper Functions
   ============================================================================ */

/* Calculate miner reward from offer amount.
   Returns: offer_amount * AT_OFFER_MINER_PERCENT / 100 */
static inline ulong
at_sched_exec_miner_reward( ulong offer_amount ) {
  return (offer_amount * AT_OFFER_MINER_PERCENT) / 100UL;
}

/* Calculate burn amount from offer.
   Returns: offer_amount * AT_OFFER_BURN_PERCENT / 100 */
static inline ulong
at_sched_exec_burn_amount( ulong offer_amount ) {
  return (offer_amount * AT_OFFER_BURN_PERCENT) / 100UL;
}

/* Check if error is retryable (should defer vs fail permanently).
   Returns: 1 if retryable, 0 if permanent failure. */
static inline int
at_sched_exec_error_is_retryable( at_scheduled_exec_error_kind_t kind ) {
  switch( kind ) {
    case AT_SCHED_ERROR_KIND_INTERNAL_ERROR:
    case AT_SCHED_ERROR_KIND_CONTRACT_NOT_FOUND:
      return 1;  /* May be temporary */
    default:
      return 0;  /* Permanent failures */
  }
}

/* Check if an execution can be deferred (hasn't exceeded max deferrals). */
static inline int
at_sched_exec_can_defer( at_scheduled_exec_full_t const * exec ) {
  return exec && exec->defer_count < AT_MAX_DEFER_COUNT;
}

/* Initialize block results structure. */
static inline void
at_block_sched_exec_results_init( at_block_sched_exec_results_t * results ) {
  if( !results ) return;
  results->results = NULL;
  results->result_count = 0;
  results->result_capacity = 0;
  results->total_gas_used = 0;
  results->total_miner_rewards = 0;
  results->success_count = 0;
  results->failure_count = 0;
  results->deferred_count = 0;
  results->aggregated_transfers = NULL;
  results->aggregated_transfer_count = 0;
  results->aggregated_transfer_capacity = 0;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_at_scheduled_exec_h */
