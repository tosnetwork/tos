#ifndef HEADER_at_runtime_at_runtime_h
#define HEADER_at_runtime_at_runtime_h

/* Runtime module for Avatar
   This provides the execution environment for TBPF programs. */

#include "at/infra/at_util_base.h"
#include "at/infra/at_flamenco_base.h"
#include "at_runtime_const.h"

/* Error codes for runtime operations */
#define AT_RUNTIME_SUCCESS                 (0)
#define AT_RUNTIME_ERR_INVAL               (-1)
#define AT_RUNTIME_ERR_SIGSTACK            (-2)
#define AT_RUNTIME_ERR_SIGCOST             (-3)
#define AT_RUNTIME_ERR_SIGILL              (-4)
#define AT_RUNTIME_ERR_SIGSEGV             (-5)
#define AT_RUNTIME_ERR_SIGBUS              (-6)
#define AT_RUNTIME_ERR_SIGFPE              (-7)
#define AT_RUNTIME_ERR_PRIVILEGE           (-8)
#define AT_RUNTIME_ERR_ACCOUNT_MODIFIED    (-9)
#define AT_RUNTIME_ERR_ALREADY_BORROWED    (-10)
#define AT_RUNTIME_ERR_NOT_ENOUGH_BALANCE  (-11)

/* Instruction info - describes an instruction to execute */
struct at_instr_info {
  at_pubkey_t         program_id;        /* Program to invoke */
  uchar const *       data;              /* Instruction data */
  ulong               data_len;          /* Length of instruction data */
  at_pubkey_t const * accounts;          /* Account pubkeys referenced */
  uchar               accounts_cnt;      /* Number of accounts */
  uchar const *       is_signer;         /* Is account[i] a signer? */
  uchar const *       is_writable;       /* Is account[i] writable? */
};
typedef struct at_instr_info at_instr_info_t;

/* Slot context - slot-level execution state */
struct at_exec_slot_ctx {
  ulong           slot;               /* Current slot number */
  ulong           parent_slot;        /* Parent slot number */
  at_pubkey_t     leader;             /* Current slot leader */
  ulong           lamports_per_sig;   /* Lamports per signature */
};
typedef struct at_exec_slot_ctx at_exec_slot_ctx_t;

/* Transaction context - transaction-level execution state */
struct at_exec_txn_ctx {
  at_exec_slot_ctx_t * slot_ctx;         /* Slot context */
  at_pubkey_t const *  accounts;         /* Transaction account pubkeys */
  ulong                accounts_cnt;     /* Number of accounts */
  at_borrowed_account_t * borrowed;      /* Borrowed accounts */
  ulong                compute_units;    /* Remaining compute units */
  ulong                heap_size;        /* Allocated heap size */
  uchar                instruction_idx;  /* Current instruction index */
};
typedef struct at_exec_txn_ctx at_exec_txn_ctx_t;

AT_PROTOTYPES_BEGIN

/* Runtime initialization and cleanup */

int at_runtime_init( void );
void at_runtime_fini( void );

/* Compute unit operations */

static inline int
at_runtime_consume_cu( at_exec_instr_ctx_t * ctx, ulong cu ) {
  if( !ctx || !ctx->txn_ctx ) return AT_RUNTIME_ERR_INVAL;
  if( ctx->txn_ctx->compute_units < cu ) {
    ctx->txn_ctx->compute_units = 0UL;
    return AT_RUNTIME_ERR_SIGCOST;
  }
  ctx->txn_ctx->compute_units -= cu;
  return AT_RUNTIME_SUCCESS;
}

static inline ulong
at_runtime_remaining_cu( at_exec_instr_ctx_t const * ctx ) {
  if( !ctx || !ctx->txn_ctx ) return 0UL;
  return ctx->txn_ctx->compute_units;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_runtime_at_runtime_h */
