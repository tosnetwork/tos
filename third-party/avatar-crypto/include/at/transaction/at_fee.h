#ifndef HEADER_at_tos_at_fee_h
#define HEADER_at_tos_at_fee_h

/* at_fee.h - TOS Fee Model for Avatar

   Implements fee calculation and deduction for TOS transactions.
   Fee is paid in TOS. Burn is handled only for contract gas.
*/

#include "at/transaction/at_txn.h"
#include "at/transaction/at_txn_types.h"
#include "at/core/storage/at_store.h"
#include "at/account/at_account.h"

AT_PROTOTYPES_BEGIN

/* ==========================================================================
   Fee Constants (TOS Rust config)
   ========================================================================== */

#define AT_FEE_PER_KB                 (10000UL) /* 0.0001 TOS per KB */
#define AT_FEE_PER_TRANSFER           (5000UL)  /* 0.00005 TOS per transfer */
#define AT_FEE_PER_ACCOUNT_CREATION   (0UL)     /* Free account creation */
#define AT_FEE_PER_MULTISIG_SIGNATURE (500UL)   /* Defined in TOS Rust config but NOT used in fee schedule — fee uses FEE_PER_TRANSFER */

/* Contract execution gas costs (charged during VM syscalls) */
#define AT_FEE_PER_STORE_CONTRACT           (100UL)  /* Base cost per persistent store op */
#define AT_FEE_PER_BYTE_STORED_CONTRACT     (5UL)    /* Per byte (key+value) in persistent store */
#define AT_FEE_PER_BYTE_IN_CONTRACT_MEMORY  (1UL)    /* Per byte (key+value) in transient memory */
#define AT_FEE_PER_BYTE_OF_EVENT_DATA       (2UL)    /* Per byte of event emission data */

/* UNO (privacy) fee model — same values as standard, separate for clarity */
#define AT_UNO_FEE_PER_KB              (10000UL)
#define AT_UNO_FEE_PER_TRANSFER        (5000UL)
#define AT_UNO_FEE_PER_ACCOUNT_CREATION (0UL)
#define AT_UNO_BURN_FEE_PER_TRANSFER   (AT_UNO_FEE_PER_TRANSFER)  /* Burned, not to miner */

/* ==========================================================================
   Checked Arithmetic Helpers
   ========================================================================== */

static inline int
at_checked_add( ulong a, ulong b, ulong * out ) {
  return __builtin_uaddl_overflow( a, b, out ) ? -1 : 0;
}

static inline int
at_checked_sub( ulong a, ulong b, ulong * out ) {
  return __builtin_usubl_overflow( a, b, out ) ? -1 : 0;
}

static inline int
at_checked_mul( ulong a, ulong b, ulong * out ) {
  return __builtin_umull_overflow( a, b, out ) ? -1 : 0;
}

/* ==========================================================================
   Fee Types
   ========================================================================== */

typedef enum {
  AT_FEE_MODE_TOS         = 0,
  AT_FEE_MODE_LEGACY_1    = 1,
} at_fee_mode_t;

/* Fee calculation result */
typedef struct {
  ulong required_fee;  /* Total fee required */
  ulong legacy_cost;   /* Legacy mode cost (always 0 for active paths) */
  ulong tos_cost;      /* If paying with TOS */
  ulong burn_amount;   /* Burned amount (contracts only; 0 for normal fees) */
  ulong miner_reward;  /* Miner reward (equals required_fee for normal fees) */
} at_fee_result_t;

/* Error codes */
#define AT_FEE_OK                      (0)
#define AT_FEE_ERR_INVALID            (-1)
#define AT_FEE_ERR_OVERFLOW           (-2)
#define AT_FEE_ERR_INSUFFICIENT_BALANCE (-3)
#define AT_FEE_ERR_INSUFFICIENT_RESOURCE (-4)

/* ==========================================================================
   Fee Calculation
   ========================================================================== */

int
at_fee_calculate( at_txn_t const * txn,
                  ulong tx_size_bytes,
                  at_fee_result_t * result );

int
at_fee_calculate_transfers( ulong recipient_count,
                            ulong new_address_count,
                            ulong multisig_count,
                            ulong tx_size_bytes,
                            at_fee_result_t * result );

/* ==========================================================================
   Fee Deduction
   ========================================================================== */

int
at_fee_deduct( at_store_t * store,
               uchar const payer[32],
               uchar const miner[32],
               at_fee_mode_t mode,
               at_fee_result_t const * fee,
               ulong topoheight,
               ulong * fee_paid_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_fee_h */
