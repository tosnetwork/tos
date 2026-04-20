#ifndef HEADER_at_tos_at_txn_types_h
#define HEADER_at_tos_at_txn_types_h

/* at_txn_types.h - TOS Transaction Type Definitions

   This header defines core TOS transaction types with their
   discriminator values.

   Wire format: Big-endian byte order
   Reference: TOS Protocol Specification Phase-5-Transaction.md
*/

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Transaction Type Discriminators                                     */
/**********************************************************************/

typedef enum {
  /* === Basic Transactions (0-4) === */
  AT_TXN_TYPE_BURN                  = 0,   /* Burn TOS tokens */
  AT_TXN_TYPE_TRANSFERS             = 1,   /* Up to 500 recipients */
  AT_TXN_TYPE_MULTISIG              = 2,   /* Up to 255 signers */
  AT_TXN_TYPE_INVOKE_CONTRACT       = 3,   /* Call smart contract */
  AT_TXN_TYPE_DEPLOY_CONTRACT       = 4,   /* Deploy TBPF bytecode */

  /* === Privacy/UNO (5-7) === */
  AT_TXN_TYPE_UNO_TRANSFERS         = 5,   /* UNO private transfers */
  AT_TXN_TYPE_SHIELD                = 6,   /* TOS -> UNO (enter privacy) */
  AT_TXN_TYPE_UNSHIELD              = 7,   /* UNO -> TOS (exit privacy) */

  /* Maximum valid type */
  AT_TXN_TYPE_MAX                   = 7
} at_txn_type_t;

/**********************************************************************/
/* Transaction Type Validation                                         */
/**********************************************************************/

/* Check if a transaction type discriminator is valid */
static inline int
at_txn_type_is_valid( uchar type_id ) {
  switch( type_id ) {
    case AT_TXN_TYPE_BURN:
    case AT_TXN_TYPE_TRANSFERS:
    case AT_TXN_TYPE_MULTISIG:
    case AT_TXN_TYPE_INVOKE_CONTRACT:
    case AT_TXN_TYPE_DEPLOY_CONTRACT:
    case AT_TXN_TYPE_UNO_TRANSFERS:
    case AT_TXN_TYPE_SHIELD:
    case AT_TXN_TYPE_UNSHIELD:
      return 1;
    default:
      return 0;
  }
}

/* Check if transaction type is a UNO/privacy operation */
static inline int
at_txn_type_is_uno( uchar type_id ) {
  return type_id >= AT_TXN_TYPE_UNO_TRANSFERS &&
         type_id <= AT_TXN_TYPE_UNSHIELD;
}

/* Check if transaction type is a contract operation */
static inline int
at_txn_type_is_contract( uchar type_id ) {
  return type_id == AT_TXN_TYPE_INVOKE_CONTRACT ||
         type_id == AT_TXN_TYPE_DEPLOY_CONTRACT;
}

/**********************************************************************/
/* Transaction Type Names (for debugging)                              */
/**********************************************************************/

/* Get human-readable name for transaction type */
static inline char const *
at_txn_type_name( uchar type_id ) {
  switch( type_id ) {
    case AT_TXN_TYPE_BURN:               return "Burn";
    case AT_TXN_TYPE_TRANSFERS:          return "Transfers";
    case AT_TXN_TYPE_MULTISIG:           return "MultiSig";
    case AT_TXN_TYPE_INVOKE_CONTRACT:    return "InvokeContract";
    case AT_TXN_TYPE_DEPLOY_CONTRACT:    return "DeployContract";
    case AT_TXN_TYPE_UNO_TRANSFERS:      return "UnoTransfers";
    case AT_TXN_TYPE_SHIELD:             return "Shield";
    case AT_TXN_TYPE_UNSHIELD:           return "Unshield";
    default:                              return "Unknown";
  }
}

/**********************************************************************/
/* Fee Type                                                            */
/**********************************************************************/

/* TOS supports different fee payment types */
typedef enum {
  AT_FEE_TYPE_TOS       = 0,  /* Pay fee in TOS */
  AT_FEE_TYPE_LEGACY_1  = 1,  /* Legacy fee id, retired */
  AT_FEE_TYPE_UNO       = 2,  /* Pay fee in UNO */
} at_fee_type_t;

/* Check if fee type is valid */
static inline int
at_fee_type_is_valid( uchar fee_type ) {
  return fee_type == AT_FEE_TYPE_TOS || fee_type == AT_FEE_TYPE_UNO;
}

/**********************************************************************/
/* Chain ID                                                            */
/**********************************************************************/

/* TOS chain identifiers */
typedef enum {
  AT_CHAIN_MAINNET  = 0,  /* Main network */
  AT_CHAIN_TESTNET  = 1,  /* Test network */
  AT_CHAIN_STAGENET = 2,  /* Stage network */
  AT_CHAIN_DEVNET   = 3,  /* Development network */
} at_chain_id_t;

/* Check if chain ID is valid */
static inline int
at_chain_id_is_valid( uchar chain_id ) {
  return chain_id <= AT_CHAIN_DEVNET;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_types_h */
