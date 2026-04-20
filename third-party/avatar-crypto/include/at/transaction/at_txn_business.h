#ifndef HEADER_at_tos_at_txn_business_h
#define HEADER_at_tos_at_txn_business_h

/* at_txn_business.h - Common Business Validation Helpers

   This header provides common validation utilities for business-level
   transaction validation, including:
   - Time validation (reasonable timestamps, expiry checks)
   - Duplicate detection for 32-byte items
   - Common constants for business rules
*/

#include "at/transaction/at_txn.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Time Validation Constants                                           */
/**********************************************************************/

/* Timestamp tolerance: ±1 hour from current time */
#define AT_TIME_TOLERANCE_SECS    (3600UL)

/* Approval expiry: 7 days */
#define AT_APPROVAL_EXPIRY_SECS   (7UL * 24UL * 60UL * 60UL)

/**********************************************************************/
/* Time Validation Functions                                           */
/**********************************************************************/

/* Check if a timestamp is within reasonable bounds of current time.
   Returns 0 if valid, negative error code otherwise. */
int at_verify_timestamp_reasonable( ulong ts, ulong current_time );

/* Check if an approval timestamp has not expired.
   Returns 0 if valid (not expired), negative error code if expired. */
int at_verify_approval_not_expired( ulong approval_ts, ulong current_time );

/**********************************************************************/
/* Duplicate Detection Functions                                       */
/**********************************************************************/

/* Check for duplicates in an array of 32-byte items.
   items: pointer to first item
   count: number of items
   stride: bytes between start of each item (must be >= 32)
   Returns 0 if no duplicates found, AT_TXN_VERIFY_DUPLICATE if found. */
int at_verify_no_duplicates_32( uchar const * items, ulong count, ulong stride );

/* Check that a 32-byte item is not in an array.
   Returns 0 if not found (valid), AT_TXN_VERIFY_DUPLICATE if found. */
int at_verify_not_in_list_32( uchar const item[32],
                               uchar const * list,
                               ulong count,
                               ulong stride );

/**********************************************************************/
/* Zero/Non-Zero Validation                                            */
/**********************************************************************/

/* Check if a 32-byte hash is non-zero.
   Returns 0 if non-zero (valid), AT_TXN_VERIFY_INVALID if all zeros. */
int at_verify_hash_nonzero( uchar const hash[32] );

/**********************************************************************/
/* Self-Operation Validation                                           */
/**********************************************************************/

/* Check that sender is not equal to target (for operations that
   disallow self-targeting).
   Returns 0 if different (valid), AT_TXN_VERIFY_SELF_OP if same. */
int at_verify_not_self( uchar const sender[32], uchar const target[32] );

/**********************************************************************/
/* Simple Type Validation Functions                                    */
/**********************************************************************/

/* Validate MultiSig transaction (Type 2) - stateless business rules.
   - No duplicate participants
   - Threshold achievable (1 <= threshold <= participants_cnt)
   Returns AT_TXN_VERIFY_SUCCESS (0) on success, negative error code on failure. */
int at_multisig_validate_stateless( at_txn_t const * txn,
                                     uchar const *    raw,
                                     uchar const *    payload,
                                     ulong            payload_sz );

/**********************************************************************/
/* MultiSig Signature Verification (Stateful)                          */
/**********************************************************************/

/* Forward declaration for at_store_t */
struct at_store;
typedef struct at_store at_store_t;

/* Verify multisig signatures on a transaction.

   If the source account has multisig enabled (threshold > 0), this function
   verifies that:
   1. tx.multisig_cnt == account.threshold (must be exactly equal)
   2. All participant IDs are valid (< participants_cnt)
   3. No duplicate participant IDs
   4. All signatures verify against the participant's public key

   If the account does NOT have multisig enabled:
   - tx.multisig_cnt MUST be 0 (no signatures allowed)

   Returns:
     AT_TXN_VERIFY_SUCCESS  - Valid (or account has no multisig)
     AT_TXN_VERIFY_THRESHOLD - Signature count != threshold
     AT_TXN_VERIFY_SIG_ERR  - Signature verification failed
     AT_TXN_VERIFY_INVALID  - Invalid participant ID
     AT_TXN_VERIFY_DUPLICATE - Duplicate participant ID */
int at_txn_verify_multisig( at_store_t *    store,
                             at_txn_t const * txn,
                             uchar const *    raw );

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_txn_business_h */
