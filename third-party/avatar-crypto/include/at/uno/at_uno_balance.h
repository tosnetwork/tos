#ifndef HEADER_at_uno_at_uno_balance_h
#define HEADER_at_uno_at_uno_balance_h

/* at_uno_balance.h - UNO Encrypted Balance Storage

   UNO uses Twisted ElGamal encryption for confidential balances.
   Balances are stored as ciphertexts (commitment, handle) and support
   homomorphic addition/subtraction.

   Storage Schema:
   - AT_CF_UNO_BALANCES: [account_id:8][asset_id:8] -> [latest_topo:8]
   - AT_CF_VERSIONED_UNO_BALANCES: [topo:8][account_id:8][asset_id:8] -> [versioned_balance]

   Versioned Balance Format:
   - previous_topoheight: Option<u64> (1 + 0-8 bytes)
   - balance_type: u8 (0=input, 1=output, 2=both)
   - final_balance: Ciphertext (64 bytes)
   - output_balance: Option<Ciphertext> (1 + 0/64 bytes)
*/

#include "at/core/storage/at_store.h"
#include "at/account/at_account.h"
#include "at/transaction/at_txn_uno.h"
#include "at/crypto/at_elgamal.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Versioned UNO Balance                                               */
/**********************************************************************/

/* Matches TOS Rust VersionedUnoBalance structure */
typedef struct {
  int   has_previous_topoheight;
  ulong previous_topoheight;
  at_balance_type_t balance_type;
  at_uno_ciphertext_t final_balance;
  int   has_output_balance;
  at_uno_ciphertext_t output_balance;
} at_versioned_uno_balance_t;

/* Serialized size: max 9 (Option<u64>) + 1 + 64 + (1+64) = 139 bytes */
#define AT_VERSIONED_UNO_BALANCE_MAX_SZ (139UL)

/* UNO account summary equivalent to Rust UnoAccountSummary. */
typedef struct {
  int   has_output_topoheight;
  ulong output_topoheight;
  ulong stable_topoheight;
} at_uno_account_summary_t;

/* Spendable UNO balance entry equivalent to Rust UnoBalance with topoheight. */
typedef struct {
  ulong topoheight;
  at_versioned_uno_balance_t version;
} at_uno_balance_entry_t;

/* Serialize versioned UNO balance to wire format.
   Returns bytes written, or -1 on error. */
int
at_versioned_uno_balance_serialize( at_versioned_uno_balance_t const * vbal,
                                     uchar * buf,
                                     ulong buf_sz );

/* Deserialize versioned UNO balance from wire format.
   Returns 0 on success, -1 on error. */
int
at_versioned_uno_balance_deserialize( uchar const * buf,
                                       ulong buf_sz,
                                       at_versioned_uno_balance_t * vbal_out );

/**********************************************************************/
/* UNO Balance Operations                                              */
/**********************************************************************/

/* Get current UNO balance for an account and asset.
   Returns AT_STORE_OK on success, AT_STORE_ERR_NOT_FOUND if no balance exists. */
int
at_uno_balance_get( at_store_t *         store,
                     uchar const          pubkey[32],
                     uchar const          asset[32],
                     at_uno_ciphertext_t * balance_out );

/* Get versioned UNO balance at a specific topoheight.
   Returns AT_STORE_OK on success, AT_STORE_ERR_NOT_FOUND if no balance exists. */
int
at_uno_balance_get_at_topo( at_store_t *               store,
                             uchar const                pubkey[32],
                             uchar const                asset[32],
                             ulong                      topoheight,
                             at_versioned_uno_balance_t * vbal_out );

/* Check if UNO balance exists for an account and asset (current).
   Returns AT_STORE_OK if exists, AT_STORE_ERR_NOT_FOUND if not exists. */
int
at_uno_balance_exists( at_store_t *  store,
                       uchar const   pubkey[32],
                       uchar const   asset[32] );

/* Check if UNO balance exists at a specific topoheight.
   Returns AT_STORE_OK if exists, AT_STORE_ERR_NOT_FOUND if not exists. */
int
at_uno_balance_exists_at_topo( at_store_t *  store,
                               uchar const   pubkey[32],
                               uchar const   asset[32],
                               ulong         topoheight );

/* Set UNO balance for an account and asset.
   Creates or updates the versioned balance entry. */
int
at_uno_balance_set( at_store_t *               store,
                     uchar const                pubkey[32],
                     uchar const                asset[32],
                     at_uno_ciphertext_t const * balance,
                     ulong                      topoheight );

/* Add to UNO balance using homomorphic addition.
   new_balance = old_balance + delta (point-wise addition)

   If no existing balance, initializes with delta.
   Returns AT_STORE_OK on success. */
int
at_uno_balance_add( at_store_t *               store,
                     uchar const                pubkey[32],
                     uchar const                asset[32],
                     at_uno_ciphertext_t const * delta,
                     ulong                      topoheight );

/* Subtract from UNO balance using homomorphic subtraction.
   new_balance = old_balance - delta (point-wise subtraction)

   Returns AT_STORE_ERR_NOT_FOUND if no existing balance.
   Note: This does NOT verify non-negativity - that must be done via
   range proofs during transaction verification. */
int
at_uno_balance_sub( at_store_t *               store,
                     uchar const                pubkey[32],
                     uchar const                asset[32],
                     at_uno_ciphertext_t const * delta,
                     ulong                      topoheight );

/**********************************************************************/
/* Ciphertext Arithmetic                                               */
/**********************************************************************/

/* Add two ciphertexts: result = a + b
   result.commitment = a.commitment + b.commitment
   result.handle = a.handle + b.handle
   Returns 0 on success, -1 on error. */
int
at_uno_ciphertext_add( at_uno_ciphertext_t *       result,
                        at_uno_ciphertext_t const * a,
                        at_uno_ciphertext_t const * b );

/* Subtract two ciphertexts: result = a - b
   result.commitment = a.commitment - b.commitment
   result.handle = a.handle - b.handle
   Returns 0 on success, -1 on error. */
int
at_uno_ciphertext_sub( at_uno_ciphertext_t *       result,
                        at_uno_ciphertext_t const * a,
                        at_uno_ciphertext_t const * b );

/* Check if a ciphertext is the zero ciphertext (identity).
   Returns 1 if zero, 0 if non-zero, -1 on error. */
int
at_uno_ciphertext_is_zero( at_uno_ciphertext_t const * ct );

/**********************************************************************/
/* Storage Key Helpers                                                 */
/**********************************************************************/

/* Key sizes */
#define AT_UNO_BALANCE_KEY_SZ           (16UL)   /* account_id + asset_id */
#define AT_VERSIONED_UNO_BALANCE_KEY_SZ (24UL)   /* topo + account_id + asset_id */

/* Build key for AT_CF_UNO_BALANCES */
static inline void
at_uno_balance_build_key( uchar key_out[16],
                          ulong account_id,
                          ulong asset_id ) {
  at_store_write_u64_be( key_out, account_id );
  at_store_write_u64_be( key_out + 8, asset_id );
}

/* Build key for AT_CF_VERSIONED_UNO_BALANCES */
static inline void
at_versioned_uno_balance_build_key( uchar key_out[24],
                                    ulong topoheight,
                                    ulong account_id,
                                    ulong asset_id ) {
  at_store_write_u64_be( key_out, topoheight );
  at_store_write_u64_be( key_out + 8, account_id );
  at_store_write_u64_be( key_out + 16, asset_id );
}

AT_PROTOTYPES_END

#endif /* HEADER_at_uno_at_uno_balance_h */
