#ifndef HEADER_at_tos_at_account_h
#define HEADER_at_tos_at_account_h

/* at_account.h - Backend-agnostic Account Operations for Avatar (TOS-Compatible)

   This module implements TOS-compatible account storage with 100%
   binary compatibility for database interoperability.

   TOS Serialization Rules:
   - All integers: BIG-ENDIAN
   - Option<T>: 1 byte flag (0=None, 1=Some) + optional value
   - Account fields: id, registered_at, nonce_pointer, multisig_pointer, energy_pointer

   Usage:
     at_account_t acc;
     int err = at_account_query_into( store, pubkey, &acc );
     if( err == AT_STORE_ERR_NOT_FOUND ) {
       err = at_account_create( store, pubkey, initial_balance, topo, &acc );
     }
*/

#include "at/core/storage/at_store.h"

AT_PROTOTYPES_BEGIN

struct at_exec_ctx;

/* ============================================================================
   TOS-Compatible Account Structure
   See: tos/daemon/src/core/storage/rocksdb/types/account.rs

   Serialization Order (all big-endian):
     1. id (u64, 8 bytes)
     2. registered_at (Option<u64>: 1 byte flag + optional 8 bytes)
     3. nonce_pointer (Option<u64>)
     4. multisig_pointer (Option<u64>)
     5. energy_pointer (Option<u64>)

   Min size: 8 + 1 + 1 + 1 + 1 = 12 bytes (all None)
   Max size: 8 + 9 + 9 + 9 + 9 = 44 bytes (all Some)
   ============================================================================ */

/* at_account_t represents a TOS-compatible account.
   Note: This is the in-memory representation. Serialization uses
   TOS-compatible variable-length format. */
typedef struct at_account {
  ulong id;                       /* Unique account ID */
  int   has_registered_at;        /* 1 if registered_at is set */
  ulong registered_at;            /* Topoheight when first seen */
  int   has_nonce_pointer;        /* 1 if nonce_pointer is set */
  ulong nonce_pointer;            /* Pointer to latest VersionedNonce */
  int   has_multisig_pointer;     /* 1 if multisig_pointer is set */
  ulong multisig_pointer;         /* Pointer to latest multisig config */
  int   has_energy_pointer;       /* 1 if energy_pointer is set */
  ulong energy_pointer;           /* Pointer to latest EnergyResource */
} at_account_t;

/* Serialized account max size */
#define AT_ACCOUNT_SERIALIZED_MAX_SIZE 44

/* ============================================================================
   TOS-Compatible VersionedNonce Structure
   See: tos/common/src/account/nonce.rs

   Serialization Order (all big-endian):
     1. previous_topoheight (Option<u64>)
     2. nonce (u64, 8 bytes)
   ============================================================================ */

typedef struct at_versioned_nonce {
  int   has_previous_topoheight;  /* 1 if previous_topoheight is set */
  ulong previous_topoheight;      /* 0 = no previous version */
  ulong nonce;
} at_versioned_nonce_t;

#define AT_VERSIONED_NONCE_SERIALIZED_MAX_SIZE 17  /* 9 + 8 */

/* ============================================================================
   TOS-Compatible VersionedBalance Structure
   See: tos/common/src/account/balance.rs

   Serialization Order (all big-endian):
     1. previous_topoheight (Option<u64>)
     2. balance_type (u8: 0=Input, 1=Output, 2=Both)
     3. final_balance (u64, 8 bytes)
     4. output_balance (Option<u64>)
   ============================================================================ */

/* Balance type enum - matches TOS BalanceType */
typedef enum {
  AT_BALANCE_TYPE_INPUT  = 0,  /* Only incoming funds */
  AT_BALANCE_TYPE_OUTPUT = 1,  /* Only outgoing funds */
  AT_BALANCE_TYPE_BOTH   = 2,  /* Both incoming and outgoing */
} at_balance_type_t;

typedef struct at_versioned_balance {
  int              has_previous_topoheight;  /* 1 if previous_topoheight is set */
  ulong            previous_topoheight;      /* 0 = no previous version */
  at_balance_type_t balance_type;            /* Input/Output/Both */
  ulong            final_balance;            /* Current balance */
  int              has_output_balance;       /* 1 if output_balance is set */
  ulong            output_balance;           /* For multi-TX tracking */
} at_versioned_balance_t;

#define AT_VERSIONED_BALANCE_SERIALIZED_MAX_SIZE 27  /* 9 + 1 + 8 + 9 = 27 */

/* ============================================================================
   TOS-Compatible Energy Resource Structure
   See: tos/daemon/src/core/storage/rocksdb/types/energy.rs
   ============================================================================ */

typedef struct at_energy_resource {
  ulong frozen_amount;            /* Amount of frozen tokens */
  ulong energy_amount;            /* Available energy */
  ulong freeze_timestamp;         /* When tokens were frozen */
  ulong unfreeze_timestamp;       /* When tokens can be unfrozen */
  int   has_previous_topoheight;  /* 1 if previous_topoheight is set */
  ulong previous_topoheight;      /* 0 = no previous version */
} at_energy_resource_t;

/* TOS energy status helper view (matches common/src/utils/energy_fee.rs). */
typedef struct at_energy_status {
  ulong energy;
  ulong available_energy;
  ulong frozen_tos;
} at_energy_status_t;

/* Equivalent of EnergyStatus::usage_percentage in TOS Rust. */
static inline double
at_energy_status_usage_percentage( at_energy_status_t const * status ) {
  if( !status || status->energy==0UL ) return 0.0;
  ulong used = status->energy > status->available_energy
             ? (status->energy - status->available_energy)
             : 0UL;
  return ((double)used / (double)status->energy) * 100.0;
}

/* Equivalent of EnergyStatus::is_energy_low in TOS Rust. */
static inline int
at_energy_status_is_low( at_energy_status_t const * status ) {
  if( !status ) return 1;
  return (status->energy==0UL) || (status->available_energy < (status->energy / 10UL));
}

/* ============================================================================
   Account Serialization Helpers
   ============================================================================ */

/* Serialize an account to TOS-compatible binary format.
   Returns number of bytes written, or negative on error.
   buf must have at least AT_ACCOUNT_SERIALIZED_MAX_SIZE bytes. */
int at_account_serialize( at_account_t const * acc, uchar * buf, ulong buf_sz );

/* Deserialize an account from TOS-compatible binary format.
   Returns AT_STORE_OK on success. */
int at_account_deserialize( uchar const * buf, ulong buf_sz, at_account_t * acc_out );

/* Serialize a versioned nonce to TOS-compatible binary format.
   Returns number of bytes written, or negative on error. */
int at_versioned_nonce_serialize( at_versioned_nonce_t const * vnonce, uchar * buf, ulong buf_sz );

/* Deserialize a versioned nonce from TOS-compatible binary format. */
int at_versioned_nonce_deserialize( uchar const * buf, ulong buf_sz, at_versioned_nonce_t * vnonce_out );

/* Serialize a versioned balance to TOS-compatible binary format.
   Returns number of bytes written, or negative on error. */
int at_versioned_balance_serialize( at_versioned_balance_t const * vbal, uchar * buf, ulong buf_sz );

/* Deserialize a versioned balance from TOS-compatible binary format. */
int at_versioned_balance_deserialize( uchar const * buf, ulong buf_sz, at_versioned_balance_t * vbal_out );

/* ============================================================================
   Account Queries
   ============================================================================ */

/* at_account_query queries an account by pubkey.
   Returns NULL if not found; caller must call at_account_free on result. */
at_account_t *
at_account_query( at_store_t * store, uchar const pubkey[32] );

/* at_account_free frees an account returned by at_account_query. */
void
at_account_free( at_account_t * account );

/* at_account_query_into queries an account into a caller-provided buffer.
   Returns AT_STORE_OK on success, AT_STORE_ERR_NOT_FOUND if not found. */
int
at_account_query_into( at_store_t * store,
                       uchar const pubkey[32],
                       at_account_t * account_out );

/* at_account_query_by_id queries an account by its numeric ID.
   Returns AT_STORE_OK on success, AT_STORE_ERR_NOT_FOUND if not found.
   Also fills pubkey_out with the account's public key. */
int
at_account_query_by_id( at_store_t * store,
                        ulong account_id,
                        at_account_t * account_out,
                        uchar pubkey_out[32] );

/* ============================================================================
   Account Creation
   ============================================================================ */

/* at_account_create creates a new account with initial balance.
   Atomically:
   - Allocates a new account ID
   - Stores account in AT_CF_ACCOUNT
   - Stores mapping in AT_CF_ACCOUNT_BY_ID
   - Creates initial balance entry
   Returns AT_STORE_OK on success, AT_STORE_ERR_EXISTS if account already exists. */
int
at_account_create( at_store_t * store,
                   uchar const pubkey[32],
                   ulong initial_balance,
                   ulong topoheight,
                   at_account_t * account_out );

/* at_account_get_or_create gets an existing account or creates a new one.
   Returns AT_STORE_OK on success. */
int
at_account_get_or_create( at_store_t * store,
                          uchar const pubkey[32],
                          ulong topoheight,
                          at_account_t * account_out );

/* at_account_get_or_create_in_exec_ctx_batch gets or creates an account for an
   active execution batch and writes registration entries into the supplied batch.
   This allows callers to participate in a single atomic commit path and reuse
   block-local account metadata cache.

   Args:
     store:     Storage instance
     batch:     Batch receiving registration writes when account is new
     exec_ctx:  Execution context used for NEXT_ACCOUNT_ID cache and duplicate guard
     pubkey:    Account public key
     topoheight: Current topoheight for registration
     account_out: On success, receives the account record

   Returns AT_STORE_OK on success or AT_STORE_* error code. */
int
at_account_get_or_create_in_exec_ctx_batch( at_store_t * store,
                                            at_store_batch_t * batch,
                                            struct at_exec_ctx * exec_ctx,
                                            uchar const pubkey[32],
                                            ulong topoheight,
                                            at_account_t * account_out );

/* ============================================================================
   Account Existence Checks
   ============================================================================ */

/* at_account_exists checks if an account exists.
   Returns 1 if exists, 0 if not, negative on error. */
int
at_account_exists( at_store_t * store, uchar const pubkey[32] );

/* at_account_is_empty checks if an account is empty.
   An account is empty if: nonce=0, balance=0, no code.
   Returns 1 if empty, 0 if not, negative on error. */
int
at_account_is_empty( at_store_t * store, uchar const pubkey[32] );

/* ============================================================================
   Balance Operations
   ============================================================================ */

/* at_account_get_balance gets the current balance for an account.
   Returns AT_STORE_OK on success, AT_STORE_ERR_NOT_FOUND if account doesn't exist.
   Uses native asset (asset_id = 0). */
int
at_account_get_balance( at_store_t * store,
                        uchar const pubkey[32],
                        ulong * balance_out );

/* at_account_get_balance_asset gets the current balance for an account and asset hash. */
int
at_account_get_balance_asset( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              ulong * balance_out );

/* at_account_get_balance_at_topo gets balance at a specific topoheight.
   Traverses the versioned balance chain to find the balance at or before topo. */
int
at_account_get_balance_at_topo( at_store_t * store,
                                uchar const pubkey[32],
                                ulong topoheight,
                                ulong * balance_out );

/* at_account_get_balance_asset_at_topo gets balance for an asset at a specific topoheight. */
int
at_account_get_balance_asset_at_topo( at_store_t * store,
                                      uchar const pubkey[32],
                                      uchar const asset[32],
                                      ulong topoheight,
                                      ulong * balance_out );

/* at_account_set_balance sets the balance for an account.
   Creates a new versioned balance entry. */
int
at_account_set_balance( at_store_t * store,
                        uchar const pubkey[32],
                        ulong balance,
                        ulong topoheight );

/* at_account_set_balance_asset sets balance for an account and asset hash. */
int
at_account_set_balance_asset( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              ulong balance,
                              ulong topoheight );

/* at_account_set_versioned_balance sets a versioned balance with all TOS fields.
   This is the full version supporting balance_type and output_balance.
   Used by exec_ctx commit for proper TOS Rust alignment.

   Args:
     store:       Storage instance
     pubkey:      Account public key
     asset:       Asset hash (zeros = native TOS)
     vbal:        Full versioned balance structure
     topoheight:  Current topoheight for the new version

   TOS Rust Reference: daemon/src/core/state/chain_state/apply.rs:1311-1355 */
int
at_account_set_versioned_balance( at_store_t * store,
                                  uchar const pubkey[32],
                                  uchar const asset[32],
                                  at_versioned_balance_t const * vbal,
                                  ulong topoheight );

/* at_account_set_versioned_balance_batch - batch-aware version for atomic commits.
   Adds versioned balance write to an external batch instead of committing immediately.
   Used by exec_ctx to commit all balance changes atomically.

   Args:
     store:       Storage instance (for account lookup)
     batch:       External batch to add operations to
     pubkey:      Account public key
     asset:       Asset hash (zeros = native TOS)
     vbal:        Full versioned balance structure
     topoheight:  Current topoheight for the new version

   Returns AT_STORE_OK on success. Caller must commit batch separately. */
int
at_account_set_versioned_balance_batch( at_store_t * store,
                                        at_store_batch_t * batch,
                                        uchar const pubkey[32],
                                        uchar const asset[32],
                                        at_versioned_balance_t const * vbal,
                                        ulong topoheight );

/* Batch-aware version with execution context.
   Provides optional block-local account cache so newly created accounts can share
   NEXT_ACCOUNT_ID allocation and account registration writes within the same batch.
   If exec_ctx is NULL, falls back to legacy behavior. */
int
at_account_set_versioned_balance_batch_with_ctx( at_store_t * store,
                                                at_store_batch_t * batch,
                                                struct at_exec_ctx * exec_ctx,
                                                uchar const pubkey[32],
                                                uchar const asset[32],
                                                at_versioned_balance_t const * vbal,
                                                ulong topoheight );

/* at_account_transfer transfers amount from sender to receiver.
   Atomically updates both balances and creates versioned entries.
   Returns AT_STORE_ERR_INVALID if sender has insufficient balance. */
int
at_account_transfer( at_store_t * store,
                     uchar const sender[32],
                     uchar const receiver[32],
                     ulong amount,
                     ulong topoheight );

/* at_account_transfer_asset transfers asset amount from sender to receiver. */
int
at_account_transfer_asset( at_store_t * store,
                           uchar const sender[32],
                           uchar const receiver[32],
                           uchar const asset[32],
                           ulong amount,
                           ulong topoheight );

/* at_account_add_balance adds amount to an account's balance.
   Creates a new versioned balance entry. */
int
at_account_add_balance( at_store_t * store,
                        uchar const pubkey[32],
                        ulong amount,
                        ulong topoheight );

/* at_account_add_balance_asset adds amount to an account's balance for an asset. */
int
at_account_add_balance_asset( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              ulong amount,
                              ulong topoheight );

/* at_account_sub_balance subtracts amount from an account's balance.
   Returns AT_STORE_ERR_INVALID if insufficient balance. */
int
at_account_sub_balance( at_store_t * store,
                        uchar const pubkey[32],
                        ulong amount,
                        ulong topoheight );

/* at_account_sub_balance_asset subtracts amount from an account's balance for an asset. */
int
at_account_sub_balance_asset( at_store_t * store,
                              uchar const pubkey[32],
                              uchar const asset[32],
                              ulong amount,
                              ulong topoheight );

/* ============================================================================
   Nonce Operations
   ============================================================================ */

/* at_account_get_nonce gets the current nonce for an account.
   Returns 0 if account doesn't exist or has no nonce. */
int
at_account_get_nonce( at_store_t * store,
                      uchar const pubkey[32],
                      ulong * nonce_out );

/* at_account_get_nonce_at_topo gets nonce at a specific topoheight. */
int
at_account_get_nonce_at_topo( at_store_t * store,
                              uchar const pubkey[32],
                              ulong topoheight,
                              ulong * nonce_out );

/* at_account_set_nonce sets the nonce for an account.
   Creates a new versioned nonce entry. */
int
at_account_set_nonce( at_store_t * store,
                      uchar const pubkey[32],
                      ulong nonce,
                      ulong topoheight );

/* at_account_set_nonce_batch - batch-aware version for atomic commits.
   Adds versioned nonce write to an external batch instead of committing immediately.
   Used by exec_ctx to commit all nonce changes atomically.

   Args:
     store:       Storage instance (for account lookup)
     batch:       External batch to add operations to
     pubkey:      Account public key
     nonce:       New nonce value
     topoheight:  Current topoheight for the new version

   Returns AT_STORE_OK on success. Caller must commit batch separately. */
int
at_account_set_nonce_batch( at_store_t * store,
                            at_store_batch_t * batch,
                            uchar const pubkey[32],
                            ulong nonce,
                            ulong topoheight );

/* Batch-aware version with execution context.
   See at_account_set_versioned_balance_batch_with_ctx for details. */
int
at_account_set_nonce_batch_with_ctx( at_store_t * store,
                                     at_store_batch_t * batch,
                                     struct at_exec_ctx * exec_ctx,
                                     uchar const pubkey[32],
                                     ulong nonce,
                                     ulong topoheight );

/* at_account_check_and_increment_nonce atomically checks and increments nonce.
   Returns AT_STORE_ERR_INVALID if current nonce doesn't match expected_nonce. */
int
at_account_check_and_increment_nonce( at_store_t * store,
                                      uchar const pubkey[32],
                                      ulong expected_nonce,
                                      ulong topoheight );

/* ============================================================================
   Energy Operations
   ============================================================================ */

/* at_account_get_energy gets the current energy for an account.
   Returns 0 if account doesn't exist or has no energy. */
int
at_account_get_energy( at_store_t * store,
                       uchar const pubkey[32],
                       ulong * energy_out );

/* at_account_get_energy_resource gets the full energy resource. */
int
at_account_get_energy_resource( at_store_t * store,
                                uchar const pubkey[32],
                                at_energy_resource_t * resource_out );

int
at_account_get_energy_resource_with_ctx( at_store_t *         store,
                                         struct at_exec_ctx * exec_ctx,
                                         uchar const          pubkey[32],
                                         at_energy_resource_t * resource_out );

/* at_account_freeze freezes tokens to generate energy.
   amount: tokens to freeze
   freeze_days: how long to freeze (affects energy multiplier)
   current_time: current timestamp
   topoheight: current block height */
int
at_account_freeze( at_store_t * store,
                   uchar const pubkey[32],
                   ulong amount,
                   ulong freeze_days,
                   ulong current_time,
                   ulong topoheight );

int
at_account_freeze_with_ctx( at_store_t *         store,
                            struct at_exec_ctx * exec_ctx,
                            uchar const          pubkey[32],
                            ulong                amount,
                            ulong                freeze_days,
                            ulong                current_time,
                            ulong                topoheight,
                            ulong                reference_topoheight );

/* at_account_unfreeze unfreezes tokens when the lock period has expired. */
int
at_account_unfreeze( at_store_t * store,
                     uchar const pubkey[32],
                     ulong current_time,
                     ulong topoheight );

int
at_account_unfreeze_with_ctx( at_store_t *         store,
                              struct at_exec_ctx * exec_ctx,
                              uchar const          pubkey[32],
                              ulong                current_time,
                              ulong                topoheight );

/* at_account_consume_energy consumes energy for transaction fees. */
int
at_account_consume_energy( at_store_t * store,
                           uchar const pubkey[32],
                           ulong amount,
                           ulong topoheight );

/* at_account_set_energy_resource directly sets energy resource (for testing).
   This bypasses the normal freeze flow and directly sets the energy amount. */
int
at_account_set_energy_resource( at_store_t * store,
                                uchar const pubkey[32],
                                ulong energy_amount,
                                ulong topoheight );

int
at_account_set_energy_resource_with_ctx( at_store_t *         store,
                                         struct at_exec_ctx * exec_ctx,
                                         uchar const          pubkey[32],
                                         ulong                energy_amount,
                                         ulong                topoheight );

/* at_account_set_energy_resource_full sets full energy resource fields. */
int
at_account_set_energy_resource_full( at_store_t * store,
                                     uchar const pubkey[32],
                                     ulong frozen_amount,
                                     ulong energy_amount,
                                     ulong freeze_timestamp,
                                     ulong unfreeze_timestamp,
                                     ulong topoheight );

int
at_account_set_energy_resource_full_with_ctx( at_store_t *         store,
                                              struct at_exec_ctx * exec_ctx,
                                              uchar const          pubkey[32],
                                              ulong                frozen_amount,
                                              ulong                energy_amount,
                                              ulong                freeze_timestamp,
                                              ulong                unfreeze_timestamp,
                                              ulong                topoheight );

/* ============================================================================
   Delegated Energy Operations

   Delegated energy is energy received from other accounts via FreezeTosDelegate.
   This is tracked separately from the account's own frozen energy.
   ============================================================================ */

/* at_account_add_received_energy adds delegated energy to an account.
   This is called when someone delegates energy to this account via FreezeTosDelegate.
   The energy is added to the account's total energy but tracked separately. */
int
at_account_add_received_energy( at_store_t * store,
                                 uchar const pubkey[32],
                                 ulong amount,
                                 ulong topoheight );

int
at_account_add_received_energy_with_ctx( at_store_t *         store,
                                         struct at_exec_ctx * exec_ctx,
                                         uchar const          pubkey[32],
                                         ulong                amount,
                                         ulong                topoheight );

/* at_account_sub_received_energy subtracts delegated energy from an account.
   This is called when a delegator unfreezes their delegation to this account.
   Returns AT_STORE_ERR_INVALID if the account doesn't have enough energy. */
int
at_account_sub_received_energy( at_store_t * store,
                                 uchar const pubkey[32],
                                 ulong amount,
                                 ulong topoheight );

int
at_account_sub_received_energy_with_ctx( at_store_t *         store,
                                         struct at_exec_ctx * exec_ctx,
                                         uchar const          pubkey[32],
                                         ulong                amount,
                                         ulong                topoheight );

/* at_account_get_received_energy gets the total delegated energy received by an account.
   This is the sum of all energy received via FreezeTosDelegate from other accounts. */
int
at_account_get_received_energy( at_store_t * store,
                                 uchar const pubkey[32],
                                 ulong * energy_out );

/* ============================================================================
   Contract Operations (Avatar Extension)

   Note: TOS native accounts don't have code_hash/code_size. These operations
   use separate storage (AT_CF_CONTRACTS) for contract bytecode and are
   Avatar-specific extensions for smart contract support.
   ============================================================================ */

/* at_account_set_code stores contract bytecode.
   Stores bytecode in AT_CF_CONTRACTS by code_hash. */
int
at_account_set_code( at_store_t * store,
                     uchar const pubkey[32],
                     uchar const * bytecode,
                     ulong bytecode_sz,
                     ulong topoheight );

/* at_account_get_code_hash gets the code hash for a contract. */
int
at_account_get_code_hash( at_store_t * store,
                          uchar const pubkey[32],
                          uchar code_hash_out[32] );

/* at_account_get_code_size gets the code size for a contract. */
int
at_account_get_code_size( at_store_t * store,
                          uchar const pubkey[32],
                          ulong * code_size_out );

/* ============================================================================
   Self-Destruct
   ============================================================================ */

/* at_account_selfdestruct marks account for destruction and transfers
   remaining balance to beneficiary. */
int
at_account_selfdestruct( at_store_t * store,
                         uchar const pubkey[32],
                         uchar const beneficiary[32],
                         ulong topoheight );

/* at_account_is_selfdestructed checks if account is marked for destruction. */
int
at_account_is_selfdestructed( at_store_t * store, uchar const pubkey[32] );

/* ============================================================================
   Account Update
   ============================================================================ */

/* at_account_update updates an account's metadata in the database.
   Does not update balance/nonce/energy (use specific functions for those). */
int
at_account_update( at_store_t * store,
                   uchar const pubkey[32],
                   at_account_t const * account );

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_account_h */
