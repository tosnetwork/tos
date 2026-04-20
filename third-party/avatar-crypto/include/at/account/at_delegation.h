#ifndef HEADER_at_tos_at_delegation_h
#define HEADER_at_tos_at_delegation_h

/* at_delegation.h - TOS Energy Delegation Records

   This module manages delegated freeze records for the energy system.
   When a user freezes TOS with delegation, they lock their tokens and
   give energy to other accounts (delegatees).

   Key Concepts:
   - Delegator: The account that freezes TOS and delegates energy
   - Delegatee: The account that receives delegated energy
   - Each delegation record contains multiple entries (up to 32 delegatees)
   - Each account can have up to 32 delegation records

   Energy Formula (TOS-aligned):
     energy = (amount_in_atomic / COIN_VALUE) * 2 * freeze_duration_days
     Example: 1 TOS (100,000,000 atomic) * 7 days = 1 * 2 * 7 = 14 energy

   Storage Schema:
     AT_CF_DELEGATION_RECORDS: {delegator_pubkey[32]}{record_index[4]} -> DelegatedFreezeRecord
     AT_CF_DELEGATOR_STATE: {delegator_pubkey[32]} -> DelegatorState

   Wire Format (Big-Endian):
     DelegateRecordEntry: [delegatee:32][amount:8][energy:8] = 48 bytes
     DelegatedFreezeRecord: [count:8][entries*count][duration:4][freeze_topo:8][unlock_topo:8][total_amount:8][total_energy:8]
*/

#include "at/core/storage/at_store.h"
#include "at/transaction/at_txn.h"

AT_PROTOTYPES_BEGIN

struct at_exec_ctx;

/**********************************************************************/
/* Constants                                                           */
/**********************************************************************/

/* Maximum delegation records per account (matches TOS Rust) */
#define AT_MAX_DELEGATION_RECORDS (32UL)

/* Maximum entries per delegation record (matches TOS Rust) */
#define AT_MAX_DELEGATION_ENTRIES (32UL)

/* Minimum delegation amount: 1 TOS in atomic units */
#define AT_DELEGATION_MIN_AMOUNT (100000000UL)

/* Wire constraints for freeze-delegate payload parsing */
#define AT_DELEGATION_MIN_DAYS              (3UL)
#define AT_DELEGATION_MAX_DAYS              (365UL)
#define AT_DELEGATION_OP_FREEZE_DELEGATE    (1U)
#define AT_DELEGATION_WIRE_ENTRY_SZ         (40UL)   /* delegatee(32) + amount(8) */
#define AT_DELEGATION_WIRE_MIN_SZ           (13UL)   /* op(1) + count(8) + days(4) */
#define AT_DELEGATION_WIRE_MAX_DELEGATEES   (500UL)

/* Entry size in storage: delegatee(32) + amount(8) + energy(8) */
#define AT_DELEGATE_RECORD_ENTRY_SZ (48UL)

/**********************************************************************/
/* Delegation Record Entry                                             */
/**********************************************************************/

typedef struct {
  uint days;
} at_freeze_duration_t;

typedef struct {
  uchar delegatee[32];
  ulong amount;
} at_delegation_entry_t;

typedef struct {
  ulong                count;
  uint                 entries_off;   /* Offset to entries in raw txn bytes */
  at_freeze_duration_t duration;
  ulong                total_amount;
} at_freeze_delegate_t;

static inline int
at_freeze_duration_is_valid( at_freeze_duration_t const * d ) {
  return d->days >= AT_DELEGATION_MIN_DAYS && d->days <= AT_DELEGATION_MAX_DAYS;
}

static inline int
at_freeze_delegate_parse( uchar const *         data,
                          ulong                 data_sz,
                          uint                  base_off,
                          at_freeze_delegate_t * out ) {
  if( AT_UNLIKELY( data_sz < AT_DELEGATION_WIRE_MIN_SZ ) ) return -1;
  if( AT_UNLIKELY( data[0] != AT_DELEGATION_OP_FREEZE_DELEGATE ) ) return -1;

  out->count = at_be64_to_native( data + 1 );
  if( AT_UNLIKELY( out->count == 0 || out->count > AT_DELEGATION_WIRE_MAX_DELEGATEES ) ) {
    return -1;
  }

  ulong expected_sz = 1UL + 8UL + (out->count * AT_DELEGATION_WIRE_ENTRY_SZ) + 4UL;
  if( AT_UNLIKELY( data_sz < expected_sz ) ) return -1;

  out->entries_off = base_off + 9U;

  ulong duration_off = 9UL + (out->count * AT_DELEGATION_WIRE_ENTRY_SZ);
  out->duration.days = at_be32_to_native( data + duration_off );
  if( AT_UNLIKELY( !at_freeze_duration_is_valid( &out->duration ) ) ) return -1;

  out->total_amount = 0UL;
  for( ulong i = 0UL; i < out->count; i++ ) {
    ulong entry_off = 9UL + (i * AT_DELEGATION_WIRE_ENTRY_SZ);
    ulong amount = at_be64_to_native( data + entry_off + 32UL );
    if( AT_UNLIKELY( amount < AT_DELEGATION_MIN_AMOUNT ) ) return -1;
    if( AT_UNLIKELY( __builtin_uaddl_overflow( out->total_amount, amount, &out->total_amount ) ) ) {
      return -1;
    }
  }

  return 0;
}

static inline int
at_freeze_delegate_get_entry( at_freeze_delegate_t const * fd,
                              uchar const *                raw,
                              ulong                        idx,
                              at_delegation_entry_t *      out ) {
  if( AT_UNLIKELY( idx >= fd->count ) ) return -1;
  ulong off = fd->entries_off + (idx * AT_DELEGATION_WIRE_ENTRY_SZ);
  at_memcpy( out->delegatee, raw + off, 32 );
  out->amount = at_be64_to_native( raw + off + 32 );
  return 0;
}

/* Single entry within a delegated freeze record.
   Tracks energy delegated to one delegatee. */
typedef struct at_delegate_record_entry {
  uchar delegatee[32];  /* Delegatee public key (receives energy) */
  ulong amount;         /* Amount of TOS delegated (atomic units) */
  ulong energy;         /* Energy given = (amount/COIN_VALUE) * 2 * days */
} at_delegate_record_entry_t;

/**********************************************************************/
/* Delegated Freeze Record                                             */
/**********************************************************************/

/* A delegated freeze record represents a single freeze-delegate operation.
   One transaction can delegate to up to 32 delegatees.
   Each account can have up to 32 such records. */
typedef struct at_delegated_freeze_record {
  uint  record_index;                                    /* Index within delegator's records (0-31) */
  ulong duration_days;                                   /* Freeze duration in days (3-365) */
  ulong freeze_topoheight;                               /* When tokens were frozen */
  ulong unlock_topoheight;                               /* When tokens can be unfrozen */
  ulong total_amount;                                    /* Sum of all entry amounts */
  ulong total_energy;                                    /* Sum of all entry energies */
  ulong entry_count;                                     /* Number of entries (1-32) */
  at_delegate_record_entry_t entries[AT_MAX_DELEGATION_ENTRIES]; /* Delegation entries */
} at_delegated_freeze_record_t;

/* Serialized size calculation for a delegated freeze record */
#define AT_DELEGATED_FREEZE_RECORD_HEADER_SZ (4 + 8 + 8 + 8 + 8 + 8 + 8)  /* 52 bytes */
#define AT_DELEGATED_FREEZE_RECORD_MAX_SZ (AT_DELEGATED_FREEZE_RECORD_HEADER_SZ + \
                                           (AT_DELEGATE_RECORD_ENTRY_SZ * AT_MAX_DELEGATION_ENTRIES))

/**********************************************************************/
/* Delegator State                                                     */
/**********************************************************************/

/* Tracks all delegation records for a delegator account.
   Stored separately from the account to keep account structure simple. */
typedef struct at_delegator_state {
  ulong record_count;                              /* Number of active delegation records (0-32) */
  uint  record_indices[AT_MAX_DELEGATION_RECORDS]; /* Active record indices */
} at_delegator_state_t;

#define AT_DELEGATOR_STATE_SZ (8 + 4 * AT_MAX_DELEGATION_RECORDS)  /* 136 bytes */

/**********************************************************************/
/* Delegation Record Operations                                        */
/**********************************************************************/

/* Create a new delegated freeze record from transaction data.
   Calculates energy for each entry based on amount and duration.
   Returns 0 on success, -1 on failure. */
int
at_delegation_record_create( at_delegated_freeze_record_t * record,
                              uint                           record_index,
                              at_freeze_delegate_t const *   fd,
                              uchar const *                  raw,
                              ulong                          freeze_topoheight,
                              ulong                          blocks_per_day );

/* Serialize a delegation record to buffer.
   Returns number of bytes written, or -1 on error. */
int
at_delegation_record_serialize( at_delegated_freeze_record_t const * record,
                                 uchar *                               buf,
                                 ulong                                 buf_sz );

/* Deserialize a delegation record from buffer.
   Returns 0 on success, -1 on failure. */
int
at_delegation_record_deserialize( uchar const *                  buf,
                                   ulong                          buf_sz,
                                   at_delegated_freeze_record_t * record );

/* Find entry by delegatee pubkey.
   Returns entry index, or -1 if not found. */
int
at_delegation_record_find_entry( at_delegated_freeze_record_t const * record,
                                  uchar const                          delegatee[32] );

/* Check if record can be unlocked at given topoheight.
   Returns 1 if unlockable, 0 if still locked. */
int
at_delegation_record_can_unlock( at_delegated_freeze_record_t const * record,
                                  ulong                                 current_topoheight );

/**********************************************************************/
/* Delegator State Operations                                          */
/**********************************************************************/

/* Initialize delegator state (empty). */
void
at_delegator_state_init( at_delegator_state_t * state );

/* Serialize delegator state to buffer.
   Returns number of bytes written, or -1 on error. */
int
at_delegator_state_serialize( at_delegator_state_t const * state,
                               uchar *                       buf,
                               ulong                         buf_sz );

/* Deserialize delegator state from buffer.
   Returns 0 on success, -1 on failure. */
int
at_delegator_state_deserialize( uchar const *          buf,
                                 ulong                  buf_sz,
                                 at_delegator_state_t * state );

/* Add a record index to delegator state.
   Returns 0 on success, -1 if state is full (32 records). */
int
at_delegator_state_add_record( at_delegator_state_t * state,
                                uint                   record_index );

/* Remove a record index from delegator state.
   Returns 0 on success, -1 if not found. */
int
at_delegator_state_remove_record( at_delegator_state_t * state,
                                   uint                   record_index );

/* Allocate next available record index.
   Returns the new index (0-31), or -1 if full. */
int
at_delegator_state_alloc_index( at_delegator_state_t * state );

/**********************************************************************/
/* Storage Operations                                                  */
/**********************************************************************/

/* Store a delegation record in the database.
   Key: {delegator_pubkey[32]}{record_index[4]}
   Returns AT_STORE_OK on success. */
int
at_delegation_record_store( at_store_t *                         store,
                             uchar const                          delegator[32],
                             at_delegated_freeze_record_t const * record );

int
at_delegation_record_store_with_ctx( at_store_t *                         store,
                                     struct at_exec_ctx *                 exec_ctx,
                                     uchar const                          delegator[32],
                                     at_delegated_freeze_record_t const * record );

/* Load a delegation record from the database.
   Returns AT_STORE_OK on success, AT_STORE_ERR_NOT_FOUND if not exists. */
int
at_delegation_record_load( at_store_t *                   store,
                           uchar const                    delegator[32],
                           uint                           record_index,
                           at_delegated_freeze_record_t * record );

int
at_delegation_record_load_with_ctx( at_store_t *                   store,
                                    struct at_exec_ctx *           exec_ctx,
                                    uchar const                    delegator[32],
                                    uint                           record_index,
                                    at_delegated_freeze_record_t * record );

/* Delete a delegation record from the database.
   Returns AT_STORE_OK on success. */
int
at_delegation_record_delete( at_store_t * store,
                              uchar const  delegator[32],
                              uint         record_index );

int
at_delegation_record_delete_with_ctx( at_store_t *         store,
                                      struct at_exec_ctx * exec_ctx,
                                      uchar const          delegator[32],
                                      uint                 record_index );

/* Load delegator state from the database.
   Returns AT_STORE_OK on success, initializes empty state if not found. */
int
at_delegator_state_load( at_store_t *           store,
                         uchar const            delegator[32],
                         at_delegator_state_t * state );

int
at_delegator_state_load_with_ctx( at_store_t *           store,
                                  struct at_exec_ctx *   exec_ctx,
                                  uchar const            delegator[32],
                                  at_delegator_state_t * state );

/* Store delegator state in the database.
   Returns AT_STORE_OK on success. */
int
at_delegator_state_store( at_store_t *                 store,
                           uchar const                  delegator[32],
                           at_delegator_state_t const * state );

int
at_delegator_state_store_with_ctx( at_store_t *                 store,
                                   struct at_exec_ctx *         exec_ctx,
                                   uchar const                  delegator[32],
                                   at_delegator_state_t const * state );

/**********************************************************************/
/* Energy Calculation                                                  */
/**********************************************************************/

/* Calculate energy from amount and duration (TOS-aligned formula).
   energy = (amount_atomic / COIN_VALUE) * 2 * duration_days
   Returns 0 on overflow. */
static inline ulong
at_delegation_calculate_energy( ulong amount_atomic, ulong duration_days ) {
  /* Convert to whole TOS */
  ulong amount_whole_tos = amount_atomic / AT_DELEGATION_MIN_AMOUNT;
  if( amount_whole_tos == 0 ) return 0;

  /* Calculate energy with overflow check */
  ulong energy = 0;
  if( __builtin_umull_overflow( amount_whole_tos, 2UL, &energy ) ) return 0;
  if( __builtin_umull_overflow( energy, duration_days, &energy ) ) return 0;

  return energy;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_delegation_h */
