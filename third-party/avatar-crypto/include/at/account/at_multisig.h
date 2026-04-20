#ifndef HEADER_at_tos_at_multisig_h
#define HEADER_at_tos_at_multisig_h

/* at_multisig.h - TOS MultiSig Account Configuration Storage

   This module implements TOS-compatible versioned multisig storage with 100%
   binary compatibility for database interoperability.

   TOS MultiSig Model:
   - MultiSig is an ACCOUNT CONFIGURATION, not a transaction wrapper
   - Once configured, ANY transaction from the account needs threshold signatures
   - Signatures are provided in the transaction's `multisig` field

   Storage Format:
   - Column Family: AT_CF_VERSIONED_MULTISIG (20)
   - Key: [topoheight:8 BE][account_id:8 BE] = 16 bytes
   - Value (VersionedMultisig):
       [previous_topoheight: Option<u64>]  -- 1 or 9 bytes
       [threshold: 1]
       [participants_count: 1]
       [participants: 32 * count]

   TOS Serialization Rules:
   - All integers: BIG-ENDIAN
   - Option<T>: 1 byte flag (0=None, 1=Some) + optional value
*/

#include "at/core/storage/at_store.h"

struct at_exec_ctx;

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                           */
/**********************************************************************/

#define AT_VERSIONED_MULTISIG_MAX_PARTICIPANTS (255UL)
#define AT_VERSIONED_MULTISIG_MAX_SZ           (9UL + 1UL + 1UL + 255UL * 32UL)  /* ~8.2KB */
#define AT_VERSIONED_MULTISIG_KEY_SZ           (16UL)  /* topo(8) + account_id(8) */

/**********************************************************************/
/* Versioned MultiSig Structure                                        */
/**********************************************************************/

/* TOS-compatible versioned multisig configuration.
   Stored in AT_CF_VERSIONED_MULTISIG column family. */
typedef struct at_versioned_multisig {
  int   has_previous_topoheight;  /* 1 if previous_topoheight is set */
  ulong previous_topoheight;      /* Pointer to previous version */
  uchar threshold;                /* 0=disabled, 1-255=required signatures */
  uchar participants_cnt;         /* Number of authorized participants */
  uchar participants[AT_VERSIONED_MULTISIG_MAX_PARTICIPANTS][32];  /* Public keys */
} at_versioned_multisig_t;

/**********************************************************************/
/* Serialization Functions                                             */
/**********************************************************************/

/* Serialize a versioned multisig to TOS-compatible binary format.
   Returns number of bytes written, or negative on error.

   Format:
     [previous_topoheight: Option<u64>]
     [threshold: 1]
     [participants_count: 1]
     [participants: 32 * participants_count] */
int at_versioned_multisig_serialize( at_versioned_multisig_t const * ms,
                                      uchar * buf,
                                      ulong buf_sz );

/* Deserialize a versioned multisig from TOS-compatible binary format.
   Returns AT_STORE_OK on success, negative error code on failure. */
int at_versioned_multisig_deserialize( uchar const * buf,
                                        ulong buf_sz,
                                        at_versioned_multisig_t * ms_out );

/**********************************************************************/
/* Storage Operations                                                  */
/**********************************************************************/

/* Get current multisig configuration for an account.
   Returns AT_STORE_OK if found, AT_STORE_ERR_NOT_FOUND if not configured. */
int at_multisig_get( at_store_t * store,
                      uchar const pubkey[32],
                      at_versioned_multisig_t * config_out );

/* Get multisig configuration at a specific topoheight.
   Traverses the versioned chain to find config at or before topoheight.
   Returns AT_STORE_OK if found, AT_STORE_ERR_NOT_FOUND if not configured. */
int at_multisig_get_at_topo( at_store_t * store,
                              uchar const pubkey[32],
                              ulong topoheight,
                              at_versioned_multisig_t * config_out );

/* Set multisig configuration for an account.
   Creates a new versioned entry and updates account's multisig_pointer.
   Returns AT_STORE_OK on success. */
int at_multisig_set( at_store_t * store,
                      uchar const pubkey[32],
                      at_versioned_multisig_t const * config,
                      ulong topoheight );

/* Set multisig configuration in a caller-provided batch (atomic with other writes).
   Creates a new versioned multisig entry and updates account pointer.
   Returns AT_STORE_OK on success. */
int at_multisig_set_batch( at_store_t * store,
                           at_store_batch_t * batch,
                           uchar const pubkey[32],
                           at_versioned_multisig_t const * config,
                           ulong topoheight );

/* Batch-aware version with execution context.
   Supports block-local account creation cache for newly created accounts.
   If exec_ctx is NULL, falls back to direct account lookup/create behavior. */
int at_multisig_set_batch_with_ctx( at_store_t * store,
                                    at_store_batch_t * batch,
                                    struct at_exec_ctx * exec_ctx,
                                    uchar const pubkey[32],
                                    at_versioned_multisig_t const * config,
                                    ulong topoheight );

/* Check if an account has multisig enabled.
   Returns 1 if enabled (threshold > 0), 0 if disabled or not configured,
   negative on error. */
int at_multisig_is_enabled( at_store_t * store, uchar const pubkey[32] );

/* Get the threshold for an account's multisig (0 if disabled).
   Returns AT_STORE_OK on success, AT_STORE_ERR_NOT_FOUND if not configured.
   If not configured, threshold_out is set to 0. */
int at_multisig_get_threshold( at_store_t * store,
                                uchar const pubkey[32],
                                uchar * threshold_out );

/**********************************************************************/
/* Verification Helper                                                 */
/**********************************************************************/

/* Check if a participant ID is valid for the multisig configuration.
   Returns 1 if valid, 0 if invalid. */
static inline int
at_multisig_is_valid_participant( at_versioned_multisig_t const * ms,
                                   uchar participant_id ) {
  if( !ms ) return 0;
  return participant_id < ms->participants_cnt;
}

/* Get participant public key by ID.
   Returns pointer to 32-byte public key, or NULL if invalid. */
static inline uchar const *
at_multisig_get_participant( at_versioned_multisig_t const * ms,
                              uchar participant_id ) {
  if( !ms || participant_id >= ms->participants_cnt ) {
    return NULL;
  }
  return ms->participants[participant_id];
}

AT_PROTOTYPES_END

#endif /* HEADER_at_tos_at_multisig_h */
