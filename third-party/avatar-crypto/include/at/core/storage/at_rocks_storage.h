#ifndef HEADER_at_rocks_at_rocks_storage_h
#define HEADER_at_rocks_at_rocks_storage_h

/* at_rocks_storage.h - Contract storage operations for at_rocks

   Provides SLOAD/SSTORE operations for EVM contract storage with
   topoheight-based versioning.

   Storage keys are 32 bytes (EVM storage slots).
   Storage values are 32 bytes (EVM words).
   Internally, keys/values are encoded as ValueCell::Default(U256)
   and indexed by (contract_id, data_id) for TOS compatibility.

   Usage:
     uchar value[32];
     int err = at_rocks_storage_read( db, contract, key, value );
     if( err == AT_ROCKS_ERR_NOT_FOUND ) {
       at_memset( value, 0, 32 );  // Unset slots are zero
     }

     // Write storage
     at_rocks_storage_write( db, contract, key, new_value, topoheight );
*/

#include "at_rocks.h"

AT_PROTOTYPES_BEGIN

/* ============================================================================
   Contract Storage (SLOAD/SSTORE)
   ============================================================================ */

/* at_rocks_storage_read reads a storage slot (SLOAD).
   Returns AT_ROCKS_OK on success.
   Returns AT_ROCKS_ERR_NOT_FOUND if slot not set (value is zeroed). */
int
at_rocks_storage_read( at_rocks_t * db,
                        uchar const contract[32],
                        uchar const key[32],
                        uchar value[32] );

/* at_rocks_storage_read_at_topo reads a storage slot at a specific topoheight.
   Traverses the version chain to find the value at or before the given topo. */
int
at_rocks_storage_read_at_topo( at_rocks_t * db,
                                uchar const contract[32],
                                uchar const key[32],
                                ulong topoheight,
                                uchar value[32] );

/* at_rocks_storage_write writes a storage slot (SSTORE).
   Creates a new versioned entry linking to the previous version. */
int
at_rocks_storage_write( at_rocks_t * db,
                         uchar const contract[32],
                         uchar const key[32],
                         uchar const value[32],
                         ulong topoheight );

/* at_rocks_storage_remove removes a storage slot.
   Semantically equivalent to writing zero, but may optimize storage.
   Creates a versioned "tombstone" entry. */
int
at_rocks_storage_remove( at_rocks_t * db,
                          uchar const contract[32],
                          uchar const key[32],
                          ulong topoheight );

/* at_rocks_storage_exists checks if a storage slot exists and is non-zero.
   Returns 1 if exists and non-zero, 0 if not set or zero, negative on error. */
int
at_rocks_storage_exists( at_rocks_t * db,
                          uchar const contract[32],
                          uchar const key[32] );

/* ============================================================================
   Contract Bytecode Storage
   ============================================================================ */

/* at_rocks_contract_load loads contract bytecode by contract hash.
   Caller must NOT free the returned bytecode pointer.
   The pointer is valid until the next operation on db.
   For persistent access, copy the data. */
int
at_rocks_contract_load( at_rocks_t * db,
                         uchar const contract[32],
                         uchar const ** bytecode_out,
                         ulong * bytecode_sz_out );

/* at_rocks_contract_load_copy loads contract bytecode, copying to caller's buffer.
   Returns AT_ROCKS_ERR_FULL if buffer too small. */
int
at_rocks_contract_load_copy( at_rocks_t * db,
                              uchar const contract[32],
                              uchar * bytecode_out,
                              ulong * bytecode_sz_inout );

/* at_rocks_contract_store stores contract bytecode by contract hash. */
int
at_rocks_contract_store( at_rocks_t * db,
                          uchar const contract[32],
                          uchar const * bytecode,
                          ulong bytecode_sz,
                          ulong topoheight );

/* at_rocks_contract_exists checks if contract code exists by hash.
   Returns 1 if exists, 0 if not, negative on error. */
int
at_rocks_contract_exists( at_rocks_t * db,
                           uchar const contract[32] );

/* ============================================================================
   EVM Opcode Support (by address)
   ============================================================================ */

/* at_rocks_contract_load_by_address loads contract bytecode by account address. */
int
at_rocks_contract_load_by_address( at_rocks_t * db,
                                    uchar const address[32],
                                    uchar const ** bytecode_out,
                                    ulong * bytecode_sz_out );

/* at_rocks_contract_get_size returns code size for an address (EXTCODESIZE).
   Returns 0 for EOA or non-existent accounts. */
int
at_rocks_contract_get_size( at_rocks_t * db,
                             uchar const address[32],
                             ulong * size_out );

/* at_rocks_contract_get_hash returns code hash for an address (EXTCODEHASH).
   Returns zero hash for EOA, special empty hash for non-existent.
   EIP-1052: Returns 0 for accounts that don't exist or are empty. */
int
at_rocks_contract_get_hash( at_rocks_t * db,
                             uchar const address[32],
                             uchar code_hash_out[32] );

/* at_rocks_contract_copy copies a segment of code (EXTCODECOPY).
   Copies `length` bytes starting at `code_offset` into `dest`.
   Pads with zeros if code_offset + length exceeds code size. */
int
at_rocks_contract_copy( at_rocks_t * db,
                         uchar const address[32],
                         ulong code_offset,
                         ulong length,
                         uchar * dest );

/* ============================================================================
   Storage Iteration
   ============================================================================ */

/* at_rocks_storage_iter_t iterates over all storage slots for a contract */
typedef struct at_rocks_storage_iter at_rocks_storage_iter_t;

/* at_rocks_storage_iter_new creates an iterator over contract storage. */
at_rocks_storage_iter_t *
at_rocks_storage_iter_new( at_rocks_t * db, uchar const contract[32] );

/* at_rocks_storage_iter_valid returns 1 if at a valid position. */
int
at_rocks_storage_iter_valid( at_rocks_storage_iter_t * iter );

/* at_rocks_storage_iter_next advances to the next slot. */
void
at_rocks_storage_iter_next( at_rocks_storage_iter_t * iter );

/* at_rocks_storage_iter_key returns the current storage key.
   Copies to key_out. */
void
at_rocks_storage_iter_key( at_rocks_storage_iter_t * iter, uchar key_out[32] );

/* at_rocks_storage_iter_value returns the current storage value.
   Copies to value_out. */
void
at_rocks_storage_iter_value( at_rocks_storage_iter_t * iter, uchar value_out[32] );

/* at_rocks_storage_iter_destroy destroys the iterator. */
void
at_rocks_storage_iter_destroy( at_rocks_storage_iter_t * iter );

AT_PROTOTYPES_END

#endif /* HEADER_at_rocks_at_rocks_storage_h */
