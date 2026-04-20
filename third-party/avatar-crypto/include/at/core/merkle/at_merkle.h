#ifndef HEADER_at_core_merkle_at_merkle_h
#define HEADER_at_core_merkle_at_merkle_h

/* at_merkle.h - Merkle tree builder (TOS Rust aligned)

   Mirrors ~/tos/daemon/src/core/merkle.rs:
     - bottom-up binary Merkle construction
     - pairs of hashes are concatenated and hashed
     - if odd, duplicate the last hash

   Hash function: BLAKE3-256 (tos_common::crypto::hash)
   Hash size: 32 bytes
*/

#include "at/infra/at_util_base.h"
#include "at/infra/alloc/at_alloc.h"

AT_PROTOTYPES_BEGIN

#define AT_MERKLE_HASH_SZ (32UL)

typedef struct {
  at_alloc_t * alloc;                 /* allocator for internal buffers */
  uchar (*hashes)[AT_MERKLE_HASH_SZ]; /* dynamic array of hashes */
  ulong len;
  ulong cap;
} at_merkle_builder_t;

/* Initialize an empty builder */
void at_merkle_builder_init( at_merkle_builder_t * b, at_alloc_t * alloc );

/* Initialize with capacity */
int at_merkle_builder_init_with_capacity( at_merkle_builder_t * b, at_alloc_t * alloc, ulong capacity );

/* Initialize from an array of hashes (copied) */
int at_merkle_builder_init_from_hashes( at_merkle_builder_t *       b,
                                        at_alloc_t *                alloc,
                                        uchar const (*hashes)[AT_MERKLE_HASH_SZ],
                                        ulong                     count );

/* Free internal storage */
void at_merkle_builder_destroy( at_merkle_builder_t * b );

/* Add a hash (copied) */
int at_merkle_builder_add( at_merkle_builder_t * b, uchar const hash[AT_MERKLE_HASH_SZ] );

/* Add an element by hashing its bytes */
int at_merkle_builder_add_element( at_merkle_builder_t * b, uchar const * bytes, ulong bytes_sz );

/* Add raw bytes by hashing and appending */
int at_merkle_builder_add_bytes( at_merkle_builder_t * b, uchar const * bytes, ulong bytes_sz );

/* Add a byte array of HASH_SZ as a hash */
int at_merkle_builder_add_as_hash( at_merkle_builder_t * b, uchar const hash_bytes[AT_MERKLE_HASH_SZ] );

/* Build the merkle tree and return the root hash in out_root.
   Returns out_root on success, NULL on error (including empty builder). */
uchar * at_merkle_builder_build( at_merkle_builder_t * b, uchar out_root[AT_MERKLE_HASH_SZ] );

/* Verify the merkle tree against a root hash.
   Returns 1 on match, 0 on mismatch or error. */
int at_merkle_builder_verify( at_merkle_builder_t * b, uchar const root[AT_MERKLE_HASH_SZ] );

AT_PROTOTYPES_END

#endif /* HEADER_at_core_merkle_at_merkle_h */
