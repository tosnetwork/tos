#ifndef HEADER_at_blockdag_at_dag_hash_indexset_h
#define HEADER_at_blockdag_at_dag_hash_indexset_h

/* at_dag_hash_indexset.h - IndexSet<Hash> for BlockDAG algorithms

   Instantiates the dynamic IndexSet template with 32-byte block hash
   keys for O(1) membership testing.  Replaces O(n) linear scans in
   reachability, topological ordering, and reorganization algorithms.

   Aligned with TOS Rust's IndexSet<Hash> / HashSet<Hash> usage. */

#include "at/infra/at_util_base.h"
#include "bits/at_bits.h"
#include "at/core/blockdag/at_dag_config.h"

/* Block hash key type — wraps uchar[32] for pass-by-value IndexSet usage */

typedef struct { uchar b[AT_BLOCK_HASH_SZ]; } at_dag_hash_key_t;

/* Entry type: key + memoized hash */

typedef struct {
  at_dag_hash_key_t  key;
  uint               hash;
} at_dag_hash_entry_t;

/* Helper: convert raw hash pointer to key type */

static inline at_dag_hash_key_t
at_dag_hash_key_from( uchar const * hash ) {
  at_dag_hash_key_t k;
  at_memcpy( k.b, hash, AT_BLOCK_HASH_SZ );
  return k;
}

/* Helper: check if key is the null sentinel (all-zero).
   No valid block hash is all-zero (SHA3 outputs). */

static inline int
at_dag_hash_key_is_zero( at_dag_hash_key_t const * k ) {
  ulong a, b, c, d;
  at_memcpy( &a, k->b,      8 );
  at_memcpy( &b, k->b + 8,  8 );
  at_memcpy( &c, k->b + 16, 8 );
  at_memcpy( &d, k->b + 24, 8 );
  return !(a | b | c | d);
}

/* Helper: hash a block hash key to uint.
   Uses first 4 bytes of the SHA3 hash (already well-distributed)
   mixed with seed via at_uint_hash. */

static inline uint
at_dag_hash_key_hash( at_dag_hash_key_t const * k, ulong seed ) {
  uint h;
  at_memcpy( &h, k->b, sizeof(uint) );
  return at_uint_hash( h ^ (uint)seed );
}

/* Instantiate dynamic IndexSet template for block hashes */

#define IDXSET_NAME               dag_hash_idxset
#define IDXSET_T                  at_dag_hash_entry_t
#define IDXSET_KEY_T              at_dag_hash_key_t
#define IDXSET_KEY                key
#define IDXSET_HASH               hash
#define IDXSET_KEY_NULL           ((at_dag_hash_key_t){{0}})
#define IDXSET_KEY_INVAL(k)       at_dag_hash_key_is_zero(&(k))
#define IDXSET_KEY_EQUAL(k0,k1)   (at_memcmp((k0).b, (k1).b, AT_BLOCK_HASH_SZ)==0)
#define IDXSET_KEY_EQUAL_IS_SLOW  1
#define IDXSET_KEY_HASH(k,s)      at_dag_hash_key_hash(&(k),(s))
#define IDXSET_MEMOIZE            1
#include "infra/tmpl/at_indexset_dynamic.c"

#endif /* HEADER_at_blockdag_at_dag_hash_indexset_h */
