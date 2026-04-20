#ifndef HEADER_at_waltz_p2p_at_bloom_h
#define HEADER_at_waltz_p2p_at_bloom_h

/* at_bloom.h - Bloom Filter for P2P Gossip

   Provides efficient probabilistic duplicate detection for
   transaction and block hash propagation.

   Configuration:
   - 8KB filter (65536 bits)
   - 8 hash functions (murmur3 with different seeds)
   - ~10% false positive rate at 4000 items
*/

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

#define AT_BLOOM_BITS       (65536UL)   /* 64K bits = 8KB */
#define AT_BLOOM_BYTES      (AT_BLOOM_BITS / 8UL)
#define AT_BLOOM_HASH_CNT   (8)         /* Number of hash functions */

/**********************************************************************/
/* Bloom Filter Structure                                             */
/**********************************************************************/

typedef struct {
  uchar bits[AT_BLOOM_BYTES];    /* Bit array */
  uint  item_cnt;                /* Number of items added */
} at_bloom_t;

/**********************************************************************/
/* Lifecycle                                                          */
/**********************************************************************/

/* at_bloom_init initializes a bloom filter (zeroes all bits).
   Returns bloom on success, NULL on failure. */
at_bloom_t *
at_bloom_init( at_bloom_t * bloom );

/* at_bloom_clear resets the bloom filter (zeroes all bits). */
void
at_bloom_clear( at_bloom_t * bloom );

/**********************************************************************/
/* Operations                                                         */
/**********************************************************************/

/* at_bloom_add adds an item to the bloom filter.
   data is pointer to data, sz is size in bytes.
   Common use: at_bloom_add(bloom, hash, 32) for 32-byte hashes. */
void
at_bloom_add( at_bloom_t *  bloom,
              uchar const * data,
              ulong         sz );

/* at_bloom_add_hash adds a 32-byte hash to the bloom filter. */
static inline void
at_bloom_add_hash( at_bloom_t * bloom, uchar const hash[32] ) {
  at_bloom_add( bloom, hash, 32 );
}

/* at_bloom_may_contain checks if an item might be in the filter.
   Returns 1 if item might be present (or is definitely present).
   Returns 0 if item is definitely NOT present.
   False positives possible, false negatives impossible. */
int
at_bloom_may_contain( at_bloom_t const * bloom,
                      uchar const *      data,
                      ulong              sz );

/* at_bloom_may_contain_hash checks if a 32-byte hash might be present. */
static inline int
at_bloom_may_contain_hash( at_bloom_t const * bloom, uchar const hash[32] ) {
  return at_bloom_may_contain( bloom, hash, 32 );
}

/**********************************************************************/
/* Statistics                                                         */
/**********************************************************************/

/* at_bloom_item_cnt returns number of items added. */
static inline uint
at_bloom_item_cnt( at_bloom_t const * bloom ) {
  return bloom ? bloom->item_cnt : 0;
}

/* at_bloom_fp_rate estimates current false positive rate.
   Returns approximate false positive probability (0.0 to 1.0). */
double
at_bloom_fp_rate( at_bloom_t const * bloom );

/* at_bloom_bit_cnt returns number of set bits. */
uint
at_bloom_bit_cnt( at_bloom_t const * bloom );

/**********************************************************************/
/* Merge                                                              */
/**********************************************************************/

/* at_bloom_merge combines two bloom filters using bitwise OR.
   Result is stored in dst.
   Useful for aggregating filters from multiple peers. */
void
at_bloom_merge( at_bloom_t *       dst,
                at_bloom_t const * src );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_bloom_h */