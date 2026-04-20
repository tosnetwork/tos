#ifndef HEADER_at_src_disco_verify_at_verify_tile_h
#define HEADER_at_src_disco_verify_at_verify_tile_h

/* The verify tile verifies that the cryptographic signatures of
   incoming transactions match the data being signed.  Transactions with
   invalid signatures are filtered out of the frag stream.

   TOS uses Schnorr-variant signatures on Ristretto255 with SHA3-512. */

#include "../at_topo.h"
#include "at/transaction/at_txn.h"
#include "at/crypto/at_schnorr.h"
#include "at/crypto/at_sha3.h"

/* Re-export verification constants from at_txn.h */
/* AT_TXN_VERIFY_SUCCESS, AT_TXN_VERIFY_PARSE_ERR, etc. */

/* at_verify_in_ctx_t is a context object for each in (producer) mcache
   connected to the verify tile. */

typedef struct {
  at_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} at_verify_in_ctx_t;

/* TODO: Implement based on TOS requirements - define AT_TXN_ACTUAL_SIG_MAX */
#ifndef AT_TXN_ACTUAL_SIG_MAX
#define AT_TXN_ACTUAL_SIG_MAX 8  /* Placeholder - adjust based on TOS */
#endif

typedef struct {
  at_sha3_512_t * sha[ AT_TXN_ACTUAL_SIG_MAX ];

  /* TODO: Implement based on TOS requirements - bundle support */
  int   bundle_failed;
  ulong bundle_id;

  ulong round_robin_idx;
  ulong round_robin_cnt;

  /* tcache for deduplication */
  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * tcache_sync;
  ulong * tcache_ring;
  ulong * tcache_map;

  /* TODO: Implement based on TOS requirements - define IN_KIND constants */
  ulong              in_kind[ 32 ];
  at_verify_in_ctx_t in[ 32 ];

  at_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  ulong       hashmap_seed;

  struct {
    ulong parse_fail_cnt;
    ulong verify_fail_cnt;
    ulong dedup_fail_cnt;
    /* TODO: Implement based on TOS requirements - bundle_peer_fail_cnt */
    ulong bundle_peer_fail_cnt;
    /* TODO: Implement based on TOS requirements - gossiped_votes_cnt */
    ulong gossiped_votes_cnt;
  } metrics;
} at_verify_ctx_t;

/* at_txn_t and verification functions are now in at/transaction/at_txn.h */

/* Verify a transaction from raw UDP payload.
   This is the main entry point for the verify tile.

   Returns AT_TXN_VERIFY_SUCCESS (0) on valid transaction.
   The txn structure is filled in on success. */
static inline int
at_verify_tile_process( at_verify_ctx_t * ctx,
                        at_txn_t *        txn,
                        uchar const *     udp_payload,
                        ulong             payload_sz ) {
  (void)ctx;  /* TODO: Use ctx for metrics, tcache dedup */

  /* Parse and verify transaction */
  int rc = at_txn_verify( txn, udp_payload, payload_sz );
  if( AT_UNLIKELY( rc != AT_TXN_VERIFY_SUCCESS ) ) {
    /* TODO: Update ctx->metrics based on error type */
    return rc;
  }

  /* TODO: Deduplication check using tcache
     ulong hash64 = at_txn_hash64( txn );
     if( at_tcache_query( ctx->tcache, hash64 ) ) {
       ctx->metrics.dedup_fail_cnt++;
       return AT_TXN_VERIFY_DEDUP;
     }
     at_tcache_insert( ctx->tcache, hash64 );
  */

  return AT_TXN_VERIFY_SUCCESS;
}

#endif /* HEADER_at_src_disco_verify_at_verify_tile_h */