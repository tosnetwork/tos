#ifndef HEADER_at_ballet_at_rangeproofs_transcript_h
#define HEADER_at_ballet_at_rangeproofs_transcript_h

/* at_rangeproofs_transcript.h - Transcript helpers for range proofs

   Reference: Bulletproofs paper and Merlin transcript specification. */

#include "at_crypto_base.h"
#include "at_merlin.h"
#include "at_ristretto255.h"

#define AT_TRANSCRIPT_SUCCESS 0
#define AT_TRANSCRIPT_ERROR  -1

#define AT_TRANSCRIPT_LITERAL AT_MERLIN_LITERAL

AT_PROTOTYPES_BEGIN

/* Domain separators:
   - range proof
   - inner product proof
 */

static inline void
at_rangeproofs_transcript_domsep_range_proof( at_merlin_transcript_t * transcript,
                                              ulong const              n,
                                              ulong const              m ) {
  /* Must match Rust bulletproofs crate exactly:
     - "rangeproof v1" (not "range-proof")
     - n and m separately (not nm) */
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL("dom-sep"), (uchar *)AT_MERLIN_LITERAL("rangeproof v1") );
  at_merlin_transcript_append_u64( transcript, AT_MERLIN_LITERAL("n"), n );
  at_merlin_transcript_append_u64( transcript, AT_MERLIN_LITERAL("m"), m );
}

static inline void
at_rangeproofs_transcript_domsep_inner_product( at_merlin_transcript_t * transcript,
                                                ulong const             n ) {
  /* Must match Rust bulletproofs crate exactly: "ipp v1" not "inner-product" */
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL("dom-sep"), (uchar *)AT_MERLIN_LITERAL("ipp v1") );
  at_merlin_transcript_append_u64( transcript, AT_MERLIN_LITERAL("n"), n );
}

/* Append message:
   - point
   - validate_and_append_point
   - scalar
 */

static inline void
at_rangeproofs_transcript_append_point( at_merlin_transcript_t * transcript,
                                        char const * const       label,
                                        uint const               label_len,
                                        uchar const              point[ 32 ] ) {
  at_merlin_transcript_append_message( transcript, label, label_len, point, 32 );
}

static inline int
at_rangeproofs_transcript_validate_and_append_point( at_merlin_transcript_t * transcript,
                                                     char const * const       label,
                                                     uint const               label_len,
                                                     uchar const              point[ 32 ] ) {
  if ( AT_UNLIKELY( at_memeq( point, at_ristretto255_compressed_zero, 32 ) ) ) {
    return AT_TRANSCRIPT_ERROR;
  }
  at_rangeproofs_transcript_append_point( transcript, label, label_len, point );
  return AT_TRANSCRIPT_SUCCESS;
}

static inline void
at_rangeproofs_transcript_append_scalar( at_merlin_transcript_t * transcript,
                                         char const * const       label,
                                         uint const               label_len,
                                         uchar const              scalar[ 32 ] ) {
  at_merlin_transcript_append_message( transcript, label, label_len, scalar, 32 );
}

/* Challenge:
   - scalar
*/

static inline uchar *
at_rangeproofs_transcript_challenge_scalar( uchar                    scalar[ 32 ],
                                            at_merlin_transcript_t * transcript,
                                            char const * const       label,
                                            uint const               label_len ) {
  uchar unreduced[ 64 ];
  at_merlin_transcript_challenge_bytes( transcript, label, label_len, unreduced, 64 );
  return at_curve25519_scalar_reduce(scalar, unreduced);
}

AT_PROTOTYPES_END
#endif /* HEADER_at_ballet_at_rangeproofs_transcript_h */