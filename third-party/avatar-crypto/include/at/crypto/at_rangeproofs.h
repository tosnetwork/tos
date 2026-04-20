#ifndef HEADER_at_ballet_at_rangeproofs_h
#define HEADER_at_ballet_at_rangeproofs_h

/* at_rangeproofs.h - Bulletproofs range proof verification

   Implements range proof verification for confidential transactions.
   Based on the Bulletproofs protocol for efficient range proofs.

   Reference: https://eprint.iacr.org/2017/1066.pdf */

#include "at_crypto_base.h"
#include "at_rangeproofs_transcript.h"

/* Rangeproofs tables are included from the .c file.
   The generators are decompressed at initialization time from compressed form.
   These declarations match the definitions in at_rangeproofs_table_bulletproofs.c */

#define AT_RANGEPROOFS_SUCCESS 0
#define AT_RANGEPROOFS_ERROR  -1

#define AT_RANGEPROOFS_MAX_COMMITMENTS 8

struct __attribute__((packed)) at_rangeproofs_ipp_vecs {
  uchar l[ 32 ]; /* point */
  uchar r[ 32 ]; /* point */
};
typedef struct at_rangeproofs_ipp_vecs at_rangeproofs_ipp_vecs_t;

struct __attribute__((packed)) at_rangeproofs_range_proof {
  uchar a          [ 32 ]; /* point */
  uchar s          [ 32 ]; /* point */
  uchar t1         [ 32 ]; /* point */
  uchar t2         [ 32 ]; /* point */
  uchar tx         [ 32 ]; /* scalar */
  uchar tx_blinding[ 32 ]; /* scalar */
  uchar e_blinding [ 32 ]; /* scalar */
};
typedef struct at_rangeproofs_range_proof at_rangeproofs_range_proof_t;

struct at_rangeproofs_ipp_proof {
  const uchar                       logn; /* log(bit_length): 6 for u64, 7 for u128, 8 for u256 */
  const at_rangeproofs_ipp_vecs_t * vecs; /* log(bit_length) points */
  const uchar *                     a;    /* scalar */
  const uchar *                     b;    /* scalar */
};
typedef struct at_rangeproofs_ipp_proof at_rangeproofs_ipp_proof_t;

AT_PROTOTYPES_BEGIN

int
at_rangeproofs_verify(
  at_rangeproofs_range_proof_t const * range_proof,
  at_rangeproofs_ipp_proof_t const *   ipp_proof,
  uchar const                          commitments [ 32 ],
  uchar const                          bit_lengths [ 1 ],
  uchar const                          batch_len,
  at_merlin_transcript_t *             transcript );

AT_PROTOTYPES_END
#endif /* HEADER_at_ballet_at_rangeproofs_h */