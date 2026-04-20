#ifndef HEADER_at_src_ballet_keccak256_at_keccak256_h
#define HEADER_at_src_ballet_keccak256_at_keccak256_h

/* at_keccak256 provides APIs for Keccak256 hashing of messages. */

#include "at_crypto_base.h"

/* AT_KECCAK256_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a at_keccak256_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define AT_KECCAK256_ALIGN     (128UL)
#define AT_KECCAK256_FOOTPRINT (256UL)

/* AT_KECCAK256_HASH_SZ describe the size of a KECCAK256 hash in bytes. */

#define AT_KECCAK256_HASH_SZ    (32UL) /* == 2^AT_KECCAK256_LG_HASH_SZ, explicit to workaround compiler limitations */

/* A at_keccak256_t should be treated as an opaque handle of a keccak256
   calculation state.  (It technically isn't here facilitate compile
   time declarations of at_keccak256_t memory.) */

#define AT_KECCAK256_MAGIC (0xF17EDA2CE7EC2560) /* FIREDANCE KEC256 V0 */

#define AT_KECCAK256_STATE_SZ (25UL)
#define AT_KECCAK256_OUT_SZ (32UL)
#define AT_KECCAK256_RATE ((sizeof(ulong)*AT_KECCAK256_STATE_SZ) - (2*AT_KECCAK256_OUT_SZ))

struct __attribute__((aligned(AT_KECCAK256_ALIGN))) at_keccak256_private {

  /* This point is 128-byte aligned */

  /* This point is 64-byte aligned */

  ulong state[ 25 ];

  /* This point is 32-byte aligned */

  ulong magic;    /* ==AT_KECCAK256_MAGIC */
  ulong padding_start; /* Number of buffered bytes, in [0,AT_KECCAK256_BUF_MAX) */

  /* Padding to 128-byte here */
};

typedef struct at_keccak256_private at_keccak256_t;

AT_PROTOTYPES_BEGIN

/* at_keccak256_{align,footprint,new,join,leave,delete} usage is identical to
   that of at_sha256.  See ../sha256/at_sha256.h */

AT_FN_CONST ulong
at_keccak256_align( void );

AT_FN_CONST ulong
at_keccak256_footprint( void );

void *
at_keccak256_new( void * shmem );

at_keccak256_t *
at_keccak256_join( void * shsha );

void *
at_keccak256_leave( at_keccak256_t * sha );

void *
at_keccak256_delete( void * shsha );

/* at_keccak256_init starts a keccak256 calculation.  sha is assumed to be a
   current local join to a keccak256 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

at_keccak256_t *
at_keccak256_init( at_keccak256_t * sha );

/* at_keccak256_append adds sz bytes locally pointed to by data an
   in-progress keccak256 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a keccak256 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a keccak256
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   64. */

at_keccak256_t *
at_keccak256_append( at_keccak256_t * sha,
                     void const *     data,
                     ulong            sz );

/* at_keccak256_fini finishes a a keccak256 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a keccak256 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 32-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
at_keccak256_fini( at_keccak256_t * sha,
                   void *           hash );

/* at_keccak256_hash is a convenience implementation of:

     at_keccak256_t keccak[1];
     return at_keccak256_fini( at_keccak256_append( at_keccak256_init( keccak ), data, sz ), hash )

  It may eventually be streamlined. */

void *
at_keccak256_hash( void const * data,
                   ulong        sz,
                   void *       hash );

AT_PROTOTYPES_END

/**********************************************************************/
/* Keccak256 Batch API (SIMD accelerated)                              */
/**********************************************************************/

/* Select batch implementation based on platform features */
#ifndef AT_KECCAK256_BATCH_IMPL
#if AT_HAS_AVX512
#define AT_KECCAK256_BATCH_IMPL 2  /* AVX-512: 8 parallel hashes */
#elif AT_HAS_AVX
#define AT_KECCAK256_BATCH_IMPL 1  /* AVX2: 4 parallel hashes */
#else
#define AT_KECCAK256_BATCH_IMPL 0  /* Reference: sequential */
#endif
#endif

#if AT_KECCAK256_BATCH_IMPL==0 /* Reference batching implementation */

#define AT_KECCAK256_BATCH_ALIGN     (1UL)
#define AT_KECCAK256_BATCH_FOOTPRINT (1UL)
#define AT_KECCAK256_BATCH_MAX       (1UL)

typedef uchar at_keccak256_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_keccak256_batch_align    ( void ) { return alignof(at_keccak256_batch_t); }
AT_FN_CONST static inline ulong at_keccak256_batch_footprint( void ) { return sizeof (at_keccak256_batch_t); }

static inline at_keccak256_batch_t * at_keccak256_batch_init( void * mem ) { return (at_keccak256_batch_t *)mem; }

static inline at_keccak256_batch_t *
at_keccak256_batch_add( at_keccak256_batch_t * batch,
                        void const *           data,
                        ulong                  sz,
                        void *                 hash ) {
  at_keccak256_hash( data, sz, hash );
  return batch;
}

static inline void * at_keccak256_batch_fini ( at_keccak256_batch_t * batch ) { return (void *)batch; }
static inline void * at_keccak256_batch_abort( at_keccak256_batch_t * batch ) { return (void *)batch; }

AT_PROTOTYPES_END

#elif AT_KECCAK256_BATCH_IMPL==1 /* AVX2 batching: 4 parallel hashes */

#define AT_KECCAK256_BATCH_ALIGN     (128UL)
#define AT_KECCAK256_BATCH_FOOTPRINT (1024UL)
#define AT_KECCAK256_BATCH_MAX       (4UL)

struct at_keccak256_private_batch {
  void const * data[4];
  ulong        sz[4];
  void *       hash[4];
  ulong        cnt;
};

typedef struct at_keccak256_private_batch at_keccak256_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_keccak256_batch_align    ( void ) { return AT_KECCAK256_BATCH_ALIGN; }
AT_FN_CONST static inline ulong at_keccak256_batch_footprint( void ) { return AT_KECCAK256_BATCH_FOOTPRINT; }

static inline at_keccak256_batch_t *
at_keccak256_batch_init( void * mem ) {
  at_keccak256_batch_t * batch = (at_keccak256_batch_t *)mem;
  batch->cnt = 0;
  return batch;
}

static inline at_keccak256_batch_t *
at_keccak256_batch_add( at_keccak256_batch_t * batch,
                        void const *           data,
                        ulong                  sz,
                        void *                 hash ) {
  ulong idx = batch->cnt;
  if( idx < AT_KECCAK256_BATCH_MAX ) {
    batch->data[idx] = data;
    batch->sz[idx]   = sz;
    batch->hash[idx] = hash;
    batch->cnt = idx + 1;
  }
  return batch;
}

/* Implementation in at_keccak256_batch_avx2.c */
void * at_keccak256_batch_fini_avx2( at_keccak256_batch_t * batch );

static inline void *
at_keccak256_batch_fini( at_keccak256_batch_t * batch ) {
  return at_keccak256_batch_fini_avx2( batch );
}

static inline void *
at_keccak256_batch_abort( at_keccak256_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#elif AT_KECCAK256_BATCH_IMPL==2 /* AVX-512 batching: 8 parallel hashes */

#define AT_KECCAK256_BATCH_ALIGN     (128UL)
#define AT_KECCAK256_BATCH_FOOTPRINT (2048UL)
#define AT_KECCAK256_BATCH_MAX       (8UL)

struct at_keccak256_private_batch {
  void const * data[8];
  ulong        sz[8];
  void *       hash[8];
  ulong        cnt;
};

typedef struct at_keccak256_private_batch at_keccak256_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_keccak256_batch_align    ( void ) { return AT_KECCAK256_BATCH_ALIGN; }
AT_FN_CONST static inline ulong at_keccak256_batch_footprint( void ) { return AT_KECCAK256_BATCH_FOOTPRINT; }

static inline at_keccak256_batch_t *
at_keccak256_batch_init( void * mem ) {
  at_keccak256_batch_t * batch = (at_keccak256_batch_t *)mem;
  batch->cnt = 0;
  return batch;
}

static inline at_keccak256_batch_t *
at_keccak256_batch_add( at_keccak256_batch_t * batch,
                        void const *           data,
                        ulong                  sz,
                        void *                 hash ) {
  ulong idx = batch->cnt;
  if( idx < AT_KECCAK256_BATCH_MAX ) {
    batch->data[idx] = data;
    batch->sz[idx]   = sz;
    batch->hash[idx] = hash;
    batch->cnt = idx + 1;
  }
  return batch;
}

/* Implementation in at_keccak256_batch_avx512.c */
void * at_keccak256_batch_fini_avx512( at_keccak256_batch_t * batch );

static inline void *
at_keccak256_batch_fini( at_keccak256_batch_t * batch ) {
  return at_keccak256_batch_fini_avx512( batch );
}

static inline void *
at_keccak256_batch_abort( at_keccak256_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#endif /* AT_KECCAK256_BATCH_IMPL */

#endif /* HEADER_at_src_ballet_keccak256_at_keccak256_h */