#ifndef HEADER_at_src_ballet_sha3_at_sha3_h
#define HEADER_at_src_ballet_sha3_at_sha3_h

/* at_sha3 provides APIs for SHA3-256 and SHA3-512 hashing of messages.
   - SHA3-256 is used for TOS transaction hashing
   - SHA3-512 is used for TOS signature hashing */

#include "at_crypto_base.h"

/**********************************************************************/
/* SHA3-256                                                            */
/**********************************************************************/

/* SHA3-256 parameters:
   - State size: 1600 bits = 200 bytes = 25 ulongs
   - Capacity: 2 * 256 = 512 bits = 64 bytes
   - Rate: 1600 - 512 = 1088 bits = 136 bytes
   - Output: 256 bits = 32 bytes */

#define AT_SHA3_256_ALIGN     (128UL)
#define AT_SHA3_256_FOOTPRINT (256UL)
#define AT_SHA3_256_HASH_SZ   (32UL)

#define AT_SHA3_256_MAGIC     (0xF17EDA2CE73A3256UL)
#define AT_SHA3_256_STATE_SZ  (25UL)
#define AT_SHA3_256_OUT_SZ    (32UL)
#define AT_SHA3_256_RATE      (136UL)  /* 1088 bits = 136 bytes */

struct __attribute__((aligned(AT_SHA3_256_ALIGN))) at_sha3_256_private {
  ulong state[ 25 ];
  ulong magic;
  ulong padding_start;
};

typedef struct at_sha3_256_private at_sha3_256_t;

/**********************************************************************/
/* SHA3-512                                                            */
/**********************************************************************/

/* AT_SHA3_512_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a at_sha3_512_t. */

#define AT_SHA3_512_ALIGN     (128UL)
#define AT_SHA3_512_FOOTPRINT (256UL)

/* AT_SHA3_512_HASH_SZ is the size of a SHA3-512 hash in bytes. */

#define AT_SHA3_512_HASH_SZ (64UL)

/* SHA3-512 parameters:
   - State size: 1600 bits = 200 bytes = 25 ulongs
   - Capacity: 2 * 512 = 1024 bits = 128 bytes
   - Rate: 1600 - 1024 = 576 bits = 72 bytes */

#define AT_SHA3_512_MAGIC    (0xF17EDA2CE73A3512UL) /* FIREDANCE SHA3512 */
#define AT_SHA3_512_STATE_SZ (25UL)
#define AT_SHA3_512_OUT_SZ   (64UL)
#define AT_SHA3_512_RATE     (72UL)  /* 576 bits = 72 bytes */

struct __attribute__((aligned(AT_SHA3_512_ALIGN))) at_sha3_512_private {
  ulong state[ 25 ];
  ulong magic;
  ulong padding_start;
};

typedef struct at_sha3_512_private at_sha3_512_t;

AT_PROTOTYPES_BEGIN

/**********************************************************************/
/* SHA3-256 API                                                        */
/**********************************************************************/

AT_FN_CONST ulong at_sha3_256_align( void );
AT_FN_CONST ulong at_sha3_256_footprint( void );

void *          at_sha3_256_new( void * shmem );
at_sha3_256_t * at_sha3_256_join( void * shsha );
void *          at_sha3_256_leave( at_sha3_256_t * sha );
void *          at_sha3_256_delete( void * shsha );

at_sha3_256_t * at_sha3_256_init( at_sha3_256_t * sha );
at_sha3_256_t * at_sha3_256_append( at_sha3_256_t * sha, void const * data, ulong sz );
void *          at_sha3_256_fini( at_sha3_256_t * sha, void * hash );
void *          at_sha3_256_hash( void const * data, ulong sz, void * hash );

/**********************************************************************/
/* SHA3-512 API                                                        */
/**********************************************************************/

/* at_sha3_512_{align,footprint} return alignment and footprint requirements */

AT_FN_CONST ulong
at_sha3_512_align( void );

AT_FN_CONST ulong
at_sha3_512_footprint( void );

/* at_sha3_512_{new,join,leave,delete} for shared memory lifecycle */

void *
at_sha3_512_new( void * shmem );

at_sha3_512_t *
at_sha3_512_join( void * shsha );

void *
at_sha3_512_leave( at_sha3_512_t * sha );

void *
at_sha3_512_delete( void * shsha );

/* at_sha3_512_init starts a SHA3-512 calculation.
   Returns sha with initialized state. */

at_sha3_512_t *
at_sha3_512_init( at_sha3_512_t * sha );

/* at_sha3_512_append adds sz bytes to an in-progress calculation.
   Returns sha with updated state. */

at_sha3_512_t *
at_sha3_512_append( at_sha3_512_t * sha,
                    void const *    data,
                    ulong           sz );

/* at_sha3_512_fini finishes a SHA3-512 calculation.
   Writes 64-byte hash result to hash buffer.
   Returns hash. */

void *
at_sha3_512_fini( at_sha3_512_t * sha,
                  void *          hash );

/* at_sha3_512_hash is a convenience one-shot hash function.
   Equivalent to init + append + fini. */

void *
at_sha3_512_hash( void const * data,
                  ulong        sz,
                  void *       hash );

AT_PROTOTYPES_END

/**********************************************************************/
/* SHA3-512 Batch API (SIMD accelerated)                               */
/**********************************************************************/

#if 0 /* SHA3-512 batch API details */

/* AT_SHA3_512_BATCH_{ALIGN,FOOTPRINT} return the alignment and footprint
   in bytes required for a region of memory to hold the state of an
   in-progress set of SHA3-512 calculations.  ALIGN will be an integer
   power of 2 and FOOTPRINT will be a multiple of ALIGN. */

#define AT_SHA3_512_BATCH_ALIGN     ...
#define AT_SHA3_512_BATCH_FOOTPRINT ...

/* AT_SHA3_512_BATCH_MAX returns the batch size used under the hood.
   Will be positive. */

#define AT_SHA3_512_BATCH_MAX       ...

/* A at_sha3_512_batch_t is an opaque handle for a set of SHA3-512
   calculations. */

struct at_sha3_512_private_batch;
typedef struct at_sha3_512_private_batch at_sha3_512_batch_t;

/* at_sha3_512_batch_{align,footprint} return
   AT_SHA3_512_BATCH_{ALIGN,FOOTPRINT} respectively. */

ulong at_sha3_512_batch_align    ( void );
ulong at_sha3_512_batch_footprint( void );

/* at_sha3_512_batch_init starts a new batch of SHA3-512 calculations.
   Returns a handle to the in-progress batch calculation. */

at_sha3_512_batch_t *
at_sha3_512_batch_init( void * mem );

/* at_sha3_512_batch_add adds a message to the batch.
   Result will be written to hash (64 bytes) after fini. */

at_sha3_512_batch_t *
at_sha3_512_batch_add( at_sha3_512_batch_t * batch,
                       void const *          data,
                       ulong                 sz,
                       void *                hash );

/* at_sha3_512_batch_fini finishes the batch, computing all hashes. */

void *
at_sha3_512_batch_fini( at_sha3_512_batch_t * batch );

/* at_sha3_512_batch_abort aborts an in-progress batch. */

void *
at_sha3_512_batch_abort( at_sha3_512_batch_t * batch );

#endif

/* Select batch implementation based on platform features */
#ifndef AT_SHA3_512_BATCH_IMPL
#if AT_HAS_AVX512
#define AT_SHA3_512_BATCH_IMPL 2  /* AVX-512: 8 parallel hashes */
#elif AT_HAS_AVX
#define AT_SHA3_512_BATCH_IMPL 1  /* AVX2: 4 parallel hashes */
#else
#define AT_SHA3_512_BATCH_IMPL 0  /* Reference: sequential */
#endif
#endif

#if AT_SHA3_512_BATCH_IMPL==0 /* Reference batching implementation */

#define AT_SHA3_512_BATCH_ALIGN     (1UL)
#define AT_SHA3_512_BATCH_FOOTPRINT (1UL)
#define AT_SHA3_512_BATCH_MAX       (1UL)

typedef uchar at_sha3_512_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha3_512_batch_align    ( void ) { return alignof(at_sha3_512_batch_t); }
AT_FN_CONST static inline ulong at_sha3_512_batch_footprint( void ) { return sizeof (at_sha3_512_batch_t); }

static inline at_sha3_512_batch_t * at_sha3_512_batch_init( void * mem ) { return (at_sha3_512_batch_t *)mem; }

static inline at_sha3_512_batch_t *
at_sha3_512_batch_add( at_sha3_512_batch_t * batch,
                       void const *          data,
                       ulong                 sz,
                       void *                hash ) {
  at_sha3_512_hash( data, sz, hash );
  return batch;
}

static inline void * at_sha3_512_batch_fini ( at_sha3_512_batch_t * batch ) { return (void *)batch; }
static inline void * at_sha3_512_batch_abort( at_sha3_512_batch_t * batch ) { return (void *)batch; }

AT_PROTOTYPES_END

#elif AT_SHA3_512_BATCH_IMPL==1 /* AVX2 batching: 4 parallel hashes */

#define AT_SHA3_512_BATCH_ALIGN     (128UL)
#define AT_SHA3_512_BATCH_FOOTPRINT (1024UL)
#define AT_SHA3_512_BATCH_MAX       (4UL)

struct at_sha3_512_private_batch {
  void const * data[4];
  ulong        sz[4];
  void *       hash[4];
  ulong        cnt;
};

typedef struct at_sha3_512_private_batch at_sha3_512_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha3_512_batch_align    ( void ) { return AT_SHA3_512_BATCH_ALIGN; }
AT_FN_CONST static inline ulong at_sha3_512_batch_footprint( void ) { return AT_SHA3_512_BATCH_FOOTPRINT; }

static inline at_sha3_512_batch_t *
at_sha3_512_batch_init( void * mem ) {
  at_sha3_512_batch_t * batch = (at_sha3_512_batch_t *)mem;
  batch->cnt = 0;
  return batch;
}

static inline at_sha3_512_batch_t *
at_sha3_512_batch_add( at_sha3_512_batch_t * batch,
                       void const *          data,
                       ulong                 sz,
                       void *                hash ) {
  ulong idx = batch->cnt;
  if( idx < AT_SHA3_512_BATCH_MAX ) {
    batch->data[idx] = data;
    batch->sz[idx]   = sz;
    batch->hash[idx] = hash;
    batch->cnt = idx + 1;
  }
  return batch;
}

/* Implementation in at_sha3_batch_avx2.c */
void * at_sha3_512_batch_fini_avx2( at_sha3_512_batch_t * batch );

static inline void *
at_sha3_512_batch_fini( at_sha3_512_batch_t * batch ) {
  return at_sha3_512_batch_fini_avx2( batch );
}

static inline void *
at_sha3_512_batch_abort( at_sha3_512_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#elif AT_SHA3_512_BATCH_IMPL==2 /* AVX-512 batching: 8 parallel hashes */

#define AT_SHA3_512_BATCH_ALIGN     (128UL)
#define AT_SHA3_512_BATCH_FOOTPRINT (2048UL)
#define AT_SHA3_512_BATCH_MAX       (8UL)

struct at_sha3_512_private_batch {
  void const * data[8];
  ulong        sz[8];
  void *       hash[8];
  ulong        cnt;
};

typedef struct at_sha3_512_private_batch at_sha3_512_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha3_512_batch_align    ( void ) { return AT_SHA3_512_BATCH_ALIGN; }
AT_FN_CONST static inline ulong at_sha3_512_batch_footprint( void ) { return AT_SHA3_512_BATCH_FOOTPRINT; }

static inline at_sha3_512_batch_t *
at_sha3_512_batch_init( void * mem ) {
  at_sha3_512_batch_t * batch = (at_sha3_512_batch_t *)mem;
  batch->cnt = 0;
  return batch;
}

static inline at_sha3_512_batch_t *
at_sha3_512_batch_add( at_sha3_512_batch_t * batch,
                       void const *          data,
                       ulong                 sz,
                       void *                hash ) {
  ulong idx = batch->cnt;
  if( idx < AT_SHA3_512_BATCH_MAX ) {
    batch->data[idx] = data;
    batch->sz[idx]   = sz;
    batch->hash[idx] = hash;
    batch->cnt = idx + 1;
  }
  return batch;
}

/* Implementation in at_sha3_batch_avx512.c */
void * at_sha3_512_batch_fini_avx512( at_sha3_512_batch_t * batch );

static inline void *
at_sha3_512_batch_fini( at_sha3_512_batch_t * batch ) {
  return at_sha3_512_batch_fini_avx512( batch );
}

static inline void *
at_sha3_512_batch_abort( at_sha3_512_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#endif /* AT_SHA3_512_BATCH_IMPL */

/**********************************************************************/
/* SHA3-256 Batch API (SIMD accelerated)                               */
/**********************************************************************/

/* Select batch implementation based on platform features */
#ifndef AT_SHA3_256_BATCH_IMPL
#if AT_HAS_AVX512
#define AT_SHA3_256_BATCH_IMPL 2  /* AVX-512: 8 parallel hashes */
#elif AT_HAS_AVX
#define AT_SHA3_256_BATCH_IMPL 1  /* AVX2: 4 parallel hashes */
#else
#define AT_SHA3_256_BATCH_IMPL 0  /* Reference: sequential */
#endif
#endif

#if AT_SHA3_256_BATCH_IMPL==0 /* Reference batching implementation */

#define AT_SHA3_256_BATCH_ALIGN     (1UL)
#define AT_SHA3_256_BATCH_FOOTPRINT (1UL)
#define AT_SHA3_256_BATCH_MAX       (1UL)

typedef uchar at_sha3_256_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha3_256_batch_align    ( void ) { return alignof(at_sha3_256_batch_t); }
AT_FN_CONST static inline ulong at_sha3_256_batch_footprint( void ) { return sizeof (at_sha3_256_batch_t); }

static inline at_sha3_256_batch_t * at_sha3_256_batch_init( void * mem ) { return (at_sha3_256_batch_t *)mem; }

static inline at_sha3_256_batch_t *
at_sha3_256_batch_add( at_sha3_256_batch_t * batch,
                       void const *          data,
                       ulong                 sz,
                       void *                hash ) {
  at_sha3_256_hash( data, sz, hash );
  return batch;
}

static inline void * at_sha3_256_batch_fini ( at_sha3_256_batch_t * batch ) { return (void *)batch; }
static inline void * at_sha3_256_batch_abort( at_sha3_256_batch_t * batch ) { return (void *)batch; }

AT_PROTOTYPES_END

#elif AT_SHA3_256_BATCH_IMPL==1 /* AVX2 batching: 4 parallel hashes */

#define AT_SHA3_256_BATCH_ALIGN     (128UL)
#define AT_SHA3_256_BATCH_FOOTPRINT (1024UL)
#define AT_SHA3_256_BATCH_MAX       (4UL)

struct at_sha3_256_private_batch {
  void const * data[4];
  ulong        sz[4];
  void *       hash[4];
  ulong        cnt;
};

typedef struct at_sha3_256_private_batch at_sha3_256_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha3_256_batch_align    ( void ) { return AT_SHA3_256_BATCH_ALIGN; }
AT_FN_CONST static inline ulong at_sha3_256_batch_footprint( void ) { return AT_SHA3_256_BATCH_FOOTPRINT; }

static inline at_sha3_256_batch_t *
at_sha3_256_batch_init( void * mem ) {
  at_sha3_256_batch_t * batch = (at_sha3_256_batch_t *)mem;
  batch->cnt = 0;
  return batch;
}

static inline at_sha3_256_batch_t *
at_sha3_256_batch_add( at_sha3_256_batch_t * batch,
                       void const *          data,
                       ulong                 sz,
                       void *                hash ) {
  ulong idx = batch->cnt;
  if( idx < AT_SHA3_256_BATCH_MAX ) {
    batch->data[idx] = data;
    batch->sz[idx]   = sz;
    batch->hash[idx] = hash;
    batch->cnt = idx + 1;
  }
  return batch;
}

/* Implementation in at_sha3_batch_avx2.c */
void * at_sha3_256_batch_fini_avx2( at_sha3_256_batch_t * batch );

static inline void *
at_sha3_256_batch_fini( at_sha3_256_batch_t * batch ) {
  return at_sha3_256_batch_fini_avx2( batch );
}

static inline void *
at_sha3_256_batch_abort( at_sha3_256_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#elif AT_SHA3_256_BATCH_IMPL==2 /* AVX-512 batching: 8 parallel hashes */

#define AT_SHA3_256_BATCH_ALIGN     (128UL)
#define AT_SHA3_256_BATCH_FOOTPRINT (2048UL)
#define AT_SHA3_256_BATCH_MAX       (8UL)

struct at_sha3_256_private_batch {
  void const * data[8];
  ulong        sz[8];
  void *       hash[8];
  ulong        cnt;
};

typedef struct at_sha3_256_private_batch at_sha3_256_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha3_256_batch_align    ( void ) { return AT_SHA3_256_BATCH_ALIGN; }
AT_FN_CONST static inline ulong at_sha3_256_batch_footprint( void ) { return AT_SHA3_256_BATCH_FOOTPRINT; }

static inline at_sha3_256_batch_t *
at_sha3_256_batch_init( void * mem ) {
  at_sha3_256_batch_t * batch = (at_sha3_256_batch_t *)mem;
  batch->cnt = 0;
  return batch;
}

static inline at_sha3_256_batch_t *
at_sha3_256_batch_add( at_sha3_256_batch_t * batch,
                       void const *          data,
                       ulong                 sz,
                       void *                hash ) {
  ulong idx = batch->cnt;
  if( idx < AT_SHA3_256_BATCH_MAX ) {
    batch->data[idx] = data;
    batch->sz[idx]   = sz;
    batch->hash[idx] = hash;
    batch->cnt = idx + 1;
  }
  return batch;
}

/* Implementation in at_sha3_batch_avx512.c */
void * at_sha3_256_batch_fini_avx512( at_sha3_256_batch_t * batch );

static inline void *
at_sha3_256_batch_fini( at_sha3_256_batch_t * batch ) {
  return at_sha3_256_batch_fini_avx512( batch );
}

static inline void *
at_sha3_256_batch_abort( at_sha3_256_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#endif /* AT_SHA3_256_BATCH_IMPL */

#endif /* HEADER_at_src_ballet_sha3_at_sha3_h */