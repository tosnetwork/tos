#ifndef HEADER_at_src_ballet_sha256_at_sha256_h
#define HEADER_at_src_ballet_sha256_at_sha256_h

/* at_sha256 provides APIs for SHA-256 hashing of messages. */

#include "at_crypto_base.h"

/* AT_SHA256_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a at_sha256_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define AT_SHA256_ALIGN     (128UL)
#define AT_SHA256_FOOTPRINT (128UL)

/* AT_SHA256_{LG_HASH_SZ,HASH_SZ} describe the size of a SHA256 hash
   in bytes.  HASH_SZ==2^LG_HASH_SZ==32. */

#define AT_SHA256_LG_HASH_SZ (5)
#define AT_SHA256_HASH_SZ    (32UL) /* == 2^AT_SHA256_LG_HASH_SZ, explicit to workaround compiler limitations */

/* AT_SHA256_{LG_BLOCK_SZ,BLOCK_SZ} describe the size of a SHA256
   hash block in byte.  BLOCK_SZ==2^LG_BLOCK_SZ==64. */

#define AT_SHA256_LG_BLOCK_SZ (6)
#define AT_SHA256_BLOCK_SZ    (64UL) /* == 2^AT_SHA256_LG_BLOCK_SZ, explicit to workaround compiler limitations */

/* A at_sha256_t should be treated as an opaque handle of a sha256
   calculation state.  (It technically isn't here facilitate compile
   time declarations of at_sha256_t memory.) */

#define AT_SHA256_MAGIC (0xF17EDA2CE54A2560) /* FIREDANCE SHA256 V0 */

/* AT_SHA256_PRIVATE_{LG_BUF_MAX,BUF_MAX} describe the size of the
   internal buffer used by the sha256 computation object.  This is for
   internal use only.  BUF_MAX==2^LG_BUF_MAX==2*AT_SHA256_HASH_SZ==64. */

#define AT_SHA256_PRIVATE_LG_BUF_MAX AT_SHA256_LG_BLOCK_SZ
#define AT_SHA256_PRIVATE_BUF_MAX    AT_SHA256_BLOCK_SZ

struct __attribute__((aligned(AT_SHA256_ALIGN))) at_sha256_private {

  /* This point is 128-byte aligned */

  uchar buf[ AT_SHA256_PRIVATE_BUF_MAX ];

  /* This point is 64-byte aligned */

  uint  state[ AT_SHA256_HASH_SZ / sizeof(uint) ];

  /* This point is 32-byte aligned */

  ulong magic;    /* ==AT_SHA256_MAGIC */
  ulong buf_used; /* Number of buffered bytes, in [0,AT_SHA256_BUF_MAX) */
  ulong bit_cnt;  /* How many bits have been appended total */

  /* Padding to 128-byte here */
};

typedef struct at_sha256_private at_sha256_t;

AT_PROTOTYPES_BEGIN

/* at_sha256_{align,footprint,new,join,leave,delete} usage is identical to
   that of their at_sha512 counterparts.  See ../sha512/at_sha512.h */

AT_FN_CONST ulong
at_sha256_align( void );

AT_FN_CONST ulong
at_sha256_footprint( void );

void *
at_sha256_new( void * shmem );

at_sha256_t *
at_sha256_join( void * shsha );

void *
at_sha256_leave( at_sha256_t * sha );

void *
at_sha256_delete( void * shsha );

/* at_sha256_init starts a sha256 calculation.  sha is assumed to be a
   current local join to a sha256 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

at_sha256_t *
at_sha256_init( at_sha256_t * sha );

/* at_sha256_append adds sz bytes locally pointed to by data an
   in-progress sha256 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a sha256 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a sha256
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   64 for all but the last append (it is also preferable if sz is less
   than 56 for the last append). */

at_sha256_t *
at_sha256_append( at_sha256_t * sha,
                  void const *  data,
                  ulong         sz );

/* at_sha256_fini finishes a sha256 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a sha256 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 32-byte
   buffer pointed to by hash will be populated with the calculation
   result). */
/* FIXME: THIS SHOULD PROBABLY RETURN A AT_SHA256_T */

void *
at_sha256_fini( at_sha256_t * sha,
                void *        hash );

/* at_sha256_hash is a streamlined implementation of:

     at_sha256_t sha[1];
     return at_sha256_fini( at_sha256_append( at_sha256_init( sha ), data, sz ), hash )

   This can be faster for small messages because it can eliminate
   function call overheads, branches, copies and data marshalling under
   the hood (things like binary Merkle tree construction were designed
   do lots of such operations). */
/* FIXME: ADD NEW/JOIN/LEAVE/DELETE TO DOCUMENTATION */
/* FIXME: PROBABLY SHOULD HAVE AN ABORT API */
/* FIXME: UPDATE OTHER HASH FUNCTIONS SIMILARLY */

void *
at_sha256_hash( void const * data,
                ulong        sz,
                void *       hash );

/* at_sha256_hash_32_repeated hashes the 32 bytes pointed to by data,
   then hashes the hash, and repeats, doing a total of cnt hashes.  It
   is a streamlined version of:

   uchar temp[32];
   at_memcpy( temp, data, 32UL );
   for( ulong i=0UL; i<cnt; i++ ) at_sha256_hash( temp, 32UL, temp );
   at_memcpy( hash, temp, 32UL );
   return hash;

   This eliminates function call overhead and data marshalling.  cnt==0
   is okay, in which case this just copies data to hash.  Always returns
   hash.  data and hash must be valid, non-NULL pointers, even when
   cnt==0. */
void *
at_sha256_hash_32_repeated( void const * data,
                            void *       hash,
                            ulong        cnt );

AT_PROTOTYPES_END

#if 0 /* SHA256 batch API details */

/* AT_SHA256_BATCH_{ALIGN,FOOTPRINT} return the alignment and footprint
   in bytes required for a region of memory to can hold the state of an
   in-progress set of SHA-256 calculations.  ALIGN will be an integer
   power of 2 and FOOTPRINT will be a multiple of ALIGN.  These are to
   facilitate compile time declarations. */

#define AT_SHA256_BATCH_ALIGN     ...
#define AT_SHA256_BATCH_FOOTPRINT ...

/* AT_SHA256_BATCH_MAX returns the batch size used under the hood.
   Will be positive.  Users should not normally need use this for
   anything. */

#define AT_SHA256_BATCH_MAX       ...

/* A at_sha256_batch_t is an opaque handle for a set of SHA-256
   calculations. */

struct at_sha256_private_batch;
typedef struct at_sha256_private_batch at_sha256_batch_t;

/* at_sha256_batch_{align,footprint} return
   AT_SHA256_BATCH_{ALIGN,FOOTPRINT} respectively. */

ulong at_sha256_batch_align    ( void );
ulong at_sha256_batch_footprint( void );

/* at_sha256_batch_init starts a new batch of SHA-256 calculations.  The
   state of the in-progress calculation will be held in the memory
   region whose first byte in the local address space is pointed to by
   mem.  The region should have the appropriate alignment and footprint
   and should not be read, changed or deleted until fini or abort is
   called on the in-progress calculation.

   Returns a handle to the in-progress batch calculation.  As this is
   used in HPC contexts, does no input validation. */

at_sha256_batch_t *
at_sha256_batch_init( void * mem );

/* at_sha256_batch_add adds the sz byte message whose first byte in the
   local address space is pointed to by data to the in-progress batch
   calculation whose handle is batch.  The result of the calculation
   will be stored at the 32-byte memory region whose first byte in the
   local address space is pointed to by hash.

   There are _no_ alignment restrictions on data and hash and _no_
   restrictions on sz.  After a message is added, that message should
   not be changed or deleted until the fini or abort is called on the
   in-progress calculation.  Likewise, the hash memory region shot not
   be read, written or deleted until the calculation has completed.

   Messages can overlap and/or be added to a batch multiple times.  Each
   hash location added to a batch should not overlap any other hash
   location of calculation state or message region.  (Hash reuse /
   overlap have indeterminant but non-crashing behavior as the
   implementation under the hood is free to execute the elements of the
   batch in whatever order it sees fit and potentially do those
   calculations incrementally / in the background / ... as the batch is
   assembled.)

   Depending on the implementation, it might help performance to cluster
   adds of similar sized messages together.  Likewise, it can be
   advantageous to use aligned message regions, aligned hash regions and
   messages sizes that are a multiple of a SHA block size.  None of this
   is required though.

   Returns batch (which will still be an in progress batch calculation).
   As this is used in HPC contexts, does no input validation. */

at_sha256_batch_t *
at_sha256_batch_add( at_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash );

/* at_sha256_batch_fini finishes a set of SHA-256 calculations.  On
   return, all the hash memory regions will be populated with the
   corresponding message hash.  Returns a pointer to the memory region
   used to hold the calculation state (contents undefined) and the
   calculation will no longer be in progress.  As this is used in HPC
   contexts, does no input validation. */

void *
at_sha256_batch_fini( at_sha256_batch_t * batch );

/* at_sha256_batch_abort aborts an in-progress set of SHA-256
   calculations.  There is no guarantee which individual messages (if
   any) had their hashes computed and the contents of the hash memory
   regions is undefined.  Returns a pointer to the memory region used to
   hold the calculation state (contents undefined) and the calculation
   will no longer be in progress.  As this is used in HPC contexts, does
   no input validation. */

void *
at_sha256_batch_abort( at_sha256_batch_t * batch );

#endif

#ifndef AT_SHA256_BATCH_IMPL
#if AT_HAS_AVX512
#define AT_SHA256_BATCH_IMPL 2
#elif AT_HAS_AVX && !defined(__tune_znver1__) && !defined(__tune_znver2__) && !defined(__tune_znver3__)
#define AT_SHA256_BATCH_IMPL 1
#else
#define AT_SHA256_BATCH_IMPL 0
#endif
#endif

#if AT_SHA256_BATCH_IMPL==0 /* Reference batching implementation */

#define AT_SHA256_BATCH_ALIGN     (1UL)
#define AT_SHA256_BATCH_FOOTPRINT (1UL)
#define AT_SHA256_BATCH_MAX       (1UL)

typedef uchar at_sha256_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha256_batch_align    ( void ) { return alignof(at_sha256_batch_t); }
AT_FN_CONST static inline ulong at_sha256_batch_footprint( void ) { return sizeof (at_sha256_batch_t); }

static inline at_sha256_batch_t * at_sha256_batch_init( void * mem ) { return (at_sha256_batch_t *)mem; }

static inline at_sha256_batch_t *
at_sha256_batch_add( at_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  at_sha256_hash( data, sz, hash );
  return batch;
}

static inline void * at_sha256_batch_fini ( at_sha256_batch_t * batch ) { return (void *)batch; }
static inline void * at_sha256_batch_abort( at_sha256_batch_t * batch ) { return (void *)batch; }

AT_PROTOTYPES_END

#elif AT_SHA256_BATCH_IMPL==1 /* AVX accelerated batching implementation */

#define AT_SHA256_BATCH_ALIGN     (128UL)
#define AT_SHA256_BATCH_FOOTPRINT (256UL)
#define AT_SHA256_BATCH_MAX       (8UL)

/* This is exposed here to facilitate inlining various operations */

struct __attribute__((aligned(AT_SHA256_BATCH_ALIGN))) at_sha256_private_batch {
  void const * data[ AT_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        sz  [ AT_SHA256_BATCH_MAX ]; /* AVX aligned */
  void *       hash[ AT_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        cnt;
};

typedef struct at_sha256_private_batch at_sha256_batch_t;

AT_PROTOTYPES_BEGIN

/* Internal use only */

void
at_sha256_private_batch_avx( ulong          batch_cnt,    /* In [1,AT_SHA256_BATCH_MAX] */
                             void const *   batch_data,   /* Indexed [0,AT_SHA256_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used, essentially a msg_t const * const * */
                             ulong const *  batch_sz,     /* Indexed [0,AT_SHA256_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used */
                             void * const * batch_hash ); /* Indexed [0,AT_SHA256_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used */

AT_FN_CONST static inline ulong at_sha256_batch_align    ( void ) { return alignof(at_sha256_batch_t); }
AT_FN_CONST static inline ulong at_sha256_batch_footprint( void ) { return sizeof (at_sha256_batch_t); }

static inline at_sha256_batch_t *
at_sha256_batch_init( void * mem ) {
  at_sha256_batch_t * batch = (at_sha256_batch_t *)mem;
  batch->cnt = 0UL;
  return batch;
}

static inline at_sha256_batch_t *
at_sha256_batch_add( at_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  ulong batch_cnt = batch->cnt;
  batch->data[ batch_cnt ] = data;
  batch->sz  [ batch_cnt ] = sz;
  batch->hash[ batch_cnt ] = hash;
  batch_cnt++;
  if( AT_UNLIKELY( batch_cnt==AT_SHA256_BATCH_MAX ) ) {
    at_sha256_private_batch_avx( batch_cnt, batch->data, batch->sz, batch->hash );
    batch_cnt = 0UL;
  }
  batch->cnt = batch_cnt;
  return batch;
}

static inline void *
at_sha256_batch_fini( at_sha256_batch_t * batch ) {
  ulong batch_cnt = batch->cnt;
  if( AT_LIKELY( batch_cnt ) ) at_sha256_private_batch_avx( batch_cnt, batch->data, batch->sz, batch->hash );
  return (void *)batch;
}

static inline void *
at_sha256_batch_abort( at_sha256_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#elif AT_SHA256_BATCH_IMPL==2 /* AVX-512 accelerated batching implementation */

#define AT_SHA256_BATCH_ALIGN     (128UL)
#define AT_SHA256_BATCH_FOOTPRINT (512UL)
#define AT_SHA256_BATCH_MAX       (16UL)

/* This is exposed here to facilitate inlining various operations */

struct __attribute__((aligned(AT_SHA256_BATCH_ALIGN))) at_sha256_private_batch {
  void const * data[ AT_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        sz  [ AT_SHA256_BATCH_MAX ]; /* AVX aligned */
  void *       hash[ AT_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        cnt;
};

typedef struct at_sha256_private_batch at_sha256_batch_t;

AT_PROTOTYPES_BEGIN

/* Internal use only */

void
at_sha256_private_batch_avx512( ulong          batch_cnt,    /* In [1,AT_SHA256_BATCH_MAX] */
                                void const *   batch_data,   /* Indexed [0,AT_SHA256_BATCH_MAX), aligned 32,
                                                                only [0,batch_cnt) used, essentially a msg_t const * const * */
                                ulong const *  batch_sz,     /* Indexed [0,AT_SHA256_BATCH_MAX), aligned 32,
                                                                only [0,batch_cnt) used */
                                void * const * batch_hash ); /* Indexed [0,AT_SHA256_BATCH_MAX), aligned 32,
                                                                only [0,batch_cnt) used */

AT_FN_CONST static inline ulong at_sha256_batch_align    ( void ) { return alignof(at_sha256_batch_t); }
AT_FN_CONST static inline ulong at_sha256_batch_footprint( void ) { return sizeof (at_sha256_batch_t); }

static inline at_sha256_batch_t *
at_sha256_batch_init( void * mem ) {
  at_sha256_batch_t * batch = (at_sha256_batch_t *)mem;
  batch->cnt = 0UL;
  return batch;
}

static inline at_sha256_batch_t *
at_sha256_batch_add( at_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  ulong batch_cnt = batch->cnt;
  batch->data[ batch_cnt ] = data;
  batch->sz  [ batch_cnt ] = sz;
  batch->hash[ batch_cnt ] = hash;
  batch_cnt++;
  if( AT_UNLIKELY( batch_cnt==AT_SHA256_BATCH_MAX ) ) {
    at_sha256_private_batch_avx512( batch_cnt, batch->data, batch->sz, batch->hash );
    batch_cnt = 0UL;
  }
  batch->cnt = batch_cnt;
  return batch;
}

static inline void *
at_sha256_batch_fini( at_sha256_batch_t * batch ) {
  ulong batch_cnt = batch->cnt;
  if( AT_LIKELY( batch_cnt ) ) at_sha256_private_batch_avx512( batch_cnt, batch->data, batch->sz, batch->hash );
  return (void *)batch;
}

static inline void *
at_sha256_batch_abort( at_sha256_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#else
#error "Unsupported AT_SHA256_BATCH_IMPL"
#endif

#endif /* HEADER_at_src_ballet_sha256_at_sha256_h */