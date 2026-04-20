#ifndef HEADER_at_src_ballet_sha512_at_sha512_h
#define HEADER_at_src_ballet_sha512_at_sha512_h

/* at_sha512 provides APIs for SHA-512 hashing of messages. */

#include "at_crypto_base.h"

/* AT_SHA512_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a at_sha512_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define AT_SHA512_ALIGN     (128UL)
#define AT_SHA512_FOOTPRINT (256UL)

#define AT_SHA384_ALIGN     AT_SHA512_ALIGN
#define AT_SHA384_FOOTPRINT AT_SHA512_FOOTPRINT

/* AT_SHA512_{LG_HASH_SZ,HASH_SZ} describe the size of a SHA512 hash
   in bytes.  HASH_SZ==2^LG_HASH_SZ==64. */

#define AT_SHA512_LG_HASH_SZ (6)
#define AT_SHA512_HASH_SZ    (64UL) /* == 2^AT_SHA512_LG_HASH_SZ, explicit to workaround compiler limitations */

/* AT_SHA512_{LG_BLOCK_SZ,BLOCK_SZ} describe the size of a SHA512
   hash block in byte.  BLOCK_SZ==2^LG_BLOCK_SZ==128. */

#define AT_SHA512_LG_BLOCK_SZ (7)
#define AT_SHA512_BLOCK_SZ    (128UL) /* == 2^AT_SHA512_LG_BLOCK_SZ, explicit to workaround compiler limitations */

/* AT_SHA384_HASH_SZ describes the size of a SHA384 hash in bytes. */

#define AT_SHA384_HASH_SZ    (48UL)

/* AT_SHA384_{LG_BLOCK_SZ,BLOCK_SZ} are identical to their SHA512
   variants.  (SHA384 uses the same internal state as SHA512) */

#define AT_SHA384_LG_BLOCK_SZ AT_SHA512_LG_BLOCK_SZ
#define AT_SHA384_BLOCK_SZ    AT_SHA512_BLOCK_SZ

/* A at_sha512_t should be treated as an opaque handle of a sha512
   calculation state.  (It technically isn't here facilitate compile
   time declarations of at_sha512_t memory.) */

#define AT_SHA512_MAGIC (0xF17EDA2CE54A5120) /* FIREDANCE SHA512 V0 */

/* AT_SHA512_PRIVATE_{LG_BUF_MAX,BUF_MAX} describe the size of the
   internal buffer used by the sha512 computation object.  This is for
   internal use only.  BUF_MAX==2^LG_BUF_MAX==2*AT_SHA512_HASH_SZ==128. */

#define AT_SHA512_PRIVATE_LG_BUF_MAX (7)
#define AT_SHA512_PRIVATE_BUF_MAX    (128UL) /* == 2^AT_SHA512_PRIVATE_LG_BUF_MAX, explicit to workaround compiler limitations */

struct __attribute__((aligned(AT_SHA512_ALIGN))) at_sha512_private {

  /* This point is 128-byte aligned */

  uchar buf[ AT_SHA512_PRIVATE_BUF_MAX ]; /* Buffered message bytes (these have not been added to the hash yet),
                                             indexed [0,buf_used) */

  /* This point is 128-byte aligned */

  ulong state[ AT_SHA512_HASH_SZ / sizeof(ulong) ]; /* Current state of the hash */

  /* This point is 64-byte aligned */

  ulong magic;      /* ==AT_SHA512_MAGIC */
  ulong buf_used;   /* Number of buffered bytes, in [0,AT_SHA512_PRIVATE_BUF_MAX) */
  ulong bit_cnt_lo; /* How many bits have been appended total (lower 64-bit) */
  ulong bit_cnt_hi; /* "                                      (upper 64-bit) */

  /* Padding to 128-byte here */
};

typedef struct at_sha512_private at_sha512_t;

typedef struct at_sha512_private at_sha384_t;

AT_PROTOTYPES_BEGIN

/* at_sha512_{align,footprint} give the needed alignment and footprint
   of a memory region suitable to hold a sha512 calculation state.
   Declaration / aligned_alloc / at_alloca friendly (e.g. a memory
   region declared as "at_sha512_t _sha[1];", or created by
   "aligned_alloc(alignof(at_sha512_t),sizeof(at_sha512_t))" or created
   by "at_alloca(alignof(at_sha512_t),sizeof(at_sha512_t))" will all
   automatically have the needed alignment and footprint).
   at_sha512_{align,footprint} return the same value as
   AT_SHA512_{ALIGN,FOOTPRINT}.

   at_sha512_new formats memory region with suitable alignment and
   footprint suitable for holding a sha512 calculation state.  Assumes
   shmem points on the caller to the first byte of the memory region
   owned by the caller to use.  Returns shmem on success and NULL on
   failure (logs details).  The memory region will be owned by the state
   on successful return.  The caller is not joined on return.

   at_sha512_join joins the caller to a sha512 calculation state.
   Assumes shsha points to the first byte of the memory region holding
   the state.  Returns a local handle to the join on success (this is
   not necessarily a simple cast of the address) and NULL on failure
   (logs details).

   at_sha512_leave leaves the caller's current local join to a sha512
   calculation state.  Returns a pointer to the memory region holding
   the state on success (this is not necessarily a simple cast of the
   address) and NULL on failure (logs details).  The caller is not
   joined on successful return.

   at_sha512_delete unformats a memory region that holds a sha512
   calculation state.  Assumes shsha points on the caller to the first
   byte of the memory region holding the state and that nobody is
   joined.  Returns a pointer to the memory region on success and NULL
   on failure (logs details).  The caller has ownership of the memory
   region on successful return. */

AT_FN_CONST ulong
at_sha512_align( void );

AT_FN_CONST ulong
at_sha512_footprint( void );

#define at_sha384_align     at_sha512_align
#define at_sha384_footprint at_sha512_footprint

void *
at_sha512_new( void * shmem );

at_sha512_t *
at_sha512_join( void * shsha );

void *
at_sha512_leave( at_sha512_t * sha );

void *
at_sha512_delete( void * shsha );

#define at_sha384_new    at_sha512_new
#define at_sha384_join   at_sha512_join
#define at_sha384_leave  at_sha512_leave
#define at_sha384_delete at_sha512_delete

/* at_sha512_init starts a sha512 calculation.  sha is assumed to be a
   current local join to a sha512 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

at_sha512_t *
at_sha512_init( at_sha512_t * sha );

at_sha512_t *
at_sha384_init( at_sha512_t * sha );

/* at_sha512_append adds sz bytes locally pointed to by data an
   in-progress sha512 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a sha512 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a sha512
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   128 for all but the last append (it is also preferable if sz is less
   than 112 for the last append). */

at_sha512_t *
at_sha512_append( at_sha512_t * sha,
                  void const *  data,
                  ulong         sz );

#define at_sha384_append at_sha512_append

/* at_sha512_fini finishes a a sha512 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a sha512 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 64-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 64-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
at_sha512_fini( at_sha512_t * sha,
                void *        hash );

/* at_sha512_clear safely clears after a sha512 calculation.
   sha is assumed to be a current local join to a sha512 calculation
   state.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded. */

static inline void
at_sha512_clear( at_sha512_t * sha ) {
  at_sha512_init( sha );
  at_memset_explicit( sha->buf, 0, AT_SHA512_PRIVATE_BUF_MAX );
}

void *
at_sha384_fini( at_sha384_t * sha,
                void *        hash );

/* at_sha512_hash is a streamlined implementation of:

     at_sha512_t sha[1];
     return at_sha512_fini( at_sha512_append( at_sha512_init( sha ), data, sz ), hash )

   This can be faster for small messages because it can eliminate
   function call overheads, branches, copies and data marshalling under
   the hood (things like binary Merkle tree construction were designed
   do lots of such operations). */

void *
at_sha512_hash( void const * data,
                ulong        sz,
                void *       hash );

void *
at_sha384_hash( void const * data,
                ulong        sz,
                void *       hash );

AT_PROTOTYPES_END

/* See at_sha256.h for details on how use the batching API */

#ifndef AT_SHA512_BATCH_IMPL
#if AT_HAS_AVX512
#define AT_SHA512_BATCH_IMPL 2
#elif AT_HAS_AVX
#define AT_SHA512_BATCH_IMPL 1
#else
#define AT_SHA512_BATCH_IMPL 0
#endif
#endif

#if AT_SHA512_BATCH_IMPL==0 /* Reference batching implementation */

#define AT_SHA512_BATCH_ALIGN     (1UL)
#define AT_SHA512_BATCH_FOOTPRINT (1UL)
#define AT_SHA512_BATCH_MAX       (1UL)

typedef uchar at_sha512_batch_t;

AT_PROTOTYPES_BEGIN

AT_FN_CONST static inline ulong at_sha512_batch_align    ( void ) { return alignof(at_sha512_batch_t); }
AT_FN_CONST static inline ulong at_sha512_batch_footprint( void ) { return sizeof (at_sha512_batch_t); }

static inline at_sha512_batch_t * at_sha512_batch_init( void * mem ) { return (at_sha512_batch_t *)mem; }

static inline at_sha512_batch_t *
at_sha512_batch_add( at_sha512_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  at_sha512_hash( data, sz, hash );
  return batch;
}

static inline void * at_sha512_batch_fini ( at_sha512_batch_t * batch ) { return (void *)batch; }
static inline void * at_sha512_batch_abort( at_sha512_batch_t * batch ) { return (void *)batch; }

AT_PROTOTYPES_END

#elif AT_SHA512_BATCH_IMPL==1 /* AVX accelerated batching implementation */

#define AT_SHA512_BATCH_ALIGN     (128UL)
#define AT_SHA512_BATCH_FOOTPRINT (128UL)
#define AT_SHA512_BATCH_MAX       (4UL)

/* This is exposed here to facilitate inlining various operations */

struct __attribute__((aligned(AT_SHA512_BATCH_ALIGN))) at_sha512_private_batch {
  void const * data[ AT_SHA512_BATCH_MAX ]; /* AVX aligned */
  ulong        sz  [ AT_SHA512_BATCH_MAX ]; /* AVX aligned */
  void *       hash[ AT_SHA512_BATCH_MAX ]; /* AVX aligned */
  ulong        cnt;
};

typedef struct at_sha512_private_batch at_sha512_batch_t;

AT_PROTOTYPES_BEGIN

/* Internal use only */

void
at_sha512_private_batch_avx( ulong          batch_cnt,    /* In [1,AT_SHA512_BATCH_MAX] */
                             void const *   batch_data,   /* Indexed [0,AT_SHA512_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used, essentially a msg_t const * const * */
                             ulong const *  batch_sz,     /* Indexed [0,AT_SHA512_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used */
                             void * const * batch_hash ); /* Indexed [0,AT_SHA512_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used */

AT_FN_CONST static inline ulong at_sha512_batch_align    ( void ) { return alignof(at_sha512_batch_t); }
AT_FN_CONST static inline ulong at_sha512_batch_footprint( void ) { return sizeof (at_sha512_batch_t); }

static inline at_sha512_batch_t *
at_sha512_batch_init( void * mem ) {
  at_sha512_batch_t * batch = (at_sha512_batch_t *)mem;
  batch->cnt = 0UL;
  return batch;
}

static inline at_sha512_batch_t *
at_sha512_batch_add( at_sha512_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  ulong batch_cnt = batch->cnt;
  batch->data[ batch_cnt ] = data;
  batch->sz  [ batch_cnt ] = sz;
  batch->hash[ batch_cnt ] = hash;
  batch_cnt++;
  if( AT_UNLIKELY( batch_cnt==AT_SHA512_BATCH_MAX ) ) {
    at_sha512_private_batch_avx( batch_cnt, batch->data, batch->sz, batch->hash );
    batch_cnt = 0UL;
  }
  batch->cnt = batch_cnt;
  return batch;
}

static inline void *
at_sha512_batch_fini( at_sha512_batch_t * batch ) {
  ulong batch_cnt = batch->cnt;
  if( AT_LIKELY( batch_cnt ) ) at_sha512_private_batch_avx( batch_cnt, batch->data, batch->sz, batch->hash );
  return (void *)batch;
}

static inline void *
at_sha512_batch_abort( at_sha512_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#elif AT_SHA512_BATCH_IMPL==2 /* AVX-512 accelerated batching implementation */

#define AT_SHA512_BATCH_ALIGN     (128UL)
#define AT_SHA512_BATCH_FOOTPRINT (256UL)
#define AT_SHA512_BATCH_MAX       (8UL)

/* This is exposed here to facilitate inlining various operations */

struct __attribute__((aligned(AT_SHA512_BATCH_ALIGN))) at_sha512_private_batch {
  void const * data[ AT_SHA512_BATCH_MAX ]; /* AVX-512 aligned */
  ulong        sz  [ AT_SHA512_BATCH_MAX ]; /* AVX-512 aligned */
  void *       hash[ AT_SHA512_BATCH_MAX ]; /* AVX-512 aligned */
  ulong        cnt;
};

typedef struct at_sha512_private_batch at_sha512_batch_t;

AT_PROTOTYPES_BEGIN

/* Internal use only */

void
at_sha512_private_batch_avx512( ulong          batch_cnt,    /* In [1,AT_SHA512_BATCH_MAX] */
                                void const *   batch_data,   /* Indexed [0,AT_SHA512_BATCH_MAX), aligned 64,
                                                                only [0,batch_cnt) used, essentially a msg_t const * const * */
                                ulong const *  batch_sz,     /* Indexed [0,AT_SHA512_BATCH_MAX), aligned 64,
                                                                only [0,batch_cnt) used */
                                void * const * batch_hash ); /* Indexed [0,AT_SHA512_BATCH_MAX), aligned 64,
                                                                only [0,batch_cnt) used */

AT_FN_CONST static inline ulong at_sha512_batch_align    ( void ) { return alignof(at_sha512_batch_t); }
AT_FN_CONST static inline ulong at_sha512_batch_footprint( void ) { return sizeof (at_sha512_batch_t); }

static inline at_sha512_batch_t *
at_sha512_batch_init( void * mem ) {
  at_sha512_batch_t * batch = (at_sha512_batch_t *)mem;
  batch->cnt = 0UL;
  return batch;
}

static inline at_sha512_batch_t *
at_sha512_batch_add( at_sha512_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  ulong batch_cnt = batch->cnt;
  batch->data[ batch_cnt ] = data;
  batch->sz  [ batch_cnt ] = sz;
  batch->hash[ batch_cnt ] = hash;
  batch_cnt++;
  if( AT_UNLIKELY( batch_cnt==AT_SHA512_BATCH_MAX ) ) {
    at_sha512_private_batch_avx512( batch_cnt, batch->data, batch->sz, batch->hash );
    batch_cnt = 0UL;
  }
  batch->cnt = batch_cnt;
  return batch;
}

static inline void *
at_sha512_batch_fini( at_sha512_batch_t * batch ) {
  ulong batch_cnt = batch->cnt;
  if( AT_LIKELY( batch_cnt ) ) at_sha512_private_batch_avx512( batch_cnt, batch->data, batch->sz, batch->hash );
  return (void *)batch;
}

static inline void *
at_sha512_batch_abort( at_sha512_batch_t * batch ) {
  return (void *)batch;
}

AT_PROTOTYPES_END

#else
#error "Unsupported AT_SHA512_BATCH_IMPL"
#endif

#endif /* HEADER_at_src_ballet_sha512_at_sha512_h */