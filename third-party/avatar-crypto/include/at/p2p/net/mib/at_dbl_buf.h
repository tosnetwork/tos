#ifndef HEADER_at_src_p2p_net_mib_at_dbl_buf_h
#define HEADER_at_src_p2p_net_mib_at_dbl_buf_h

/* at_dbl_buf.h provides a concurrent lock-free double buffer.  A double
   buffer contains two buffers that take turns holding a message for
   consumers and receiving a new message by a producer.

   Supports a single producer thread and an arbitrary number of consumer
   threads.  Optimized for rare updates and frequent polling (e.g. config).
   Use an at_tango mcache/dcache pair if you need frequent updates.

   Currently assumes a memory model that preserves store order across
   threads (e.g. x86-TSO).  Does not use atomics or hardware fences. */

#include "at/infra/at_util_base.h"
#include "at/infra/bits/at_bits.h"
#include "at/infra/log/at_log.h"

#if AT_HAS_SSE
#include <emmintrin.h>
#endif

/* at_dbl_buf_t is the header of a dbl_buf object.  May not be locally
   declared. */

union __attribute__((aligned(16UL))) at_dbl_buf {

  struct {
    ulong magic; /* ==AT_DBL_BUF_MAGIC */
    ulong mtu;
    ulong buf0;  /* offset to first  buffer from beginning of struct */
    ulong buf1;  /*   — " —   second              — " —              */
    ulong seq;   /* latest msg seq no */
    ulong sz;    /* latest msg size */
    ulong pad[2];
    /* objects follow here */
  };

#if AT_HAS_SSE
  struct {
    __m128i magic_mtu;
    __m128i buf0_buf1;
    __m128i seq_sz;
    __m128i pad2;
  };
#endif
};

typedef union at_dbl_buf at_dbl_buf_t;

#define AT_DBL_BUF_MAGIC (0xa6c6f85d431c03ceUL) /* random */

#define AT_DBL_BUF_ALIGN (16UL)
#define AT_DBL_BUF_FOOTPRINT(mtu)                                         \
  AT_LAYOUT_FINI( AT_LAYOUT_APPEND( AT_LAYOUT_APPEND( AT_LAYOUT_INIT,     \
    AT_DBL_BUF_ALIGN, sizeof(at_dbl_buf_t) ),                             \
    AT_DBL_BUF_ALIGN, AT_ULONG_ALIGN_UP( (mtu), AT_DBL_BUF_ALIGN )<<1UL ),\
    AT_DBL_BUF_ALIGN )

AT_PROTOTYPES_BEGIN

/* at_dbl_buf_{align,footprint} describe the memory region of a double
   buffer.  mtu is the largest possible message size. */

ulong
at_dbl_buf_align( void );

ulong
at_dbl_buf_footprint( ulong mtu );

/* at_dbl_buf_new formats a memory region for use as a double buffer.
   shmem points to the memory region matching at_dbl_buf_{align,footprint}.
   Initially, the active object of the double buffer will have sequence
   number seq0 and zero byte size.  */

void *
at_dbl_buf_new( void * shmem,
                ulong  mtu,
                ulong  seq0 );

at_dbl_buf_t *
at_dbl_buf_join( void * shbuf );

void *
at_dbl_buf_leave( at_dbl_buf_t * buf );

/* at_dbl_buf_delete unformats the memory region backing a dbl_buf and
   releases ownership back to the caller.  Returns shbuf. */

void *
at_dbl_buf_delete( void * shbuf );

/* at_dbl_buf_obj_mtu returns the max message size a dbl_buf can store. */

static inline ulong
at_dbl_buf_obj_mtu( at_dbl_buf_t * buf ) {
  return buf->mtu;
}

/* at_dbl_buf_seq_query peeks the current sequence number. */

static inline ulong
at_dbl_buf_seq_query( at_dbl_buf_t * buf ) {
  AT_COMPILER_MFENCE();
  ulong seq = AT_VOLATILE_CONST( buf->seq );
  AT_COMPILER_MFENCE();
  return seq;
}

/* at_dbl_buf_slot returns a pointer to the buffer for the given sequence
   number. */

AT_FN_PURE static inline void *
at_dbl_buf_slot( at_dbl_buf_t * buf,
                 ulong          seq ) {
  return (seq&1UL) ? ((char *)buf)+buf->buf1 : ((char *)buf)+buf->buf0;
}

/* at_dbl_buf_insert appends a message to the double buffer.

   Note: It is NOT safe to call this function from multiple threads. */

void
at_dbl_buf_insert( at_dbl_buf_t * buf,
                   void const *   msg,
                   ulong          sz );

/* at_dbl_buf_try_read does a speculative read the most recent message
   (from the caller's POV).  The read may be overrun by a writer.  out
   points to a buffer of at_dbl_buf_obj_mtu(buf) bytes.  opt_seqp points to
   a ulong or NULL.

   On success:
   - returns the size of the message read
   - a copy of the message is stored at out
   - *opt_seqp is set to the msg sequence number (if non-NULL)

   On failure (due to overrun):
   - returns ULONG_MAX
   - out buffer is clobbered
   - *opt_seq is clobbered (if non-NULL) */

static inline ulong
at_dbl_buf_try_read( at_dbl_buf_t * buf,
                     void *         out,
                     ulong          out_sz,
                     ulong *        opt_seqp ) {
  ulong  seq = at_dbl_buf_seq_query( buf );
  void * src = at_dbl_buf_slot( buf, seq );
  ulong  sz  = AT_VOLATILE_CONST( buf->sz );
  if( out_sz<sz ) AT_LOG_ERR(( "at_dbl_buf_try_read failed: output buffer too small: out_sz: %lu, sz: %lu", out_sz, sz ));
  at_memcpy( out, src, sz );
  if( AT_UNLIKELY( seq!=at_dbl_buf_seq_query( buf ) ) ) return ULONG_MAX;
  at_ulong_store_if( !!opt_seqp, opt_seqp, seq );
  return sz;
}

/* at_dbl_buf_read does a blocking read. */

ulong
at_dbl_buf_read( at_dbl_buf_t * buf,
                 ulong          buf_sz,
                 void *         obj,
                 ulong *        opt_seqp );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_p2p_net_mib_at_dbl_buf_h */
