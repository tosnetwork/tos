#ifndef HEADER_at_src_util_spad_at_spad_h
#define HEADER_at_src_util_spad_at_spad_h

/* APIs for high performance persistent inter-process shared scratch pad
   memories.  A spad as a scratch pad that behaves very much like a
   thread's stack:

   - Spad allocations are very fast O(1) assembly.

   - Spad allocations are grouped into a frames.

   - Frames are nested.

   - Pushing and popping frames are also very fast O(1) assembly.

   - All allocations in a frame are automatically freed when the frame
     is popped.

   Unlike a thread's stack, the most recent allocation can be trimmed,
   the most recent sequence of allocations be undone, operations on a
   spad can by done more than one thread, threads can operate on
   multiple spads and, if the spad is backed by a shared memory region
   (e.g. wksp), spad allocations can be shared with different processes.
   Also, it flexibly supports tight integration with real-time
   streaming, custom allocation alignments, programmatic usage queries,
   validation, and a large dynamic range of allocation sizes and
   alignments.  Further, the API can be changed at compile time to
   implementations with extra instrumentation for debugging and/or
   sanitization. */

#include "../bits/at_bits.h"

/* AT_SPAD_{ALIGN,FOOTPRINT} give the alignment and footprint of a
   at_spad_t.  ALIGN is an integer power of 2.  FOOTPRINT is a multiple
   of ALIGN.  mem_max is assumed to be at most 2^63 such that the result
   is guaranteed to never overflow a ulong.  These are provided to
   facilitate compile time declarations a at_spad_t.  128 is natural
   alignment for x86 adjacent cache line prefetching and PCI-e device
   interfacing like NICs and GPUs (e.g warp size).  Other possible
   useful alignments here include 256 (recent x86 DRAM memory fetch),
   512 (direct IO) and 4096 (x86 normal pages size).

   AT_SPAD_LG_ALIGN is log2 AT_SPAD_ALIGN.  Note: AT_SPAD_ALIGN is
   declared explicitly to workaround legacy compiler issues. */

#define AT_SPAD_LG_ALIGN (7)

#define AT_SPAD_ALIGN (128)

#define AT_SPAD_FOOTPRINT(mem_max)                                    \
  AT_LAYOUT_FINI( AT_LAYOUT_APPEND( AT_LAYOUT_APPEND( AT_LAYOUT_INIT, \
    AT_SPAD_ALIGN, sizeof(at_spad_t) ), /* metadata */                \
    AT_SPAD_ALIGN, (mem_max)         ), /* memory region */           \
    AT_SPAD_ALIGN )

/* A at_spad_t * is an opaque handle of a scratch pad memory */

struct at_spad_private;
typedef struct at_spad_private at_spad_t;

/* AT_SPAD_FRAME_MAX gives the maximum number of frames in a spad. */

#define AT_SPAD_FRAME_MAX (128UL)

/* AT_SPAD_ALLOC_ALIGN_DEFAULT gives the default alignment for spad
   allocations.  Must be an integer power of 2 in [1,AT_SPAD_ALIGN].  16
   is uint128 and SSE natural alignment.  Other possible useful
   alignments here include 8 (minimum on a 64-bit target malloc/free
   conformanc), 32 (AVX2) and 64 (cache line and AVX-512). */

#define AT_SPAD_ALLOC_ALIGN_DEFAULT (16UL)

/* Asserts that the default spad alignment is greater than or equal to
   the asan and msan alignment when DEEPASAN / MSAN is enabled. */
#ifdef AT_HAS_DEEPASAN
AT_STATIC_ASSERT( AT_SPAD_ALLOC_ALIGN_DEFAULT >= AT_ASAN_ALIGN,
                  "default spad alignment must be greater than or equal to asan alignment" );
#endif

#ifdef AT_HAS_MSAN
AT_STATIC_ASSERT( AT_SPAD_ALLOC_ALIGN_DEFAULT >= AT_MSAN_ALIGN,
                  "default spad alignment must be greater than or equal to msan alignment" );
#endif

/* Internal use only *************************************************/

/* Note: Details are exposed here to facilitate inlining of spad
   operations as they are typically used in performance critical
   contexts. */

#define AT_SPAD_MAGIC (0xf17eda2ce759ad00UL) /* Reference SPAD version 0 */

/* spad internals */

struct __attribute__((aligned(AT_SPAD_ALIGN))) at_spad_private {

  /* This point is AT_SPAD_ALIGN aligned */

  ulong magic; /* ==AT_SPAD_MAGIC */

  /* off[i] for i in [0,AT_SPAD_FRAME_MAX) gives the byte offset into
     the spad memory where allocations start for frame
     AT_SPAD_FRAME_MAX-1-i.  That is, off array usage grows toward 0
     such that off[i] for i in [0,frame_free) are not in use and
     [frame_free,AT_SPAD_FRAME_MAX) descripe the locations of current
     frames.  Typical bugs (e.g. pushing too many frames) here naturally
     clobber AT_SPAD_MAGIC (invalidating the spad) and then will clobber
     any guard region before the spad (invalidating the region) but will
     not clobber metadata or spad allocations themselves. */

  ulong off[ AT_SPAD_FRAME_MAX ];

  ulong frame_free; /* number of frames free, in [0,AT_SPAD_FRAME_MAX] */
  ulong mem_max;    /* byte size of the spad memory region */
  ulong mem_used;   /* number of spad memory bytes used, in [0,mem_max] */

#if AT_SPAD_TRACK_USAGE
  ulong mem_wmark;
#endif

  /* Padding to AT_SPAD_ALIGN here */

  /* "uchar mem[ mem_max ];" spad memory here.  Grows toward +inf such
     that bytes [0,mem_used) are currently allocated and bytes
     [mem_used,mem_max) are free.  As such, typical bugs (e.g. writing
     past the end of an allocation) naturally clobber any guard region
     after the structure (invalidate the region) but will not clobber
     the above metadata.  We are don't use a flexible array here due to
     lack of C++ support (sigh). */

  /* Padding to AT_SPAD_ALIGN here */

};

AT_PROTOTYPES_BEGIN

/* at_spad_private_mem returns a pointer in the caller's local address
   space to the first byte of the spad's memory region.  Assumes spad is
   a current local join.  Lifetime of the returned pointer is the
   lifetime of the join. */

AT_FN_CONST static inline uchar *
at_spad_private_mem( at_spad_t * spad ) {
  return (uchar *)(spad+1UL);
}

AT_PROTOTYPES_END

/* End internal use only *********************************************/

AT_PROTOTYPES_BEGIN

/* constructors */

/* at_spad_reset pops all frames in use.  Assumes spad is a current
   local join.  On return, spad is not in a frame.  Fast O(1).  This
   declared here to avoid forward use by at_spad_new.  */

static inline void
at_spad_reset( at_spad_t * spad );

/* at_spad_mem_max_max returns the largest mem_max possible for a spad
   that will fit into footprint bytes.  On success, returns the largest
   mem_max such that:

     at_spad_footprint( mem_max ) == at_ulong_align_dn( footprint, AT_SPAD_ALIGN )

   On failure, returns 0.  Reasons for failure include the footprint is
   too small, the resulting mem_max is too large or the actual mem_max
   that can be support is actually 0 (which is arguably not an error).
   This is provided for users that want to specify a spad in terms of
   its footprint rather than mem_max.  FIXME: consider compile time
   variant? */

AT_FN_CONST static inline ulong
at_spad_mem_max_max( ulong footprint ) {
  ulong mem_max = at_ulong_max( at_ulong_align_dn( footprint, AT_SPAD_ALIGN ), sizeof(at_spad_t) ) - sizeof(at_spad_t);
  return at_ulong_if( mem_max<=(1UL<<63), mem_max, 0UL );
}

/* at_spad_{align,footprint} give the required alignment and footprint
   for a spad that can support up mem_max bytes total of allocations.
   at_spad_align returns AT_SPAD_ALIGN.  at_spad_footprint returns
   non-zero on success and 0 on failure (silent).  Reasons for failure
   include mem_max is too large. */

AT_FN_CONST static inline ulong
at_spad_align( void ) {
  return AT_SPAD_ALIGN;
}

AT_FN_CONST static inline ulong
at_spad_footprint( ulong mem_max ) {
  return at_ulong_if( mem_max<=(1UL<<63), AT_SPAD_FOOTPRINT( mem_max ), 0UL );
}

/* at_spad_new formats an unused memory region with the appropriate
   footprint and alignment into a spad.  shmem points in the caller's
   address space to the first byte of the region.  Returns shmem on
   success (silent) and NULL on failure.  Reasons for failure include
   NULL spad, misaligned spad and too large mem_max.  The caller is
   _not_ joined on return. */

static inline void *
at_spad_new( void * shmem,
             ulong  mem_max ) {
  at_spad_t * spad = (at_spad_t *)shmem;

  if( AT_UNLIKELY( !spad                                              ) ) return NULL;
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)spad, AT_SPAD_ALIGN ) ) ) return NULL;
  if( AT_UNLIKELY( !at_spad_footprint( mem_max )                      ) ) return NULL;

  spad->mem_max = mem_max;

  at_spad_reset( spad );

#if AT_SPAD_TRACK_USAGE
  spad->mem_wmark = 0UL;
#endif

  AT_COMPILER_MFENCE();
  AT_VOLATILE( spad->magic ) = AT_SPAD_MAGIC;
  AT_COMPILER_MFENCE();

  return spad;
}

/* at_spad_join joins a spad.  shspad points in the caller's address
   space to the first byte of the region containing the spad.  Returns a
   local handle of the join on success (this is not necessarily a simple
   cast of shspad) or NULL on failure (silent).  Reasons for failure
   include NULL spad, misaligned spad and shspad obviously does not
   contain an spad.  There is no practical limitation on the number of
   concurrent joins in a thread, process or system wide.*/

AT_FN_PURE static inline at_spad_t *
at_spad_join( void * shspad ) {
  at_spad_t * spad = (at_spad_t *)shspad;

  if( AT_UNLIKELY( !spad                                              ) ) return NULL;
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)spad, AT_SPAD_ALIGN ) ) ) return NULL;
  if( AT_UNLIKELY( spad->magic!=AT_SPAD_MAGIC                         ) ) return NULL;

  return spad;
}

/* at_spad_leave leaves a spad join.  Returns a pointer in the caller's
   address space to the first byte of the region containing the spad on
   success (this is not necessarily a simple cast of spad) and NULL on
   failure (silent).  On success, the join is no longer current but the
   spad will continue to exist.  Implicitly cancels any in-progress
   prepare. */

AT_FN_CONST static inline void *
at_spad_leave( at_spad_t * spad ) {
  return (void *)spad;
}

/* at_spad_delete unformats a memory region used as a spad.  shspad
   points in the caller's address space to the first byte of the region
   containing the spad.  Returns the shspad on success and NULL on
   failure (silent).  Reasons for failure include NULL shspad,
   misaligned shspad and shspad obviously does not contain an spad.
   Assumes there is nobody joined to the spad when it is deleted. */

static inline void *
at_spad_delete( void * shspad );

/* accessors */

/* at_spad_frame_{max,used,free} return the {max,used,free} number of
   spad frames (used+free==max and max is always AT_SPAD_FRAME_MAX).
   Assumes spad is a current local join. */

AT_FN_CONST static inline ulong at_spad_frame_max ( at_spad_t const * spad ) { (void)spad; return AT_SPAD_FRAME_MAX;        }
AT_FN_PURE  static inline ulong at_spad_frame_used( at_spad_t const * spad ) { return AT_SPAD_FRAME_MAX - spad->frame_free; }
AT_FN_PURE  static inline ulong at_spad_frame_free( at_spad_t const * spad ) { return spad->frame_free;                     }

/* at_spad_mem_{max,used,free} return the {max,used,free} number of
   bytes spad memory (used+free==max).  Assumes spad is a current local
   join. */

AT_FN_PURE static inline ulong at_spad_mem_max ( at_spad_t const * spad ) { return spad->mem_max;                  }
AT_FN_PURE static inline ulong at_spad_mem_used( at_spad_t const * spad ) { return spad->mem_used;                 }
AT_FN_PURE static inline ulong at_spad_mem_free( at_spad_t const * spad ) { return spad->mem_max - spad->mem_used; }

#if AT_SPAD_TRACK_USAGE
AT_FN_PURE static inline ulong at_spad_mem_wmark( at_spad_t const * spad ) { return spad->mem_wmark; }
#endif

/* at_spad_in_frame returns 1 if the spad is in a frame and 0 otherwise.
   Assumes spad is a current local join. */

AT_FN_PURE static inline int at_spad_in_frame( at_spad_t const * spad ) { return spad->frame_free<AT_SPAD_FRAME_MAX; }

/* operations */
/* at_spad_alloc_max returns the maximum number of bytes with initial
   byte alignment of align that can currently be allocated / prepared
   (not including any in-progress prepare).  Assumes spad is a current
   local join and in a frame and align is an integer power of 2 in
   [1,AT_SPAD_ALIGN] or 0 (indicates to use
   AT_SPAD_ALLOC_ALIGN_DEFAULT). */

AT_FN_PURE static inline ulong
at_spad_alloc_max( at_spad_t const * spad,
                   ulong             align );

/* at_spad_frame_{lo,hi} returns the range of spad memory covered by the
   current frame (not including any in-progress prepare).  That is,
   [lo,hi) is the range of bytes in the caller's address space for the
   current frame.  Assumes spad is a current local join and in a frame.
   FIXME: consider const correct versions? */

AT_FN_PURE static inline void *
at_spad_frame_lo( at_spad_t * spad );

AT_FN_PURE static inline void *
at_spad_frame_hi( at_spad_t * spad );

/* operations */

/* at_spad_push creates a new spad frame and makes it the current frame.
   Assumes spad is a current local join with at least one frame free.
   Implicitly cancels any in-progress prepare.  On return, spad will be
   in a frame and not in a prepare.  Fast O(1). */

static inline void
at_spad_push( at_spad_t * spad );

/* at_spad_pop destroys the current spad frame (which bulk frees all
   allocations made in that frame and cancels any in progress prepare)
   and (if applicable) makes the previous frame current.  Assumes spad
   is a current local join (in a frame).  On return, spad will not be in
   a prepare and, if there was a previous frame, spad will be in a frame
   and not otherwise.  Fast O(1). */

static inline void
at_spad_pop( at_spad_t * spad );

/* The construct:

     AT_SPAD_FRAME_BEGIN( spad )
       ... code block ...
     AT_SPAD_FRAME_END

   is exactly equivalent linguistically to:

     do
       ... code block ...
     while(0)

   but at_spad_{push,pop} is automatically called when the code block is
   {entered,exited}.  This includes exiting via break or (ickily)
   return.  Assumes spad has at least one frame free when the code block
   is entered.  Fast O(1). */

static inline void
at_spad_private_frame_end( at_spad_t ** _spad ) { /* declared here to avoid a at_spad_pop forward reference */
  at_spad_pop( *_spad );
}

#define AT_SPAD_FRAME_BEGIN(spad) {                                               \
  at_spad_t * _spad __attribute__((cleanup(at_spad_private_frame_end))) = (spad); \
  at_spad_push( _spad );                                                          \
  {

#define AT_SPAD_FRAME_END }}

/* at_spad_alloc allocates sz bytes with alignment align from spad.
   Returns a pointer in the caller's address space to the first byte of
   the allocation (will be non-NULL with alignment align).  Assumes spad
   is a current local join and in a frame, align is an integer power of
   2 in [1,AT_SPAD_ALIGN] or 0 (indicates to use
   AT_SPAD_ALLOC_ALIGN_DEFAULT) and sz is in [0,alloc_max].  Implicitly
   cancels any in progress prepare.  On return, spad will be in a frame
   and not in a prepare.  Fast O(1).

   The lifetime of the returned region will be until the next pop or
   delete and of the returned pointer until pop, delete or leave.  The
   allocated region will be in the region backing the spad (e.g. if the
   spad is backed by wksp memory, the returned value will be a laddr
   that can be shared with threads in other processes using that wksp). */

static inline void *
at_spad_alloc( at_spad_t * spad,
               ulong       align,
               ulong       sz );

/* at_spad_trim trims trims frame_hi to end at hi where hi is given the
   caller's local address space.  Assumes spad is a current local join
   in a frame and hi is in [frame_lo,frame_hi] (FIXME: consider
   supporting allowing trim to expand the frame to mem_hi?).  Implicitly
   cancels any in-progress prepare.  On return, spad will be in a frame
   with frame_hi==hi.  Fast O(1).

   This is mostly useful for reducing the size of the most recent
   at_spad_alloc.  E.g. call at_spad_alloc with an upper bound to the
   final size, populate the region by bumping the returned pointer and
   calling trim at the end to return whatever remains of the original
   allocation to the spad.  Alternatively could use
   prepare/publish/cancel semantics below.

   Further note that the most recent sequence allocations in a frame can
   be _completely_ undone (including alignment padding) by saving
   frame_hi before the first alloc and then calling trim after the last
   (and most recent) alloc with the saved value. */

static inline void
at_spad_trim( at_spad_t * spad,
              void *      hi );

/* at_spad_prepare starts preparing a spad allocation with alignment
   align that can be up to max bytes in size.  Returns a pointer in the
   caller's address space to the initial byte of the allocation (will be
   non-NULL with alignment align).  Assumes spad is a current local join
   in a frame, align is an integer power of 2 in [1,AT_SPAD_ALIGN] or 0
   (indicates to use AT_SPAD_ALLOC_ALIGN_DEFAULT) and max is in
   [0,alloc_max].  Implicitly cancels any in-progress prepare.  On
   return, spad will be in a frame and in a prepare.  Fast O(1).

   While in a prepare, the lifetime of the returned region and returned
   pointer to it will be until prepare, cancel, alloc, trim, push, pop,
   leave or delete.  The region will be in the region backing the spad
   (e.g. if the spad is backed by a wksp, the returned value will be a
   laddr for its lifetime that can be shared with threads in other
   processes using that wksp).

   On publication, the returned value will behave _exactly_ as if:

     at_spad_alloc( spad, align, sz )

   was called here instead of prepare.  This is mostly useful for
   optimizing allocations whose final size isn't known up front (e.g.
   buffering of real time streaming data).  Alternatively, could use
   alloc/trim semantics above.  FIXME: consider removing the
   prepare/publish/cancel APIs as it simplifies this by eliminating the
   concept of an in-progress prepare and it doesn't provide much benefit
   over alloc/trim. */

static inline void *
at_spad_prepare( at_spad_t * spad,
                 ulong       align,
                 ulong       max );

/* at_spad_cancel cancels the most recent prepare.  Assumes spad is a
   current local join and in a prepare.  On return, spad will be in a
   frame and not in a prepare.  Fast O(1).

   IMPORTANT SAFETY TIP!  This is currently equivalent to
   at_spad_publish( spad, 0 ).  As such, any alignment padding done in
   prepare will still be allocated on return.

   FIXME: consider undoing prepare's align_up too?  This requires extra
   state.  And, if a common alignment is being used, as is often the
   case (e.g. AT_SPAD_ALLOC_ALIGN_DEFAULT), as is typically the case,
   the amount of alignment padding will be typically 0.  And is usually
   negligible in other cases.  And prepare/cancel/publish are not often
   used anyway.  On top of that, it is already possible to undo the
   align_up in a supported way via the frame_hi / trim mechanism
   described above.  So this probably isn't worthwhile. */

static inline void
at_spad_cancel( at_spad_t * spad );

/* at_spad_publish finishes the allocation started in the most recent
   prepare.  Assumes spad is a current local join and in a prepare and
   sz is in [0,prepare's max].  On return, spad will be in a frame and
   not in a prepare.  Fast O(1).  See publish for more details. */

static inline void
at_spad_publish( at_spad_t * spad,
                 ulong       sz );

/* at_spad_verify returns a negative integer error code if the spad is
   obiviously corrupt if not (logs details) and 0 otherwise.  Reasons
   for failure include spad is not a current local join and frame
   metadata is corrupt (bad frames_used, bad mem_max, bad mem_used,
   frames don't nest).  This can only be used if logging services are
   available. */

int
at_spad_verify( at_spad_t const * spad );

/* The debugging variants below do additional checking and will
   AT_LOG_CRIT (dumping core) if their input requirements are not
   satisfied (they all still assume spad is a current local join).  They
   can only be used if logging services are available. */

void   at_spad_reset_debug    ( at_spad_t       * spad                          );
void * at_spad_delete_debug   ( void            * shspad                        );
ulong  at_spad_alloc_max_debug( at_spad_t const * spad, ulong  align            );
void * at_spad_frame_lo_debug ( at_spad_t       * spad                          );
void * at_spad_frame_hi_debug ( at_spad_t       * spad                          );
void   at_spad_push_debug     ( at_spad_t       * spad                          );
void   at_spad_pop_debug      ( at_spad_t       * spad                          );
void * at_spad_alloc_check    ( at_spad_t       * spad, ulong  align, ulong sz  );
#define at_spad_alloc_debug at_spad_alloc_check
void   at_spad_trim_debug     ( at_spad_t       * spad, void * hi               );
void * at_spad_prepare_debug  ( at_spad_t       * spad, ulong  align, ulong max );
void   at_spad_cancel_debug   ( at_spad_t       * spad                          );
void   at_spad_publish_debug  ( at_spad_t       * spad, ulong  sz               );

/* The sanitizer variants below have additional logic to control memory
   poisoning in ASAN/DEEPASAN and MSAN builds. */

void   at_spad_reset_sanitizer_impl    ( at_spad_t       * spad                          );
void * at_spad_delete_sanitizer_impl   ( void            * shspad                        );
ulong  at_spad_alloc_max_sanitizer_impl( at_spad_t const * spad, ulong  align            );
void * at_spad_frame_lo_sanitizer_impl ( at_spad_t       * spad                          );
void * at_spad_frame_hi_sanitizer_impl ( at_spad_t       * spad                          );
void   at_spad_push_sanitizer_impl     ( at_spad_t       * spad                          );
void   at_spad_pop_sanitizer_impl      ( at_spad_t       * spad                          );
void * at_spad_alloc_sanitizer_impl    ( at_spad_t       * spad, ulong  align, ulong sz  );
void   at_spad_trim_sanitizer_impl     ( at_spad_t       * spad, void * hi               );
void * at_spad_prepare_sanitizer_impl  ( at_spad_t       * spad, ulong  align, ulong max );
void   at_spad_cancel_sanitizer_impl   ( at_spad_t       * spad                          );
void   at_spad_publish_sanitizer_impl  ( at_spad_t       * spad, ulong  sz               );

/* fn implementations */
static inline void
at_spad_reset_impl( at_spad_t * spad ) {
  spad->frame_free = AT_SPAD_FRAME_MAX;
  spad->mem_used   = 0UL;
}

static inline void *
at_spad_delete_impl( void * shspad ) {
  at_spad_t * spad = (at_spad_t *)shspad;

  if( AT_UNLIKELY( !spad                                              ) ) return NULL;
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)spad, AT_SPAD_ALIGN ) ) ) return NULL;
  if( AT_UNLIKELY( spad->magic!=AT_SPAD_MAGIC                         ) ) return NULL;

  AT_COMPILER_MFENCE();
  AT_VOLATILE( spad->magic ) = 0UL;
  AT_COMPILER_MFENCE();

  return spad;
}

AT_FN_PURE static inline ulong
at_spad_alloc_max_impl( at_spad_t const * spad,
                        ulong             align ) {
  align = at_ulong_if( align>0UL, align, AT_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
  ulong off = at_ulong_align_up( spad->mem_used, align );
  return at_ulong_max( spad->mem_max, off ) - off;
}

AT_FN_PURE static inline void *
at_spad_frame_lo_impl( at_spad_t * spad ) {
  return at_spad_private_mem( spad ) + spad->off[ spad->frame_free ];
}

AT_FN_PURE static inline void *
at_spad_frame_hi_impl( at_spad_t * spad ) {
  return at_spad_private_mem( spad ) + spad->mem_used;
}

static inline void
at_spad_push_impl( at_spad_t * spad ) {
  spad->off[ --spad->frame_free ] = spad->mem_used;
}

static inline void
at_spad_pop_impl( at_spad_t * spad ) {
  spad->mem_used = spad->off[ spad->frame_free++ ];
}

static inline void *
at_spad_alloc_impl( at_spad_t * spad,
                    ulong       align,
                    ulong       sz ) {
  align = at_ulong_if( align>0UL, align, AT_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
  ulong   off = at_ulong_align_up( spad->mem_used, align );
  uchar * buf = at_spad_private_mem( spad ) + off;
  spad->mem_used = off + sz;
#if AT_SPAD_TRACK_USAGE
  if( AT_UNLIKELY( spad->mem_wmark < spad->mem_used ) ) {
    spad->mem_wmark = spad->mem_used;
  }
#endif

  return buf;
}

static inline void
at_spad_trim_impl( at_spad_t * spad,
              void *      hi ) {
  spad->mem_used = (ulong)hi - (ulong)at_spad_private_mem( spad );
}

static inline void *
at_spad_prepare_impl( at_spad_t * spad,
                      ulong       align,
                      ulong       max ) {
  (void)max;
  align = at_ulong_if( align>0UL, align, AT_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
  ulong   off = at_ulong_align_up( spad->mem_used, align );
  uchar * buf = at_spad_private_mem( spad ) + off;
  spad->mem_used = off;
  return buf;
}

static inline void
at_spad_cancel_impl( at_spad_t * spad ) {
  (void)spad;
}

static inline void
at_spad_publish_impl( at_spad_t * spad,
                      ulong       sz ) {
  spad->mem_used += sz;
}

/* fn definitions */
#if defined(AT_SPAD_USE_HANDHOLDING)
#define SELECT_IMPL(fn) fn##_debug
#elif (AT_HAS_DEEPASAN || AT_HAS_MSAN)
#define SELECT_IMPL(fn) fn##_sanitizer_impl
#else
#define SELECT_IMPL(fn) fn##_impl
#endif

void
at_spad_reset( at_spad_t * spad ) {
  SELECT_IMPL(at_spad_reset)(spad);
}

static inline void *
at_spad_delete( void * shspad ) {
  return SELECT_IMPL(at_spad_delete)(shspad);
}

AT_FN_PURE ulong
at_spad_alloc_max( at_spad_t const * spad,
                   ulong             align ) {
  return SELECT_IMPL(at_spad_alloc_max)(spad, align);
}

AT_FN_PURE void *
at_spad_frame_lo( at_spad_t * spad ) {
  return SELECT_IMPL(at_spad_frame_lo)(spad);
}

AT_FN_PURE void *
at_spad_frame_hi( at_spad_t * spad ) {
  return SELECT_IMPL(at_spad_frame_hi)(spad);
}

void
at_spad_push( at_spad_t * spad ) {
  SELECT_IMPL(at_spad_push)(spad);
}

void
at_spad_pop(at_spad_t *spad) {
  SELECT_IMPL(at_spad_pop)(spad);
}

void *
at_spad_alloc( at_spad_t * spad,
               ulong       align,
               ulong       sz ) {
  return SELECT_IMPL(at_spad_alloc)(spad, align, sz);
}

void
at_spad_trim( at_spad_t * spad,
              void *      hi ) {
  SELECT_IMPL(at_spad_trim)(spad, hi);
}

void *
at_spad_prepare( at_spad_t * spad,
                 ulong       align,
                 ulong       max ) {
  return SELECT_IMPL(at_spad_prepare)(spad, align, max);
}

void
at_spad_cancel(at_spad_t *spad) {
  SELECT_IMPL(at_spad_cancel)(spad);
}

void
at_spad_publish( at_spad_t * spad,
                 ulong       sz ) {
  SELECT_IMPL(at_spad_publish)(spad, sz);
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_spad_at_spad_h */