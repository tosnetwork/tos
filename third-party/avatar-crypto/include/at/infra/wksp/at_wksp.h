#ifndef HEADER_at_src_util_wksp_at_wksp_h
#define HEADER_at_src_util_wksp_at_wksp_h

#include "../tpool/at_tpool.h"
#include "../checkpt/at_checkpt.h"

/* API for creating NUMA-aware and TLB-efficient workspaces used for
   complex inter-thread and inter-process shared memory communication
   patterns.  fd must be booted to use the APIs in this module.

   For example, startup scripts could reserve some memory on each NUMA
   node backed by huge and gigantic pages:

     sudo bin/at_shmem_cfg alloc   8 gigantic 0 \
                           alloc   8 gigantic 1 \
                           alloc 256     huge 0 \
                           alloc 256     huge 1

   and then some of this memory could be formatted into at_wksp for each
   NUMA node:

     bin/at_shmem_ctl new my-wksp-numa-0 1 gigantic 0 \
                      new my-wksp-numa-1 1 gigantic 1

   Then, at application startup, processes can join these at_wksp and
   concurrently allocate memory from the desired NUMA nodes as
   necessary.  E.g.

     at_wksp_t * wksp = at_wksp_attach( "my-wksp-numa-0" ); // logs details on failure
     if( !at_wksp ) ... handle attach failure ...;

     ulong gaddr = at_wksp_alloc( wksp, align, sz ); // logs details on failure
     if( !gaddr ) ... handle alloc failure ...;

   The local address of a workspace global address can be found via:

     void * laddr = at_wksp_laddr( wksp, gaddr ); // logs details on failure
     if( !laddr ) ... handle bad (wksp,gaddr) ...;

   and the global address of a workspace local address can be found via:

     ulong gaddr = at_wksp_gaddr( wksp, laddr ); // logs details on failure
     if( !gaddr ) ... handle bad (wksp,laddr) ...;

   Allocations can be freed via:

     at_wksp_free( wksp, gaddr );

   Any join can free any allocation regardless of who made it.

   When the application is done using a wksp, it should leave it.  The
   workspace will continue to exist (it just is no longer safe to access
   in the caller's address space).  E.g.

     at_wksp_detach( wksp ); // logs details on failure

   Likewise, if the workspaces are no longer in use, they can be deleted
   via something like:

     bin/at_wksp_ctl delete my-wksp-numa-0 \
                     delete my-wksp-numa-1

   All allocations can be freed via something like:

     bin/at_wksp_ctl reset my-wksp-numa-0 \
                     reset my-wksp-numa-1

   or in code:

     at_wksp_reset( wksp, seed ); // logs details on failure

   It is the caller's responsibility to ensure that previous allocations
   to the wksp are not in use.

   Note: while this presents "aligned_alloc" style API semantics, this
   is not designed to be algorithmically optimal, HPC implementation or
   efficient at doing lots of tiny allocations.  Rather it is designed
   to be akin to an "mmap" / "sbrk" style allocator of last resort, done
   rarely and then ideally at application startup (e.g. setting up
   datastructures at box startup or used in an interprocess lockfree
   allocator as a mmap replacement).

   Instead, this tries to keep wksp fragmentation low with low overhead
   and tight packing of larger size allocations (normal page size and
   up).  It further tries to proactively limit the risk of heap
   _metadata_ corruption (proactive intraworkspace heap application
   _data_ corruption prevention is not a goal though typical mechanisms
   for such are in _direct_ opposition to efficient use of TLB, low
   fragmentation and tight allocation packing).  It is quasi-lockfree
   such that a process _killed_ in the middle of a workspace operation
   will not prevent other processes from using the workspace but a
   process _stalled_ in the middle of a workspace operations can stall
   other applications waiting to use the workspace indefinitely.
   Operators can track down an errant process stalled in the middle of
   workspace operations and blocking other processes).  Likewise
   detailed usage and metadata integrity checking and repair can be done
   via something like at_wksp_ctl check / verify / rebuild / etc.
   Practically speaking, none of this really matters if usage occurs
   predominantly during application startup / shutdown.

   See below for more details. */

/* AT_WKSP_SUCCESS is used by various APIs to indicate an operation
   successfully completed.  This will be 0.  AT_WKSP_ERR_* gives a
   number of error codes used by at_wksp APIs.  These will be negative
   integers. */

#define AT_WKSP_SUCCESS     (0)  /* Success */
#define AT_WKSP_ERR_INVAL   (-1) /* Failed due to obviously invalid inputs */
#define AT_WKSP_ERR_FAIL    (-2) /* Failed due to shared memory limitation */
#define AT_WKSP_ERR_CORRUPT (-3) /* Workspace memory corruption detected (potentially recoverable by rebuilding) */

/* AT_WKSP_{ALIGN,FOOTPRINT} describe the alignment and footprint of a
   at_wksp_t.  ALIGN is a positive integer power of 2.  FOOTPRINT is a
   multiple of ALIGN.  FOOTPRINT assumes part_max and data_max are
   non-zero and small enough that the footprint will not overflow at
   most ULONG_MAX bytes.  These are provided to facilitate compile time
   declarations. */

#define AT_WKSP_ALIGN (128UL)
#define AT_WKSP_FOOTPRINT( part_max, data_max )                                         \
  AT_LAYOUT_FINI( AT_LAYOUT_APPEND( AT_LAYOUT_APPEND( AT_LAYOUT_APPEND( AT_LAYOUT_INIT, \
    AT_WKSP_ALIGN, 128UL           ), /* header */                                      \
    64UL,          64UL*(part_max) ), /* partition info */                              \
    1UL,           (data_max)+1UL  ), /* data region and footer */                      \
    AT_WKSP_ALIGN )                   /* tail padding */

/* AT_WKSP_ALIGN_DEFAULT gives the default alignments of a wksp
   allocation.  This is a positive integer power of two of at least 16
   (for malloc compatibility).  Additional details described in
   at_wksp_alloc. */

#define AT_WKSP_ALIGN_DEFAULT (4096UL)

/* AT_WKSP_CSTR_MAX is the number of bytes maximum that can be in a wksp
   global address cstr. */

#define AT_WKSP_CSTR_MAX (AT_SHMEM_NAME_MAX + 21UL)

/* AT_WKSP_CHECKPT_STYLE_* specifies the streaming format to use for
   a workspace checkpoint.  These are non-zero.

     V1 - the stream will have extensive workspace metadata followed by
          the used workspace partitions.  No compression or hashing is
          done of the workspace partitions.

     V2 - similar to V1 in functionality but will be written such that
          checkpt and restore are parallelizable.

     V3 - This is actually V2 but compressed frames will be enabled.

     DEFAULT - the style to use when not specified by user.  0 indicates
     to use V3 if the target supports it and V2 if not. */

#define AT_WKSP_CHECKPT_STYLE_V1      (1)
#define AT_WKSP_CHECKPT_STYLE_V2      (2)
#define AT_WKSP_CHECKPT_STYLE_V3      (3)

#define AT_WKSP_CHECKPT_STYLE_DEFAULT (0)

#define AT_WKSP_CHECKPT_STYLE_RAW     AT_WKSP_CHECKPT_STYLE_V1 /* backward compat */

/* A at_wksp_t * is an opaque handle of a workspace */

struct at_wksp_private;
typedef struct at_wksp_private at_wksp_t;

/* A at_wksp_usage_t is used to return workspace usage stats. */

struct at_wksp_usage {
  ulong total_max;
  ulong total_cnt; ulong total_sz;
  ulong free_cnt;  ulong free_sz;
  ulong used_cnt;  ulong used_sz;
};

typedef struct at_wksp_usage at_wksp_usage_t;

AT_PROTOTYPES_BEGIN

/* Admin APIs *********************************************************/

/* It is rare to need to use the admin APIs directly (especially on a
   hosted system).  Recommend using the helper APIs below for most
   needs. */

/* Constructors */

/* at_wksp_part_max_est computes an estimated maximum number of
   partitions for a workspace that needs to fit within footprint bytes
   and has sz_typical allocations typically.  Returns a positive value
   on success and 0 on failure.  Reasons for failure include footprint
   too small, sz_typical is 0 and sz_typical is so large that footprint
   has no room for metadata anyway.  Useful for determining how to pack
   a workspace tightly into a known footprint region. */

AT_FN_CONST ulong
at_wksp_part_max_est( ulong footprint,
                      ulong sz_typical );

/* at_wksp_data_max_est computes an estimated maximum data region size
   for footprint sized workspace with part_max partitions.  Returns a
   positive value on success and 0 on failure.  Reasons for failure
   include footprint is too small, part_max is 0, part_max is too large
   for under the hood implementation limitations or part_max is too
   large to have a non-zero sized data region.  Useful for determining
   how to pack a workspace into a known footprint region. */

AT_FN_CONST ulong
at_wksp_data_max_est( ulong footprint,
                      ulong part_max );

/* at_wksp_{align,footprint} give the required alignment and footprint
   for a workspace that can support up to part_max partitions and with a
   data region of data_max bytes.  at_wksp_align returns AT_WKSP_ALIGN.
   at_wksp_footprint(part_max,data_max) returns
   AT_WKSP_FOOTPRINT(part_max,data_max) on success and 0 on failure.
   Reasons for failure include zero part_max, part_max too large for
   this implementation, zero data_max, part_max/data_max requires a
   footprint that overflows a ULONG_MAX. */

AT_FN_CONST ulong
at_wksp_align( void );

AT_FN_CONST ulong
at_wksp_footprint( ulong part_max,
                   ulong data_max );

/* at_wksp_new formats an unused memory region with the appropriate
   footprint and alignment mapped into the caller's address space at
   shmem into a wksp with given name (should be a valid at_shmem name
   and will match the underlying shared memory region name / anonymous
   join for a wksp created via the shmem helpers below).  seed is the
   arbitrary value used to seed the heap priorities under the hood.
   Returns NULL on failure (logs details) or shmem on success.  The
   caller is _not_ joined on return. */

void *
at_wksp_new( void *       shmem,
             char const * name,
             uint         seed,
             ulong        part_max,
             ulong        data_max );

/* at_wksp_join joins a workspace.  shwksp is the location of the where
   the wksp has been mapped into the caller's address space.  Returns
   the local handle of the join on success or NULL on failure (logs
   details).  The caller can read / write memory in the joined workspace
   on return (a caller can do a read only join by mapping the shwksp
   into the local address as read only).  There is no practical
   limitation on the number of concurrent joins in a thread, process or
   system wide.*/

at_wksp_t *
at_wksp_join( void * shwksp );

/* at_wksp_leave leaves a workspace.  Returns shwksp on success and NULL
   on failure (logs details).  The caller should not continue to read or
   write any memory for the join on return but the workspace will
   continue to exist. */

void *
at_wksp_leave( at_wksp_t * wksp );

/* at_wksp_delete unformats a memory region used as a workspace.
   Returns the shmem on pointer on success and NULL on failure (logs
   details).  There should not be anybody joined to the workspace when
   it is deleted. */

void *
at_wksp_delete( void * shwksp );

/* Accessors */

/* at_wksp_name a cstr pointer to the wksp name (will point to a valid
   region name, e.g. at_strlen( name ) in [1,AT_SHMEM_NAME_MAX)).  Assumes
   wksp is a valid current join.  Lifetime of the returned string is the
   lifetime of the join.  The pointer value is const and the string
   pointed at is const for the lifetime of join.

   at_wksp_seed returns the seed used at creation / most recent rebuild.
   Assumes wksp is a current local join.

   at_wksp_{part_max,data_max} returns {part_max,data_max} used at
   creation.  Assumes wksp is a current local join. */

AT_FN_CONST char const * at_wksp_name    ( at_wksp_t const * wksp );
AT_FN_PURE  uint         at_wksp_seed    ( at_wksp_t const * wksp );
AT_FN_PURE  ulong        at_wksp_part_max( at_wksp_t const * wksp );
AT_FN_PURE  ulong        at_wksp_data_max( at_wksp_t const * wksp );

/* at_wksp_owner returns the id of the thread group that was currently
   in a wksp operation (0 indicates the wksp was in the process of being
   constructed) or ULONG_MAX if there was no operation in progress on
   the workspace.  Assumes wksp is a current local join.  The value will
   correspond to some point of time between when the call was made and
   the call returned. */

ulong at_wksp_owner( at_wksp_t const * wksp );

/* Misc */

/* at_wksp_strerror converts an AT_WKSP_SUCCESS / AT_WKSP_ERR_* code
   into a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

AT_FN_CONST char const *
at_wksp_strerror( int err );

/* at_wksp_verify does extensive verification of wksp.  Returns
   AT_WKSP_SUCCESS (0) if there are no issues detected with the wksp or
   AT_WKSP_ERR_CORRUPT (negative) otherwise (logs details).  wksp is a
   current local join to a workspace.  This is used internally for
   verifying the integrity of a workspace if a caller detects in an
   operation that another caller died in the middle of a wksp operation.
   Users typically do not need to call this but it can be useful in
   debugging and testing.

   IMPORTANT SAFETY TIP!  This assumes there are no concurrent
   operations on wksp. */

int
at_wksp_verify( at_wksp_t * wksp );

/* at_wksp_rebuilds a wksp.  This is used internally for rebuilding
   workspace when a caller detects that another caller died in the
   middle of an alloc or free and left the workspace in an inconsistent
   state.  Returns AT_WKSP_SUCCESS (0) if wksp was rebuilt successfully
   or a AT_WKSP_ERR_CORRUPT (negative) if it could not (logs details).

   Rebuilding operates under the principle of "do no harm".
   Specifically, rebuilding does not impact any completed wksp
   allocations (even when it fails).  It can either complete or rollback
   any partially complete alloc / free depends on far along the partial
   operation was.

   Rebuilding should be always possible outside of actual memory
   corruption or code bug.  The main reason for failure is overlapping
   allocations were discovered during the rebuild (which would either be
   caused by memory corruption or a bug).

   Users typically do not need to call this but it can be useful as a
   weak form of ASLR by changing up the seed.  This is not a fast
   operation.

   IMPORTANT SAFETY TIP!  This assumes there are no concurrent
   operations on wksp. */

int
at_wksp_rebuild( at_wksp_t * wksp,
                 uint        seed );

/* User APIs **********************************************************/

/* at_wksp_laddr map a wksp global address (an address all joiners
   agree upon) to the caller's local address space.  Invalid global
   addresses and/or 0UL will map to NULL (logs details if invalid).
   Assumes wksp is a current local join (NULL returns NULL). */

void *
at_wksp_laddr( at_wksp_t const * wksp,
               ulong             gaddr );

/* at_wksp_gaddr maps a wksp local address to the corresponding wksp
   global address (an address all joiners agree upon).  Invalid local
   addresses and/or NULL will map to 0UL (logs details if invalid).
   Assumes wksp is a current local join (NULL returns NULL). */

ulong
at_wksp_gaddr( at_wksp_t const * wksp,
               void const *      laddr );

/* at_wksp_gaddr_fast converts a laddr into a gaddr under the assumption
   wksp is a current local join and laddr is non-NULL local address in
   the wksp. */

AT_FN_CONST static inline ulong
at_wksp_gaddr_fast( at_wksp_t const * wksp,
                    void const *      laddr ) {
  return (ulong)laddr - (ulong)wksp;
}

/* at_wksp_laddr_fast converts a gaddr into a laddr under the assumption
   wksp is a current local join and gaddr is non-NULL. */

AT_FN_CONST static inline void *
at_wksp_laddr_fast( at_wksp_t const * wksp,
                    ulong             gaddr ) {
  return (void *)((ulong)wksp + gaddr);
}

/* at_wksp_alloc_at_least allocates at least sz bytes from wksp with
   an alignment of at least align (align must be a non-negative integer
   power-of-two or 0, which indicates to use the default alignment
   AT_WKSP_ALIGN_DEFAULT).  The allocation will be tagged with a
   positive value tag.  Returns the at_wksp global address of the join
   on success and "NULL" (0UL) on failure (logs details).  A zero sz
   returns "NULL" (silent).  On return, [*lo,*hi) will contain the
   actually gaddr range allocated.  On success, [*lo,*hi) will overlap
   completely [ret,ret+sz) and ret will be aligned to requested
   alignment.  Assumes lo and hi are non-NULL.

   at_wksp_alloc is a simple wrapper around at_wksp_alloc_at_least for
   use when applications do not care about details of the actual
   allocated region.

   Note that at_wksp_alloc / at_wksp_free are not HPC implementations.
   Instead, these are designed to be akin to a mmap / sbrk allocator of
   "last resort" under the hood in other allocators like at_alloc.  As
   such it prioritizes packing efficiency (best fit with arbitrary sizes
   and alignments allowed) over algorithmic efficiency (e.g.
   O(lg wksp_alloc_cnt) instead of O(1) like at_alloc) and prioritize
   robustness against heap corruption (e.g. overrunning an allocation
   might corrupt the data in other allocations but will not corrupt the
   heap structure ... as the goal of this data structure is to encourage
   minimization of TLB usage, there is very little that can be done to
   proactively prevent intraworkspace interallocation data corruption).

   These operations are "quasi-lock-free".  Specifically, while they can
   suffer priority inversion due to a slow thread stalling other threads
   from using these operations, a process that is terminated in the
   middle of these operations leaves the wksp in a recoverable state.
   The only risk is the same risk generally from any application that
   uses persistent resources: applications that are terminated abruptly
   might leave allocations in the wksp that would have been freed had
   the application terminated normally.  As the allocator has no way to
   tell the difference between such allocations and allocations that are
   intended to outlive the application, it is the caller's
   responsibility to clean up such (allocation tagging can help greatly
   simplify this for users).  It would be possible to widen this API for
   applications to explicitly signal this intent and automatically clean
   up allocations not meant to outlive their creator but the general use
   here is expected to be long lived allocations.

   Priority inversion is not expected to be an issue practically as the
   expected use case is at app startup (some non-latency critical
   processes will do a handful of wksp operations to setup workspaces
   for applications on that box going forward and then the allocations
   will not be used again until the wksp is tore down / reset / etc).
   The remaining cases (e.g. a fine grained allocator like at_alloc
   needs to procure more memory from the workspace) are expected to be
   rare enough that the O(lg N) costs still will be more than adequate.
   Note further that at_alloc allows very fast interprocess allocations
   to be done by using a wksp as an allocator of last resort (in such,
   all allocations would be strictly lock free unless they needed to
   invoke this allocator, as is typically the case in other lock free
   allocators).

   Likewise, operations do extensive allocation metadata integrity
   checks to facilitate robust persistent usage.  If there is metadata
   data corruption detected (e.g. hardware fault, code corruption, etc),
   there are fsck-like APIs to rebuild wksp metadata.  Data integrity
   protection is more defined by the application.

   Tags are application specific.  They can allow manual and automated
   processes to do various debugging, diagnostics, analytics and garbage
   collection on a workspace (e.g. superblocks from a at_alloc can be
   tagged specifically for that at_alloc to allow memory leaks in
   general to be detected at program termination with no additional
   overheads and allow such leaks cleaned up via tagged frees).
   Notably, tags are wide enough to encode gaddrs.  This opens up the
   possibly for filesystem-like complex metadata operations.

   IMPORTANT!  align technically refers to the alignment in the wksp's
   global address space.  As such, wksp must be mmaped into each local
   address space with an alignment of at least the largest alignment the
   overall application intends to use.  Common practices automatically
   satisfy this (e.g. if wksp is backed by normal/huge/gigantic pages
   and only asks for alignments of at most a normal/huge/gigantic page
   sz, this constraint is automatically satisfied as at_shmem_join needs
   to mmap wksp into the local address space with normal/huge/gigantic
   alignment anyway).  If doing more exotic things (e.g. backing wksp by
   normal pages but requiring much larger alignments), explicitly
   specifying the wksp virtual address location (e.g. in the
   at_shmem_join call) might be necessary to satisfy this constraint.

   This implementation support arbitrary sz and align efficiently but
   each allocation will use up 1-3 wksp partitions to achieve this.  As
   these are a finite resources (and typically sized for a wksp that
   handles primarily larger allocations, like a at_alloc huge
   superblock) and as there are allocators like at_alloc that faster are
   algorithmically, lower overhead and lockfree O(1) for small sizes and
   alignment, it is strongly recommended to use this as an allocator of
   last resort and/or use this for larger chunkier allocations at
   application startup (e.g. sz + align >>> cache line).  An allocator
   like at_alloc can then manage most allocations, falling back on this
   only when necessary. */

ulong
at_wksp_alloc_at_least( at_wksp_t * wksp,
                        ulong       align,
                        ulong       sz,
                        ulong       tag,
                        ulong *     lo,
                        ulong *     hi );

static inline ulong
at_wksp_alloc( at_wksp_t * wksp,
               ulong       align,
               ulong       sz,
               ulong       tag ) {
  ulong dummy[2];
  return at_wksp_alloc_at_least( wksp, align, sz, tag, dummy, dummy+1 );
}

/* at_wksp_free frees a wksp allocation.  gaddr is a global address that
   points to any byte in the allocation to free (i.e. can point to
   anything in of the gaddr range [*lo,*hi) returned by
   at_wksp_alloc_at_least).  Logs details of any weirdness detected.
   Free of "NULL" (0UL) silently returns.  There are no restrictions on
   which join might free an allocation.  See note above other details. */

void
at_wksp_free( at_wksp_t * wksp,
              ulong       gaddr );

/* at_wksp_tag returns the tag associated with an allocation.  gaddr
   is a wksp global address that points to any byte in the allocation.
   This is a fast O(lg wksp_alloc_cnt).  A return of 0 indicates that
   gaddr did not point into an allocation at some point in time between
   when this function was called until when it returned (this includes
   the cases when wksp is NULL and/or gaddr is 0).  This function is
   silent to facilitate integration with various analysis tools. */

ulong
at_wksp_tag( at_wksp_t * wksp,
             ulong       gaddr );

/* at_wksp_tag_query queries the workspace for all partitions that match
   one of the given tags.  The tag array is indexed [0,tag_cnt).
   Returns info_cnt, the number of matching partitions.  Further, if
   info_max is non-zero, will return detailed information for the first
   (from low to high gaddr) min(info_cnt,info_max).  Returns 0 if no
   partitions match any tags.  If any wonkiness encountered (e.g. wksp
   is NULL, tag is not in positive, etc) returns 0 and logs details.
   This is O(wksp_alloc_cnt*tag_cnt) currently (but could be made
   O(wksp_alloc_cnt) with some additional work). */

struct at_wksp_tag_query_info {
  ulong gaddr_lo; /* Partition covers workspace global addresses [gaddr_lo,gaddr_hi) */
  ulong gaddr_hi; /* 0<gaddr_lo<gaddr_hi */
  ulong tag;      /* Partition tag */
};

typedef struct at_wksp_tag_query_info at_wksp_tag_query_info_t;

ulong
at_wksp_tag_query( at_wksp_t *                wksp,
                   ulong const *              tag,
                   ulong                      tag_cnt,
                   at_wksp_tag_query_info_t * info,
                   ulong                      info_max );

/* at_wksp_tag_free frees all allocations in wksp that match one of the
   given tags.  The tag array is indexed [0,tag_cnt).  Logs details if
   any wonkiness encountered (e.g. wksp is NULL, tag is not in positive.
   This is O(wksp_alloc_cnt*tag_cnt) currently (but could be made
   O(wksp_alloc_cnt) with some additional work). */

void
at_wksp_tag_free( at_wksp_t *   wksp,
                  ulong const * tag,
                  ulong         tag_cnt );

/* at_wksp_memset sets all bytes in a wksp allocation to character c.
   gaddr is a global address that points to any byte in the allocation
   (i.e. can point to anything in range returned by
   at_wksp_alloc_at_least and will fill the whole range).  Logs details
   of any weirdness detected.  Clear of "NULL" (0UL) silently returns.
   Atomic with respect to other operations on this workspace. */

void
at_wksp_memset( at_wksp_t * wksp,
                ulong       gaddr,
                int         c );

/* at_wksp_reset frees all allocations from the wksp.  Logs details on
   failure. */

void
at_wksp_reset( at_wksp_t * wksp,
               uint        seed );

/* at_wksp_usage computes the wksp usage at some point in time between
   when the call was made and the call returned, populating the user
   provided usage structure with the result.  Always returns usage.

   wksp is a current local join to the workspace to compute usage.

   tag[tag_idx] for tag_idx in [0,tag_cnt) is an array of tags to
   compute the usage.  The order doesn't matter and, if a tag appears
   multiple times in the array, it will be counted once in the used
   stats.  A zero tag_cnt (potentially with a NULL tag) is fine
   (used_cnt,used_set for such will be 0,0).  A tag of 0 indicates to
   include free partitions in the used stats.

   total_max is the maximum partitions the wksp can have.  This will be
   positive (==part_max).

   total_sz is the number of bytes the wksp has available for
   partitioning (==data_max).  As the partitioning always covers the
   entire wksp, total_sz is constant for the lifetime of the wksp.

   total_cnt is the number of partitions the wksp currently has.  This
   will be in [1,total_max].

   free_cnt/sz is the number of free partitions / free bytes the wksp
   currently has.  A free partition has a tag of 0 and is currently
   available for splitting to satisfy the a future at_wksp_alloc
   request.

   used_cnt/sz is the number of partitions / bytes used by wksp
   partitions whose tags match those in the provided tag set.

   This is O(wksp_alloc_cnt*tag_cnt) and will lock the wksp while
   running (and potentially block the caller if others are holding onto
   the lock).  So use in testing, etc.  Likewise, the precise meaning of
   the statistics computed by this API are dependent on the
   implementation details under the hood (that is do not be surprised if
   this API gets changed in the future). */

at_wksp_usage_t *
at_wksp_usage( at_wksp_t *       wksp,
               ulong const *     tag,
               ulong             tag_cnt,
               at_wksp_usage_t * usage );

/* shmem APIs *********************************************************/

/* at_wksp_new_named creates a shared memory region named name and
   formats as a workspace.  Ignoring error trapping, this is a shorthand
   for:

     // Size the workspace to use all the memory
     ulong footprint = sum( sub_page_cnt[*] )*page_sz
     ulong part_max  = opt_part_max ? opt_part_max : at_wksp_part_max_est( footprint, 64 KiB );
     ulong data_max  = at_wksp_data_max_est( footprint, part_max );

     // Create the shared memory region and format as a workspace
     at_shmem_create_multi( name, page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx, mode );
     void * shmem = at_shmem_join( name, AT_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL ) );
     at_wksp_new( shmem, name, seed, part_max, data_max );
     at_shmem_leave( shmem, NULL, NULL );

   The 64 KiB above is where at_alloc currently transitions to directly
   allocating from the wksp.

   Returns AT_WKSP_SUCCESS (0) on success and an AT_WKSP_ERR_*
   (negative) on failure (logs details).  Reasons for failure include
   INVAL (user arguments obviously bad) and FAIL (could not procure or
   format the shared memory region). */

int
at_wksp_new_named( char const *  name,
                   ulong         page_sz,
                   ulong         sub_cnt,
                   ulong const * sub_page_cnt,
                   ulong const * sub_cpu_idx,
                   ulong         mode,
                   uint          seed,
                   ulong         opt_part_max );

/* at_wksp_delete_named deletes a workspace created with
   at_wksp_new_named.  There should not be any other joins / attachments
   to wksp when this is called.  Returns AT_WKSP_SUCCESS (0) on success
   and AT_WKSP_ERR_* (negative) on failure (logs details). */

int
at_wksp_delete_named( char const * name );

/* at_wksp_new_anon creates a workspace local to this thread group that
   otherwise looks and behaves _exactly_ like a workspace shared between
   multiple thread groups on this host of the same name, TLB and NUMA
   properties.  Ignoring error trapping, this is a shorthand for:

     // Size the workspace to use all the memory
     ulong page_cnt  = sum( sub_page_cnt[*] );
     ulong footprint = page_cnt*page_sz;
     ulong part_max  = opt_part_max ? opt_part_max : at_wksp_part_max_est( footprint, 64 KiB );
     ulong data_max  = at_wksp_data_max_est( footprint, part_max );

     // Create the anonymous memory region and format as a workspace
     void * mem = at_shmem_acquire_multi( page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx );
     at_wksp_t * wksp = at_wksp_join( at_wksp_new( mem, name, seed, part_max, data_max ) );
     at_shmem_join_anonymous( name, AT_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, page_sz, page_cnt );

   There should be must no current shmem joins to name and the anonymous
   join will shadow any preexisting at_shmem region with the same name
   in the calling thread group).  Returns the joined workspace on
   success and NULL on failure (logs details).  The final leave and
   delete to this workspace should be through at_wksp_delete_anon. */

at_wksp_t *
at_wksp_new_anon( char const *  name,
                  ulong         page_sz,
                  ulong         sub_cnt,
                  ulong const * sub_page_cnt,
                  ulong const * sub_cpu_idx,
                  uint          seed,
                  ulong         opt_part_max );

/* at_wksp_delete_anon deletes a workspace created with at_wksp_new_anon
   There should not be any other joins / attachments to wksp when this
   is called.  This cannot fail from the caller's POV; logs details if
   any wonkiness is detected during the delete. */

void
at_wksp_delete_anon( at_wksp_t * wksp );

/* TODO: eliminate these legacy versions of the in favor of the above. */

static inline at_wksp_t *
at_wksp_new_anonymous( ulong         page_sz,
                       ulong         page_cnt,
                       ulong         cpu_idx,
                       char const *  name,
                       ulong         opt_part_max ) {
  return at_wksp_new_anon( name, page_sz, 1UL, &page_cnt, &cpu_idx, 0U, opt_part_max );
}

static inline void at_wksp_delete_anonymous( at_wksp_t * wksp ) { at_wksp_delete_anon( wksp ); }

/* at_wksp_attach attach to the workspace held by the shared memory
   region with the given name.  If there are regions with the same name
   backed by different page sizes, defaults to the region backed by the
   largest page size.  Returns wksp on success and NULL on failure
   (details are logged).  Multiple attachments within are fine (all but
   the first attachment will be a reasonably fast O(1) call); all
   attachments in a process will use the same local at_wksp_t handle.
   Every attach should be paired with a detach.  TODO: CONST-VARIANTS? */

at_wksp_t *
at_wksp_attach( char const * name );

/* at_wksp_detach detaches from the given workspace.  All but the last
   detach should be a reasonably fast O(1) call.  Returns non-zero on
   failure. */

int
at_wksp_detach( at_wksp_t * wksp );

/* at_wksp_containing maps a at_wksp local addr to the corresponding
   at_wksp local join.  Returns NULL if laddr does not appear to be from
   a locally joined at_wksp.  Always silent such that this can be used
   to detect if a pointer is from a at_wksp or not.  This is not a
   terribly fast call.  This API can only be used on laddrs in wksp are
   either named or anonymous workspaces. */

at_wksp_t *
at_wksp_containing( void const * laddr );

/* at_wksp_alloc_laddr is the same as at_wksp_alloc but returns a
   pointer in the caller's local address space if the allocation was
   successful (and NULL if not).  Ignoring error trapping, this is a
   shorthand for:

     at_wksp_laddr( wksp, at_wksp_alloc( wksp, align, sz, tag ) ) */

void *
at_wksp_alloc_laddr( at_wksp_t * wksp,
                     ulong       align,
                     ulong       sz,
                     ulong       tag );

/* at_wksp_free_laddr is the same as at_wksp_free but takes a pointer
   in the caller's local address space into a workspace allocation.
   Ignoring error trapping, this is a shorthand for:

     at_wksp_t * wksp = at_wksp_containing( laddr );
     at_wksp_free( wksp, at_wksp_gaddr( wksp, laddr ) );

   This API can only be used on laddrs in wksp are either named or
   anonymous workspaces. */

void
at_wksp_free_laddr( void * laddr );

/* cstr helper APIs ***************************************************/

/* Overall, these are meant for use at application startup / shutdown
   and not in critical loops. */

/* at_wksp_cstr prints the wksp global address gaddr into cstr as a
   [at_wksp_name(wksp)]:[gaddr].  Caller promises that cstr has room for
   AT_WKSP_CSTR_MAX bytes.  Returns cstr on success and NULL on failure
   (logs details).  Reasons for failure include NULL wksp, gaddr not in
   the data region (or one past), NULL cstr. */

char *
at_wksp_cstr( at_wksp_t const * wksp,
              ulong             gaddr,
              char *            cstr );

/* at_wksp_cstr_laddr is the same at_wksp_cstr but takes a pointer in
   the caller's local address space to a wksp location.  Ignoring error
   trapping, this is a shorthand for:

     at_wksp_t * wksp = at_wksp_containing( laddr );
     return at_wksp_cstr( wksp, at_wksp_gaddr( wksp, laddr ), cstr );

   Returns NULL if laddr does not point strictly inside a workspace
   (logs details).  This API can only be used on laddrs in wksp are
   either named or anonymous workspaces. */

char *
at_wksp_cstr_laddr( void const * laddr,
                    char *       cstr );

/* at_wksp_cstr_alloc allocates sz bytes with alignment align from name
   or anonymous wksp with name.  align and sz have the exact same
   semantics as at_wksp_alloc.  cstr must be non-NULL with space for up
   to AT_WKSP_CSTR_MAX bytes.

   Returns cstr on success and NULL on failure (logs details).  On
   success, cstr will contain a [name]:[gaddr] string suitable for use
   by at_wksp_map and at_wksp_cstr_free.  cstr will be untouched
   otherwise.  Ignoring error trapping, this is a shorthand for:

     at_wksp_t * wksp  = at_wksp_attach( name );
     ulong       gaddr = at_wksp_alloc( wksp, align, sz );
     at_wksp_detach( wksp );
     sprintf( cstr, "%s:%lu", name, gaddr );
     return cstr;

   As such, if doing many allocations from the same wksp, it is faster
   to do a at_wksp_attach upfront, followed by the allocations and then
   a wksp detach (and faster still to use the advanced APIs to further
   amortize the at_wksp_attach / at_wksp_detach calls). */

char *
at_wksp_cstr_alloc( char const * name,
                    ulong        align,
                    ulong        sz,
                    ulong        tag,
                    char *       cstr );

/* at_wksp_cstr_free frees a wksp allocation specified by a cstr
   containing [name]:[gaddr].  Ignoring parsing and error trapping, this
   is a shorthand for:

      at_wksp_t * wksp = at_wksp_attach( name );
      at_wksp_free( wksp, gaddr );
      at_wksp_detach( wksp );

   As such, if doing many frees from the same wksp, it is faster to do a
   at_wksp_attach upfront, followed by the frees and then a
   at_wksp_detach (and faster still to use the advanced APIs to further
   amortize the at_wksp_attach / at_wksp_detach calls.) */

void
at_wksp_cstr_free( char const * cstr );

/* at_wksp_cstr_tag queries the tag of a wksp allocation specified by a
   cstr containing [name]:[gaddr].  Ignoring parsing and error trapping,
   this is a shorthand for:

      at_wksp_t * wksp = at_wksp_attach( name );
      ulong tag = at_wksp_tag( wksp, gaddr );
      at_wksp_detach( wksp );

   As such, if doing many queries on the same wksp, it is faster to do
   at_wksp_attach upfront, followed by the queries and then a
   at_wksp_detach (and faster still to use the advanced APIs to further
   amortize the at_wksp_attach / at_wksp_detach calls.) */

ulong
at_wksp_cstr_tag( char const * cstr );

/* at_wksp_cstr_memset memsets a wksp allocation specified by a cstr
   containing [name]:[gaddr] to c.  Ignoring parsing and error trapping,
   equivalent to:

      at_wksp_t * wksp = at_wksp_attach( name );
      at_wksp_memset( wksp, gaddr, c );
      at_wksp_detach( wksp );

   As such, if doing many memset in the same wksp, it is faster to do a
   at_wksp_attach upfront, followed by the memsets and then a
   at_wksp_detach (and faster still to use the advanced APIs to further
   amortize the at_wksp_attach / at_wksp_detach calls.) */

void
at_wksp_cstr_memset( char const * cstr,
                     int          c );

/* at_wksp_map returns a pointer in the caller's address space to
   the wksp allocation specified by a cstr containing [name]:[gaddr].
   [name] is the name of the shared memory region holding the wksp.
   [gaddr] is converted to a number via at_cstr_to_ulong that should
   correspond to a valid non-NULL global address in that wksp.  Ignoring
   parsing, edge cases and error trapping, this is a shorthand for:

     at_wksp_laddr( at_wksp_attach( name ), gaddr )

   Returns non-NULL on successful (the lifetime of the returned pointer
   will be until at_wksp_unmap is called on it).  Returns NULL and logs
   details on failure.

   at_wksp_map is algorithmically efficient and reasonably low overhead
   (especially if is this not the first attachment to the wksp).

   TODO: consider const-correct variant? */

void *
at_wksp_map( char const * cstr );

/* at_wksp_unmap unmaps a pointer returned by at_wksp_map, logs details
   if anything weird is detected.  Ignoring error trapping, this is a
   shorthand for:

     at_wksp_detach( at_wksp_containing( laddr ) )

   Undefined behavior if laddr is not currently mapped by at_wksp_map.
   at_wksp_unmap is not algorithmically efficient but practically still
   quite fast (especially if this is not the last attachment to wksp).
   This API can only be used on laddrs in wksp are either named or
   anonymous workspaces. */

void
at_wksp_unmap( void const * laddr );

/* pod helper APIs ****************************************************/

/* Ignoring error trapping, at_wksp_pod_attach( cstr ) is shorthand
   for:

     at_pod_join( at_wksp_map( cstr ) )

   Cannot fail from the caller's point of view (will terminate the
   thread group of the caller with a detailed AT_LOG_ERR message on
   failure.  Calls to at_wksp_pod_attach should be paired with calls to
   at_wksp_pod_detach when pod usage is done. */

uchar const *
at_wksp_pod_attach( char const * cstr );

/* Ignoring error trapping, at_wksp_pod_detach( pod ) is shorthand for:

     at_wksp_unmap( at_pod_leave( pod ) )

   Provided for symmetry with at_wksp_pod_attach.  Cannot fail from the
   caller's point of view (will terminate the thread group of the caller
   with a detailed AT_LOG_ERR message on failure and will AT_LOG_WARNING
   if anything wonky occurs in the unmap under the hood). */

void
at_wksp_pod_detach( uchar const * pod );

/* Ignoring error trapping, at_wksp_pod_map( pod, path ) is shorthand
   for:

     at_wksp_map( at_pod_query_cstr( pod, path, NULL ) )

   Cannot fail from the caller's point of view (will terminate the
   thread group of the caller with detailed AT_LOG_ERR message on
   failure).  Calls to at_wksp_pod_map should be paired with calls to
   at_wksp_pod_unmap. */

void *
at_wksp_pod_map( uchar const * pod,
                 char const *  path );

/* Ignoring error trapping, at_wksp_pod_unmap( obj ) is shorthand for:

     at_wksp_unmap( obj )

   Provided for symmetry with at_wksp_pod_map.  Cannot fail from the
   caller's point of view (will terminate the thread group of the caller
   with a detailed AT_LOG_ERR message on failure and will AT_LOG_WARNING
   if anything wonky occurs in the unmap under the hood). */

void
at_wksp_pod_unmap( void * obj );

/* io APIs ************************************************************/

/* at_wksp_checkpt_tpool will write the wksp's state to a file using
   tpool threads [t0,t1).  Assumes the caller is thread t0 and threads
   (t0,t1) are available.  The file will be located at path with UNIX
   style permissions given by mode.  style specifies the checkpt style
   and should be a AT_WKSP_CHECKPT_STYLE_* value or 0 (0 indicates to
   use AT_WKSP_CHECKPT_STYLE_DEFAULT).  uinfo points to a cstr with
   optional additional user context (NULL will be treated as the empty
   string "" ... if the strlen is longer than 16384 bytes, the info will
   be truncated to a strlen of 16383).

   Returns AT_WKSP_SUCCESS (0) on success or a AT_WKSP_ERR_* on failure
   (logs details).  Reasons for failure include INVAL (NULL wksp, NULL
   path, bad mode, unsupported style), CORRUPT (wksp memory corruption
   detected), FAIL (fail already exists, I/O error).  On failure, this
   will make a best effort to clean up after any partially written
   checkpt file.

   at_wksp_checkpt is a convenience wrapper for serial checkpts. */

int
at_wksp_checkpt_tpool( at_tpool_t * tpool,
                       ulong        t0,
                       ulong        t1,
                       at_wksp_t *  wksp,
                       char const * path,
                       ulong        mode,
                       int          style,
                       char const * uinfo );

static inline int
at_wksp_checkpt( at_wksp_t *  wksp,
                 char const * path,
                 ulong        mode,
                 int          style,
                 char const * uinfo ) {
  return at_wksp_checkpt_tpool( NULL, 0UL, 1UL, wksp, path, mode, style, uinfo );
}

/* at_wksp_restore_tpool will replace all allocations in the current
   workspace with the allocations from the checkpt at path.  The
   restored workspace will use the given seed.  Tpool threads [t0,t1)
   will be used for the restore.  Assumes the caller is thread t0 and
   threads (t0,t1) are available.

   IMPORTANT!  It is okay for wksp to have a different size, backing
   page sz and/or numa affinity than the original wksp.  The only
   requirements are the wksp be able to support as many allocations as
   are in the checkpt and that these partitions can be restored to their
   original positions in wksp's global address space.  If wksp has
   part_max in checkpt's [alloc_cnt,part_max] and a data_max>=checkpt's
   data_max, this is guaranteed.  Likewise, the number and range of
   threads used on restore does _not_ need to match the range used on
   checkpt.

   Returns AT_WKSP_SUCCESS (0) on success or a AT_WKSP_ERR_* on failure
   (logs details).  Reasons for failure include INVAL (NULL wksp, NULL
   path), FAIL or CORRUPT (couldn't open checkpt, I/O error, checkpt
   format error, incompatible wksp for checkpt, etc ... logs details).
   For the INVAL and FAIL cases, the original workspace allocations was
   untouched.  For the CORRUPT case, original workspace allocations were
   removed because the checkpt issues were detected after the restore
   process began (a best effort to reset wksp to the empty state was
   done before return).

   at_wksp_restore is a convenience wrapper for serial restores. */

int
at_wksp_restore_tpool( at_tpool_t * tpool,
                       ulong        t0,
                       ulong        t1,
                       at_wksp_t *  wksp,
                       char const * path,
                       uint         seed );

static inline int
at_wksp_restore( at_wksp_t *  wksp,
                 char const * path,
                 uint         seed ) {
  return at_wksp_restore_tpool( NULL, 0UL, 1UL, wksp, path, seed );
}

/* at_wksp_preview previews the wksp checkpt at path.  On success,
   returns AT_WKSP_SUCCESS (0), path seems to contain a supported wksp
   checkpt and, if opt_preview was non-NULL, *opt_preview will contain,
   at a minimum, the info needed to create a new wksp with the same
   parameters as the wksp at path.  On failure, returns a AT_WKSP_ERR
   (negative, silent) and *_opt_preview is unchanged.  Returns for
   failure include INVAL (NULL path), FAIL (unable to read checkpt
   header at path), CORRUPT (the leading bytes at path don't appear to
   be a wksp checkpt). */

struct at_wksp_preview {
  int   style;
  uint  seed;
  ulong part_max;
  ulong data_max;
  char  name[ AT_SHMEM_NAME_MAX ]; /* cstr holding the original wksp name */
};

typedef struct at_wksp_preview at_wksp_preview_t;

int
at_wksp_preview( char const *        path,
                 at_wksp_preview_t * _opt_preview );

/* at_wksp_printf pretty prints to fd (e.g. fileno(stdout)) information
   about the wksp checkpt at path.  verbose specifies the verbosity
   level.  Typical verbose levels are:

     <0 - do not print
      0 - preview info
      1 - verbose 0 + metadata
      2 - verbose 1 + build and user info
      3 - verbose 2 + partition summary info
      4 - verbose 3 + individual allocated partition metdata
     >4 - verbose 4 + hex dumps of allocated partition data

   but this can vary for different checkpt styles.  The return value has
   the same interpretation as printf. */

int
at_wksp_printf( int          fd,
                char const * path,
                int          verbose );

/* at_wksp_mprotect marks all the memory in a workspace as read-only
   (flag==1) or read-write (flag==0). Accessing read-only memory produces
   a seg fault. */

void
at_wksp_mprotect( at_wksp_t * wksp, int flag );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_wksp_at_wksp_h */