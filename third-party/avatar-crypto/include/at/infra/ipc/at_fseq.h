#ifndef HEADER_at_src_tango_fseq_at_fseq_h
#define HEADER_at_src_tango_fseq_at_fseq_h

/* fseq provides APIs for wrapping up a sequence number as a persistent
   shared memory object (primarily for use in rx->tx flow control
   communications but potentially could be used for other cases of
   making sequence numbers visible to other processes at run-time). */

#include "at_tango_base.h"

/* AT_FSEQ_{ALIGN,FOOTPRINT} specify the alignment and footprint needed
   for a fseq.  ALIGN is a positive integer power of 2.  FOOTPRINT is a
   multiple of ALIGN.  ALIGN is recommended to be at least double cache
   line to mitigate various kinds of false sharing.  These are provided
   to facilitate compile time declarations. */

#define AT_FSEQ_ALIGN     (128UL)
#define AT_FSEQ_FOOTPRINT (128UL)

/* AT_FSEQ_APP_{ALIGN,FOOTPRINT} specify the alignment and footprint of
   a fseq's application region.  ALIGN is a positive integer power of 2.
   FOOTPRINT is a multiple of ALIGN. */

#define AT_FSEQ_APP_ALIGN     (32UL)
#define AT_FSEQ_APP_FOOTPRINT (96UL)

AT_PROTOTYPES_BEGIN

/* at_fseq_{align,footprint} return the required alignment and footprint
   of a memory region suitable for use as a fseq.  at_fseq_align returns
   AT_FSEQ_ALIGN.  at_fseq_footprint returns AT_FSEQ_FOOTPRINT. */

AT_FN_CONST ulong
at_fseq_align( void );

AT_FN_CONST ulong
at_fseq_footprint( void );

/* at_fseq_new formats an unused memory region for use as a fseq.  Assumes
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  The fseq will be
   initialized to seq0 and the application region will be cleared to 0.
   Returns shmem (and the memory region it points to will be formatted
   as a fseq, caller is not joined) and NULL on failure (logs details).
   Reasons for failure include an obviously bad memory region. */

void *
at_fseq_new( void * shmem,
             ulong  seq0 );

/* at_fseq_join joins the caller to the fseq.  shfseq points to the first
   byte of the memory region backing the fseq in the caller's address
   space.  Returns a pointer in the local address space to the fseq on
   success (IMPORTANT! THIS SHOULD NOT BE ASSUMED TO BE JUST A CAST OF
   SHFSEQ) or NULL on failure (logs details).  Reasons for failure
   include the shfseq is obviously not a local pointer to a memory
   region holding a fseq.  Every successful join should have a matching
   leave.  The lifetime of the join is until the matching leave or
   caller's thread group is terminated. */

ulong *
at_fseq_join( void * shfseq );

/* at_fseq_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success (IMPORTANT! THIS SHOULD
   NOT BE ASSUMED TO BE JUST A CAST OF FSEQ) and NULL on failure (logs
   details).  Reasons for failure include fseq is NULL. */

void *
at_fseq_leave( ulong const * fseq );

/* at_fseq_delete unformats a memory region used as a fseq.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g. shfseq
   obviously does not point to a fseq ... logs details).  The ownership
   of the memory region is transferred to the caller on success. */

void *
at_fseq_delete( void * shfseq );

/* at_fseq_app_laddr returns local address of the fseq's application
   region.  This will have AT_FSEQ_APP_ALIGN alignment and room for at
   least AT_FSEQ_APP_FOOTPRINT bytes.  Assumes fseq is a current local
   join.  at_fseq_app_laddr_const is for const correctness.  The return
   values are valid for the lifetime of the local join. */

AT_FN_CONST static inline void *       at_fseq_app_laddr      ( ulong *       fseq ) { return (void       *)(fseq+2); }
AT_FN_CONST static inline void const * at_fseq_app_laddr_const( ulong const * fseq ) { return (void const *)(fseq+2); }

/* at_fseq_seq0 returns the sequencer number used when the fseq was
   created.  Assumes fseq is a current local join. */

AT_FN_PURE static inline ulong at_fseq_seq0( ulong const * fseq ) { return fseq[-1]; }

/* at_fseq_query reads the current sequence number stored the fseq.  The
   value is observed at some point between when the call started and the
   call returned.  This acts as an implicit compiler fence.  Assumes
   fseq is a current local join. */

static inline ulong
at_fseq_query( ulong const * fseq ) {
  AT_COMPILER_MFENCE();
  ulong seq = AT_VOLATILE_CONST( fseq[0] );
  AT_COMPILER_MFENCE();
  return seq;
}

/* at_fseq_update updates the sequence number stored in the fseq to seq.
   The value is updated at some point between when the call started and
   the call returned.  This acts as an implicit compiler fence.  Assumes
   fseq is a current local join. */

static inline void
at_fseq_update( ulong * fseq,
                ulong   seq ) {
  AT_COMPILER_MFENCE();
  AT_VOLATILE( fseq[0] ) = seq;
  AT_COMPILER_MFENCE();
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_tango_fseq_at_fseq_h */