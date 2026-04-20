#ifndef HEADER_at_src_tango_fctl_at_fctl_h
#define HEADER_at_src_tango_fctl_at_fctl_h

/* fctl provides a set of APIs for general purpose, ultra flexible,
   ultra low overhead credit-based flow control.  That being said,
   backpressure is the worst thing in the world for a large scale
   distributed system.  So the system should be designed to use flow
   control exceedingly sparingly and limit the number of strictly
   reliable consumers needed in the system to, ideally, zero.  That is,
   the less this API gets used, the better the overall system is. */

#include "at_tango_base.h"

/* AT_FCTL_RX_MAX_MAX returns the largest number of receivers a fctl can
   be sized to accommodate.  Should be in [1,65535]. */

#define AT_FCTL_RX_MAX_MAX (65535UL)

/* AT_FCTL_{ALIGN,FOOTPRINT} specify the alignment and footprint needed
   for a fctl.  ALIGN will be positive integer power of 2.  FOOTPRINT
   assumes rx_max is in [0,AT_FCTL_RX_MAX_RX_MAX]. */

#define AT_FCTL_ALIGN (8UL)
#define AT_FCTL_FOOTPRINT( rx_max )                                        \
  AT_LAYOUT_FINI( AT_LAYOUT_APPEND( AT_LAYOUT_APPEND( AT_LAYOUT_INIT,      \
    alignof(at_fctl_t),                     sizeof(at_fctl_t)            ), \
    alignof(at_fctl_private_rx_t), (rx_max)*sizeof(at_fctl_private_rx_t) ), \
    AT_FCTL_ALIGN )

/* A at_fctl_t is an opaque handle to a flow control object that can
   manage flow control on behalf of a transmitter for zero or more
   (potentially dynamic) reliable (i.e. backpressure allowed) receivers. */

struct at_fctl_private;
typedef struct at_fctl_private at_fctl_t;

/* Private APIs *******************************************************/

/* For the most part, applications should not interact with these
   directly.  They are exposed to facilitate compile time inlining of
   flow control operations in performance critical loops. */

struct at_fctl_private_rx {
  long          cr_max;     /* See at_fctl_cfg_rx_add for details, should be positive */
  ulong const * seq_laddr;  /* ", NULL indicates an inactive rx */
  ulong *       slow_laddr; /* " */
};

typedef struct at_fctl_private_rx at_fctl_private_rx_t;

struct at_fctl_private {
  ushort rx_max;    /* Maximum number of receivers for this fctl, in [0,AT_FCTL_RX_MAX_MAX] */
  ushort rx_cnt;    /* Current number of receivers for this fctl, in [0,rx_max] */
  int    in_refill; /* 0 / 1 if the flow control currently in a refilling state */
  ulong  cr_burst;  /* See at_fctl_cfg_done for details, in [1,LONG_MAX] (not ULONG_MAX) */
  ulong  cr_max;    /* ", in [cr_burst,LONG_MAX] */
  ulong  cr_resume; /* ", in [cr_burst,cr_max  ] */
  ulong  cr_refill; /* ", In [1,cr_resume      ] */
  /* rx_max at_fctl_private_rx_t array indexed [0,rx_max) follows.  Only
     elements [0,rx_cnt) are in use.  Only elements with non-NULL
     seq_laddr are currently allowed to backpressure this fctl. */
};

AT_PROTOTYPES_BEGIN

/* at_fctl_rx returns a pointer to the fctl's rx array.  Assumes fctl is
   valid.  at_fctl_rx_const is a const correct version. */

AT_FN_CONST static inline at_fctl_private_rx_t *
at_fctl_private_rx( at_fctl_t * fctl ) {
  return (at_fctl_private_rx_t *)(fctl+1UL);
}

AT_FN_CONST static inline at_fctl_private_rx_t const *
at_fctl_private_rx_const( at_fctl_t const * fctl ) {
  return (at_fctl_private_rx_t const *)(fctl+1UL);
}

AT_PROTOTYPES_END

/* Public APIs ********************************************************/

AT_PROTOTYPES_BEGIN

/* Constructor APIs */

/* at_fctl_{align,footprint} return the required alignment and footprint
   of a memory region suitable for use as fctl that can manage flow control
   for up to rx_max reliable consumers.  align returns AT_FCTL_ALIGN
   (will be a power of two).  rx_max should be in [0,AT_FCTL_RX_MAX_MAX].
   If not, footprint will silently return 0 (and thus can be used by the
   caller to validate rx_max configuration parameters). */

AT_FN_CONST static inline ulong
at_fctl_align( void ) {
  return AT_FCTL_ALIGN;
}

AT_FN_CONST static inline ulong
at_fctl_footprint( ulong rx_max ) {
  if( AT_UNLIKELY( rx_max>AT_FCTL_RX_MAX_MAX ) ) return 0UL;
  return AT_FCTL_FOOTPRINT( rx_max );
}

/* at_fctl_new takes ownership of the memory region pointed to by shmem
   (which is assumed to be non-NULL with the appropriate alignment and
   footprint) and formats it as fctl.  Typically this memory region will
   just be local to the user though it can be placed in a shared region
   to allow remote monitors to inspect / modify various portions of it,
   facilitate hotswapping, etc.  Returns mem on success and NULL on
   failure (logs details).  The fctl will be initialized to an
   unconfigured state with zero receivers attached to it on success
   return.  Reasons for failure include an obviously bad shmem region
   and too large rx_max.

   at_fctl_join joins the caller to a memory region holding the state of
   a fctl.  shfctl points to a memory region in the local address space
   that holds a fctl.  Returns an opaque handle of the local join in the
   local address space to the fctl (which might not be the same thing as
   shfctl ... the separation of new and join is to facilitate
   interprocess shared memory usage patterns while supporting
   transparent upgrade of users of this to more elaborate algorithms
   where address translations under the hood may not be trivial).

   at_fctl_leave leaves the current fctl join.  Returns a pointer in the
   local address space to the memory region holding the state of the
   fctl.  The join should not be used afterward.

   at_fctl_delete unformats the memory region currently used to hold the
   state of a fctl and returns ownership of the underlying memory region
   to the caller.  There should be no joins in the system on the fctl.
   Returns a pointer to the underlying memory region. */

void *
at_fctl_new( void * shmem,
             ulong  rx_max );

static inline at_fctl_t * at_fctl_join  ( void *      shfctl ) { return (at_fctl_t *)shfctl; }
static inline void *      at_fctl_leave ( at_fctl_t * fctl   ) { return (void *)fctl;        }
static inline void *      at_fctl_delete( void *      shfctl ) { return shfctl;              }

/* at_fctl_cfg_rx_add adds flow control details for a receiver to the
   given fctl.  Assumes the fctl configuration is not yet complete.
   Each receiver is assigned an index starting from zero sequentially
   as they are added.  This index is used to communicate diagnostic
   information to the user (e.g. see at_fctl_cr_query rx_idx_slow).

   cr_max is how many credits are safe for the transmitter to burst to
   the receiver when this receiver is fully caught up.  Should be in
   [1,LONG_MAX] (not ULONG_MAX).

   seq_laddr is the location in the user's local address space where the
   user can query a lower bound of where this receiver is currently at
   in the underlying sequence space.  The user is guaranteed that the
   receiver has processed all sequence numbers strictly before
   *seq_laddr.  NULL is fine here (the fctl will ignore this receiver
   until it is set, potentially post configuration).

   slow_laddr is the location in the user's local address space where
   the fctl should accumulate statistics for which receiver is running
   the slowest.  It is fine if other events are accumulated to this
   location (e.g. the user doesn't need ultra fine grained diagnostics).

   Returns fctl on success and NULL on failure (logs details).  Reasons
   for failure include NULL fctl, NULL slow_laddr, too many fctl
   receivers, too small cr_max, too large cr_max. */

at_fctl_t *
at_fctl_cfg_rx_add( at_fctl_t *   fctl,
                    ulong         cr_max,
                    ulong const * seq_laddr,
                    ulong *       slow_laddr );

/* at_fctl_cfg_done completes the configuration of a flow control.
   Assumes the fctl configuration is not yet complete.

   cr_burst is the maximum number of credits a transmitter will use in a
   burst (i.e. deduct from its credits available before checking that it
   still had credits available again, e.g. MTU for Ethernet-like
   protocols, MSS for a byte oriented TCP-like protocols, number of
   slots in a batch for slot oriented protocols like a batch of frag
   metadata, etc).  Should be in [1,cr_burst_max] where cr_burst_max is
   min(rx[:].cr_max) and LONG_MAX when there are no receivers.

   cr_max is an upper bound of the number of credits a transmitter can
   have (e.g. how many credits a transmitter should get from a query
   when there are no active receivers).  Should be in
   [cr_burst,LONG_MAX].  0 indicates to pick a reasonable default for
   the configured receivers (e.g. cr_burst_max).  This limit is mostly
   for dynamic configured flow control situations (e.g. it provides an
   upper limit to how lazy the transmitter can be with flow control
   operations).

   cr_resume is the credit threshold (in a >= sense) for the fctl to
   stop trying to refill credits from active receivers.  Should be in
   [cr_burst,actual_cr_max] where actual_cr_max is the value determined
   above.  0 indicates to pick a reasonable default (e.g.
   cr_burst+floor((2/3)(actual_cr_max-cr_burst)).

   cr_refill is the credit threshold (in a < sense) for the fctl to
   start trying to refill its credits from active receivers.  Should be
   in [cr_burst,actual_cr_resume] where actual_cr_resume is the value
   determined above.  0 indicates to pick a reasonable default (e.g.
   cr_burst+floor((1/2)(actual_cr_resume-cr_burst)).

   Returns fctl on success (fctl configuration will be complete on
   return) and NULL on failure (logs details).  Reasons for failure
   include NULL fctl, too large cr_max, cr_resume, cr_refill.

   TL;DR Just say zeros for cr_{max,resume,refill} if you don't
   understand the above and this will usually do something reasonable. */

at_fctl_t *
at_fctl_cfg_done( at_fctl_t * fctl,
                  ulong       cr_burst,
                  ulong       cr_max,
                  ulong       cr_resume,
                  ulong       cr_refill );

/* Accessor APIs */

/* at_fctl_{rx_max,rx_cnt,
            cr_burst,cr_max,cr_resume,cr_refill,
            rx_cr_max,rx_seq_laddr,
            rx_seq_slow_laddr,rx_seq_slow_laddr_const}
   return the values configured during fctl initialization.

   These assume fctl is a local join to a configured fctl.  rx_cr_max,
   rx_seq_laddr, rx_slow_laddr and rx_slow_laddr_const further assume
   rx_idx is in [0,rx_cnt).  slow_laddr_const is a const-correct
   version of rx_slow_laddr. */

AT_FN_PURE static inline ulong at_fctl_rx_max   ( at_fctl_t const * fctl ) { return (ulong)fctl->rx_max; }
AT_FN_PURE static inline ulong at_fctl_rx_cnt   ( at_fctl_t const * fctl ) { return (ulong)fctl->rx_cnt; }
AT_FN_PURE static inline ulong at_fctl_cr_burst ( at_fctl_t const * fctl ) { return fctl->cr_burst;      }
AT_FN_PURE static inline ulong at_fctl_cr_max   ( at_fctl_t const * fctl ) { return fctl->cr_max;        }
AT_FN_PURE static inline ulong at_fctl_cr_resume( at_fctl_t const * fctl ) { return fctl->cr_resume;     }
AT_FN_PURE static inline ulong at_fctl_cr_refill( at_fctl_t const * fctl ) { return fctl->cr_refill;     }

AT_FN_PURE static inline ulong
at_fctl_rx_cr_max( at_fctl_t const * fctl,
                   ulong             rx_idx ) {
  return (ulong)at_fctl_private_rx_const( fctl )[rx_idx].cr_max;
}

AT_FN_PURE static inline ulong const *
at_fctl_rx_seq_laddr( at_fctl_t const * fctl,
                      ulong             rx_idx ) {
  return at_fctl_private_rx_const( fctl )[rx_idx].seq_laddr;
}

AT_FN_PURE static inline ulong *
at_fctl_rx_slow_laddr( at_fctl_t * fctl,
                       ulong       rx_idx ) {
  return at_fctl_private_rx( fctl )[rx_idx].slow_laddr;
}

AT_FN_PURE static inline ulong const *
at_fctl_rx_slow_laddr_const( at_fctl_t const * fctl,
                             ulong             rx_idx ) {
  return at_fctl_private_rx_const( fctl )[rx_idx].slow_laddr;
}

/* at_fctl_rx_cr_return updates users of _rx_seq flow control (e.g. from
   rx_seq_laddr above) the position of the receiver in sequence space
   (in the sense that the receiver has consumed all sequence numbers
   strictly before rx_seq cyclic).  This should be done moderately
   frequently (e.g. in background housekeeping) after the receiver has
   moved forward in sequence space since the last update and should be
   monotonically non-decreasing.  Even more aggressively is usually
   fine.  This also should be done when the receiver is shutdown to
   facilitate cleanly restarting a consumer and what not.  This also
   serves as a compiler memory fence to ensure credits are returned at a
   well defined point in the instruction stream (e.g. so that compiler
   doesn't move any loads that might be clobbered by the return to after
   the return). */

static inline void
at_fctl_rx_cr_return( ulong * _rx_seq,
                      ulong   rx_seq ) {
  AT_COMPILER_MFENCE();
  AT_VOLATILE( *_rx_seq ) = rx_seq;
  AT_COMPILER_MFENCE();
}

/**********************************************************************/

/* at_fctl_cr_query returns a lower bound of the number of credits
   available to a transmitter that has published up to but NOT INCLUDING
   tx_seq.  Will be in [0,cr_max].  On return, *_rx_idx_slow will
   contain the lowest indexed receiver that constrained the result or
   ULONG_MAX if the query result wasn't receiver constrained.

   This involves interthread communication so should be used sparingly. */

AT_FN_UNUSED static ulong /* Work around -Winline */
at_fctl_cr_query( at_fctl_t const * fctl,
                  ulong             tx_seq,
                  ulong *           _rx_idx_slow ) {
  at_fctl_private_rx_t const * rx     = at_fctl_private_rx_const( fctl );
  ulong                        rx_cnt = (ulong)fctl->rx_cnt;

  ulong cr_query    = fctl->cr_max;
  ulong rx_idx_slow = ULONG_MAX;

  /* Note: it is possible to do this in vectorized / in parallel */

  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
    ulong const * _rx_seq = rx[ rx_idx ].seq_laddr;
    if( AT_UNLIKELY( !_rx_seq ) ) continue; /* Skip inactive rx */

    ulong rx_seq      = AT_VOLATILE_CONST( *_rx_seq );
    ulong rx_cr_query = (ulong)at_long_max( rx[ rx_idx ].cr_max - at_long_max( at_seq_diff( tx_seq, rx_seq ), 0L ), 0L );
    rx_idx_slow       = at_ulong_if( rx_cr_query<cr_query, rx_idx, rx_idx_slow );
    cr_query          = at_ulong_min( rx_cr_query, cr_query );
  }

  _rx_idx_slow[0] = rx_idx_slow;
  return cr_query;
}

/* at_fctl_tx_cr_update returns the new number of credits available to
   a transmitter given the current number of credits available to that
   transmitter and the transmitter's position in sequence space.

   The vast majority of flow control scenarios (even incredibly
   intricate dynamic heterogeneous multiple consumer) can typically be
   handled with just this one call in the transmitter's run loop.

   It assumes that reliable receivers are updating their position in
   sequence space moderately frequently, the transmitter and receivers
   have reasonably large credit maxes (to provide a lot of tolerance for
   temporary receiver lagging and enough flexibility to keep the vast
   majority of flow credit management out of the critical path) and that
   reliable receivers asymptotically can keep up with the transmitter on
   average (which is implied anyway as otherwise the overall system is
   inherently doomed). */

static inline ulong
at_fctl_tx_cr_update( at_fctl_t * fctl,
                      ulong       cr_avail,
                      ulong       tx_seq ) {

  int in_refill = fctl->in_refill;

  if( AT_UNLIKELY( (cr_avail<fctl->cr_refill) | in_refill ) ) { /* Yes, strictly "<" */

    /* The number of credits available has just dropped below the
       transmitters refill threshold (such that we should enter the
       refilling state) or the transmitter is already in the refilling
       state ... query the receivers for the number of credits that
       might be available. */

    ulong rx_idx_slow;
    ulong cr_query = at_fctl_cr_query( fctl, tx_seq, &rx_idx_slow );

    if( AT_LIKELY( cr_query>=fctl->cr_resume ) ) { /* Yes, strictly ">=" */

      /* We got enough credits to resume.  Update the credits available
         and exit the refilling state. */

      fctl->in_refill = 0;
      cr_avail = cr_query;

    } else if( AT_LIKELY( !in_refill ) ) {

      /* We didn't get enough credits to resume and we are just entering
         the refilling state.  Attribute this event to the slowest
         receiver (i.e. rx_idx_low is likely limiting system performance
         / potentially causing backpressure / etc).  We don't bother
         with a proper atomic increment as this is just diagnostic;
         exact precision is not required for correctness (also, if there
         is no multiplexing of the rx's slow counter with counters on
         different threads, as is often the case, it will be exact
         anyway).  Note that because the refilling is typically
         triggered well before the transmitter is actual not able to
         send, this counter should be more thought of as a "rx_idx_slow
         might be a source of stalls on the transmitter" as opposed to
         "rx_idx_slow caused a stall". */

      if( AT_LIKELY( rx_idx_slow!=ULONG_MAX ) ) {
        ulong * slow = at_fctl_private_rx( fctl )[ rx_idx_slow ].slow_laddr;
        AT_COMPILER_MFENCE();
        slow[0] += 1UL;
        AT_COMPILER_MFENCE();
      }
      fctl->in_refill = 1;

    } /* else {

      // We didn't get enough credits to resume and we were already
      // in the refilling state.  So, nothing to update.

    } */

  }

  return cr_avail;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_src_tango_fctl_at_fctl_h */