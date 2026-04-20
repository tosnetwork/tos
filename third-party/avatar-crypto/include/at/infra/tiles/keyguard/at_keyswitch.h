#ifndef HEADER_at_disco_keyguard_at_keyswitch_h
#define HEADER_at_disco_keyguard_at_keyswitch_h

/* at_keyswitch.h - Validator key switching mechanism

   Provides APIs for out-of-band switching of the validator's identity
   key. This allows hot key rotation without stopping the validator. */

#include "at/infra/tiles/at_disco_base.h"

#define AT_KEYSWITCH_ALIGN     (128UL)
#define AT_KEYSWITCH_FOOTPRINT (128UL)

#define AT_KEYSWITCH_MAGIC (0xa7a7a7c37830000UL) /* avatar ks ver 0 */

/* Keyswitch states */
#define AT_KEYSWITCH_STATE_UNLOCKED       (0UL)
#define AT_KEYSWITCH_STATE_LOCKED         (1UL)
#define AT_KEYSWITCH_STATE_SWITCH_PENDING (2UL)
#define AT_KEYSWITCH_STATE_UNHALT_PENDING (3UL)
#define AT_KEYSWITCH_STATE_FAILED         (4UL)
#define AT_KEYSWITCH_STATE_COMPLETED      (5UL)

struct __attribute__((aligned(AT_KEYSWITCH_ALIGN))) at_keyswitch_private {
  ulong magic;     /* ==AT_KEYSWITCH_MAGIC */
  ulong state;
  ulong result;
  ulong param;
  uchar bytes[ 64UL ];
  /* Padding to AT_KEYSWITCH_ALIGN here */
};

typedef struct at_keyswitch_private at_keyswitch_t;

AT_PROTOTYPES_BEGIN

/* at_keyswitch_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a keyswitch.
   at_keyswitch_align returns AT_KEYSWITCH_ALIGN. */

AT_FN_CONST ulong
at_keyswitch_align( void );

AT_FN_CONST ulong
at_keyswitch_footprint( void );

/* at_keyswitch_new formats an unused memory region for use as a
   keyswitch. Assumes shmem is a non-NULL pointer to this region in the
   local address space with the required footprint and alignment. The
   keyswitch will be initialized to have the given state (should be in
   [0,UINT_MAX]). Returns shmem (and the memory region it points to
   will be formatted as a keyswitch, caller is not joined) and NULL on
   failure (logs details). Reasons for failure include an obviously bad
   shmem region. */

void *
at_keyswitch_new( void * shmem,
                  ulong  state );

/* at_keyswitch_join joins the caller to the keyswitch. shks points to
   the first byte of the memory region backing the keyswitch in the
   caller's address space. Returns a pointer in the local address space
   to the keyswitch on success (this should not be assumed to be just a
   cast of shks) or NULL on failure (logs details). Reasons for failure
   include the shks is obviously not a local pointer to a memory region
   holding a keyswitch. Every successful join should have a matching
   leave. The lifetime of the join is until the matching leave or
   caller's thread group is terminated. */

at_keyswitch_t *
at_keyswitch_join( void * shks );

/* at_keyswitch_leave leaves a current local join. Returns a pointer to
   the underlying shared memory region on success (this should not be
   assumed to be just a cast of ks) and NULL on failure (logs details).
   Reasons for failure include ks is NULL. */

void *
at_keyswitch_leave( at_keyswitch_t const * ks );

/* at_keyswitch_delete unformats a memory region used as a keyswitch.
   Assumes nobody is joined to the region. Returns a pointer to the
   underlying shared memory region or NULL if used obviously in error
   (e.g. shks obviously does not point to a keyswitch ... logs details).
   The ownership of the memory region is transferred to the caller on
   success. */

void *
at_keyswitch_delete( void * shks );

/* at_keyswitch_state_query observes the current state posted to the
   keyswitch. Assumes ks is a current local join. This is a compiler
   fence. Returns the current state on the ks at some point in time
   between when this was called and this returned. */

static inline ulong
at_keyswitch_state_query( at_keyswitch_t const * ks ) {
  AT_COMPILER_MFENCE();
  ulong s = AT_VOLATILE_CONST( ks->state );
  AT_COMPILER_MFENCE();
  return s;
}

/* at_keyswitch_param_query observes the current param posted to the
   keyswitch. Assumes ks is a current local join. This is a compiler
   fence. Returns the current param on the ks at some point in time
   between when this was called and this returned. */

static inline ulong
at_keyswitch_param_query( at_keyswitch_t const * ks ) {
  AT_COMPILER_MFENCE();
  ulong s = AT_VOLATILE_CONST( ks->param );
  AT_COMPILER_MFENCE();
  return s;
}

/* at_keyswitch_result_query observes the current result posted to the
   keyswitch. Assumes ks is a current local join. This is a compiler
   fence. Returns the current result on the ks at some point in time
   between when this was called and this returned. */

static inline ulong
at_keyswitch_result_query( at_keyswitch_t const * ks ) {
  AT_COMPILER_MFENCE();
  ulong s = AT_VOLATILE_CONST( ks->result );
  AT_COMPILER_MFENCE();
  return s;
}

/* at_keyswitch_state sets the state of the keyswitch. Assumes ks is a
   current local join and the caller is currently allowed to do a
   transition to the new state. */

static inline void
at_keyswitch_state( at_keyswitch_t * ks,
                    ulong            s ) {
  AT_COMPILER_MFENCE();
  AT_VOLATILE( ks->state ) = s;
  AT_COMPILER_MFENCE();
}

/* at_keyswitch_param sets the param of the keyswitch. */

static inline void
at_keyswitch_param( at_keyswitch_t * ks,
                    ulong            p ) {
  AT_COMPILER_MFENCE();
  AT_VOLATILE( ks->param ) = p;
  AT_COMPILER_MFENCE();
}

/* at_keyswitch_result sets the result of the keyswitch. */

static inline void
at_keyswitch_result( at_keyswitch_t * ks,
                     ulong            r ) {
  AT_COMPILER_MFENCE();
  AT_VOLATILE( ks->result ) = r;
  AT_COMPILER_MFENCE();
}

/* at_keyswitch_bytes returns a pointer to the 64-byte buffer in the
   keyswitch for storing key data during transitions. */

static inline uchar *
at_keyswitch_bytes( at_keyswitch_t * ks ) {
  return ks->bytes;
}

static inline uchar const *
at_keyswitch_bytes_const( at_keyswitch_t const * ks ) {
  return ks->bytes;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_keyguard_at_keyswitch_h */