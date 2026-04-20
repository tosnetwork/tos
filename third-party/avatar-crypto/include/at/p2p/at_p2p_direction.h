#ifndef HEADER_at_waltz_p2p_at_p2p_direction_h
#define HEADER_at_waltz_p2p_at_p2p_direction_h

/* at_p2p_direction.h - TOS-aligned Direction/TimedDirection helpers

   Mirrors common/src/api/daemon/direction.rs:
   - Direction: In / Out / Both with update transition rules
   - TimedDirection: Direction + sent/received timestamps
*/

#include "at/infra/at_util_base.h"

AT_PROTOTYPES_BEGIN

typedef enum {
  AT_DIRECTION_NONE = 0,
  AT_DIRECTION_IN   = 1,
  AT_DIRECTION_OUT  = 2,
  AT_DIRECTION_BOTH = 3
} at_direction_t;

typedef struct {
  uchar direction;   /* at_direction_t encoded as uchar */
  uchar _pad[7];
  ulong received_at; /* Valid for IN/BOTH */
  ulong sent_at;     /* Valid for OUT/BOTH */
} at_timed_direction_t;

/* at_direction_update applies TOS Direction::update transition rules.
   Returns 1 if direction was updated, 0 otherwise. */
int
at_direction_update( uchar * direction,
                     uchar   incoming );

/* Constructors */
at_timed_direction_t
at_timed_direction_in( ulong received_at );

at_timed_direction_t
at_timed_direction_out( ulong sent_at );

at_timed_direction_t
at_timed_direction_both( ulong received_at,
                         ulong sent_at );

/* Predicates */
int
at_timed_direction_is_both( at_timed_direction_t const * direction );

int
at_timed_direction_is_in( at_timed_direction_t const * direction );

int
at_timed_direction_is_out( at_timed_direction_t const * direction );

int
at_timed_direction_contains_in( at_timed_direction_t const * direction );

int
at_timed_direction_contains_out( at_timed_direction_t const * direction );

/* at_timed_direction_update applies TOS TimedDirection::update transition rules.
   Returns 1 if direction was updated, 0 otherwise. */
int
at_timed_direction_update( at_timed_direction_t *       direction,
                           at_timed_direction_t const * incoming );

AT_PROTOTYPES_END

#endif /* HEADER_at_waltz_p2p_at_p2p_direction_h */
