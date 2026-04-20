#ifndef HEADER_at_store_snapshot_iterator_mode_h
#define HEADER_at_store_snapshot_iterator_mode_h

#include "at/core/storage/at_store.h"

/* at_store_snapshot_iterator_mode.h
   TOS snapshot/iterator_mode.rs aligned C helper:
   unified iterator seek/advance/valid checks. */

AT_PROTOTYPES_BEGIN

typedef enum at_store_snapshot_direction {
  AT_STORE_SNAPSHOT_DIRECTION_FORWARD = 0,
  AT_STORE_SNAPSHOT_DIRECTION_REVERSE = 1
} at_store_snapshot_direction_t;

typedef enum at_store_snapshot_iter_mode_kind {
  AT_STORE_SNAPSHOT_ITER_MODE_START       = 0,
  AT_STORE_SNAPSHOT_ITER_MODE_END         = 1,
  AT_STORE_SNAPSHOT_ITER_MODE_FROM        = 2,
  AT_STORE_SNAPSHOT_ITER_MODE_WITH_PREFIX = 3,
  AT_STORE_SNAPSHOT_ITER_MODE_RANGE       = 4
} at_store_snapshot_iter_mode_kind_t;

typedef struct at_store_snapshot_iter_mode {
  at_store_snapshot_iter_mode_kind_t kind;
  at_store_snapshot_direction_t       direction;
  void const *                        key;
  ulong                               key_sz;
  void const *                        lower_bound;
  ulong                               lower_bound_sz;
  void const *                        upper_bound; /* exclusive */
  ulong                               upper_bound_sz;
} at_store_snapshot_iter_mode_t;

at_store_snapshot_iter_mode_t
at_store_snapshot_iter_mode_start( void );

at_store_snapshot_iter_mode_t
at_store_snapshot_iter_mode_end( void );

at_store_snapshot_iter_mode_t
at_store_snapshot_iter_mode_from( void const *                    key,
                                  ulong                           key_sz,
                                  at_store_snapshot_direction_t   direction );

at_store_snapshot_iter_mode_t
at_store_snapshot_iter_mode_with_prefix( void const *                  prefix,
                                         ulong                         prefix_sz,
                                         at_store_snapshot_direction_t direction );

at_store_snapshot_iter_mode_t
at_store_snapshot_iter_mode_range( void const *                    lower_bound,
                                   ulong                           lower_bound_sz,
                                   void const *                    upper_bound,
                                   ulong                           upper_bound_sz,
                                   at_store_snapshot_direction_t   direction );

int
at_store_snapshot_iter_seek_mode( at_store_iter_t *                          iter,
                                  at_store_snapshot_iter_mode_t const *       mode );

int
at_store_snapshot_iter_valid_mode( at_store_iter_t *                          iter,
                                   at_store_snapshot_iter_mode_t const *       mode );

void
at_store_snapshot_iter_next_mode( at_store_iter_t *                           iter,
                                  at_store_snapshot_iter_mode_t const *        mode );

AT_PROTOTYPES_END

#endif /* HEADER_at_store_snapshot_iterator_mode_h */
