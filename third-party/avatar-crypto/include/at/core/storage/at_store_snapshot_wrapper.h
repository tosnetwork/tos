#ifndef HEADER_at_store_snapshot_wrapper_h
#define HEADER_at_store_snapshot_wrapper_h

#include "at/core/storage/at_store.h"

/* at_store_snapshot_wrapper.h
   TOS snapshot/wrapper.rs aligned C helper:
   keeps a detached snapshot and swaps it into store for guarded access. */

#if AT_HAS_THREADS
#include <pthread.h>
#endif

AT_PROTOTYPES_BEGIN

typedef struct at_store_snapshot_wrapper {
  at_store_t * store;
  void *       snapshot; /* opaque at_store_snapshot_mod_t* */
#if AT_HAS_THREADS
  pthread_mutex_t mutex;
#endif
} at_store_snapshot_wrapper_t;

typedef struct at_store_snapshot_guard {
  at_store_snapshot_wrapper_t * wrapper;
  int                           active;
} at_store_snapshot_guard_t;

typedef enum at_store_holder_kind {
  AT_STORE_HOLDER_KIND_STORE    = 0,
  AT_STORE_HOLDER_KIND_SNAPSHOT = 1
} at_store_holder_kind_t;

typedef struct at_store_holder {
  at_store_holder_kind_t kind;
  union {
    at_store_t *                 store;
    at_store_snapshot_wrapper_t * wrapper;
  } as;
} at_store_holder_t;

typedef struct at_store_read_guard {
  at_store_t *              store;
  at_store_snapshot_guard_t snapshot_guard;
  int                       via_snapshot;
} at_store_read_guard_t;

typedef struct at_store_write_guard {
  at_store_t *              store;
  at_store_snapshot_guard_t snapshot_guard;
  int                       via_snapshot;
} at_store_write_guard_t;

int
at_store_snapshot_wrapper_init( at_store_snapshot_wrapper_t * wrapper,
                                at_store_t *                  store );

void
at_store_snapshot_wrapper_fini( at_store_snapshot_wrapper_t * wrapper );

int
at_store_snapshot_wrapper_has_snapshot( at_store_snapshot_wrapper_t const * wrapper,
                                        int *                               has_snapshot_out );

int
at_store_snapshot_wrapper_lock( at_store_snapshot_wrapper_t * wrapper,
                                at_store_snapshot_guard_t *   guard_out );

int
at_store_snapshot_guard_unlock( at_store_snapshot_guard_t * guard );

at_store_holder_t
at_store_holder_from_store( at_store_t * store );

at_store_holder_t
at_store_holder_from_snapshot( at_store_snapshot_wrapper_t * wrapper );

int
at_store_holder_read_lock( at_store_holder_t const * holder,
                           at_store_read_guard_t *   guard_out );

int
at_store_holder_write_lock( at_store_holder_t const * holder,
                            at_store_write_guard_t *  guard_out );

void
at_store_holder_read_unlock( at_store_read_guard_t * guard );

void
at_store_holder_write_unlock( at_store_write_guard_t * guard );

AT_PROTOTYPES_END

#endif /* HEADER_at_store_snapshot_wrapper_h */
