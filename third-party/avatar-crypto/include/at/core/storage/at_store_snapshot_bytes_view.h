#ifndef HEADER_at_store_snapshot_bytes_view_h
#define HEADER_at_store_snapshot_bytes_view_h

#include "at/core/storage/at_store.h"

/* at_store_snapshot_bytes_view.h
   TOS snapshot/bytes_view.rs aligned C helper:
   unified zero-copy/copyable view over byte storage. */

AT_PROTOTYPES_BEGIN

typedef enum at_store_bytes_view_kind {
  AT_STORE_BYTES_VIEW_NONE  = 0,
  AT_STORE_BYTES_VIEW_REF   = 1,
  AT_STORE_BYTES_VIEW_OWNED = 2
} at_store_bytes_view_kind_t;

typedef struct at_store_bytes_view {
  uchar const *              data;
  ulong                      data_sz;
  at_store_bytes_view_kind_t kind;
  uchar *                    owned;
  at_alloc_t *               alloc;
} at_store_bytes_view_t;

void
at_store_bytes_view_init_empty( at_store_bytes_view_t * view );

void
at_store_bytes_view_init_ref( at_store_bytes_view_t * view,
                              void const *            data,
                              ulong                   data_sz );

int
at_store_bytes_view_init_copy( at_store_bytes_view_t * view,
                               at_alloc_t *            alloc,
                               void const *            data,
                               ulong                   data_sz );

void
at_store_bytes_view_fini( at_store_bytes_view_t * view );

int
at_store_bytes_view_from_iter_key( at_store_iter_t * iter,
                                   at_store_bytes_view_t * view );

int
at_store_bytes_view_from_iter_val( at_store_iter_t * iter,
                                   at_store_bytes_view_t * view );

AT_FN_PURE static inline void const *
at_store_bytes_view_data( at_store_bytes_view_t const * view ) {
  return view ? (void const *)view->data : NULL;
}

AT_FN_PURE static inline ulong
at_store_bytes_view_size( at_store_bytes_view_t const * view ) {
  return view ? view->data_sz : 0UL;
}

AT_FN_PURE static inline int
at_store_bytes_view_is_empty( at_store_bytes_view_t const * view ) {
  return !view || view->data_sz == 0UL;
}

AT_PROTOTYPES_END

#endif /* HEADER_at_store_snapshot_bytes_view_h */
