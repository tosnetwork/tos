#ifndef HEADER_at_store_snapshot_mod_h
#define HEADER_at_store_snapshot_mod_h

#include "at/core/storage/at_store.h"
#include "at/core/storage/at_store_snapshot_bytes_view.h"
#include "at/core/storage/at_store_snapshot_iterator_mode.h"

/* at_store_snapshot_mod.h
   TOS snapshot/mod.rs aligned in-memory snapshot overlay:
   per-column writes + merged lazy iteration with disk iterator. */

AT_PROTOTYPES_BEGIN

typedef enum at_store_snapshot_entry_state {
  AT_STORE_SNAPSHOT_ENTRY_STORED  = 1,
  AT_STORE_SNAPSHOT_ENTRY_DELETED = 2,
  AT_STORE_SNAPSHOT_ENTRY_ABSENT  = 3
} at_store_snapshot_entry_state_t;

typedef struct at_store_snapshot_write {
  uchar * key;
  ulong   key_sz;
  uchar * val;
  ulong   val_sz;
  int     has_val;
} at_store_snapshot_write_t;

typedef struct at_store_snapshot_changes {
  at_store_snapshot_write_t * writes;
  ulong                       cnt;
  ulong                       cap;
} at_store_snapshot_changes_t;

typedef struct at_store_snapshot_mod {
  at_alloc_t *                 alloc;
  at_store_snapshot_changes_t  trees[ AT_CF_COUNT ];
} at_store_snapshot_mod_t;

int
at_store_snapshot_mod_init( at_store_snapshot_mod_t * snapshot,
                            at_alloc_t *              alloc );

void
at_store_snapshot_mod_fini( at_store_snapshot_mod_t * snapshot );

int
at_store_snapshot_mod_clone_mut( at_store_snapshot_mod_t *       out,
                                 at_store_snapshot_mod_t const * src,
                                 at_alloc_t *                    alloc );

int
at_store_snapshot_mod_put( at_store_snapshot_mod_t *         snapshot,
                           at_cf_t                           cf,
                           void const *                      key,
                           ulong                             key_sz,
                           void const *                      val,
                           ulong                             val_sz,
                           at_store_snapshot_entry_state_t * prev_state_out );

int
at_store_snapshot_mod_delete( at_store_snapshot_mod_t *         snapshot,
                              at_cf_t                           cf,
                              void const *                      key,
                              ulong                             key_sz,
                              at_store_snapshot_entry_state_t * prev_state_out );

int
at_store_snapshot_mod_get( at_store_snapshot_mod_t const * snapshot,
                           at_cf_t                         cf,
                           void const *                    key,
                           ulong                           key_sz,
                           at_store_snapshot_entry_state_t * state_out,
                           at_store_bytes_view_t *           value_out );

int
at_store_snapshot_mod_get_size( at_store_snapshot_mod_t const * snapshot,
                                at_cf_t                         cf,
                                void const *                    key,
                                ulong                           key_sz,
                                at_store_snapshot_entry_state_t * state_out,
                                ulong *                          size_out );

int
at_store_snapshot_mod_contains( at_store_snapshot_mod_t const * snapshot,
                                at_cf_t                         cf,
                                void const *                    key,
                                ulong                           key_sz,
                                int *                           has_state_out,
                                int *                           present_out );

int
at_store_snapshot_mod_contains_key( at_store_snapshot_mod_t const * snapshot,
                                    at_cf_t                         cf,
                                    void const *                    key,
                                    ulong                           key_sz,
                                    int *                           present_out );

ulong
at_store_snapshot_mod_count_entries( at_store_snapshot_mod_t const *          snapshot,
                                     at_cf_t                                  cf,
                                     at_store_snapshot_iter_mode_t const *    mode,
                                     at_store_iter_t *                        disk_iter );

int
at_store_snapshot_mod_is_empty( at_store_snapshot_mod_t const *             snapshot,
                                at_cf_t                                     cf,
                                at_store_snapshot_iter_mode_t const *       mode,
                                at_store_iter_t *                           disk_iter );

typedef int (*at_store_snapshot_visit_raw_fn)( void *                             ctx,
                                               at_store_bytes_view_t const *      key,
                                               at_store_bytes_view_t const *      val );

int
at_store_snapshot_mod_lazy_iter_raw( at_store_snapshot_mod_t const *         snapshot,
                                     at_cf_t                                 cf,
                                     at_store_snapshot_iter_mode_t const *   mode,
                                     at_store_iter_t *                       disk_iter,
                                     at_store_snapshot_visit_raw_fn          visitor,
                                     void *                                  visitor_ctx,
                                     ulong *                                 yielded_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_store_snapshot_mod_h */
