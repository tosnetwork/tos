#ifndef HEADER_at_core_mempool_at_mempool_h
#define HEADER_at_core_mempool_at_mempool_h

#include "at/infra/alloc/at_alloc.h"
#include "at/core/mempool/at_mempool_types.h"
#include "at/core/storage/at_store.h"

AT_PROTOTYPES_BEGIN

typedef struct at_mempool at_mempool_t;
typedef void (*at_mempool_delete_cb_t)( void *                     ctx,
                                        uchar const                hash[32],
                                        at_mempool_entry_t const * entry );

/* Lifecycle */
int  at_mempool_init( at_mempool_t * mp,
                      at_alloc_t *   alloc,
                      ulong          max_txs,
                      ulong          max_senders,
                      ulong          max_txs_per_sender,
                      ulong          max_assets_per_acc );
void at_mempool_fini( at_mempool_t * mp );
at_mempool_t * at_mempool_new( at_alloc_t * alloc,
                               ulong        max_txs,
                               ulong        max_senders,
                               ulong        max_txs_per_sender,
                               ulong        max_assets_per_acc );
void at_mempool_set_disable_zkp_cache( at_mempool_t * mp, int disable );

/* Global handle (used by tiles) */
void            at_mempool_global_set( at_mempool_t * mp );
at_mempool_t *  at_mempool_global_get( void );

/* Core operations */
int   at_mempool_add_raw( at_mempool_t * mp,
                          uchar const *  raw,
                          ulong          raw_sz,
                          int            broadcast );
int   at_mempool_add_raw_with_state( at_mempool_t * mp,
                                     at_store_t *   store,
                                     void const *   environment,
                                     ulong          stable_topoheight,
                                     ulong          topoheight,
                                     uint           block_version,
                                     uchar const *  raw,
                                     ulong          raw_sz,
                                     int            broadcast );
int   at_mempool_clear( at_mempool_t * mp );
typedef struct {
  uchar  hash[32];
  uchar *raw;
  ulong  raw_sz;
} at_mempool_drain_entry_t;

typedef struct {
  uchar  hash[32];
  uchar *raw;
  ulong  raw_sz;
  ulong  first_seen_sec;
} at_mempool_deleted_entry_t;
int   at_mempool_drain( at_mempool_t *               mp,
                        at_mempool_drain_entry_t **  out_entries,
                        ulong *                      out_cnt,
                        at_alloc_t *                 alloc );
void  at_mempool_drain_free( at_mempool_drain_entry_t * entries,
                             ulong                     cnt,
                             at_alloc_t *               alloc );
int   at_mempool_stop( at_mempool_t * mp );
int   at_mempool_remove_hash( at_mempool_t * mp,
                              uchar const   hash[32] );
int   at_mempool_contains( at_mempool_t const * mp,
                           uchar const         hash[32] );
int   at_mempool_get_entry( at_mempool_t const * mp,
                            uchar const         hash[32],
                            at_mempool_entry_t * out_entry );
ulong at_mempool_size( at_mempool_t const * mp );
int   at_mempool_is_mainnet( at_mempool_t const * mp );

/* Fee rate estimation (per KB) */
int  at_mempool_estimate_fee_rates( at_mempool_t const * mp,
                                    ulong *             low_out,
                                    ulong *             medium_out,
                                    ulong *             high_out );
int  at_mempool_clean_up( at_mempool_t * mp,
                          at_store_t *   store,
                          void const *   environment,
                          ulong          stable_topoheight,
                          ulong          topoheight,
                          uint           block_version,
                          int            full );
int  at_mempool_clean_up_cb( at_mempool_t *          mp,
                             at_store_t *            store,
                             void const *            environment,
                             ulong                   stable_topoheight,
                             ulong                   topoheight,
                             uint                    block_version,
                             int                     full,
                             at_mempool_delete_cb_t  on_delete,
                             void *                  on_delete_ctx );
int  at_mempool_clean_up_deleted( at_mempool_t *                mp,
                                  at_store_t *                  store,
                                  void const *                  environment,
                                  ulong                         stable_topoheight,
                                  ulong                         topoheight,
                                  uint                          block_version,
                                  int                           full,
                                  at_mempool_deleted_entry_t ** out_entries,
                                  ulong *                       out_cnt,
                                  at_alloc_t *                  alloc );
void at_mempool_clean_up_deleted_free( at_mempool_deleted_entry_t * entries,
                                       ulong                        cnt,
                                       at_alloc_t *                 alloc );

/* Snapshot inventory for notify-inv */
int  at_mempool_snapshot_hashes( ulong   skip,
                                 ushort max,
                                 uchar  out[][32],
                                 ushort * out_cnt,
                                 int * out_has_more );

/* Cache access */
int  at_mempool_get_cache( at_mempool_t const * mp,
                           uchar const         owner[32],
                           at_mempool_cache_t * out_cache );

/* Iteration */
int  at_mempool_iter_init( at_mempool_t const * mp,
                           at_mempool_iter_t * it );
int  at_mempool_iter_next( at_mempool_iter_t * it,
                           at_mempool_entry_t * out_entry );

/* Cache iteration (per-sender groups) */
int  at_mempool_cache_iter_init( at_mempool_t const * mp,
                                 at_mempool_cache_iter_t * it );
int  at_mempool_cache_iter_next( at_mempool_cache_iter_t * it,
                                 at_mempool_cache_t const ** out_cache );

/* Cache helpers */
int  at_mempool_cache_get_hash_for_nonce( at_mempool_cache_t const * cache,
                                          ulong                      nonce,
                                          uchar                      out_hash[32] );

/* Tx selector (TOS daemon/core/tx_selector.rs parity) */
int  at_mempool_compare_tx_priority( at_mempool_entry_t const * a,
                                     at_mempool_entry_t const * b );
int  at_mempool_create_tx_selector_grouped( at_mempool_tx_selector_t * out_selector,
                                            at_alloc_t *               alloc,
                                            at_mempool_tx_group_t const * groups,
                                            ulong                      group_cnt );
int  at_mempool_create_tx_selector( at_mempool_t const *      mp,
                                    at_alloc_t *              alloc,
                                    at_mempool_tx_selector_t * out_selector );
int  at_mempool_add_tx_group( at_mempool_tx_selector_t * selector,
                              at_mempool_entry_t const * entries,
                              ulong                      entry_cnt );
int  at_mempool_get_next_tx( at_mempool_tx_selector_t * selector,
                             at_mempool_entry_t *       out_entry );
int  at_mempool_tx_selector_is_empty( at_mempool_tx_selector_t const * selector );
void at_mempool_tx_selector_fini( at_mempool_tx_selector_t * selector );

/* Allocator access (for transient work buffers) */
at_alloc_t * at_mempool_get_alloc( at_mempool_t const * mp );

AT_PROTOTYPES_END

#endif /* HEADER_at_core_mempool_at_mempool_h */
