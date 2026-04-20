#ifndef HEADER_at_blockdag_at_reorg_h
#define HEADER_at_blockdag_at_reorg_h

/* at_reorg.h - DAG reorganization rollback/replay helpers */

#include "at/infra/at_util_base.h"
#include "at/core/blockdag/at_dag_provider.h"
#include "at/core/storage/at_store.h"
#include "at/core/state/at_executor.h"

AT_PROTOTYPES_BEGIN

typedef int
(*at_dag_reorg_block_commit_cb_t)( void *             callback_ctx,
                                   uchar const *       block_hash,
                                   ulong               topoheight,
                                   void const *        block_wire,
                                   ulong               block_wire_sz );

/* Reorganize DAG state and replay execution above stable limit.
   Returns 0 on success, -1 on error. out_reorged is set to 1 if any
   rollback/replay was performed, 0 otherwise. If new_block_hash is
   non-NULL and the block ends up orphaned, its txs are linked to it. */
int
at_dag_reorg_replay( at_dag_provider_t * dag,
                     at_store_t *        store,
                     at_executor_t *     exec,
                     uchar const *       new_block_hash,
                     at_topoheight_t     stable_limit,
                     int *               out_reorged,
                     void *              callback_ctx,
                     at_dag_reorg_block_commit_cb_t commit_cb );

/* Returns 1 if a reorg wrote new ordering since last poll, else 0. */
int
at_dag_reorg_poll_and_clear( void );

/* Checkpoint-based deep-reorg prevention.
   get returns the current checkpoint topoheight.
   set updates and returns the previous value. */
ulong at_dag_get_checkpoint_topoheight( void );
ulong at_dag_set_checkpoint_topoheight( ulong topoheight );

AT_PROTOTYPES_END

#endif /* HEADER_at_blockdag_at_reorg_h */
