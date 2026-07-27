#pragma once

#include "vm/cells.h"
#include "tos/tos-types.h"

namespace tos_wallet_index {

// Index every wc=0 transaction in an applied block into the wallet index, and
// (re)index token ownership verified against the post-apply shard state.
// Installed as tos::validator::g_wc0_block_index_hook by validator-engine.
// Best-effort: swallows parse errors so it never affects block application.
// `state_root` may be null; token indexing is then skipped (fail-closed).
// `block_id` must be the full BlockIdExt (not just workchain+seqno): the
// crash-recovery marker is keyed off it, and workchain+seqno alone is not
// unique across a shard split/merge.
void wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id);

}  // namespace tos_wallet_index
