#pragma once

#include "vm/cells.h"

namespace tos_wallet_index {

// Index every wc=0 transaction in an applied block into the wallet index, and
// (re)index token ownership verified against the post-apply shard state.
// Installed as tos::validator::g_wc0_block_index_hook by validator-engine.
// Best-effort: swallows parse errors so it never affects block application.
// `state_root` may be null; token indexing is then skipped (fail-closed).
void wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, int workchain,
                     unsigned seqno);

}  // namespace tos_wallet_index
