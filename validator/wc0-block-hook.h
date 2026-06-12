#pragma once

#include <functional>

#include "vm/cells.h"

namespace tos {
namespace validator {

// Global hook invoked when a block is applied, so an out-of-library indexer
// (installed by validator-engine) can index wc=0 transactions without the
// validator library depending on the indexer implementation. Empty by default.
//
// Signature: (block root cell, post-apply shard state root cell, workchain id,
// block seqno). The state root is the indexer's ground truth: token ownership
// is verified against committed contract state, never against message claims.
// It may be null (e.g. data re-indexed without state at hand) — the callee must
// then degrade to state-independent indexing only. Best-effort: the callee must
// not throw into the consensus path.
extern std::function<void(td::Ref<vm::Cell>, td::Ref<vm::Cell>, int, unsigned)> g_wc0_block_index_hook;

}  // namespace validator
}  // namespace tos
