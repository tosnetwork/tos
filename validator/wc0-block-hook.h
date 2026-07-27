#pragma once

#include <functional>

#include "vm/cells.h"
#include "tos/tos-types.h"

namespace tos {
namespace validator {

// Global hook invoked when a block is applied, so an out-of-library indexer
// (installed by validator-engine) can index wc=0 transactions without the
// validator library depending on the indexer implementation. Empty by default.
//
// Signature: (block root cell, post-apply shard state root cell, full block
// id). The full BlockIdExt (not just workchain+seqno) is required so a
// crash-recovery marker keyed off it unambiguously identifies one specific
// block, even across shard splits/merges where a different shard can reuse
// the same seqno. The state root is the indexer's ground truth: token
// ownership is verified against committed contract state, never against
// message claims. It may be null (e.g. data re-indexed without state at
// hand) — the callee must then degrade to state-independent indexing only.
// Best-effort: the callee must not throw into the consensus path.
extern std::function<void(td::Ref<vm::Cell>, td::Ref<vm::Cell>, BlockIdExt)> g_wc0_block_index_hook;

}  // namespace validator
}  // namespace tos
