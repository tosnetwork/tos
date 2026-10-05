#pragma once

#include <functional>

#include "td/utils/Status.h"
#include "tos/tos-types.h"
#include "vm/cells.h"

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
// message claims.
// Either cell may be null: ApplyBlock passes only what it already holds and
// never reads anything back for the hook, so a block whose data was already
// in the database arrives as its id alone. The callee must then obtain the
// data itself, off the block-application path.
// The callee must return without waiting (no I/O, no lock held across I/O)
// and must not throw into the consensus path.
extern std::function<void(td::Ref<vm::Cell>, td::Ref<vm::Cell>, BlockIdExt)> g_wc0_block_index_hook;

}  // namespace validator
}  // namespace tos
