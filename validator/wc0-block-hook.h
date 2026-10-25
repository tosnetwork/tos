#pragma once

#include <functional>

#include "td/utils/Status.h"
#include "tos/tos-types.h"
#include "vm/cells.h"

namespace tos {
namespace validator {

// Retired embedding seam retained for regression fixtures. Production block
// application never invokes it; standalone replay reads committed archives.
extern std::function<void(td::Ref<vm::Cell>, td::Ref<vm::Cell>, BlockIdExt, BlockSeqno)> g_wc0_block_index_hook;

}  // namespace validator
}  // namespace tos
