#include "wc0-block-hook.h"

namespace tos {
namespace validator {

std::function<void(td::Ref<vm::Cell>, td::Ref<vm::Cell>, BlockIdExt)> g_wc0_block_index_hook;

void hand_stored_block_to_index(const td::Result<td::Ref<vm::Cell>> &block_root, td::Ref<vm::Cell> state_root,
                                const BlockIdExt &id) {
  if (!g_wc0_block_index_hook) {
    return;
  }
  auto root = block_root.is_ok() ? block_root.ok() : td::Ref<vm::Cell>{};
  g_wc0_block_index_hook(std::move(root), std::move(state_root), id);
}

}  // namespace validator
}  // namespace tos
