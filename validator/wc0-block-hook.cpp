#include "wc0-block-hook.h"

namespace tos {
namespace validator {

std::function<void(td::Ref<vm::Cell>, td::Ref<vm::Cell>, BlockIdExt)> g_wc0_block_index_hook;

}  // namespace validator
}  // namespace tos
