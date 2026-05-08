/*
    JVM Workchain — genesis ShardAccounts builder.

    Under v2 account-native topology there is no genesis JVM account; the
    initial wc=3 ShardAccounts dict is empty and contracts are materialized
    later by the host `action_create_account` path.  This produces the
    canonical `hme_empty$0` cell.

    Mirrors build_uno_zerostate_accounts_cell() (wc=2) and
    build_evm_zerostate_accounts_cell() (wc=1) at the dict-builder level.

    Source: TOS-specific integration point.
*/
#include "jvm/core/zerostate.h"

#include "block/block-auto.h"
#include "block/block-parse.h"  // block::tlb::aug_ShardAccounts
#include "block/block.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace jvm_workchain {

td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell() {
    // Empty AugmentedDictionary(256, aug_ShardAccounts) — the wc=3 genesis
    // shard has no preexisting accounts under the v2 account-native model.
    vm::AugmentedDictionary accounts_dict(256, block::tlb::aug_ShardAccounts);
    vm::CellBuilder cb;
    if (!accounts_dict.append_dict_to_bool(cb)) {
        return {};
    }
    return cb.finalize();
}

}  // namespace jvm_workchain
