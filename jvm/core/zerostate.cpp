/*
    JVM Workchain — genesis ShardAccounts builder.

    The empty form returns the canonical `hme_empty$0` cell so the
    wc=3 ShardAccounts dict is well-formed even when no wallets are
    seeded at genesis.

    The parameterized form walks the supplied wallet list, materializes
    each one through `build_jvm_genesis_wallet`, and inserts the
    resulting ShardAccount entry into an `aug_ShardAccounts` dictionary
    keyed on the derived wc=3 address.  Duplicate-address detection
    relies on the AugmentedDictionary itself failing the second
    `set_builder` for the same key.

    Source: TOS-specific integration point.
*/
#include "jvm/core/zerostate.h"

#include "block/block-auto.h"
#include "block/block-parse.h"  // block::tlb::aug_ShardAccounts
#include "block/block.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"

namespace jvm_workchain {

namespace {

td::Ref<vm::Cell> finalize_accounts_dict(vm::AugmentedDictionary& dict) {
    vm::CellBuilder cb;
    if (!dict.append_dict_to_bool(cb)) {
        return {};
    }
    return cb.finalize();
}

}  // namespace

td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell() {
    vm::AugmentedDictionary accounts_dict(256, block::tlb::aug_ShardAccounts);
    return finalize_accounts_dict(accounts_dict);
}

td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell(
    const std::vector<JvmGenesisWallet>& wallets,
    const std::array<std::uint8_t, 32>& stdlib_hash,
    td::Slice wallet_class_bytes) {
    vm::AugmentedDictionary accounts_dict(256, block::tlb::aug_ShardAccounts);
    for (const auto& wallet : wallets) {
        auto built_res = build_jvm_genesis_wallet(wallet, stdlib_hash,
                                                   wallet_class_bytes);
        if (built_res.is_error()) {
            return {};
        }
        auto built = built_res.move_as_ok();
        // ShardAccount value is the cellslice of `^Account ||
        // last_trans_hash || last_trans_lt`; `set_builder` accepts a
        // CellBuilder, so we reconstruct it from the entry cell.
        auto entry_cs = vm::load_cell_slice(built.shard_account_cell);
        vm::CellBuilder vcb;
        if (!vcb.append_cellslice_bool(std::move(entry_cs))) {
            return {};
        }
        if (!accounts_dict.set_builder(
                td::ConstBitPtr{built.address.data()}, 256, vcb)) {
            // Duplicate address (caller declared two wallets with the
            // same (deployer, salt, class_hash, init_args, manifest));
            // fail the whole genesis build.
            return {};
        }
    }
    return finalize_accounts_dict(accounts_dict);
}

}  // namespace jvm_workchain
