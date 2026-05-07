/*
    JVM Workchain — genesis account builder.

    Produces the ShardAccounts dict cell for the wc=3 shard genesis block.
    The cell contains exactly one account: the singleton executor account at
    0x0000…0001 seeded as acc_uninit with zero balance.

    Mirrors build_uno_zerostate_accounts_cell() (wc=2) and
    build_evm_zerostate_accounts_cell() (wc=1).

    TLB layout used (from block.tlb / block-auto.h):
      account$1
        addr:MsgAddressInt  ← addr_std$10 anycast:Nothing wc=3 addr=0x0…01
        storage_stat:StorageInfo
        storage:AccountStorage
      = Account;

      account_storage$_
        last_trans_lt:uint64
        balance:CurrencyCollection
        state:AccountState
      = AccountStorage;

      account_uninit$00 = AccountState;

    Source: TOS-specific integration point.
*/
#include "jvm/core/zerostate.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"
#include "td/utils/bits.h"

namespace jvm_workchain {

namespace {

constexpr int kJvmWorkchainId = 3;

// Singleton executor address: 0x0000…0001, matching dispatch-engine.cpp and
// doc/jvm-roadmap.md §Singleton executor account.
constexpr unsigned char kJvmExecutorAddressBytes[32] = {
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1,
};

}  // namespace

td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell() {
    using td::make_refint;

    // 1. AccountStorage = last_trans_lt:0 balance:zero state:account_uninit$00
    vm::CellBuilder as_cb;
    as_cb.store_long_bool(0, 64);                                 // last_trans_lt
    bool ok = block::CurrencyCollection{make_refint(0)}.store(as_cb);  // balance
    if (!ok) {
        return {};
    }
    as_cb.store_long_bool(0, 2);                                  // account_uninit$00
    auto storage_cell = as_cb.finalize();

    // 2. StorageInfo.used computed from the storage cell (deterministic).
    vm::CellStorageStat stats;
    auto stat_status = stats.compute_used_storage(td::Ref<vm::Cell>(storage_cell));
    if (stat_status.is_error()) {
        return {};
    }

    // 3. Account = account$1 addr:addr_std$10 wc=3 addr storage_stat storage
    vm::CellBuilder acc_cb;
    acc_cb.store_long_bool(1, 1);                                 // account$1
    acc_cb.store_long_bool(2, 2);                                 // addr_std$10
    acc_cb.store_long_bool(0, 1);                                 // anycast: nothing
    ok = acc_cb.store_long_rchk_bool(kJvmWorkchainId, 8);        // workchain_id
    if (!ok) {
        return {};
    }
    acc_cb.store_bytes(kJvmExecutorAddressBytes, 32);             // address bits
    // storage_stat:StorageInfo = used:StorageUsed extra:StorageExtraInfo
    //                            last_paid:uint32 due_payment:Maybe(Tomis)
    ok = block::store_UInt7(acc_cb, stats.cells)
         && block::store_UInt7(acc_cb, stats.bits);
    if (!ok) {
        return {};
    }
    acc_cb.store_zeroes_bool(3);                                  // extra:StorageExtraInfo (regular$0 + 2 bits)
    acc_cb.store_long_bool(0, 33);                                // last_paid:uint32(0) + due_payment:nothing
    ok = acc_cb.append_data_cell_bool(storage_cell);             // storage:AccountStorage
    if (!ok) {
        return {};
    }
    auto account_cell = acc_cb.finalize();

    // Validate — catches TLB-encoding bugs early.
    if (!block::gen::t_Account.validate_ref(account_cell)) {
        return {};
    }

    // 4. Wrap as a ShardAccount entry and insert as the sole dict value.
    //    ShardAccounts dict value layout: ^Account + last_trans_hash:bits256
    //    + last_trans_lt:uint64 (= 320 trailing zero bits at genesis).
    vm::AugmentedDictionary accounts_dict(256, block::tlb::aug_ShardAccounts);
    vm::CellBuilder vcb;
    if (!vcb.store_ref_bool(account_cell)) {
        return {};
    }
    vcb.store_zeroes_bool(256 + 64);                              // last_trans_hash + last_trans_lt
    accounts_dict.set_builder(td::ConstBitPtr{kJvmExecutorAddressBytes}, 256, vcb);

    vm::CellBuilder cb;
    accounts_dict.append_dict_to_bool(cb);
    return cb.finalize();
}

}  // namespace jvm_workchain
