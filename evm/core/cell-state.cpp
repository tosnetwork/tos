/*
    EVM Workchain — cell-native state implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/cell-state.h"
#include "evm/core/cell-codec.h"
#include "evm/core/workchain.h"

#include <silkworm/core/common/empty_hashes.hpp>
#include <ethash/keccak.hpp>

#include "block/block.h"             // store_UInt7, CurrencyCollection
#include "block/block-auto.h"        // block::gen::t_AccountState, t_Account
#include "block/evm-workchain-dispatch.h"  // get_evm_code_marker_cell
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace evm_workchain {

namespace {

bool decode_storage_slice(td::Ref<vm::CellSlice> value, evmc::bytes32& out) {
    out = {};
    if (value.is_null() || value->size() != 256 || value->size_refs() != 0) {
        return false;
    }
    return value.write().fetch_bytes(out.bytes, 32);
}

bool validate_storage_root(td::Ref<vm::Cell> root) {
    if (root.is_null()) return true;
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(root, special);
        if (special) return false;
        vm::Dictionary storage(root, 256);
        bool ok = true;
        bool walked = storage.check_for_each([&ok](td::Ref<vm::CellSlice> value,
                                                   td::ConstBitPtr /*key*/, int n) -> bool {
            evmc::bytes32 ignored{};
            if (n != 256 || !decode_storage_slice(value, ignored)) {
                ok = false;
                return false;
            }
            return true;
        });
        return walked && ok;
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

td::BitArray<64> block_num_key(silkworm::BlockNum block_num) {
    td::BitArray<64> key;
    key.store_ulong(block_num);
    return key;
}

void prune_canonical_hashes(std::unordered_map<silkworm::BlockNum, evmc::bytes32>& canonical) {
    constexpr size_t kEvmBlockHashWindow = 256;
    if (canonical.size() <= kEvmBlockHashWindow) {
        return;
    }
    std::vector<silkworm::BlockNum> nums;
    nums.reserve(canonical.size());
    for (const auto& [block_num, _] : canonical) {
        nums.push_back(block_num);
    }
    std::sort(nums.begin(), nums.end());
    const size_t remove_count = nums.size() - kEvmBlockHashWindow;
    for (size_t i = 0; i < remove_count; ++i) {
        canonical.erase(nums[i]);
    }
}

}  // namespace

thread_local silkworm::Bytes CellEvmState::tl_code_buf_;

CellEvmState::CellEvmState() : account_dict_(256) {}

// ---------------------------------------------------------------------------
// Read interface
// ---------------------------------------------------------------------------

std::optional<silkworm::Account> CellEvmState::read_account(
    const evmc::address& address) const noexcept {
    unsigned char key[32];
    address_to_key(address, key);
    auto cs = account_dict_.lookup(td::ConstBitPtr{key}, 256);
    if (cs.is_null()) return std::nullopt;
    // The dict value is a CellSlice referencing the EvmAccountData cell.
    // We stored it as a single ref; fetch it.
    if (cs->size_refs() == 0) return std::nullopt;
    auto cell = cs->prefetch_ref(0);
    silkworm::Account acct;
    td::Ref<vm::Cell> storage_root;
    if (!decode_evm_account_data(cell, acct, storage_root)) return std::nullopt;
    return acct;
}

silkworm::ByteView CellEvmState::read_code(
    const evmc::address& /*address*/, const evmc::bytes32& code_hash) const noexcept {
    if (code_hash == silkworm::kEmptyHash) return {};
    auto it = code_.find(code_hash);
    if (it == code_.end()) return {};
    // Return a ByteView pointing **into** the map entry's stable storage.
    // Earlier we copied into a single `tl_code_buf_` thread_local — that
    // was a bug: silkworm's IntraBlockState caches the ByteView in its
    // `existing_code_` map, and the next read_code() for a different
    // code_hash overwrote tl_code_buf_, invalidating the cached pointer.
    // Recursive contracts that bounce between two code_hashes saw
    // garbage. Surfaced by Phase G.1 stStaticCall recursive-bomb tests.
    return silkworm::ByteView{it->second.data(), it->second.size()};
}

evmc::bytes32 CellEvmState::read_storage(const evmc::address& address,
                                          uint64_t /*incarnation*/,
                                          const evmc::bytes32& location) const noexcept {
    evmc::bytes32 v{};
    try {
        auto storage_root = get_storage_root(address);
        if (storage_root.is_null()) return v;
        vm::Dictionary storage(storage_root, 256);
        unsigned char key[32];
        bytes32_to_key(location, key);
        auto cs = storage.lookup(td::ConstBitPtr{key}, 256);
        if (cs.is_null()) return v;
        decode_storage_slice(cs, v);
    } catch (vm::VmError&) {
        return evmc::bytes32{};
    } catch (vm::VmVirtError&) {
        return evmc::bytes32{};
    } catch (std::exception&) {
        return evmc::bytes32{};
    } catch (...) {
        return evmc::bytes32{};
    }
    return v;
}

uint64_t CellEvmState::previous_incarnation(const evmc::address&) const noexcept {
    return 0;
}

evmc::bytes32 CellEvmState::state_root_hash() const {
    // Returns the hash of the account dictionary root cell (cell-native root,
    // distinct from the Ethereum-format MPT stateRoot which is computed by
    // IncrementalTrieCalculator for RPC).
    auto root = account_dict_root();
    if (root.is_null()) return evmc::bytes32{};
    auto h = root->get_hash().as_array();
    evmc::bytes32 result{};
    std::memcpy(result.bytes, h.data(), 32);
    return result;
}

silkworm::BlockNum CellEvmState::current_canonical_block() const {
    if (canonical_.empty()) return 0;
    silkworm::BlockNum max = 0;
    for (const auto& [bn, _] : canonical_) {
        if (bn > max) max = bn;
    }
    return max;
}

std::optional<evmc::bytes32> CellEvmState::canonical_hash(
    silkworm::BlockNum block_num) const {
    auto it = canonical_.find(block_num);
    if (it == canonical_.end()) return std::nullopt;
    return it->second;
}

void CellEvmState::insert_block(const silkworm::Block& block,
                                 const evmc::bytes32& hash) {
    canonical_[block.header.number] = hash;
    prune_canonical_hashes(canonical_);
}

void CellEvmState::canonize_block(silkworm::BlockNum block_num,
                                   const evmc::bytes32& block_hash) {
    canonical_[block_num] = block_hash;
    prune_canonical_hashes(canonical_);
}

void CellEvmState::decanonize_block(silkworm::BlockNum block_num) {
    canonical_.erase(block_num);
}

std::optional<silkworm::BlockHeader> CellEvmState::read_header(
    silkworm::BlockNum block_num,
    const evmc::bytes32& block_hash) const noexcept {
    auto it = canonical_.find(block_num);
    if (it == canonical_.end() || it->second != block_hash) {
        return std::nullopt;
    }

    silkworm::BlockHeader header{};
    header.number = block_num;
    if (block_num > 0) {
        auto parent = canonical_.find(block_num - 1);
        if (parent == canonical_.end()) {
            return std::nullopt;
        }
        header.parent_hash = parent->second;
    }
    return header;
}

// ---------------------------------------------------------------------------
// Write interface
// ---------------------------------------------------------------------------

void CellEvmState::begin_block(silkworm::BlockNum, size_t) {
    // No-op: we don't accumulate per-block changesets.
}

void CellEvmState::update_account(const evmc::address& address,
                                   std::optional<silkworm::Account> /*initial*/,
                                   std::optional<silkworm::Account> current) {
    unsigned char key[32];
    address_to_key(address, key);

    if (!current.has_value()) {
        // Account deleted
        account_dict_.lookup_delete(td::ConstBitPtr{key}, 256);
        return;
    }

    // Preserve existing storage + code refs when updating an existing account.
    td::Ref<vm::Cell> storage_root, code_root;
    {
        auto cs = account_dict_.lookup(td::ConstBitPtr{key}, 256);
        if (cs.not_null() && cs->size_refs() > 0) {
            silkworm::Account prev;
            decode_evm_account_data(cs->prefetch_ref(0), prev, storage_root, code_root);
        }
    }

    auto data_cell = encode_evm_account_data(*current, storage_root, code_root);
    // Wrap the EvmAccountData cell as a single-ref CellSlice (the dict value).
    vm::CellBuilder cb;
    cb.store_ref(data_cell);
    account_dict_.set_builder(td::ConstBitPtr{key}, 256, cb);
}

void CellEvmState::update_account_code(const evmc::address& address,
                                        uint64_t /*incarnation*/,
                                        const evmc::bytes32& code_hash,
                                        silkworm::ByteView code) {
    if (code_hash == silkworm::kEmptyHash) return;
    code_[code_hash] = silkworm::Bytes{code.begin(), code.end()};

    // Also embed the bytecode in the account's EvmAccountData cell so it
    // survives restart via cp.new_data → populate_state_from_shard_accounts.
    unsigned char key[32];
    address_to_key(address, key);
    auto cs = account_dict_.lookup(td::ConstBitPtr{key}, 256);
    silkworm::Account acct{};
    td::Ref<vm::Cell> storage_root;
    if (cs.not_null() && cs->size_refs() > 0) {
        td::Ref<vm::Cell> _old_code;
        decode_evm_account_data(cs->prefetch_ref(0), acct, storage_root, _old_code);
    }
    acct.code_hash = code_hash;
    auto code_cell = encode_evm_bytecode(
        td::Slice(reinterpret_cast<const char*>(code.data()), code.size()));
    auto data_cell = encode_evm_account_data(acct, storage_root, code_cell);
    vm::CellBuilder vcb;
    vcb.store_ref(data_cell);
    account_dict_.set_builder(td::ConstBitPtr{key}, 256, vcb);
}

void CellEvmState::update_storage(const evmc::address& address,
                                   uint64_t /*incarnation*/,
                                   const evmc::bytes32& location,
                                   const evmc::bytes32& /*initial*/,
                                   const evmc::bytes32& current) {
    static const evmc::bytes32 zero{};

    auto storage_root = get_storage_root(address);
    vm::Dictionary storage(storage_root.is_null() ? td::Ref<vm::Cell>{} : storage_root,
                            256);

    unsigned char key[32];
    bytes32_to_key(location, key);

    if (current == zero) {
        storage.lookup_delete(td::ConstBitPtr{key}, 256);
    } else {
        vm::CellBuilder vb;
        vb.store_bytes(current.bytes, 32);
        storage.set_builder(td::ConstBitPtr{key}, 256, vb);
    }

    set_storage_root(address, storage.get_root_cell());
}

// ---------------------------------------------------------------------------
// Cell-native extensions
// ---------------------------------------------------------------------------

void CellEvmState::for_each_account(
    std::function<void(const unsigned char[32], const silkworm::Account&)> cb) const {
    account_dict_.check_for_each([&cb](td::Ref<vm::CellSlice> value,
                                        td::ConstBitPtr key, int n) -> bool {
        if (n != 256 || value.is_null() || value->size_refs() == 0) return true;
        auto data_cell = value->prefetch_ref(0);
        silkworm::Account acct;
        td::Ref<vm::Cell> storage_root;
        if (!decode_evm_account_data(data_cell, acct, storage_root)) return true;
        unsigned char key_bytes[32];
        td::BitPtr{key_bytes}.copy_from(key, 256);
        cb(key_bytes, acct);
        return true;
    });
}

void CellEvmState::for_each_storage(
    const evmc::address& address,
    std::function<void(const evmc::bytes32&, const evmc::bytes32&)> cb) const {
    auto storage_root = get_storage_root(address);
    if (storage_root.is_null()) return;
    try {
        vm::Dictionary storage(storage_root, 256);
        storage.check_for_each([&cb](td::Ref<vm::CellSlice> value,
                                      td::ConstBitPtr key, int n) -> bool {
            if (n != 256) return false;
            evmc::bytes32 slot{};
            td::BitPtr{slot.bytes}.copy_from(key, 256);
            evmc::bytes32 v{};
            if (!decode_storage_slice(value, v)) return false;
            cb(slot, v);
            return true;
        });
    } catch (vm::VmError&) {
        return;
    } catch (vm::VmVirtError&) {
        return;
    } catch (std::exception&) {
        return;
    } catch (...) {
        return;
    }
}

CellEvmStateSizeStats CellEvmState::count_entries_bounded(
    size_t max_accounts,
    size_t max_storage_slots) const noexcept {
    CellEvmStateSizeStats stats;
    try {
        account_dict_.check_for_each(
            [&](td::Ref<vm::CellSlice> value, td::ConstBitPtr, int n) -> bool {
                if (n != 256 || value.is_null() || value->size_refs() == 0) {
                    stats.malformed = true;
                    return false;
                }
                if (++stats.accounts > max_accounts) {
                    stats.exceeded = true;
                    return false;
                }

                auto data_cell = value->prefetch_ref(0);
                silkworm::Account acct;
                td::Ref<vm::Cell> storage_root;
                if (!decode_evm_account_data(data_cell, acct, storage_root)) {
                    stats.malformed = true;
                    return false;
                }
                if (storage_root.is_null()) {
                    return true;
                }

                bool special = false;
                (void)vm::load_cell_slice_special(storage_root, special);
                if (special) {
                    stats.malformed = true;
                    return false;
                }
                vm::Dictionary storage(storage_root, 256);
                storage.check_for_each(
                    [&](td::Ref<vm::CellSlice> storage_value, td::ConstBitPtr, int storage_n) -> bool {
                        if (storage_n != 256) {
                            stats.malformed = true;
                            return false;
                        }
                        evmc::bytes32 unused{};
                        if (!decode_storage_slice(storage_value, unused)) {
                            stats.malformed = true;
                            return false;
                        }
                        if (++stats.storage_slots > max_storage_slots) {
                            stats.exceeded = true;
                            return false;
                        }
                        return true;
                    });
                return !stats.exceeded && !stats.malformed;
            });
    } catch (vm::VmError&) {
        stats.malformed = true;
    } catch (vm::VmVirtError&) {
        stats.malformed = true;
    } catch (std::exception&) {
        stats.malformed = true;
    } catch (...) {
        stats.malformed = true;
    }
    return stats;
}

td::Ref<vm::Cell> CellEvmState::serialize_to_cell() const {
    return account_dict_root();
}

bool CellEvmState::load_from_cell(td::Ref<vm::Cell> root) {
    if (root.is_null()) {
        account_dict_ = vm::Dictionary(256);
        code_.clear();
        return true;
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(root, special);
        if (special) return false;

        vm::Dictionary new_account_dict(root, 256);
        std::unordered_map<evmc::bytes32, silkworm::Bytes> new_code;
        bool ok = true;
        bool walked = new_account_dict.check_for_each([&ok, &new_code](td::Ref<vm::CellSlice> value,
                                                                        td::ConstBitPtr /*key*/, int n) -> bool {
            if (n != 256 || value.is_null() || value->size() != 0 || value->size_refs() != 1) {
                ok = false;
                return false;
            }
            silkworm::Account acct;
            td::Ref<vm::Cell> storage_root, code_root;
            if (!decode_evm_account_data(value->prefetch_ref(0), acct, storage_root, code_root)) {
                ok = false;
                return false;
            }
            if (!validate_storage_root(storage_root)) {
                ok = false;
                return false;
            }
            if (acct.code_hash == silkworm::kEmptyHash) {
                if (code_root.not_null()) {
                    ok = false;
                    return false;
                }
                return true;
            }
            if (code_root.is_null()) {
                ok = false;
                return false;
            }
            auto bytes = decode_evm_bytecode(code_root);
            if (bytes.empty()) {
                ok = false;
                return false;
            }
            new_code[acct.code_hash] = silkworm::Bytes{bytes.begin(), bytes.end()};
            return true;
        });
        if (!walked || !ok) return false;
        account_dict_ = std::move(new_account_dict);
        code_ = std::move(new_code);
        return true;
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

td::Ref<vm::Cell> CellEvmState::account_dict_root() const {
    return account_dict_.get_root_cell();
}

td::Ref<vm::Cell> CellEvmState::serialize_block_hashes_to_cell() const {
    if (canonical_.empty()) return {};

    std::vector<std::pair<silkworm::BlockNum, evmc::bytes32>> entries;
    entries.reserve(canonical_.size());
    for (const auto& entry : canonical_) {
        entries.push_back(entry);
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    constexpr size_t kEvmBlockHashWindow = 256;
    if (entries.size() > kEvmBlockHashWindow) {
        entries.erase(entries.begin(), entries.end() - kEvmBlockHashWindow);
    }

    vm::Dictionary dict(64);
    for (const auto& [block_num, hash] : entries) {
        auto key = block_num_key(block_num);
        vm::CellBuilder value_cb;
        value_cb.store_bytes(hash.bytes, 32);
        dict.set_builder(key.bits(), 64, value_cb);
    }
    return dict.get_root_cell();
}

bool CellEvmState::load_block_hashes_from_cell(td::Ref<vm::Cell> root) {
    canonical_.clear();
    if (root.is_null()) {
        return true;
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(root, special);
        if (special) return false;

        vm::Dictionary dict(root, 64);
        std::unordered_map<silkworm::BlockNum, evmc::bytes32> loaded;
        bool ok = true;
        bool walked = dict.check_for_each([&loaded, &ok](td::Ref<vm::CellSlice> value,
                                                         td::ConstBitPtr key, int n) -> bool {
            if (n != 64 || value.is_null() ||
                value->size() != 256 || value->size_refs() != 0) {
                ok = false;
                return false;
            }
            td::BitArray<64> key_bits(key);
            evmc::bytes32 hash{};
            if (!value.write().fetch_bytes(hash.bytes, 32)) {
                ok = false;
                return false;
            }
            loaded[key_bits.to_ulong()] = hash;
            return true;
        });
        if (!walked || !ok) return false;
        prune_canonical_hashes(loaded);
        canonical_ = std::move(loaded);
        return true;
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

void CellEvmState::clear_block_cache() {
    canonical_.clear();
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> CellEvmState::get_storage_root(const evmc::address& address) const {
    unsigned char key[32];
    address_to_key(address, key);
    auto cs = account_dict_.lookup(td::ConstBitPtr{key}, 256);
    if (cs.is_null() || cs->size_refs() == 0) return {};
    auto data_cell = cs->prefetch_ref(0);
    silkworm::Account acct;
    td::Ref<vm::Cell> storage_root;
    if (!decode_evm_account_data(data_cell, acct, storage_root)) return {};
    return storage_root;
}

void CellEvmState::set_storage_root(const evmc::address& address,
                                     td::Ref<vm::Cell> root) {
    unsigned char key[32];
    address_to_key(address, key);
    auto cs = account_dict_.lookup(td::ConstBitPtr{key}, 256);
    silkworm::Account acct{};
    td::Ref<vm::Cell> code_root;
    if (cs.not_null() && cs->size_refs() > 0) {
        td::Ref<vm::Cell> old_storage;
        decode_evm_account_data(cs->prefetch_ref(0), acct, old_storage, code_root);
    }
    auto data_cell = encode_evm_account_data(acct, root, code_root);
    vm::CellBuilder cb;
    cb.store_ref(data_cell);
    account_dict_.set_builder(td::ConstBitPtr{key}, 256, cb);
}

// ---------------------------------------------------------------------------
// Free helper: build a wc=1 ShardAccount inner Account cell wrapping an
// EvmAccountData cell as StateInit.data.
// ---------------------------------------------------------------------------
//
// Schema (block.tlb):
//   account$1 addr:MsgAddressInt storage_stat:StorageInfo storage:AccountStorage
//   AccountStorage = last_trans_lt:uint64 balance:CurrencyCollection state:AccountState
//   StateInit = split_depth:Maybe special:Maybe code:Maybe ^Cell data:Maybe ^Cell library:Maybe ^Cell
//   StorageInfo = used:StorageUsed extra:StorageExtraInfo last_paid:uint32 due_payment:Maybe
//   StorageUsed = cells:VarUInteger7 bits:VarUInteger7
//
// Phase A choices:
//   - outer balance = 0 (EVM balance lives in EvmAccountData; avoids double-counting in masterchain global balance)
//   - code = canonical 0x45 marker cell (deduplicated via CellDb)
//   - library = nothing
//   - last_paid = 0, due_payment = nothing
//   - last_trans_lt (in AccountStorage) = 0
//
// Determinism: all field stores are in fixed order with literal values; the
// only inputs are the address and the EvmAccountData cell. Cell hash is a
// pure function of these.
td::Ref<vm::Cell> build_evm_shard_account_cell(
    const td::Bits256& addr_bits,
    const td::Ref<vm::Cell>& evm_account_data_cell,
    const td::Ref<vm::Cell>& code_cell) {
    using td::make_refint;

    // 1. StateInit = split_depth:nothing special:nothing
    //                code:Just ^(real bytecode if contract, else marker)
    //                data:Just ^evm_data library:nothing
    auto code_to_store = code_cell.not_null()
                             ? code_cell
                             : evm_workchain_dispatch::get_evm_code_marker_cell();
    vm::CellBuilder si_cb;
    si_cb.store_long_bool(0, 1);  // split_depth: nothing
    si_cb.store_long_bool(0, 1);  // special: nothing
    si_cb.store_maybe_ref(code_to_store);
    si_cb.store_maybe_ref(evm_account_data_cell);
    si_cb.store_maybe_ref({});    // library: nothing
    auto state_init_cell = si_cb.finalize();

    // 2. AccountStorage = last_trans_lt:0 balance:zero state:account_active$1 StateInit
    vm::CellBuilder as_cb;
    as_cb.store_long_bool(0, 64);                                  // last_trans_lt
    bool ok = block::CurrencyCollection{make_refint(0)}.store(as_cb);  // balance
    CHECK(ok);
    ok = block::gen::t_AccountState.pack_account_active(
        as_cb, vm::load_cell_slice_ref(state_init_cell));         // state
    CHECK(ok);
    auto storage_cell = as_cb.finalize();

    // 3. StorageInfo.used = computed from the storage cell (deterministic)
    vm::CellStorageStat stats;
    auto stat_status = stats.compute_used_storage(td::Ref<vm::Cell>(storage_cell));
    CHECK(stat_status.is_ok());

    // 4. Account = account$1 addr:addr_std$10 wc=1 addr storage_stat storage
    vm::CellBuilder acc_cb;
    acc_cb.store_long_bool(1, 1);                                  // account$1
    acc_cb.store_long_bool(2, 2);                                  // addr_std$10
    acc_cb.store_long_bool(0, 1);                                  // anycast: nothing
    acc_cb.store_long_rchk_bool(kWorkchainId, 8);                  // workchain_id (1)
    acc_cb.store_bits_bool(addr_bits.bits(), 256);                 // address
    // storage_stat:StorageInfo
    ok = block::store_UInt7(acc_cb, stats.cells)                    // used.cells
         && block::store_UInt7(acc_cb, stats.bits);                 // used.bits
    CHECK(ok);
    acc_cb.store_zeroes_bool(3);                                    // extra:StorageExtraInfo (regular$0 = 3 bits 0)
    acc_cb.store_long_bool(0, 33);                                  // last_paid:uint32 + due_payment:nothing
    acc_cb.append_data_cell_bool(storage_cell);                     // storage:AccountStorage
    auto account_cell = acc_cb.finalize();

    // Validate (catches encoding bugs early in dev; cheap in release).
    CHECK(block::gen::t_Account.validate_ref(account_cell));
    return account_cell;
}

}  // namespace evm_workchain
