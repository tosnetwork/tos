/*
    EVM Workchain — cell-native state implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-cell-state.h"
#include "evm-cell-codec.h"

#include <silkworm/core/common/empty_hashes.hpp>
#include <ethash/keccak.hpp>

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include <cstring>

namespace evm_workchain {

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
    // Use thread_local buffer — caller may copy
    tl_code_buf_ = it->second;
    return tl_code_buf_;
}

evmc::bytes32 CellEvmState::read_storage(const evmc::address& address,
                                          uint64_t /*incarnation*/,
                                          const evmc::bytes32& location) const noexcept {
    auto storage_root = get_storage_root(address);
    if (storage_root.is_null()) return evmc::bytes32{};
    vm::Dictionary storage(storage_root, 256);
    unsigned char key[32];
    bytes32_to_key(location, key);
    auto cs = storage.lookup(td::ConstBitPtr{key}, 256);
    if (cs.is_null()) return evmc::bytes32{};
    // Storage value is stored inline as 256 bits in the slice
    evmc::bytes32 v{};
    if (cs->size() >= 256) {
        cs.write().fetch_bytes(v.bytes, 32);
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
}

void CellEvmState::canonize_block(silkworm::BlockNum block_num,
                                   const evmc::bytes32& block_hash) {
    canonical_[block_num] = block_hash;
}

void CellEvmState::decanonize_block(silkworm::BlockNum block_num) {
    canonical_.erase(block_num);
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

    // Preserve existing storage root when updating an existing account.
    auto storage_root = get_storage_root(address);

    auto data_cell = encode_evm_account_data(*current, storage_root);
    // Wrap the EvmAccountData cell as a single-ref CellSlice (the dict value).
    vm::CellBuilder cb;
    cb.store_ref(data_cell);
    account_dict_.set_builder(td::ConstBitPtr{key}, 256, cb);
}

void CellEvmState::update_account_code(const evmc::address& /*address*/,
                                        uint64_t /*incarnation*/,
                                        const evmc::bytes32& code_hash,
                                        silkworm::ByteView code) {
    if (code_hash == silkworm::kEmptyHash) return;
    code_[code_hash] = silkworm::Bytes{code.begin(), code.end()};
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
    vm::Dictionary storage(storage_root, 256);
    storage.check_for_each([&cb](td::Ref<vm::CellSlice> value,
                                  td::ConstBitPtr key, int n) -> bool {
        if (n != 256) return true;
        evmc::bytes32 slot{};
        td::BitPtr{slot.bytes}.copy_from(key, 256);
        evmc::bytes32 v{};
        if (value.not_null() && value->size() >= 256) {
            value.write().fetch_bytes(v.bytes, 32);
        }
        cb(slot, v);
        return true;
    });
}

td::Ref<vm::Cell> CellEvmState::serialize_to_cell() const {
    return account_dict_root();
}

bool CellEvmState::load_from_cell(td::Ref<vm::Cell> root) {
    if (root.is_null()) {
        account_dict_ = vm::Dictionary(256);
    } else {
        account_dict_ = vm::Dictionary(root, 256);
    }
    return true;
}

td::Ref<vm::Cell> CellEvmState::account_dict_root() const {
    return account_dict_.get_root_cell();
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
    if (cs.not_null() && cs->size_refs() > 0) {
        td::Ref<vm::Cell> old_root;
        decode_evm_account_data(cs->prefetch_ref(0), acct, old_root);
    }
    auto data_cell = encode_evm_account_data(acct, root);
    vm::CellBuilder cb;
    cb.store_ref(data_cell);
    account_dict_.set_builder(td::ConstBitPtr{key}, 256, cb);
}

}  // namespace evm_workchain
