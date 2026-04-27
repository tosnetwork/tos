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

#ifdef TOS_EVM_TEST_INSTRUMENTATION
std::atomic<size_t> g_cell_state_full_walks{0};
std::atomic<size_t> g_storage_index_walks{0};
#endif

namespace {

constexpr unsigned long long kEvmTrieWitnessMagic = 0x545249ull;  // "TRI"
constexpr unsigned kEvmTrieWitnessMagicBits = 24;
constexpr unsigned kEvmTrieWitnessVersion = 1;

bool decode_storage_slice(td::Ref<vm::CellSlice> value, evmc::bytes32& out) {
    out = {};
    if (value.is_null() || value->size() != 256 || value->size_refs() != 0) {
        return false;
    }
    return value.write().fetch_bytes(out.bytes, 32);
}

bool is_zero_bytes32(const evmc::bytes32& value) {
    return value == evmc::bytes32{};
}

silkworm::ByteView bytes32_view(const evmc::bytes32& value) {
    return silkworm::ByteView{value.bytes, 32};
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
    const evmc::address& address, const evmc::bytes32& code_hash) const noexcept {
    if (code_hash == silkworm::kEmptyHash) return {};
    if (auto it = code_.find(code_hash); it != code_.end()) {
        // Return a ByteView pointing **into** the map entry's stable storage.
        // Earlier we copied into a single `tl_code_buf_` thread_local — that
        // was a bug: silkworm's IntraBlockState caches the ByteView in its
        // `existing_code_` map, and the next read_code() for a different
        // code_hash overwrote tl_code_buf_, invalidating the cached pointer.
        // Recursive contracts that bounce between two code_hashes saw
        // garbage. Surfaced by Phase G.1 stStaticCall recursive-bomb tests.
        return silkworm::ByteView{it->second.data(), it->second.size()};
    }

    // Lazy decode path: when the state was hydrated via `TrustedLazy`, the
    // bytecode map is empty. Look up the account's EvmAccountData cell,
    // decode just this account's bytecode, sanity-check the recovered
    // code_hash matches what silkworm asked for, and cache the result.
    try {
        td::Ref<vm::Cell> account_cell;
        if (!lookup_account_data_cell(address, account_cell)) {
            return {};
        }
        silkworm::Account acct;
        td::Ref<vm::Cell> storage_root;
        td::Ref<vm::Cell> code_root;
        if (!decode_evm_account_data(account_cell, acct, storage_root, code_root)) {
            return {};
        }
        if (acct.code_hash != code_hash || code_root.is_null()) {
            return {};
        }
        auto decoded = decode_evm_bytecode(code_root);
        if (decoded.empty()) {
            return {};
        }
        auto [it, inserted] = code_.emplace(
            code_hash, silkworm::Bytes{decoded.begin(), decoded.end()});
        return silkworm::ByteView{it->second.data(), it->second.size()};
    } catch (vm::VmError&) {
        return {};
    } catch (vm::VmVirtError&) {
        return {};
    } catch (std::exception&) {
        return {};
    } catch (...) {
        return {};
    }
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
                                   std::optional<silkworm::Account> initial,
                                   std::optional<silkworm::Account> current) {
    CHECK(ensure_trie_witness());
    unsigned char key[32];
    address_to_key(address, key);

    if (!current.has_value()) {
        if (initial.has_value()) {
            delta_stats_.deleted_accounts++;
        }
        // Account deleted: drop any cached storage trie and mark it dirty so
        // `serialize_trie_witness_to_cell` removes the index entry.
        account_dict_.lookup_delete(td::ConstBitPtr{key}, 256);
        touched_storage_tries_.erase(address);
        // Insert an empty trie so the dirty flush deletes the index entry
        // (the flush helper interprets `empty()` as "remove from index").
        touched_storage_tries_.emplace(address, MptTrie{});
        dirty_storage_trie_roots_.insert(address);
        CHECK(update_account_trie_leaf(address, std::nullopt));
        return;
    }
    if (!initial.has_value()) {
        delta_stats_.new_accounts++;
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
    CHECK(update_account_trie_leaf(address, current));
}

void CellEvmState::update_account_code(const evmc::address& address,
                                        uint64_t /*incarnation*/,
                                        const evmc::bytes32& code_hash,
                                        silkworm::ByteView code) {
    if (code_hash == silkworm::kEmptyHash) return;
    CHECK(ensure_trie_witness());
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
    CHECK(update_account_trie_leaf(address, acct));
}

void CellEvmState::update_storage(const evmc::address& address,
                                   uint64_t /*incarnation*/,
                                   const evmc::bytes32& location,
                                   const evmc::bytes32& initial,
                                   const evmc::bytes32& current) {
    CHECK(ensure_trie_witness());
    static const evmc::bytes32 zero{};
    const bool was_zero = is_zero_bytes32(initial);
    const bool is_zero = is_zero_bytes32(current);
    if (was_zero && !is_zero) {
        delta_stats_.new_storage_slots++;
    } else if (!was_zero && is_zero) {
        delta_stats_.cleared_storage_slots++;
    }

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

    auto hashed_slot = keccak_bytes32_value(location);
    auto* storage_trie = get_or_load_storage_trie_for_update(address);
    CHECK(storage_trie != nullptr);
    if (current == zero) {
        CHECK(storage_trie->erase_hashed(bytes32_view(hashed_slot)));
    } else {
        auto encoded = encode_mpt_storage_value(current);
        CHECK(storage_trie->upsert_hashed(bytes32_view(hashed_slot), encoded));
    }
    // Mark the touched trie dirty so the next `serialize_trie_witness_to_cell`
    // flushes the new root cell back into the storage-trie index dictionary.
    dirty_storage_trie_roots_.insert(address);

    set_storage_root(address, storage.get_root_cell());
    auto acct = read_account(address);
    CHECK(update_account_trie_leaf(address, acct));
}

// ---------------------------------------------------------------------------
// Cell-native extensions
// ---------------------------------------------------------------------------

bool CellEvmState::for_each_account_while(
    std::function<bool(const unsigned char[32], const silkworm::Account&)> cb) const {
    bool completed = true;
    account_dict_.check_for_each([&cb, &completed](td::Ref<vm::CellSlice> value,
                                                   td::ConstBitPtr key, int n) -> bool {
        if (n != 256 || value.is_null() || value->size_refs() == 0) return true;
        auto data_cell = value->prefetch_ref(0);
        silkworm::Account acct;
        td::Ref<vm::Cell> storage_root;
        if (!decode_evm_account_data(data_cell, acct, storage_root)) return true;
        unsigned char key_bytes[32];
        td::BitPtr{key_bytes}.copy_from(key, 256);
        completed = cb(key_bytes, acct);
        return completed;
    });
    return completed;
}

void CellEvmState::for_each_account(
    std::function<void(const unsigned char[32], const silkworm::Account&)> cb) const {
    (void)for_each_account_while(
        [&cb](const unsigned char key[32], const silkworm::Account& acct) {
            cb(key, acct);
            return true;
        });
}

bool CellEvmState::for_each_storage_while(
    const evmc::address& address,
    std::function<bool(const evmc::bytes32&, const evmc::bytes32&)> cb) const {
    auto storage_root = get_storage_root(address);
    if (storage_root.is_null()) return true;
    bool completed = true;
    try {
        vm::Dictionary storage(storage_root, 256);
        storage.check_for_each([&cb, &completed](td::Ref<vm::CellSlice> value,
                                                 td::ConstBitPtr key, int n) -> bool {
            if (n != 256) {
                completed = false;
                return false;
            }
            evmc::bytes32 slot{};
            td::BitPtr{slot.bytes}.copy_from(key, 256);
            evmc::bytes32 v{};
            if (!decode_storage_slice(value, v)) {
                completed = false;
                return false;
            }
            completed = cb(slot, v);
            return completed;
        });
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
    return completed;
}

void CellEvmState::for_each_storage(
    const evmc::address& address,
    std::function<void(const evmc::bytes32&, const evmc::bytes32&)> cb) const {
    (void)for_each_storage_while(
        address,
        [&cb](const evmc::bytes32& slot, const evmc::bytes32& value) {
            cb(slot, value);
            return true;
        });
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

evmc::bytes32 CellEvmState::ethereum_state_root_hash() const {
    if (!trie_witness_ready_) {
        return evmc::bytes32{};
    }
    return account_trie_.root_hash();
}

evmc::bytes32 CellEvmState::ethereum_storage_root_hash(const evmc::address& address) const {
    if (!trie_witness_ready_) {
        return evmc::bytes32{};
    }
    const auto* trie = get_or_load_storage_trie_for_read(address);
    if (trie == nullptr || trie->empty()) {
        return silkworm::kEmptyRoot;
    }
    return trie->root_hash();
}

std::vector<silkworm::Bytes> CellEvmState::ethereum_account_proof(
    const evmc::address& address) const {
    if (!trie_witness_ready_) {
        return {};
    }
    auto hashed = keccak_evm_address(address);
    return account_trie_.proof(bytes32_view(hashed));
}

std::vector<silkworm::Bytes> CellEvmState::ethereum_storage_proof(
    const evmc::address& address,
    const evmc::bytes32& slot) const {
    if (!trie_witness_ready_) {
        return {};
    }
    const auto* trie = get_or_load_storage_trie_for_read(address);
    if (trie == nullptr || trie->empty()) {
        return {};
    }
    auto hashed = keccak_bytes32_value(slot);
    return trie->proof(bytes32_view(hashed));
}

td::Result<std::vector<silkworm::Bytes>>
CellEvmState::ethereum_account_proof_safe(const evmc::address& address) const {
    if (!trie_witness_ready_) {
        return td::Status::Error(
            "ethereum_account_proof_safe: trie witness not ready");
    }
    auto hashed = keccak_evm_address(address);
    return account_trie_.proof_safe(bytes32_view(hashed));
}

td::Result<std::vector<silkworm::Bytes>>
CellEvmState::ethereum_storage_proof_safe(const evmc::address& address,
                                          const evmc::bytes32& slot) const {
    if (!trie_witness_ready_) {
        return td::Status::Error(
            "ethereum_storage_proof_safe: trie witness not ready");
    }
    const auto* trie = get_or_load_storage_trie_for_read(address);
    if (trie == nullptr || trie->empty()) {
        return std::vector<silkworm::Bytes>{};
    }
    auto hashed = keccak_bytes32_value(slot);
    return trie->proof_safe(bytes32_view(hashed));
}

bool CellEvmState::rebuild_storage_trie_for_account(const evmc::address& address) {
    // Strict repair helper: walks the full storage dict for the account and
    // rebuilds its MPT trie. Hot-path callers should use the lazy
    // get_or_load_* helpers instead. Result is cached into
    // `touched_storage_tries_` and marked dirty so the next serialize flushes
    // it into the storage-trie index dictionary.
    MptTrie trie;
    bool ok = for_each_storage_while(
        address,
        [&trie](const evmc::bytes32& slot, const evmc::bytes32& value) {
            if (is_zero_bytes32(value)) {
                return true;
            }
            auto hashed_slot = keccak_bytes32_value(slot);
            auto encoded = encode_mpt_storage_value(value);
            return trie.upsert_hashed(bytes32_view(hashed_slot), encoded);
        });
    if (!ok) {
        return false;
    }
    touched_storage_tries_[address] = std::move(trie);
    dirty_storage_trie_roots_.insert(address);
    return true;
}

bool CellEvmState::update_account_trie_leaf(
    const evmc::address& address,
    const std::optional<silkworm::Account>& account) {
    auto hashed_addr = keccak_evm_address(address);
    if (!account.has_value()) {
        return account_trie_.erase_hashed(bytes32_view(hashed_addr));
    }
    evmc::bytes32 storage_root = silkworm::kEmptyRoot;
    // Use the lazy lookup so we don't materialise an MptTrie for accounts
    // that are not actually being mutated by this transaction.
    if (const auto* trie = get_or_load_storage_trie_for_read(address);
        trie != nullptr && !trie->empty()) {
        storage_root = trie->root_hash();
    }
    auto encoded = account->rlp(storage_root);
    return account_trie_.upsert_hashed(bytes32_view(hashed_addr), encoded);
}

bool CellEvmState::rebuild_trie_witness() noexcept {
    try {
        account_trie_.clear();
        storage_trie_index_root_ = {};
        touched_storage_tries_.clear();
        dirty_storage_trie_roots_.clear();
        bool ok = for_each_account_while(
            [this](const unsigned char key[32], const silkworm::Account& acct) {
                evmc::address address{};
                std::memcpy(address.bytes, key + 12, 20);
                if (!rebuild_storage_trie_for_account(address)) {
                    return false;
                }
                return update_account_trie_leaf(address, acct);
            });
        trie_witness_ready_ = ok;
        return ok;
    } catch (vm::VmError&) {
        trie_witness_ready_ = false;
        return false;
    } catch (vm::VmVirtError&) {
        trie_witness_ready_ = false;
        return false;
    } catch (std::exception&) {
        trie_witness_ready_ = false;
        return false;
    } catch (...) {
        trie_witness_ready_ = false;
        return false;
    }
}

bool CellEvmState::ensure_trie_witness() {
    if (trie_witness_ready_) {
        return true;
    }
    return rebuild_trie_witness();
}

td::Ref<vm::Cell> CellEvmState::serialize_trie_witness_to_cell() const {
    if (!trie_witness_ready_) {
        return {};
    }
    auto account_root = account_trie_.serialize_to_cell();

    // Flush only storage tries that the executing transaction touched. The
    // index dictionary is otherwise reused as-is, so the cost of serializing
    // is O(touched_accounts) instead of O(global storage-bearing accounts).
    td::Ref<vm::Cell> storage_root = storage_trie_index_root_;
    if (!dirty_storage_trie_roots_.empty()) {
        try {
            vm::Dictionary index(storage_root.is_null() ? td::Ref<vm::Cell>{} : storage_root,
                                  256);
            for (const auto& address : dirty_storage_trie_roots_) {
                unsigned char key[32];
                address_to_key(address, key);
                auto it = touched_storage_tries_.find(address);
                if (it == touched_storage_tries_.end() || it->second.empty()) {
                    index.lookup_delete(td::ConstBitPtr{key}, 256);
                    continue;
                }
                auto trie_cell = it->second.serialize_to_cell();
                if (trie_cell.is_null()) {
                    index.lookup_delete(td::ConstBitPtr{key}, 256);
                    continue;
                }
                vm::CellBuilder value_cb;
                value_cb.store_ref(trie_cell);
                CHECK(index.set_builder(td::ConstBitPtr{key}, 256, value_cb));
            }
            storage_root = index.get_root_cell();
            // The serialize is logically const for the witness output, but
            // we want subsequent calls to skip the flush; promote the cache.
            const_cast<CellEvmState*>(this)->storage_trie_index_root_ = storage_root;
            const_cast<CellEvmState*>(this)->dirty_storage_trie_roots_.clear();
        } catch (vm::VmError&) {
            return {};
        } catch (vm::VmVirtError&) {
            return {};
        } catch (std::exception&) {
            return {};
        } catch (...) {
            return {};
        }
    }

    if (account_root.is_null() && storage_root.is_null()) {
        return {};
    }

    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(kEvmTrieWitnessMagic),
                  kEvmTrieWitnessMagicBits);
    cb.store_long(kEvmTrieWitnessVersion, 8);
    if (account_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(account_root);
    } else {
        cb.store_long(0, 1);
    }
    if (storage_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(storage_root);
    } else {
        cb.store_long(0, 1);
    }
    return cb.finalize();
}

bool CellEvmState::load_trie_witness_from_cell(td::Ref<vm::Cell> root) {
    account_trie_.clear();
    storage_trie_index_root_ = {};
    touched_storage_tries_.clear();
    dirty_storage_trie_roots_.clear();
    trie_witness_ready_ = false;
    if (root.is_null()) {
        trie_witness_ready_ = true;
        return true;
    }
    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) return false;
        if (cs.size() < kEvmTrieWitnessMagicBits + 8 + 2) return false;
        auto magic = cs.fetch_ulong(kEvmTrieWitnessMagicBits);
        if (magic != kEvmTrieWitnessMagic) return false;
        auto version = cs.fetch_ulong(8);
        if (version != kEvmTrieWitnessVersion) return false;

        auto has_account = cs.fetch_ulong(1);
        if (has_account == 1) {
            if (cs.size_refs() == 0) return false;
            // P2 hardening: account trie is recursively validated on
            // hydration so subsequent proof/update operations can rely on
            // the cached RLP without trusting per-node `rlp_cache`.
            if (!account_trie_.load_from_cell(
                    cs.fetch_ref(),
                    MptWitnessValidationMode::StrictRecursive)) {
                return false;
            }
        }

        auto has_storage = cs.fetch_ulong(1);
        if (has_storage == 1) {
            if (cs.size_refs() == 0) return false;
            // Lazy bind: only verify the index root cell is non-special.
            // Per-account storage tries are loaded on demand via
            // `get_or_load_storage_trie_for_*`. The cost of `load_trie_witness`
            // therefore does not grow with the global number of storage-bearing
            // accounts.
            auto index_root = cs.fetch_ref();
            bool index_special = false;
            (void)vm::load_cell_slice_special(index_root, index_special);
            if (index_special) return false;
            storage_trie_index_root_ = std::move(index_root);
        }
        if (cs.size() != 0 || cs.size_refs() != 0) return false;
        trie_witness_ready_ = true;
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

td::Ref<vm::Cell> CellEvmState::serialize_to_cell() const {
    return account_dict_root();
}

bool CellEvmState::load_from_cell(td::Ref<vm::Cell> root, CellStateLoadMode mode) {
    if (root.is_null()) {
        account_dict_ = vm::Dictionary(256);
        code_.clear();
        account_trie_.clear();
        storage_trie_index_root_ = {};
        touched_storage_tries_.clear();
        dirty_storage_trie_roots_.clear();
        trie_witness_ready_ = true;
        return true;
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(root, special);
        if (special) return false;

        vm::Dictionary new_account_dict(root, 256);

        if (mode == CellStateLoadMode::TrustedLazy) {
            // Hot-path bind: the supplied root is already authenticated by the
            // surrounding TOS account state cell hash, so we skip the full
            // account/storage/code walk and only verify the cell is non-special.
            // Bytecode is decoded on demand via `read_code`, and the storage
            // witness index is resolved lazily in
            // `get_or_load_storage_trie_for_*`.
            account_dict_ = std::move(new_account_dict);
            code_.clear();
            account_trie_.clear();
            storage_trie_index_root_ = {};
            touched_storage_tries_.clear();
            dirty_storage_trie_roots_.clear();
            trie_witness_ready_ = false;
            return true;
        }

        // Strict modes: enumerate all accounts, validate storage roots, and
        // eagerly decode bytecode. Used for hydration, snapshot import,
        // manual repair, and offline state-root verification.
#ifdef TOS_EVM_TEST_INSTRUMENTATION
        g_cell_state_full_walks.fetch_add(1, std::memory_order_relaxed);
#endif
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
        storage_trie_index_root_ = {};
        touched_storage_tries_.clear();
        dirty_storage_trie_roots_.clear();
        if (mode == CellStateLoadMode::StrictValidateAndRebuildWitness) {
            return rebuild_trie_witness();
        }
        account_trie_.clear();
        trie_witness_ready_ = false;
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

void CellEvmState::set_storage_root_for_hydration(const evmc::address& address,
                                                   td::Ref<vm::Cell> root) {
    CHECK(ensure_trie_witness());
    set_storage_root(address, std::move(root));
    CHECK(rebuild_storage_trie_for_account(address));
    auto acct = read_account(address);
    CHECK(update_account_trie_leaf(address, acct));
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

// Lazy storage-trie helpers. The witness `storage_trie_index_root_` is a
// dictionary keyed by 256-bit address whose value is a single ref to the
// account's MPT storage trie root cell. We materialise an MptTrie object for
// an address only when the executing transaction actually touches that
// account's storage, and we mark it dirty so `serialize_trie_witness_to_cell`
// writes it back into the index. Read-only helpers (proof/root hash) load
// without dirty-marking.
const MptTrie* CellEvmState::get_or_load_storage_trie_for_read(
    const evmc::address& address) const {
    auto it = touched_storage_tries_.find(address);
    if (it != touched_storage_tries_.end()) {
        return &it->second;
    }
    if (storage_trie_index_root_.is_null()) {
        return nullptr;
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(storage_trie_index_root_, special);
        if (special) {
            return nullptr;
        }
#ifdef TOS_EVM_TEST_INSTRUMENTATION
        g_storage_index_walks.fetch_add(1, std::memory_order_relaxed);
#endif
        vm::Dictionary index(storage_trie_index_root_, 256);
        unsigned char key[32];
        address_to_key(address, key);
        auto value = index.lookup(td::ConstBitPtr{key}, 256);
        if (value.is_null()) {
            return nullptr;
        }
        if (value->size() != 0 || value->size_refs() != 1) {
            return nullptr;
        }
        MptTrie trie;
        if (!trie.load_from_cell(value->prefetch_ref(0))) {
            return nullptr;
        }
        auto [inserted_it, _] = touched_storage_tries_.emplace(address, std::move(trie));
        return &inserted_it->second;
    } catch (vm::VmError&) {
        return nullptr;
    } catch (vm::VmVirtError&) {
        return nullptr;
    } catch (std::exception&) {
        return nullptr;
    } catch (...) {
        return nullptr;
    }
}

MptTrie* CellEvmState::get_or_load_storage_trie_for_update(
    const evmc::address& address) {
    auto it = touched_storage_tries_.find(address);
    if (it != touched_storage_tries_.end()) {
        return &it->second;
    }
    // Reuse the read path to load lazily, then upgrade to mutable. The
    // const_cast is sound here: the cache is `mutable`, and we own the
    // non-const this pointer in this overload.
    const MptTrie* loaded = static_cast<const CellEvmState*>(this)
                                ->get_or_load_storage_trie_for_read(address);
    if (loaded != nullptr) {
        return const_cast<MptTrie*>(loaded);
    }
    // No existing entry — create an empty one for this address.
    auto [inserted_it, _] = touched_storage_tries_.emplace(address, MptTrie{});
    return &inserted_it->second;
}

bool CellEvmState::lookup_account_data_cell(const evmc::address& address,
                                            td::Ref<vm::Cell>& out) const {
    out = {};
    try {
        unsigned char key[32];
        address_to_key(address, key);
        auto cs = account_dict_.lookup(td::ConstBitPtr{key}, 256);
        if (cs.is_null() || cs->size() != 0 || cs->size_refs() != 1) {
            return false;
        }
        out = cs->prefetch_ref(0);
        return out.not_null();
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
