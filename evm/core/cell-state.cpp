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
#include <new>
#include <optional>
#include <vector>

namespace evm_workchain {

#ifdef TOS_EVM_TEST_INSTRUMENTATION
std::atomic<size_t> g_cell_state_full_walks{0};
std::atomic<size_t> g_storage_index_walks{0};
std::atomic<size_t> g_witness_consistency_checks{0};
std::atomic<int> g_witness_verify_depth_max_observed{0};
// Audit K-02 (H-01 follow-up): test-only mirror of
// `s_code_root_hash_mismatch_count_inner`. The production counter is
// always linked because RPC handlers consult it on every heavy read-only
// EVM call; this mirror exists so unit tests with
// `TOS_EVM_TEST_INSTRUMENTATION=1` can also access the same counter via
// the historical `g_*` naming convention used by the rest of the file.
std::atomic<uint64_t> g_code_root_hash_mismatch_count{0};
#endif

namespace {
// Audit K-02 (H-01 follow-up): always-on counter incremented every time
// `CellEvmState::read_code` detects a code-root vs `code_hash` mismatch.
// The lazy-decode hook in `read_code` returns an empty `ByteView` on
// mismatch (so silkworm doesn't execute the wrong bytecode) and forwards
// the consistency violation into the active
// `WitnessFlatConsistencyContext` for fail-closed consensus rollback.
// Read-only RPC paths that do NOT bind a context (eth_call's read-only
// fast path, eth_estimateGas, eth_createAccessList) would otherwise see
// the empty return as canonical "no code" and silently mishandle the
// corruption. They snapshot this counter before silkworm runs and
// compare afterwards: a non-zero delta is the definitive signal that a
// `read_code` invocation during their frame surfaced a corrupt code
// root, and the handler maps its response to JSON-RPC `-32000`.
//
// `relaxed` ordering is sufficient: handlers always observe the
// snapshot/check pair under their own request thread, so the only
// requirement is that the increment becomes visible to the same thread
// that performed the snapshot — `relaxed` is enough for that on every
// supported architecture. No cross-thread synchronization is needed
// because the per-request EVM execution holds the global EVM state
// mutex exclusively (or shared, with each request's read_code calls
// serialized inside the same critical section).
std::atomic<uint64_t> s_code_root_hash_mismatch_count_inner{0};
}  // namespace

uint64_t code_root_hash_mismatch_count() noexcept {
    return s_code_root_hash_mismatch_count_inner.load(
        std::memory_order_relaxed);
}

void reset_code_root_hash_mismatch_count_for_test() noexcept {
    s_code_root_hash_mismatch_count_inner.store(
        0, std::memory_order_relaxed);
#ifdef TOS_EVM_TEST_INSTRUMENTATION
    g_code_root_hash_mismatch_count.store(0, std::memory_order_relaxed);
#endif
}

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
    // Dynamic witness consistency hook (audit H-01): on first touch of
    // this account inside the active transaction, run a path-bounded MPT
    // proof against the flat dict before surfacing the value to the EVM.
    // The hook is a no-op when no context is bound, when a previous
    // mismatch already poisoned the context, or when this address has
    // already been verified (static precheck or earlier dynamic touch).
    verify_account_before_return(address);
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

// Audit H-01 / K-02 contract for `CellEvmState::read_code`:
//   * On a `code_hash == kEmptyHash` request the function returns an empty
//     `ByteView` to mean canonical "no code", and that is the ONLY case
//     where empty-return is a successful answer.
//   * On a non-empty `code_hash` request the function tries the hot cache,
//     then a lazy decode out of the per-account flat-state code cell. The
//     lazy path computes `keccak(decoded)` and compares against the
//     account leaf's claimed `code_hash`.
//   * If the recomputed hash does not match (or the decode produced empty
//     bytes for a non-empty `code_hash`, which is structurally the same
//     mismatch), the function (a) records the consistency violation into
//     the active `WitnessFlatConsistencyContext` so consensus / verified
//     RPC drains it on the executor frame, (b) increments the always-on
//     `s_code_root_hash_mismatch_count_inner` counter visible via
//     `code_root_hash_mismatch_count()` so RPC handlers without a verifier
//     context can fail-closed, and (c) returns an empty `ByteView` so
//     silkworm cannot execute the wrong bytecode.
//   * Therefore: a non-empty `code_hash` paired with an empty return value
//     is a hard signal of a code-root vs `code_hash` mismatch. Callers
//     that want a definitive boolean answer (no need to combine with the
//     `code_hash == kEmptyHash` path) MUST use
//     `EvmState::read_code_copy_checked`, which surfaces the same
//     condition as a `td::Status::Error`.
silkworm::ByteView CellEvmState::read_code(
    const evmc::address& address, const evmc::bytes32& code_hash) const noexcept {
    // Dynamic witness consistency hook (audit H-01): the canonical account
    // RLP carries `code_hash`, so verifying the account leaf also verifies
    // the code identity in one shot. EXTCODECOPY / EXTCODESIZE /
    // EXTCODEHASH and DELEGATECALL targets all funnel through this path,
    // making `verify_account_before_return` the right hook for them.
    verify_account_before_return(address);
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
        // Audit H-01: enforce `keccak(decoded) == code_hash` BEFORE
        // emplacing into the code cache. The flat-state account leaf
        // commits to `code_hash` via the canonical Ethereum account RLP,
        // and the surrounding `cp.new_data` cell hash binds that. But
        // the per-account `code_root` cell in flat-state is *not*
        // re-hashed against `code_hash` anywhere else — a corrupt
        // import / state sync / disk bit-flip that swaps the bytecode
        // cell payload would otherwise let the EVM execute the wrong
        // bytecode (cached forever after the first lookup, since
        // `code_` is keyed by the asked-for `code_hash`). Empty decode
        // for a non-empty `code_hash` is a special case of the same
        // mismatch.
        if (decoded.empty()) {
            record_witness_error_if_active(
                address,
                td::Slice("EVM code root decodes empty for non-empty codeHash"));
            // Audit K-02: bump the always-on mismatch counter so RPC
            // handlers without a verifier context can detect this code
            // path and fail-closed (otherwise the empty return would be
            // mistaken for canonical "no code").
            s_code_root_hash_mismatch_count_inner.fetch_add(
                1, std::memory_order_relaxed);
#ifdef TOS_EVM_TEST_INSTRUMENTATION
            g_code_root_hash_mismatch_count.fetch_add(
                1, std::memory_order_relaxed);
#endif
            return {};
        }
        auto actual_hash = keccak_code_hash(silkworm::ByteView{
            reinterpret_cast<const uint8_t*>(decoded.data()), decoded.size()});
        if (actual_hash != code_hash) {
            record_witness_error_if_active(
                address, td::Slice("EVM code root/hash mismatch"));
            // Audit K-02: bump the always-on mismatch counter for the
            // benefit of RPC handlers running without a verifier
            // context; see the contract block above `read_code`.
            s_code_root_hash_mismatch_count_inner.fetch_add(
                1, std::memory_order_relaxed);
#ifdef TOS_EVM_TEST_INSTRUMENTATION
            g_code_root_hash_mismatch_count.fetch_add(
                1, std::memory_order_relaxed);
#endif
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
    // Dynamic witness consistency hook (audit H-01): SLOAD on a slot that
    // was not declared in the access list still goes through here. Verify
    // the (address, slot) leaf before the EVM consumes the flat value so a
    // post-checkpoint flat/witness drift can never produce a divergent
    // execution result.
    verify_storage_before_return(address, location);
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
    // Dynamic witness consistency hook (audit H-01): verify the
    // pre-mutation account leaf. Mutations that race ahead of a read (e.g.
    // a CALL whose first operation is a self-balance bump) would otherwise
    // overwrite the flat dict before any read path observed the
    // pre-image. The verifier dedupes against earlier first-touch reads,
    // so the cost is paid at most once per (tx, address).
    verify_account_before_return(address);
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
        if (!update_account_trie_leaf(address, std::nullopt)) {
            trie_witness_ready_ = false;
        }
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
    if (!update_account_trie_leaf(address, current)) {
        trie_witness_ready_ = false;
    }
}

void CellEvmState::update_account_code(const evmc::address& address,
                                        uint64_t /*incarnation*/,
                                        const evmc::bytes32& code_hash,
                                        silkworm::ByteView code) {
    // Dynamic witness consistency hook (audit H-01): CREATE / CREATE2
    // commit the new code_hash through here. Verifying the
    // pre-mutation account leaf ensures the slot-of-deployment was empty
    // (or held the same designation) in both flat dict and witness — a
    // flat/witness drift on the deploy address is fatal here too.
    verify_account_before_return(address);
    if (code_hash == silkworm::kEmptyHash) return;
    // Audit H-01: defensive `keccak(code) == code_hash` on the write
    // path. Production callers (`run_evm` / silkworm CREATE) always
    // pass matching code/hash, so this is normally a free check. A
    // mismatched call would mean an upstream code-store bug or a
    // hostile mutation reaching the State adapter — refuse to persist
    // it, mark the witness as not-ready so compute_phase rejects the
    // block, and record the consistency violation for the executor's
    // drain step. `trie_witness_ready_ = false` cascades through
    // `compute-phase`'s post-execution `trie_witness_ready()` gate so
    // the rolled-back snapshot is what consensus observes.
    auto actual_hash = keccak_code_hash(code);
    if (actual_hash != code_hash) {
        record_witness_error_if_active(
            address, td::Slice("update_account_code codeHash mismatch"));
        trie_witness_ready_ = false;
        return;
    }
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
    if (!update_account_trie_leaf(address, acct)) {
        trie_witness_ready_ = false;
    }
}

void CellEvmState::update_storage(const evmc::address& address,
                                   uint64_t /*incarnation*/,
                                   const evmc::bytes32& location,
                                   const evmc::bytes32& initial,
                                   const evmc::bytes32& current) {
    // Dynamic witness consistency hook (audit H-01): verify the
    // pre-mutation slot leaf. silkworm::IntraBlockState passes the
    // pre-image as `initial`, but we still consult the underlying State
    // because IntraBlockState may have been seeded directly via a journal
    // operation that did not surface the original storage_root cell.
    verify_storage_before_return(address, location);
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
    // Hot-path mutation: bind the storage trie via shallow validation. The
    // witness root cell hash is already authenticated by the surrounding
    // cp.new_data trie witness root, and a strict recursive walk would scale
    // with the target account's full storage size — that is unmetered host
    // work. Path-budgeted decoding inside `*_safe` mutation routines bounds
    // the per-tx cost to the MPT path length.
    auto* storage_trie = get_or_load_storage_trie_for_update(
        address, MptWitnessValidationMode::Shallow);
    CHECK(storage_trie != nullptr);
    if (current == zero) {
        // Fail-closed: a corrupt lazy node along the erase path must not
        // silently clear the trie root. `erase_hashed_safe` returns OK on a
        // genuine no-op missing key and an error only when decoding fails;
        // we propagate that as `!trie_witness_ready_` so compute_phase can
        // reject the tx instead of persisting a zeroed witness.
        auto erase_status = storage_trie->erase_hashed_safe(bytes32_view(hashed_slot));
        if (erase_status.is_error()) {
            trie_witness_ready_ = false;
            return;
        }
    } else {
        auto encoded = encode_mpt_storage_value(current);
        auto upsert_status = storage_trie->upsert_hashed_safe(
            bytes32_view(hashed_slot), encoded);
        if (upsert_status.is_error()) {
            trie_witness_ready_ = false;
            return;
        }
    }
    // Mark the touched trie dirty so the next `serialize_trie_witness_to_cell`
    // flushes the new root cell back into the storage-trie index dictionary.
    dirty_storage_trie_roots_.insert(address);

    set_storage_root(address, storage.get_root_cell());
    auto acct = read_account(address);
    if (!update_account_trie_leaf(address, acct)) {
        trie_witness_ready_ = false;
    }
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
    // Used by both the EVM compute hot path (cheap root cross-check vs.
    // declared `eth_state_root`) and tests. The account trie root has
    // already been validated either via StrictRecursive (hydration) or
    // shape-bound shallow load + path-budgeted decode (consensus); the
    // safe variant returns an error only on a corrupt witness, in which
    // case we fall back to the canonical "empty" sentinel matching the
    // legacy boolean-wrapper semantics. Production callers that need to
    // distinguish "empty" from "corrupt" must use the trie's own
    // `root_hash_safe()` directly through the witness verifier.
    auto root_res = account_trie_.root_hash_safe();
    if (root_res.is_error()) {
        return silkworm::kEmptyRoot;
    }
    return root_res.move_as_ok();
}

#ifdef TOS_EVM_TEST_INSTRUMENTATION
// L-01 (audit): unsafe `*_unsafe_for_*` CellEvmState wrappers are gated
// behind `TOS_EVM_TEST_INSTRUMENTATION`. Production callers (compute
// hot path / RPC) MUST use the `_safe[_no_cache]` variants instead.
// Production builds of `evm_workchain` do NOT define the macro and so
// do not export these symbols at all.
evmc::bytes32 CellEvmState::ethereum_storage_root_hash_unsafe_for_execution_cache(
    const evmc::address& address) const {
    if (!trie_witness_ready_) {
        return evmc::bytes32{};
    }
    // Execution cache path: this is called from `update_account_trie_leaf`
    // (under the EVM unique lock) where promoting the touched storage trie
    // into the cache is exactly what we want. Public RPC and any read-only
    // path must use `ethereum_storage_root_hash_safe_no_cache` instead.
    const auto* trie = get_or_load_storage_trie_for_read(address);
    if (trie == nullptr || trie->empty()) {
        return silkworm::kEmptyRoot;
    }
    auto root_res = trie->root_hash_safe();
    if (root_res.is_error()) {
        return silkworm::kEmptyRoot;
    }
    return root_res.move_as_ok();
}

std::vector<silkworm::Bytes>
CellEvmState::ethereum_account_proof_unsafe_for_tests_only(
    const evmc::address& address) const {
    if (!trie_witness_ready_) {
        return {};
    }
    auto hashed = keccak_evm_address(address);
    return account_trie_.proof_unsafe_for_tests_only(bytes32_view(hashed));
}

std::vector<silkworm::Bytes>
CellEvmState::ethereum_storage_proof_unsafe_for_tests_only(
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
    return trie->proof_unsafe_for_tests_only(bytes32_view(hashed));
}
#endif  // TOS_EVM_TEST_INSTRUMENTATION

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

td::Result<std::vector<silkworm::Bytes>>
CellEvmState::ethereum_storage_proof_safe_no_cache(
    const evmc::address& address, const evmc::bytes32& slot) const {
    if (!trie_witness_ready_) {
        return td::Status::Error(
            "ethereum_storage_proof_safe_no_cache: trie witness not ready");
    }
    // Read-only path that does not promote the loaded trie into the
    // `touched_storage_tries_` cache, so public RPC callers operating under a
    // shared lock never trigger a `mutable` cache mutation. Returns the
    // canonical empty-trie proof when the address has no entry in the witness
    // index, matching `ethereum_storage_proof_safe` semantics.
    auto cached_it = touched_storage_tries_.find(address);
    if (cached_it != touched_storage_tries_.end()) {
        if (cached_it->second.empty()) {
            return std::vector<silkworm::Bytes>{};
        }
        auto hashed = keccak_bytes32_value(slot);
        return cached_it->second.proof_safe(bytes32_view(hashed));
    }

    if (storage_trie_index_root_.is_null()) {
        return std::vector<silkworm::Bytes>{};
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(storage_trie_index_root_, special);
        if (special) {
            return td::Status::Error(
                "ethereum_storage_proof_safe_no_cache: index root is special");
        }
        vm::Dictionary index(storage_trie_index_root_, 256);
        unsigned char key[32];
        address_to_key(address, key);
        auto value = index.lookup(td::ConstBitPtr{key}, 256);
        if (value.is_null()) {
            return std::vector<silkworm::Bytes>{};
        }
        if (value->size() != 0 || value->size_refs() != 1) {
            return td::Status::Error(
                "ethereum_storage_proof_safe_no_cache: malformed index entry");
        }
        MptTrie tmp;
        if (!tmp.load_from_cell(value->prefetch_ref(0),
                                  MptWitnessValidationMode::Shallow)) {
            return td::Status::Error(
                "ethereum_storage_proof_safe_no_cache: failed to bind trie root");
        }
        auto hashed = keccak_bytes32_value(slot);
        return tmp.proof_safe(bytes32_view(hashed));
    } catch (vm::VmError&) {
        return td::Status::Error(
            "ethereum_storage_proof_safe_no_cache: vm error");
    } catch (vm::VmVirtError&) {
        return td::Status::Error(
            "ethereum_storage_proof_safe_no_cache: vm virtual error");
    } catch (std::exception& e) {
        return td::Status::Error(
            std::string("ethereum_storage_proof_safe_no_cache: ") + e.what());
    } catch (...) {
        return td::Status::Error(
            "ethereum_storage_proof_safe_no_cache: unknown error");
    }
}

td::Result<evmc::bytes32>
CellEvmState::ethereum_storage_root_hash_safe_no_cache(
    const evmc::address& address) const {
    if (!trie_witness_ready_) {
        return td::Status::Error("EVM trie witness is not available");
    }

    // If execution already touched this account in the current snapshot, the
    // cached MptTrie has been bound and validated; reading its root via the
    // fail-closed safe API does not require any new cache write.
    auto touched = touched_storage_tries_.find(address);
    if (touched != touched_storage_tries_.end()) {
        if (touched->second.empty()) {
            return silkworm::kEmptyRoot;
        }
        return touched->second.root_hash_safe();
    }

    if (storage_trie_index_root_.is_null()) {
        return silkworm::kEmptyRoot;
    }

    try {
        bool special = false;
        (void)vm::load_cell_slice_special(storage_trie_index_root_, special);
        if (special) {
            return td::Status::Error("invalid storage trie witness");
        }
        vm::Dictionary index(storage_trie_index_root_, 256);
        unsigned char key[32];
        address_to_key(address, key);
        auto value = index.lookup(td::ConstBitPtr{key}, 256);
        if (value.is_null()) {
            return silkworm::kEmptyRoot;
        }
        if (value->size() != 0 || value->size_refs() != 1) {
            return td::Status::Error("invalid storage trie witness");
        }
        MptTrie tmp;
        if (!tmp.load_from_cell(value->prefetch_ref(0),
                                  MptWitnessValidationMode::Shallow)) {
            return td::Status::Error("invalid storage trie witness");
        }
        return tmp.root_hash_safe();
    } catch (vm::VmError&) {
        return td::Status::Error("invalid storage trie witness");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("invalid storage trie witness");
    } catch (std::exception&) {
        return td::Status::Error("invalid storage trie witness");
    } catch (...) {
        return td::Status::Error("invalid storage trie witness");
    }
}

// ---------------------------------------------------------------------------
// Dynamic flat-state / MPT witness consistency tracker
// ---------------------------------------------------------------------------
//
// Audit H-01: the static pre-execution cross-check on sender / recipient /
// access-list only catches drift on accounts and slots the transaction
// declares up front. Real EVM execution touches a much larger set:
// dynamic CALL / DELEGATECALL / EXTCODE* targets, undeclared SLOAD /
// SSTORE slots, CREATE2 destinations, EIP-7702 authorities, the
// EIP-2935 history-storage system contract, SELFDESTRUCT counterparties,
// etc. To stay correct we extend the cross-check into the State read /
// update path itself: every first-touch surfaces the targeted leaf to
// the witness MPT before the EVM consumes the flat-dict value (or before
// a mutation overwrites the pre-image).
//
// Performance: each unique first-touch costs one path-bounded MPT proof
// (≤ 256 nodes / 2 MiB by construction of the MPT path budget). Typical
// transactions touch ~5-20 accounts/slots, so the runtime overhead is
// small relative to EVM execution itself. The dedup sets bound work to
// O(unique addresses + unique (addr, slot) pairs) per transaction.

namespace {

// Defense-in-depth recursion guard for the dynamic witness verifier.
//
// Call-stack contract (correct dedup-before-verify ordering):
//
//   1. `read_account(A)` → `verify_account_before_return(A)`. Depth at
//      check site = 0. Dedup insert succeeds.
//   2. The check `t_witness_verify_depth >= kMaxWitnessVerifyDepth`
//      passes; the `WitnessVerifyDepthGuard` increments depth to 1 and
//      `verify_account_witness_matches_flat_state(A)` runs.
//   3. That helper internally calls `read_account(A)` again, which
//      re-enters `verify_account_before_return(A)`. Depth at the check
//      site = 1, but the dedup insert hits the existing entry and
//      returns BEFORE the depth check — depth never advances past 1.
//   4. The outer guard's destructor restores depth to 0.
//
// Therefore in the well-ordered case the high-water mark of
// `t_witness_verify_depth` is 1 (the value held inside the outer
// guard's lifetime), and the depth-check site only ever observes 0.
// The 1→2 transition is reachable ONLY if the dedup-before-verify
// invariant has been broken (e.g. a future refactor moves the
// `insert` call after the verify call). In that pathological case
// the second guard increment lifts depth to 2 and a third entry sees
// `2 >= kMaxWitnessVerifyDepth` and bails fail-closed instead of
// recursing unbounded into a stack overflow.
//
// The threshold is intentionally tight: kMaxWitnessVerifyDepth = 2
// catches the FIRST illegal depth (the second post-guard frame). A
// looser cap would let the broken ordering accumulate frames before
// converting to a sticky `first_error`. A tighter cap (e.g. 1) would
// reject the legitimate well-ordered call where the outer guard has
// already pushed depth to 1 at the moment a sibling re-entry's check
// runs — which never actually occurs today (dedup wins) but would
// flap if a sibling helper added a fresh first-touch on a different
// address inside `verify_*_witness_matches_flat_state`.
thread_local int t_witness_verify_depth = 0;

struct WitnessVerifyDepthGuard {
    WitnessVerifyDepthGuard() noexcept {
        ++t_witness_verify_depth;
#ifdef TOS_EVM_TEST_INSTRUMENTATION
        // Track the high-water mark inside the guard's lifetime. Each
        // ctor records the post-increment value so tests can observe
        // the maximum stack depth actually reached during a call.
        int observed = t_witness_verify_depth;
        int prev = g_witness_verify_depth_max_observed.load(
            std::memory_order_relaxed);
        while (observed > prev &&
               !g_witness_verify_depth_max_observed.compare_exchange_weak(
                   prev, observed, std::memory_order_relaxed)) {
            // CAS spin: another thread updated the value; retry with
            // the freshly observed `prev`. The loop terminates because
            // `observed` is bounded by kMaxWitnessVerifyDepth.
        }
#endif
    }
    ~WitnessVerifyDepthGuard() noexcept { --t_witness_verify_depth; }
    WitnessVerifyDepthGuard(const WitnessVerifyDepthGuard&) = delete;
    WitnessVerifyDepthGuard& operator=(const WitnessVerifyDepthGuard&) = delete;
};

constexpr int kMaxWitnessVerifyDepth = 2;

// Lower-case 0x-prefixed hex of an EVM address. Inlined so the
// recursion-broken / mismatch hot paths do not depend on external
// helpers (everything in this file must be `noexcept`-safe).
std::string format_evm_address_hex(const evmc::address& address) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 + 40);
    out.append("0x");
    for (auto b : address.bytes) {
        out.push_back(kHexDigits[(b >> 4) & 0x0F]);
        out.push_back(kHexDigits[b & 0x0F]);
    }
    return out;
}

// Lower-case 0x-prefixed hex of a 32-byte slot. Same rationale as the
// address helper: avoid pulling external dependencies into a noexcept
// path.
std::string format_evm_slot_hex(const evmc::bytes32& slot) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 + 64);
    out.append("0x");
    for (auto b : slot.bytes) {
        out.push_back(kHexDigits[(b >> 4) & 0x0F]);
        out.push_back(kHexDigits[b & 0x0F]);
    }
    return out;
}

}  // namespace

#ifdef TOS_EVM_TEST_INSTRUMENTATION
int set_witness_verify_depth_for_testing(int new_depth) noexcept {
    int prev = t_witness_verify_depth;
    t_witness_verify_depth = new_depth;
    return prev;
}

int get_witness_verify_depth_for_testing() noexcept {
    return t_witness_verify_depth;
}

// Thread-local countdown that arms a deliberate `std::bad_alloc` at the
// dedup-set insert site of the dynamic witness verifier. The sentinel
// `kWitnessBadAllocInjectionDisabled` (INT_MIN) means "off"; the verifier
// hot path performs a single signed compare against it and skips the
// decrement-and-throw block entirely, so production binaries without
// `TOS_EVM_TEST_INSTRUMENTATION` pay zero cost (the symbol is not even
// linked).
//
// When armed with `n >= 0`, the next `n` insert calls (account or
// storage, whichever fires first) succeed normally and decrement the
// counter; when the counter reaches `0` the next insert throws
// `std::bad_alloc{}`. The verifier's existing try/catch catches it and
// records "witness consistency tracker exhausted (allocation failure)"
// into the per-tx context's `first_error`, which the executor drains and
// converts into a fail-closed `WitnessMismatch` disposition.
thread_local int t_witness_consistency_inject_bad_alloc_after_n_inserts =
    kWitnessBadAllocInjectionDisabled;

int enable_bad_alloc_injection_for_test(int n) noexcept {
    int prev = t_witness_consistency_inject_bad_alloc_after_n_inserts;
    t_witness_consistency_inject_bad_alloc_after_n_inserts = n;
    return prev;
}

int get_bad_alloc_injection_for_test() noexcept {
    return t_witness_consistency_inject_bad_alloc_after_n_inserts;
}
#endif

evmc::bytes32 CellEvmState::keccak_code_hash(silkworm::ByteView code) noexcept {
    // Audit H-01: canonical `keccak(code)` for the code-hash invariant
    // enforcement on the bytecode lazy-decode and write paths. Mirrors
    // the Ethereum spec rule `account.codeHash == keccak256(code)` and
    // is `noexcept` so it can be called from the `noexcept` Silkworm
    // State overrides. ethash::keccak256 is the same primitive used to
    // derive `code_hash` on every other production path (silkworm
    // CREATE, EIP-4788/EIP-2935 predeploy seeders, RPC bytecode
    // recovery), so the comparison is bitwise sound.
    auto h = ethash::keccak256(code.data(), code.size());
    evmc::bytes32 out{};
    std::memcpy(out.bytes, h.bytes, sizeof(out.bytes));
    return out;
}

void CellEvmState::record_witness_error_if_active(
    const evmc::address& address, td::Slice what) const noexcept {
    // Audit H-01: capture a fail-closed witness consistency error from a
    // `noexcept` State path. Sticky semantics — only the first error
    // wins — match the rest of the verifier so log lines and rollback
    // logic see a single canonical failure description per tx. The
    // function never throws: the offending_what string allocation can
    // fail in pathological OOM, in which case we leave first_error
    // populated with the original status (still surfaces as a
    // fail-closed disposition through `consume_witness_consistency_error`).
    if (witness_ctx_ == nullptr || !witness_ctx_->enabled ||
        witness_ctx_->first_error.is_error()) {
        return;
    }
    try {
        witness_ctx_->first_error =
            td::Status::Error(what.str());
        witness_ctx_->offending_what =
            format_evm_address_hex(address) + ": " + what.str();
    } catch (...) {
        // OOM constructing the offending_what string. The first_error
        // captured the canonical message via td::Status::Error which
        // owns its own buffer — that is enough for the executor to
        // surface the violation as `WitnessMismatch`.
    }
}

void CellEvmState::begin_witness_consistency_check(
    WitnessFlatConsistencyContext* ctx) noexcept {
    if (ctx == nullptr) {
        // Defensive: a nullptr means the caller asked for a no-op; clear
        // any stale pointer so a previously-aborted transaction can't
        // leak a dangling context into the next one.
        witness_ctx_ = nullptr;
        return;
    }
    ctx->enabled = true;
    witness_ctx_ = ctx;
}

void CellEvmState::end_witness_consistency_check() noexcept {
    if (witness_ctx_ != nullptr) {
        witness_ctx_->enabled = false;
    }
    witness_ctx_ = nullptr;
}

td::Status CellEvmState::consume_witness_consistency_error() noexcept {
    if (witness_ctx_ == nullptr) {
        return td::Status::OK();
    }
    if (witness_ctx_->first_error.is_error()) {
        td::Status taken = std::move(witness_ctx_->first_error);
        witness_ctx_->first_error = td::Status::OK();
        return taken;
    }
    return td::Status::OK();
}

void CellEvmState::verify_account_before_return(
    const evmc::address& address) const noexcept {
    if (witness_ctx_ == nullptr || !witness_ctx_->enabled ||
        witness_ctx_->first_error.is_error()) {
        return;
    }
    // CRITICAL: the dedup `insert` MUST happen BEFORE the call to
    // `verify_account_witness_matches_flat_state`. The verifier internally
    // calls `read_account` (and the safe storage-root helper that may also
    // touch flat-dict reads), which re-enters this hook. Insert-then-check
    // ensures the second entry hits the `!inserted` early-return below
    // (dedup hit) and bails harmlessly. Reordering — moving the insert
    // after the verify call — would cause unbounded recursion. The
    // `WitnessVerifyDepthGuard` below is a defense-in-depth backstop: if a
    // future refactor accidentally breaks the dedup invariant, we cap the
    // stack at two levels and surface a sticky error instead of crashing.
    try {
#ifdef TOS_EVM_TEST_INSTRUMENTATION
        // Test-only OOM injection. The sentinel comparison is a single
        // signed compare against INT_MIN; production builds without
        // TOS_EVM_TEST_INSTRUMENTATION omit this entire block.
        if (t_witness_consistency_inject_bad_alloc_after_n_inserts !=
            kWitnessBadAllocInjectionDisabled) {
            if (t_witness_consistency_inject_bad_alloc_after_n_inserts <= 0) {
                throw std::bad_alloc{};
            }
            --t_witness_consistency_inject_bad_alloc_after_n_inserts;
        }
#endif
        auto [_, inserted] = witness_ctx_->checked_accounts.insert(address);
        if (!inserted) {
            return;
        }
    } catch (const std::bad_alloc&) {
        witness_ctx_->first_error =
            td::Status::Error(
                "witness consistency tracker exhausted (allocation failure)");
        witness_ctx_->offending_what =
            std::string("account-tracker insert: account ") +
            format_evm_address_hex(address);
        return;
    } catch (...) {
        witness_ctx_->first_error =
            td::Status::Error("witness consistency tracker exhausted");
        witness_ctx_->offending_what =
            std::string("account-tracker insert: account ") +
            format_evm_address_hex(address);
        return;
    }
    if (t_witness_verify_depth >= kMaxWitnessVerifyDepth) {
        // Defense-in-depth: dedup-before-verify invariant has been broken
        // (likely a future refactor). Mark first_error and bail before we
        // blow the stack. The compute-phase rollback path picks this up.
        witness_ctx_->first_error =
            td::Status::Error("witness verifier recursion broken");
        witness_ctx_->offending_what =
            std::string("dynamic account witness recursion: account ") +
            format_evm_address_hex(address);
        return;
    }
    WitnessVerifyDepthGuard depth_guard;
#ifdef TOS_EVM_TEST_INSTRUMENTATION
    g_witness_consistency_checks.fetch_add(1, std::memory_order_relaxed);
#endif
    // Run the path-bounded cross-check. The implementation never throws —
    // it returns errors as `td::Status` and uses internal try/catch on its
    // VM call path — but defensive try/catch here guards against any
    // future helper that escalates to an exception.
    try {
        auto st = verify_account_witness_matches_flat_state(address);
        if (st.is_error()) {
            // Strict offending hint: include the EVM address as
            // lower-case 0x-hex so the rollback log line carries the
            // exact identity that drifted, not just a coarse
            // "account" tag. Existing matchers that look for the
            // substring "account" still match because the prefix
            // remains "dynamic account witness".
            witness_ctx_->offending_what =
                std::string("dynamic account witness: account ") +
                format_evm_address_hex(address);
            witness_ctx_->first_error = std::move(st);
        }
    } catch (...) {
        witness_ctx_->first_error =
            td::Status::Error("dynamic account witness verifier threw");
        witness_ctx_->offending_what =
            std::string("dynamic account witness: account ") +
            format_evm_address_hex(address);
    }
}

void CellEvmState::verify_storage_before_return(
    const evmc::address& address,
    const evmc::bytes32& slot) const noexcept {
    if (witness_ctx_ == nullptr || !witness_ctx_->enabled ||
        witness_ctx_->first_error.is_error()) {
        return;
    }
    // CRITICAL: the dedup `insert` MUST happen BEFORE the call to
    // `verify_storage_witness_matches_flat_state`. The verifier internally
    // calls `read_storage`, which re-enters this hook. Insert-then-check
    // ensures the second entry is a no-op (dedup hit). Reordering — e.g.
    // verifying first and inserting only on success — would cause
    // unbounded recursion through `read_storage` → verify_storage_before_return
    // → verify_storage_witness_matches_flat_state → read_storage → ...
    // The `WitnessVerifyDepthGuard` below caps the stack so a broken
    // invariant fails closed instead of crashing.
    StorageKey key{};
    key.address = address;
    key.slot = slot;
    try {
#ifdef TOS_EVM_TEST_INSTRUMENTATION
        // Test-only OOM injection. The sentinel comparison is a single
        // signed compare against INT_MIN; production builds without
        // TOS_EVM_TEST_INSTRUMENTATION omit this entire block.
        if (t_witness_consistency_inject_bad_alloc_after_n_inserts !=
            kWitnessBadAllocInjectionDisabled) {
            if (t_witness_consistency_inject_bad_alloc_after_n_inserts <= 0) {
                throw std::bad_alloc{};
            }
            --t_witness_consistency_inject_bad_alloc_after_n_inserts;
        }
#endif
        auto [_, inserted] = witness_ctx_->checked_storage.insert(key);
        if (!inserted) {
            return;
        }
    } catch (const std::bad_alloc&) {
        witness_ctx_->first_error =
            td::Status::Error(
                "witness consistency tracker exhausted (allocation failure)");
        witness_ctx_->offending_what =
            std::string("storage-tracker insert: account ") +
            format_evm_address_hex(address) + " slot " +
            format_evm_slot_hex(slot);
        return;
    } catch (...) {
        witness_ctx_->first_error =
            td::Status::Error("witness consistency tracker exhausted");
        witness_ctx_->offending_what =
            std::string("storage-tracker insert: account ") +
            format_evm_address_hex(address) + " slot " +
            format_evm_slot_hex(slot);
        return;
    }
    if (t_witness_verify_depth >= kMaxWitnessVerifyDepth) {
        // Defense-in-depth: dedup-before-verify invariant has been broken.
        // Cap recursion before we blow the stack and surface a sticky
        // first_error so the compute-phase rolls back fail-closed.
        witness_ctx_->first_error =
            td::Status::Error("witness verifier recursion broken");
        witness_ctx_->offending_what =
            std::string("dynamic storage witness recursion: account ") +
            format_evm_address_hex(address) + " slot " +
            format_evm_slot_hex(slot);
        return;
    }
    WitnessVerifyDepthGuard depth_guard;
#ifdef TOS_EVM_TEST_INSTRUMENTATION
    g_witness_consistency_checks.fetch_add(1, std::memory_order_relaxed);
#endif
    try {
        auto st = verify_storage_witness_matches_flat_state(address, slot);
        if (st.is_error()) {
            // Strict offending hint: include the (account, slot) pair
            // as lower-case 0x-hex so the log line carries the exact
            // tuple that drifted. Substring matchers looking for
            // "storage" continue to work via the prefix.
            witness_ctx_->offending_what =
                std::string("dynamic storage witness: account ") +
                format_evm_address_hex(address) + " slot " +
                format_evm_slot_hex(slot);
            witness_ctx_->first_error = std::move(st);
        }
    } catch (...) {
        witness_ctx_->first_error =
            td::Status::Error("dynamic storage witness verifier threw");
        witness_ctx_->offending_what =
            std::string("dynamic storage witness: account ") +
            format_evm_address_hex(address) + " slot " +
            format_evm_slot_hex(slot);
    }
}

td::Status CellEvmState::verify_account_witness_matches_flat_state(
    const evmc::address& address) const {
    if (!trie_witness_ready_) {
        return td::Status::Error("EVM trie witness is not available");
    }

    // Re-encode the canonical Ethereum account RLP from the flat dict. Use
    // the safe storage-root helper so the storage side is fail-closed and
    // never promotes a cache entry under a const path.
    std::optional<silkworm::Account> flat_account = read_account(address);
    auto storage_root_res = ethereum_storage_root_hash_safe_no_cache(address);
    if (storage_root_res.is_error()) {
        return storage_root_res.move_as_error();
    }
    evmc::bytes32 storage_root = storage_root_res.move_as_ok();

    // Walk the account MPT shallowly along the keccak(address) path and read
    // the leaf value, bounded by the path budget. A canonical absence is
    // returned as `std::nullopt`.
    auto hashed_addr = keccak_evm_address(address);
    auto value_res = account_trie_.value_at_hashed_safe(bytes32_view(hashed_addr));
    if (value_res.is_error()) {
        return value_res.move_as_error();
    }
    std::optional<silkworm::Bytes> witness_leaf = value_res.move_as_ok();

    if (!flat_account.has_value()) {
        if (witness_leaf.has_value()) {
            return td::Status::Error(
                "account witness mismatch: flat absent, witness present");
        }
        return td::Status::OK();
    }

    silkworm::Bytes expected_rlp = flat_account->rlp(storage_root);
    if (!witness_leaf.has_value()) {
        return td::Status::Error(
            "account witness mismatch: flat present, witness absent");
    }
    if (witness_leaf->size() != expected_rlp.size() ||
        std::memcmp(witness_leaf->data(), expected_rlp.data(),
                    expected_rlp.size()) != 0) {
        return td::Status::Error(
            "account witness mismatch: leaf RLP differs from flat state");
    }
    return td::Status::OK();
}

td::Status CellEvmState::verify_storage_witness_matches_flat_state(
    const evmc::address& address, const evmc::bytes32& slot) const {
    if (!trie_witness_ready_) {
        return td::Status::Error("EVM trie witness is not available");
    }

    // Read the flat storage value via the same code path read_storage uses.
    evmc::bytes32 flat_value = read_storage(address, /*incarnation=*/0, slot);
    const bool flat_is_zero = is_zero_bytes32(flat_value);

    // Locate the per-account storage trie via a SHALLOW load out of
    // `storage_trie_index_root_`; never touches `touched_storage_tries_`.
    MptTrie tmp;
    bool storage_trie_present = false;
    try {
        if (!storage_trie_index_root_.is_null()) {
            bool special = false;
            (void)vm::load_cell_slice_special(storage_trie_index_root_, special);
            if (special) {
                return td::Status::Error("invalid storage trie witness");
            }
            vm::Dictionary index(storage_trie_index_root_, 256);
            unsigned char key[32];
            address_to_key(address, key);
            auto value = index.lookup(td::ConstBitPtr{key}, 256);
            if (value.not_null()) {
                if (value->size() != 0 || value->size_refs() != 1) {
                    return td::Status::Error(
                        "invalid storage trie witness");
                }
                if (!tmp.load_from_cell(value->prefetch_ref(0),
                                          MptWitnessValidationMode::Shallow)) {
                    return td::Status::Error(
                        "invalid storage trie witness");
                }
                storage_trie_present = !tmp.empty();
            }
        }
    } catch (vm::VmError&) {
        return td::Status::Error("invalid storage trie witness");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("invalid storage trie witness");
    } catch (std::exception&) {
        return td::Status::Error("invalid storage trie witness");
    } catch (...) {
        return td::Status::Error("invalid storage trie witness");
    }

    auto hashed_slot = keccak_bytes32_value(slot);
    std::optional<silkworm::Bytes> witness_leaf;
    if (storage_trie_present) {
        auto value_res = tmp.value_at_hashed_safe(bytes32_view(hashed_slot));
        if (value_res.is_error()) {
            return value_res.move_as_error();
        }
        witness_leaf = value_res.move_as_ok();
    }

    if (flat_is_zero) {
        // Canonical Ethereum: zero values are not present in the storage trie.
        if (witness_leaf.has_value()) {
            return td::Status::Error(
                "storage witness mismatch: flat zero, witness present");
        }
        return td::Status::OK();
    }

    silkworm::Bytes expected_rlp = encode_mpt_storage_value(flat_value);
    if (!witness_leaf.has_value()) {
        return td::Status::Error(
            "storage witness mismatch: flat present, witness absent");
    }
    if (witness_leaf->size() != expected_rlp.size() ||
        std::memcmp(witness_leaf->data(), expected_rlp.data(),
                    expected_rlp.size()) != 0) {
        return td::Status::Error(
            "storage witness mismatch: leaf RLP differs from flat state");
    }
    return td::Status::OK();
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
        // Fail-closed: a corrupt lazy node along the erase path leaves the
        // account trie root unchanged rather than zeroing it. Surface the
        // underlying status as a boolean false so the caller can mark the
        // witness as not-ready.
        auto status = account_trie_.erase_hashed_safe(bytes32_view(hashed_addr));
        return status.is_ok();
    }
    evmc::bytes32 storage_root = silkworm::kEmptyRoot;
    // Hot-path lookup: shallow load is sufficient — a strict recursive walk
    // over a large storage trie just to read its current root would
    // reintroduce O(account storage size) host work for every leaf update.
    if (const auto* trie = get_or_load_storage_trie_for_read(
            address, MptWitnessValidationMode::Shallow);
        trie != nullptr && !trie->empty()) {
        auto root = trie->root_hash_safe();
        if (root.is_error()) {
            return false;
        }
        storage_root = root.move_as_ok();
    }
    auto encoded = account->rlp(storage_root);
    auto status = account_trie_.upsert_hashed_safe(
        bytes32_view(hashed_addr), encoded);
    return status.is_ok();
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

bool CellEvmState::load_trie_witness_from_cell(td::Ref<vm::Cell> root,
                                                TrieWitnessLoadMode mode) {
    account_trie_.clear();
    storage_trie_index_root_ = {};
    touched_storage_tries_.clear();
    dirty_storage_trie_roots_.clear();
    trie_witness_ready_ = false;
    if (root.is_null()) {
        trie_witness_ready_ = true;
        return true;
    }
    // Choose how aggressively the account-trie root is validated. Strict mode
    // recursively recomputes every node's RLP — appropriate for hydration /
    // import / repair. Trusted-shallow mode only binds the root cell and
    // defers per-node decoding to the proof / mutation path under a path
    // budget. The storage-trie index root is always lazily bound regardless
    // of mode (its per-account entries are only decoded when an executing
    // transaction actually touches that account).
    const auto account_trie_mode =
        (mode == TrieWitnessLoadMode::StrictRecursive)
            ? MptWitnessValidationMode::StrictRecursive
            : MptWitnessValidationMode::Shallow;
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
            if (!account_trie_.load_from_cell(cs.fetch_ref(), account_trie_mode)) {
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
    if (!update_account_trie_leaf(address, acct)) {
        trie_witness_ready_ = false;
    }
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
    const evmc::address& address, MptWitnessValidationMode mode) const {
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
        if (!trie.load_from_cell(value->prefetch_ref(0), mode)) {
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

const MptTrie* CellEvmState::get_or_load_storage_trie_for_read(
    const evmc::address& address) const {
    // Legacy entry point: keep StrictRecursive semantics for repair / import
    // callers that haven't been migrated yet. Hot-path callers must pass
    // `MptWitnessValidationMode::Shallow` explicitly.
    return get_or_load_storage_trie_for_read(
        address, MptWitnessValidationMode::StrictRecursive);
}

MptTrie* CellEvmState::get_or_load_storage_trie_for_update(
    const evmc::address& address, MptWitnessValidationMode mode) {
    auto it = touched_storage_tries_.find(address);
    if (it != touched_storage_tries_.end()) {
        return &it->second;
    }
    // Reuse the read path to load lazily, then upgrade to mutable. The
    // const_cast is sound here: the cache is `mutable`, and we own the
    // non-const this pointer in this overload.
    const MptTrie* loaded = static_cast<const CellEvmState*>(this)
                                ->get_or_load_storage_trie_for_read(address, mode);
    if (loaded != nullptr) {
        return const_cast<MptTrie*>(loaded);
    }
    // No existing entry — create an empty one for this address.
    auto [inserted_it, _] = touched_storage_tries_.emplace(address, MptTrie{});
    return &inserted_it->second;
}

MptTrie* CellEvmState::get_or_load_storage_trie_for_update(
    const evmc::address& address) {
    return get_or_load_storage_trie_for_update(
        address, MptWitnessValidationMode::StrictRecursive);
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
