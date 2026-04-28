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
#include <atomic>
#include <cstring>
#include <optional>
#include <vector>

namespace evm_workchain {

namespace {
// Audit K-02 (H-01 follow-up): always-on counter incremented every time
// `CellEvmState::read_code` detects a code-root vs `code_hash` mismatch.
// The lazy-decode hook in `read_code` returns an empty `ByteView` on
// mismatch (so silkworm doesn't execute the wrong bytecode). RPC paths
// that would otherwise see the empty return as canonical "no code" and
// silently mishandle the corruption snapshot this counter before
// silkworm runs and compare afterwards: a non-zero delta is the
// definitive signal that a `read_code` invocation during their frame
// surfaced a corrupt code root, and the handler maps its response to
// JSON-RPC `-32000`.
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
}

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

// Lower-case 0x-prefixed hex of an EVM address. Used by the strict-load
// failure-reason builder so a hydration / repair driver can surface the
// offending account identity in a structured error message.
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
//     mismatch), the function (a) increments the always-on
//     `s_code_root_hash_mismatch_count_inner` counter visible via
//     `code_root_hash_mismatch_count()` so RPC handlers can fail-closed,
//     and (b) returns an empty `ByteView` so silkworm cannot execute the
//     wrong bytecode.
//   * Therefore: a non-empty `code_hash` paired with an empty return value
//     is a hard signal of a code-root vs `code_hash` mismatch. Callers
//     that want a definitive boolean answer (no need to combine with the
//     `code_hash == kEmptyHash` path) MUST use
//     `EvmState::read_code_copy_checked`, which surfaces the same
//     condition as a `td::Status::Error`.
silkworm::ByteView CellEvmState::read_code(
    const evmc::address& address, const evmc::bytes32& code_hash) const noexcept {
    if (code_hash == silkworm::kEmptyHash) return {};
    if (auto it = code_.find(code_hash); it != code_.end()) {
        // Audit H-01 (P0.3): verified-only cache invariant. Every
        // entry must satisfy `entry.hash == code_hash` (the map key);
        // the only way to violate this is direct memory corruption or
        // a writer path that bypassed `decode_and_verify_code_root` /
        // its sister write helper. We re-check the invariant on every
        // hit so a corrupted entry fails closed instead of letting
        // silkworm execute the wrong bytecode. The check is a single
        // 32-byte compare — cheap enough for the hot path.
        if (it->second.hash != code_hash) {
            s_code_root_hash_mismatch_count_inner.fetch_add(
                1, std::memory_order_relaxed);
            return {};
        }
        // Return a ByteView pointing **into** the map entry's stable storage.
        // Earlier we copied into a single `tl_code_buf_` thread_local — that
        // was a bug: silkworm's IntraBlockState caches the ByteView in its
        // `existing_code_` map, and the next read_code() for a different
        // code_hash overwrote tl_code_buf_, invalidating the cached pointer.
        // Recursive contracts that bounce between two code_hashes saw
        // garbage. Surfaced by Phase G.1 stStaticCall recursive-bomb tests.
        return silkworm::ByteView{it->second.bytes.data(),
                                  it->second.bytes.size()};
    }

    // Lazy decode path: when the state was hydrated via `TrustedLazy`, the
    // bytecode map is empty. Look up the account's EvmAccountData cell,
    // decode just this account's bytecode through the H-01 chokepoint
    // (which enforces `keccak(decoded) == code_hash`), and cache the
    // verified result. The chokepoint (`decode_and_verify_code_root`) is
    // the single place that admits bytecode into the verified-only code
    // cache — every populating path funnels through it.
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
        if (acct.code_hash != code_hash) {
            // The account's authoritative leaf advertises a different
            // code_hash than what silkworm asked for. This is not a
            // code-root corruption case — it is a stale or wrong
            // `code_hash` query. Return canonical "not the code we
            // know about" without bumping the K-02 mismatch counter,
            // matching the historical contract.
            return {};
        }
        // Audit H-01 (P0.1 / P0.4): the helper enforces the canonical
        // `keccak(decoded) == code_hash` invariant and rejects the
        // empty-decode-with-non-empty-hash special case. A corrupt
        // import / state sync / disk bit-flip that swaps the bytecode
        // cell payload would otherwise let the EVM execute the wrong
        // bytecode (cached forever after the first lookup, since
        // `code_` is keyed by the asked-for `code_hash`).
        auto verified = decode_and_verify_code_root(
            code_root, code_hash, td::Slice("read_code lazy decode"));
        if (verified.is_error()) {
            // Audit K-02: bump the always-on mismatch counter so RPC
            // handlers can detect this code path and fail-closed
            // (otherwise the empty return would be mistaken for
            // canonical "no code").
            s_code_root_hash_mismatch_count_inner.fetch_add(
                1, std::memory_order_relaxed);
            return {};
        }
        auto verified_bytes = verified.move_as_ok();
        auto [it, inserted] = code_.emplace(
            code_hash,
            VerifiedCodeEntry{std::move(verified_bytes), code_hash});
        return silkworm::ByteView{it->second.bytes.data(),
                                  it->second.bytes.size()};
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
    // the canonical native commitment for this no-MPT state adapter). The
    // Ethereum-format MPT machinery has been removed; callers that need a
    // native state commitment use `compute_native_evm_state_commitment` in
    // evm/core/native-commitment.{h,cpp}.
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
    unsigned char key[32];
    address_to_key(address, key);

    if (!current.has_value()) {
        if (initial.has_value()) {
            delta_stats_.deleted_accounts++;
        }
        account_dict_.lookup_delete(td::ConstBitPtr{key}, 256);
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
}

void CellEvmState::update_account_code(const evmc::address& address,
                                        uint64_t /*incarnation*/,
                                        const evmc::bytes32& code_hash,
                                        silkworm::ByteView code) {
    if (code_hash == silkworm::kEmptyHash) return;
    // Audit H-01: defensive `keccak(code) == code_hash` on the write
    // path. Production callers (`run_evm` / silkworm CREATE) always
    // pass matching code/hash, so this is normally a free check. A
    // mismatched call would mean an upstream code-store bug or a
    // hostile mutation reaching the State adapter — refuse to persist
    // it.
    auto actual_hash = keccak_code_hash(code);
    if (actual_hash != code_hash) {
        return;
    }
    // Audit H-01 (P0.4): the verified-only cache invariant holds because
    // we just confirmed `keccak(code) == code_hash` above. Storing the
    // hash alongside the bytes lets `read_code` re-check the invariant
    // on every cache hit without recomputing keccak.
    code_[code_hash] = VerifiedCodeEntry{
        silkworm::Bytes{code.begin(), code.end()}, code_hash};

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
                                   const evmc::bytes32& initial,
                                   const evmc::bytes32& current) {
    static const evmc::bytes32 zero{};
    const bool was_zero = (initial == zero);
    const bool is_zero = (current == zero);
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

    set_storage_root(address, storage.get_root_cell());
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

#ifdef TOS_EVM_TEST_INSTRUMENTATION
void CellEvmState::poison_code_cache_for_test(
    const evmc::bytes32& cache_key,
    const evmc::bytes32& advertised_hash,
    silkworm::ByteView stored_bytes) {
    // Audit H-01 (P0.3): poisons the verified-only cache so the
    // cache-hit invariant test can drive the fail-closed branch. The
    // test calls this with `advertised_hash != cache_key` (the
    // "corrupted entry" pattern) so a subsequent `read_code(_,
    // cache_key)` hits the cache, observes the stored hash mismatch,
    // bumps the K-02 mismatch counter, and returns empty.
    code_[cache_key] = VerifiedCodeEntry{
        silkworm::Bytes{stored_bytes.begin(), stored_bytes.end()},
        advertised_hash};
}
#endif  // TOS_EVM_TEST_INSTRUMENTATION

td::Result<silkworm::Bytes> CellEvmState::decode_and_verify_code_root(
    const td::Ref<vm::Cell>& code_root,
    const evmc::bytes32& expected_hash,
    td::Slice context) {
    // Audit H-01 (P0.1 / P0.4): single chokepoint enforcing the
    // canonical Ethereum invariant `keccak(decoded) == account.codeHash`
    // for *every* path that decodes a per-account code_root cell. The
    // four explicit error cases below mirror the audit spec exactly so
    // a regression in any caller is immediately observable in the
    // returned status message. `context` is suffixed onto every error
    // so logs / counters distinguish between "strict load", "lazy
    // decode", and any future repair / import path that funnels
    // through this helper.
    auto with_context = [&](const char* base) {
        std::string out = base;
        if (context.size() != 0) {
            out += " (";
            out.append(context.data(), context.size());
            out += ")";
        }
        return td::Status::Error(std::move(out));
    };

    if (expected_hash == silkworm::kEmptyHash) {
        if (code_root.not_null()) {
            return with_context("empty codeHash has non-null code_root");
        }
        return silkworm::Bytes{};
    }

    if (code_root.is_null()) {
        return with_context("non-empty codeHash has null code_root");
    }

    auto decoded = decode_evm_bytecode(code_root);
    if (decoded.empty()) {
        return with_context("non-empty codeHash has empty decoded bytecode");
    }

    auto actual = keccak_code_hash(silkworm::ByteView{
        reinterpret_cast<const uint8_t*>(decoded.data()), decoded.size()});
    if (actual != expected_hash) {
        return with_context("EVM code_root bytecode hash mismatch");
    }
    return silkworm::Bytes{decoded.begin(), decoded.end()};
}

td::Ref<vm::Cell> CellEvmState::serialize_to_cell() const {
    return account_dict_root();
}

bool CellEvmState::load_from_cell(td::Ref<vm::Cell> root, CellStateLoadMode mode) {
    // Audit Q1 (tos16 P0 follow-up): clear any previous strict-load
    // failure reason on every entry. The strict-walk lambda below
    // re-populates this field with a structured description (offending
    // account / kind of mismatch) just before returning `false`, so a
    // surrounding hydration / repair driver can surface a forensic
    // error instead of dying on a bare boolean.
    last_strict_load_failure_reason_.clear();

    if (root.is_null()) {
        account_dict_ = vm::Dictionary(256);
        code_.clear();
        return true;
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(root, special);
        if (special) {
            last_strict_load_failure_reason_ =
                "state-root cell is special (pruned/library/merkle-update); "
                "canonical hydration cannot decode the account dict";
            return false;
        }

        vm::Dictionary new_account_dict(root, 256);

        if (mode == CellStateLoadMode::TrustedLazy) {
            // Hot-path bind (no-MPT native): the supplied root is already
            // authenticated by the surrounding TOS account state cell hash,
            // so we skip the full account/storage/code walk and only verify
            // the cell is non-special. Bytecode is decoded on demand via
            // `read_code` (which funnels through `decode_and_verify_code_root`,
            // preserving the H-01 code-hash invariant).
            account_dict_ = std::move(new_account_dict);
            code_.clear();
            return true;
        }

        // StrictValidateNative: enumerate all accounts, validate storage
        // root dictionary shape, and eagerly decode bytecode through the
        // H-01 chokepoint. Used for hydration, snapshot import, manual
        // repair, and offline native-state validation. NO MPT root is
        // computed.
        //
        // Audit H-01 (P0.2): every per-account code_root cell is decoded
        // through `decode_and_verify_code_root`, which enforces the
        // canonical Ethereum invariant `keccak(decoded) == acct.code_hash`
        // BEFORE the bytes are admitted into `new_code`. Without this, a
        // corrupt canonical state where `code_hash` and the embedded code
        // chain disagree would still hydrate "successfully" and seed the
        // verified-only cache with wrong bytecode — every subsequent
        // `read_code` cache hit would silently surface the wrong code to
        // silkworm.
        std::unordered_map<evmc::bytes32, VerifiedCodeEntry> new_code;
        bool ok = true;
        std::string& failure_reason = last_strict_load_failure_reason_;
        // Audit Q1 (tos16 P0 follow-up): capture per-account context the
        // moment the walk decides to fail. The 256-bit dict key is the
        // canonical [12 zero bytes || 20-byte address] packing produced
        // by `address_to_key`, so we recover the offending address by
        // copying the trailing 20 bytes from `key`. The reason string is
        // appended to `last_strict_load_failure_reason_` with the kind
        // of mismatch and the relevant code_hash so a surrounding
        // hydration / repair driver can emit a structured error.
        auto fail_with = [&failure_reason](td::ConstBitPtr key,
                                            const evmc::bytes32* code_hash,
                                            td::Slice what) {
            unsigned char raw[32];
            td::BitPtr{raw}.copy_from(key, 256);
            evmc::address addr{};
            std::memcpy(addr.bytes, raw + 12, 20);
            std::string reason = "strict load: ";
            reason.append(what.data(), what.size());
            reason.append(" (account=");
            reason.append(format_evm_address_hex(addr));
            if (code_hash != nullptr) {
                reason.append(", code_hash=");
                evmc::bytes32 ch_copy = *code_hash;
                std::string hex;
                hex.reserve(2 + 64);
                hex.append("0x");
                static constexpr char kHexDigits[] = "0123456789abcdef";
                for (auto b : ch_copy.bytes) {
                    hex.push_back(kHexDigits[(b >> 4) & 0x0F]);
                    hex.push_back(kHexDigits[b & 0x0F]);
                }
                reason.append(hex);
            }
            reason.append(")");
            failure_reason = std::move(reason);
        };
        bool walked = new_account_dict.check_for_each([&ok, &new_code, &fail_with](td::Ref<vm::CellSlice> value,
                                                                        td::ConstBitPtr key, int n) -> bool {
            if (n != 256 || value.is_null() || value->size() != 0 || value->size_refs() != 1) {
                ok = false;
                fail_with(key, nullptr,
                          td::Slice("malformed account dict entry shape"));
                return false;
            }
            silkworm::Account acct;
            td::Ref<vm::Cell> storage_root, code_root;
            if (!decode_evm_account_data(value->prefetch_ref(0), acct, storage_root, code_root)) {
                ok = false;
                fail_with(key, nullptr,
                          td::Slice("decode_evm_account_data failed"));
                return false;
            }
            if (!validate_storage_root(storage_root)) {
                ok = false;
                fail_with(key, &acct.code_hash,
                          td::Slice("invalid storage_root cell"));
                return false;
            }
            // Audit H-01 (P0.2): code_root + code_hash invariant. The
            // helper handles all four cases (empty/empty, empty/non-null,
            // non-empty/null, non-empty/decoded mismatch) and only
            // returns OK when `keccak(decoded) == acct.code_hash`. The
            // empty-codeHash + null code_root path returns OK with an
            // empty Bytes; we drop those entries so the cache only ever
            // holds real bytecode (matching the previous behaviour where
            // the loop short-circuited above before the decode call).
            auto verified = decode_and_verify_code_root(
                code_root, acct.code_hash, td::Slice("strict load"));
            if (verified.is_error()) {
                ok = false;
                fail_with(key, &acct.code_hash,
                          td::Slice(verified.error().message()));
                return false;
            }
            if (acct.code_hash == silkworm::kEmptyHash) {
                return true;
            }
            new_code.emplace(acct.code_hash,
                              VerifiedCodeEntry{verified.move_as_ok(),
                                                acct.code_hash});
            return true;
        });
        if (!walked || !ok) {
            if (last_strict_load_failure_reason_.empty()) {
                last_strict_load_failure_reason_ =
                    "strict load: account dict walk aborted "
                    "(malformed dict structure or per-entry validation failure)";
            }
            return false;
        }
        account_dict_ = std::move(new_account_dict);
        code_ = std::move(new_code);
        return true;
    } catch (vm::VmError& e) {
        last_strict_load_failure_reason_ =
            std::string("strict load: vm::VmError thrown during account dict walk: ") +
            e.get_msg();
        return false;
    } catch (vm::VmVirtError& e) {
        last_strict_load_failure_reason_ =
            std::string("strict load: vm::VmVirtError thrown during account dict walk: ") +
            e.get_msg();
        return false;
    } catch (std::exception& e) {
        last_strict_load_failure_reason_ =
            std::string("strict load: std::exception thrown during account dict walk: ") +
            (e.what() != nullptr ? e.what() : "<no message>");
        return false;
    } catch (...) {
        last_strict_load_failure_reason_ =
            "strict load: unknown exception thrown during account dict walk";
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
    set_storage_root(address, std::move(root));
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
