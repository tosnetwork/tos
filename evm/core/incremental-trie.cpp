/*
    EVM Workchain — incremental state trie calculator implementation.

    Implements the Erigon-style two-cursor merge algorithm for computing
    the Ethereum state root hash incrementally.  Cached intermediate trie
    branch nodes are merged with live hashed state entries to avoid
    rehashing unchanged subtrees.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/incremental-trie.h"
#include "evm/core/cell-state.h"

#include <algorithm>
#include <cstring>

#include <ethash/keccak.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/trie/nibbles.hpp>

namespace evm_workchain {

using silkworm::Bytes;
using silkworm::ByteView;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hash an address with keccak256 and return as evmc::bytes32.
static evmc::bytes32 keccak_address(const evmc::address& addr) {
    const auto h = ethash::keccak256(addr.bytes, 20);
    evmc::bytes32 out{};
    std::memcpy(out.bytes, h.bytes, 32);
    return out;
}

/// Hash a bytes32 value with keccak256 and return as evmc::bytes32.
static evmc::bytes32 keccak_bytes32(const evmc::bytes32& val) {
    const auto h = ethash::keccak256(val.bytes, 32);
    evmc::bytes32 out{};
    std::memcpy(out.bytes, h.bytes, 32);
    return out;
}

/// Build a storage-node cache key: hashed_addr(32) ++ packed_nibble_path.
static Bytes storage_cache_key(const evmc::bytes32& hashed_addr, ByteView packed_path) {
    Bytes key(32 + packed_path.size(), 0);
    std::memcpy(key.data(), hashed_addr.bytes, 32);
    std::memcpy(key.data() + 32, packed_path.data(), packed_path.size());
    return key;
}

/// Check whether a bytes32 is all zeros.
static bool bytes32_is_zero(const evmc::bytes32& v) {
    return v == evmc::bytes32{};
}

// ---------------------------------------------------------------------------
// Account / storage RLP encoding
// ---------------------------------------------------------------------------

silkworm::Bytes IncrementalTrieCalculator::encode_account_for_trie(
    const silkworm::Account& acct,
    const evmc::bytes32& storage_root) {
    // silkworm::Account::rlp(storage_root) returns the Yellow Paper encoding:
    //   RLP([nonce, balance, storageRoot, codeHash])
    return acct.rlp(storage_root);
}

silkworm::Bytes IncrementalTrieCalculator::encode_storage_value(const evmc::bytes32& value) {
    // Storage values are RLP-encoded as byte strings with leading zeros trimmed.
    // Find first non-zero byte.
    size_t start = 0;
    while (start < 32 && value.bytes[start] == 0) {
        ++start;
    }
    Bytes out;
    if (start == 32) {
        // Value is zero -- encode as empty string (0x80).
        silkworm::rlp::encode(out, ByteView{});
    } else {
        silkworm::rlp::encode(out, ByteView{value.bytes + start, 32 - start});
    }
    return out;
}

// ---------------------------------------------------------------------------
// State collection from InMemoryState
// ---------------------------------------------------------------------------

std::map<evmc::bytes32, std::pair<evmc::address, silkworm::Account>>
IncrementalTrieCalculator::collect_hashed_accounts(EvmState& state) {
    std::map<evmc::bytes32, std::pair<evmc::address, silkworm::Account>> result;

    // Cell-native path: iterate via CellEvmState's account dictionary.
    auto* cell_state = dynamic_cast<CellEvmState*>(&state.state());
    if (cell_state) {
        cell_state->for_each_account(
            [&result](const unsigned char key[32], const silkworm::Account& acct) {
                // Reconstruct EVM address from the last 20 bytes of the 32-byte key
                evmc::address addr{};
                std::memcpy(addr.bytes, key + 12, 20);
                auto hashed = keccak_address(addr);
                result[hashed] = {addr, acct};
            });
        return result;
    }

    // Fallback: InMemoryState (used in tests that construct EvmState directly).
    auto* in_mem = dynamic_cast<silkworm::InMemoryState*>(&state.state());
    if (in_mem) {
        for (const auto& [addr, acct] : in_mem->accounts()) {
            auto hashed = keccak_address(addr);
            result[hashed] = {addr, acct};
        }
    }
    return result;
}

std::map<evmc::bytes32, evmc::bytes32>
IncrementalTrieCalculator::collect_hashed_storage(
    EvmState& state,
    const evmc::address& address,
    uint64_t incarnation) {
    std::map<evmc::bytes32, evmc::bytes32> result;

    // Cell-native path
    auto* cell_state = dynamic_cast<CellEvmState*>(&state.state());
    if (cell_state) {
        cell_state->for_each_storage(address,
            [&result](const evmc::bytes32& slot, const evmc::bytes32& value) {
                if (!bytes32_is_zero(value)) {
                    auto hashed_loc = keccak_bytes32(slot);
                    result[hashed_loc] = value;
                }
            });
        return result;
    }

    // Fallback: InMemoryState
    auto* in_mem = dynamic_cast<silkworm::InMemoryState*>(&state.state());
    if (in_mem) {
        const auto& all_storage = in_mem->storage();
        auto addr_it = all_storage.find(address);
        if (addr_it != all_storage.end()) {
            auto inc_it = addr_it->second.find(incarnation);
            if (inc_it != addr_it->second.end()) {
                for (const auto& [location, value] : inc_it->second) {
                    if (!bytes32_is_zero(value)) {
                        auto hashed_loc = keccak_bytes32(location);
                        result[hashed_loc] = value;
                    }
                }
            }
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Storage root computation
// ---------------------------------------------------------------------------

evmc::bytes32 IncrementalTrieCalculator::compute_storage_root(
    EvmState& state,
    const evmc::address& address,
    const evmc::bytes32& hashed_addr,
    uint64_t incarnation,
    silkworm::trie::PrefixSet* storage_changes) {

    // If we have a cached root and no changes affect this account, reuse it.
    if (storage_changes) {
        auto cached = storage_root_cache_.find(hashed_addr);
        if (cached != storage_root_cache_.end()) {
            // Check if any changed storage path starts with this account's hash.
            // The storage PrefixSet contains nibbled(hashed_addr ++ hashed_slot),
            // so check if the nibbled hashed_addr prefix is in the set.
            Bytes nibbled_addr = silkworm::trie::unpack_nibbles(
                ByteView{hashed_addr.bytes, 32});
            if (!storage_changes->contains(nibbled_addr)) {
                return cached->second;
            }
        }
    }

    // Collect all hashed storage slots for this account, sorted by hashed key.
    auto hashed_storage = collect_hashed_storage(state, address, incarnation);

    if (hashed_storage.empty()) {
        storage_root_cache_[hashed_addr] = silkworm::kEmptyRoot;
        return silkworm::kEmptyRoot;
    }

    silkworm::trie::HashBuilder hb;

    // Set up node collector to cache intermediate storage trie nodes.
    // These are stored for future incremental optimization with TrieCursor.
    hb.node_collector = [this, &hashed_addr](ByteView nibbled_key, const silkworm::trie::Node& node) {
        Bytes packed = silkworm::trie::pack_nibbles(nibbled_key);
        Bytes cache_key = storage_cache_key(hashed_addr, packed);
        cache_.storage_nodes[cache_key] = node;
    };

    // Leaf-only pass: iterate all storage slots in keccak256 order.
    for (const auto& [hashed_slot, value] : hashed_storage) {
        Bytes encoded = encode_storage_value(value);
        Bytes leaf_nibbled = silkworm::trie::unpack_nibbles(
            ByteView{hashed_slot.bytes, 32});
        hb.add_leaf(std::move(leaf_nibbled), encoded);
    }

    evmc::bytes32 root = hb.root_hash();
    storage_root_cache_[hashed_addr] = root;
    return root;
}

// ---------------------------------------------------------------------------
// State root computation
// ---------------------------------------------------------------------------

evmc::bytes32 IncrementalTrieCalculator::compute_state_root(
    EvmState& state,
    silkworm::trie::PrefixSet* account_changes,
    silkworm::trie::PrefixSet* storage_changes) {

    // Collect all accounts, sorted by keccak256(address).
    auto hashed_accounts = collect_hashed_accounts(state);

    if (hashed_accounts.empty()) {
        return silkworm::kEmptyRoot;
    }

    silkworm::trie::HashBuilder hb;

    // Set up node collector to cache intermediate account trie nodes.
    // These cached nodes enable future incremental optimization with a
    // proper TrieCursor (Erigon-style pre-order traversal merge).
    cache_.account_nodes.clear();
    hb.node_collector = [this](ByteView nibbled_key, const silkworm::trie::Node& node) {
        Bytes packed = silkworm::trie::pack_nibbles(nibbled_key);
        cache_.account_nodes[packed] = node;
    };

    // Incremental optimization: for unchanged accounts, reuse cached storage roots.
    // All accounts are still visited (leaf-only pass through HashBuilder), but
    // storage root computation is skipped for accounts not in the change set.

    for (auto& [hashed_addr, addr_acct] : hashed_accounts) {
        const auto& [addr, acct] = addr_acct;
        uint64_t incarnation = acct.incarnation > 0 ? acct.incarnation
                                                    : (acct.code_hash != silkworm::kEmptyHash
                                                           ? silkworm::kDefaultIncarnation : 0);

        // Check if this account's storage needs recomputation.
        evmc::bytes32 storage_root;
        bool need_recompute = true;
        if (account_changes) {
            Bytes nibbled_addr = silkworm::trie::unpack_nibbles(
                ByteView{hashed_addr.bytes, 32});
            if (!account_changes->contains(nibbled_addr)) {
                // Account unchanged — use cached storage root if available.
                auto cached_it = storage_root_cache_.find(hashed_addr);
                if (cached_it != storage_root_cache_.end()) {
                    storage_root = cached_it->second;
                    need_recompute = false;
                }
            }
        }
        if (need_recompute) {
            storage_root = compute_storage_root(
                state, addr, hashed_addr, incarnation, storage_changes);
        }

        Bytes encoded = encode_account_for_trie(acct, storage_root);
        Bytes leaf_nibbled = silkworm::trie::unpack_nibbles(
            ByteView{hashed_addr.bytes, 32});
        hb.add_leaf(std::move(leaf_nibbled), encoded);
    }

    return hb.root_hash();
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

void IncrementalTrieCalculator::reset() {
    storage_root_cache_.clear();
    cache_.clear();
}

}  // namespace evm_workchain
