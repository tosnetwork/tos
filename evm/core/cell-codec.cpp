/*
    EVM Workchain — cell codec implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/cell-codec.h"

#include "evm/core/cell-state.h"
#include "evm/core/incremental-trie.h"
#include "evm/core/state.h"

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

#include <cstring>
#include <memory>
#include <mutex>

namespace evm_workchain {

namespace {

bool bytes32_equal(const evmc::bytes32& a, const evmc::bytes32& b) noexcept {
    return std::memcmp(a.bytes, b.bytes, 32) == 0;
}

bool verify_declared_eth_state_root(const td::Ref<vm::Cell>& state_root,
                                    const evmc::bytes32& declared) noexcept {
    try {
        auto cell_state = std::make_unique<CellEvmState>();
        if (state_root.not_null() && !cell_state->load_from_cell(state_root)) {
            return false;
        }
        EvmState state(std::move(cell_state));
        std::unique_lock lock(state.mutex());
        IncrementalTrieCalculator calc;
        auto computed = calc.compute_state_root(state, nullptr, nullptr);
        return bytes32_equal(computed, declared);
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

}  // namespace

td::Ref<vm::Cell> encode_evm_account_data(const silkworm::Account& acct,
                                          const td::Ref<vm::Cell>& storage_root,
                                          const td::Ref<vm::Cell>& code_root) {
    vm::CellBuilder cb;
    // magic#45564d (24 bits)
    cb.store_long(static_cast<long long>(kEvmAccountMagic), kEvmMagicBits);
    // nonce (64 bits, big-endian)
    cb.store_long(static_cast<long long>(acct.nonce), 64);
    // balance (256 bits, big-endian uint256)
    auto bal_be = intx::be::store<evmc::uint256be>(acct.balance);
    cb.store_bytes(bal_be.bytes, 32);
    // code_hash (256 bits)
    cb.store_bytes(acct.code_hash.bytes, 32);
    // storage: Maybe ^Cell  (1 bit + optional ref)
    if (storage_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(storage_root);
    } else {
        cb.store_long(0, 1);
    }
    // code: Maybe ^EvmBytecodeChunk  (1 bit + optional ref)
    if (code_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(code_root);
    } else {
        cb.store_long(0, 1);
    }
    return cb.finalize();
}

bool decode_evm_account_data(td::Ref<vm::Cell> cell,
                             silkworm::Account& acct,
                             td::Ref<vm::Cell>& storage_root,
                             td::Ref<vm::Cell>& code_root) {
    storage_root = {};
    code_root = {};
    if (cell.is_null()) return false;
    auto cs = vm::load_cell_slice(cell);
    // magic
    long long magic = 0;
    if (!cs.fetch_long_bool(kEvmMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kEvmAccountMagic) {
        return false;
    }
    // nonce
    long long nonce = 0;
    if (!cs.fetch_long_bool(64, nonce)) return false;
    acct.nonce = static_cast<uint64_t>(nonce);
    // balance
    evmc::uint256be bal_be{};
    if (!cs.fetch_bytes(bal_be.bytes, 32)) return false;
    acct.balance = intx::be::load<intx::uint256>(bal_be);
    // code_hash
    if (!cs.fetch_bytes(acct.code_hash.bytes, 32)) return false;
    // storage Maybe ^Cell
    long long has_storage = 0;
    if (!cs.fetch_long_bool(1, has_storage)) return false;
    if (has_storage) {
        if (!cs.fetch_ref_to(storage_root)) return false;
    }
    // code Maybe ^Cell — optional; absent in legacy cells, so tolerate EOF.
    if (cs.size() >= 1) {
        long long has_code = 0;
        if (cs.fetch_long_bool(1, has_code) && has_code) {
            cs.fetch_ref_to(code_root);
        }
    }
    // incarnation is not part of cell schema (always 0 in our model)
    acct.incarnation = 0;
    return true;
}

td::Ref<vm::Cell> encode_storage_value(const evmc::bytes32& value) {
    vm::CellBuilder cb;
    cb.store_bytes(value.bytes, 32);
    return cb.finalize();
}

evmc::bytes32 decode_storage_value(td::Ref<vm::Cell> cell) {
    evmc::bytes32 v{};
    if (cell.is_null()) return v;
    auto cs = vm::load_cell_slice(cell);
    if (cs.size() >= 256) {
        cs.fetch_bytes(v.bytes, 32);
    }
    return v;
}

void address_to_key(const evmc::address& addr, unsigned char out[32]) {
    std::memset(out, 0, 12);                     // left-pad
    std::memcpy(out + 12, addr.bytes, 20);       // 20-byte EVM address
}

void bytes32_to_key(const evmc::bytes32& v, unsigned char out[32]) {
    std::memcpy(out, v.bytes, 32);
}

// ---------------------------------------------------------------------------
// EVM bytecode cell chain (Phase D.2)
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> encode_evm_bytecode(td::Slice code) {
    if (code.empty()) return {};

    // Build chunks tail-first so the head is the cell whose `next` ref
    // points to the second chunk, etc. Walking the chain at decode time
    // reads in the same order chunks were produced — bytecode reads
    // left-to-right.
    td::Ref<vm::Cell> next;
    size_t total = code.size();
    // Number of chunks (ceiling division).
    size_t n_chunks = (total + kEvmBytecodeChunkBytes - 1) / kEvmBytecodeChunkBytes;
    for (size_t i = n_chunks; i-- > 0;) {
        size_t start = i * kEvmBytecodeChunkBytes;
        size_t end = std::min(start + kEvmBytecodeChunkBytes, total);
        size_t len = end - start;

        vm::CellBuilder cb;
        cb.store_bytes(code.data() + start, len);
        if (next.not_null()) {
            cb.store_long(1, 1);
            cb.store_ref(next);
        } else {
            cb.store_long(0, 1);
        }
        next = cb.finalize();
    }
    return next;
}

std::string decode_evm_bytecode(td::Ref<vm::Cell> root) {
    if (root.is_null()) return {};

    std::string out;
    auto cell = root;
    // Bound the walk so a malicious cell tree cannot DoS via cycles: 24 KB
    // EIP-170 max + headroom = ~256 chunks at 127 bytes/chunk.
    constexpr size_t kMaxChunks = 1024;
    for (size_t i = 0; i < kMaxChunks; ++i) {
        if (cell.is_null()) break;
        auto cs = vm::load_cell_slice(cell);
        unsigned bits = cs.size();
        if (bits < 1 || (bits - 1) % 8 != 0) {
            // Last bit is the Maybe tag; data must be byte-aligned.
            return {};
        }
        unsigned data_bytes = (bits - 1) / 8;
        if (data_bytes > 0) {
            size_t off = out.size();
            out.resize(off + data_bytes);
            cs.fetch_bytes(reinterpret_cast<unsigned char*>(out.data() + off), data_bytes);
        } else {
            // Skip zero data bytes (just the Maybe tag in this cell).
            cs.advance(0);
        }
        unsigned has_next = static_cast<unsigned>(cs.fetch_ulong(1));
        if (has_next == 0) {
            return out;
        }
        if (cs.size_refs() == 0) return {};
        cell = cs.prefetch_ref(0);
    }
    // Cycle / oversize — reject defensively.
    return {};
}

bool decode_cp_new_data(const td::Ref<vm::Cell>& cell,
                        td::Ref<vm::Cell>& state_root_out,
                        evmc::bytes32& eth_state_root_out,
                        td::Ref<vm::Cell>& rpc_cache_root_out) {
    state_root_out = {};
    rpc_cache_root_out = {};
    try {
        if (cell.is_null()) return false;
        auto cs = vm::load_cell_slice(cell);
        if (cs.size() < kEvmMagicBits + 1 + 256) return false;
        auto magic = cs.fetch_ulong(kEvmMagicBits);
        if (magic != kEvmAccountMagic) return false;
        auto has_root = cs.fetch_ulong(1);
        if (has_root == 1) {
            if (cs.size_refs() == 0) return false;
            state_root_out = cs.fetch_ref();
        }
        if (cs.size() < 256) return false;
        cs.fetch_bytes(eth_state_root_out.bytes, 32);
        // The has_cache Maybe-tag is mandatory in v2 (we always emit it);
        // refuse cells that omit it rather than silently treating absence as 0.
        if (cs.size() < 1) return false;
        auto has_cache = cs.fetch_ulong(1);
        if (has_cache == 1) {
            if (cs.size_refs() == 0) return false;
            rpc_cache_root_out = cs.fetch_ref();
        }
        // Audit #3 (2026-04-26): require canonical encoding. Two cells with the
        // same logical content must produce the same cell hash; trailing bits or
        // unaccounted refs would let a peer construct multiple distinct cell
        // hashes for the same EVM state, breaking account-data identity.
        if (cs.size() != 0 || cs.size_refs() != 0) return false;
        // Audit #5 follow-up: the declared eth_state_root is consensus-visible
        // account data. Reject stale/forged roots before they can seed snapshot
        // compute or restart hydration.
        return verify_declared_eth_state_root(state_root_out, eth_state_root_out);
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

}  // namespace evm_workchain
