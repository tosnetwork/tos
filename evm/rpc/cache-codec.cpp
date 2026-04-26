/*
    EVM Workchain — RPC cache cell codec implementation (Phase F scaffold).

    Encodes/decodes PersistedReceipt cells for the future side-channel
    persisted RPC cache.  See `evm-rpc-cache-codec.h` for the schema and
    `doc/evm-workchain-rpc-cache-persistence.md` for the broader Phase F
    design (Option C: side-channel cell tree referenced from `cp.new_data`
    but not contributing to consensus state_hash).

    Implementation notes
    ---------------------
    - Variable-length byte fields (`return_data`, log `data`) use the
      existing `encode_evm_bytecode` / `decode_evm_bytecode` chunk chain
      from `evm-cell-codec.cpp`.  That codec is already battle-tested for
      contract bytecode of arbitrary size and is deterministic.
    - The receipt's `logs` vector is encoded as a single inner cell
      (`PersistedLogList`) that owns one ref per log.  Up to 16 logs fit
      directly because TOS cells allow at most 4 refs per cell — so the
      list cell is itself a tiny chain (each cell holds up to 3 log refs
      and one ref to the next chunk).  This keeps the encoding inside
      the standard cell shape without requiring a HashmapE detour.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/rpc/cache-codec.h"

#include "evm/core/cell-codec.h"  // encode_evm_bytecode / decode_evm_bytecode

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

#include <cstring>

namespace evm_workchain {

namespace {

bool load_ordinary_slice(td::Ref<vm::Cell> cell, vm::CellSlice& out) noexcept {
    if (cell.is_null()) return false;
    try {
        bool special = false;
        out = vm::load_cell_slice_special(cell, special);
        return !special;
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Helpers: variable-length bytes via the EVM bytecode chunk chain.
// ---------------------------------------------------------------------------

/// Encode a byte slice as a Maybe ^Cell. Empty slice → `nothing` (0 bit).
/// Non-empty slice → `1` bit + ref to a chunk chain (encode_evm_bytecode).
void store_maybe_bytes(vm::CellBuilder& cb, td::Slice bytes) {
    if (bytes.empty()) {
        cb.store_long(0, 1);
        return;
    }
    auto chain = encode_evm_bytecode(bytes);
    if (chain.is_null()) {
        // encode_evm_bytecode never returns null for non-empty input, but
        // be defensive: store as empty.
        cb.store_long(0, 1);
        return;
    }
    cb.store_long(1, 1);
    cb.store_ref(chain);
}

bool load_maybe_bytes(vm::CellSlice& cs, silkworm::Bytes& out) {
    out.clear();
    long long has = 0;
    if (!cs.fetch_long_bool(1, has)) return false;
    if (!has) return true;
    if (cs.size_refs() == 0) return false;
    auto chunk_root = cs.fetch_ref();
    auto decoded = decode_evm_bytecode(chunk_root);
    out.assign(decoded.begin(), decoded.end());
    return true;
}

// ---------------------------------------------------------------------------
// Optional address (`std::optional<evmc::address>` ↔ to_kind:(##2) bits160?).
// ---------------------------------------------------------------------------

void store_optional_address(vm::CellBuilder& cb, const std::optional<evmc::address>& opt) {
    if (!opt.has_value()) {
        cb.store_long(0, 2);
        return;
    }
    cb.store_long(1, 2);
    cb.store_bytes(opt->bytes, 20);
}

bool load_optional_address(vm::CellSlice& cs, std::optional<evmc::address>& out) {
    out.reset();
    long long kind = 0;
    if (!cs.fetch_long_bool(2, kind)) return false;
    if (kind == 0) return true;
    if (kind != 1) return false;
    evmc::address addr{};
    if (!cs.fetch_bytes(addr.bytes, 20)) return false;
    out = addr;
    return true;
}

// ---------------------------------------------------------------------------
// PersistedLog cell (one cell per log entry, chained for the list).
// ---------------------------------------------------------------------------
//
//   persisted_log#4c4f4720
//     address:bits160
//     topic_count:(## 4)
//     topics:(Maybe ^TopicArray)
//     data:(Maybe ^Cell)
//     = PersistedLog;
//
//   topic_array#_ {n:#}
//     entries:(n * bits256) { n <= 4 }
//     = TopicArray;
//
// A single log cell: 32 (magic) + 160 (addr) + 4 (count) + 1 (topic Maybe)
// + 1 (data Maybe) = 198 bits.  Refs: 0..2.  Topics live in a side cell
// (one cell can hold 4 * 256 = 1024 bits = 128 bytes — exactly fits, since
// store_bytes is 1-byte aligned and 128 bytes is the max_bytes per call;
// we issue four separate 32-byte stores so each call is well within limit).

// Topics encoded as a parent cell holding one ref per topic (max 4 topics =
// 4 refs, exactly fits cell limits). Each topic ref is a leaf cell storing
// 32 bytes (256 bits, well within the 1023-bit per-cell limit).
//
// Inline 4 × 256 = 1024 bits would overflow a single cell (max_bits = 1023),
// so the per-topic ref form is the simplest layout that handles LOG4.
td::Ref<vm::Cell> encode_topic_array(const std::vector<evmc::bytes32>& topics) {
    if (topics.empty()) return {};
    vm::CellBuilder parent;
    auto count = topics.size();
    if (count > 4) count = 4;
    for (size_t i = 0; i < count; ++i) {
        vm::CellBuilder leaf;
        leaf.store_bytes(topics[i].bytes, 32);
        parent.store_ref(leaf.finalize());
    }
    return parent.finalize();
}

bool decode_topic_array(td::Ref<vm::Cell> cell, unsigned count,
                        std::vector<evmc::bytes32>& out) {
    out.clear();
    if (count == 0) return cell.is_null();
    if (cell.is_null()) return false;
    vm::CellSlice cs;
    if (!load_ordinary_slice(cell, cs)) return false;
    if (cs.size() != 0 || cs.size_refs() != count) return false;
    out.resize(count);
    for (unsigned i = 0; i < count; ++i) {
        auto leaf = cs.prefetch_ref(i);
        if (leaf.is_null()) return false;
        vm::CellSlice ls;
        if (!load_ordinary_slice(leaf, ls)) return false;
        if (!ls.fetch_bytes(out[i].bytes, 32)) return false;
        if (ls.size() != 0 || ls.size_refs() != 0) return false;
    }
    return true;
}

td::Ref<vm::Cell> encode_one_log(const silkworm::Log& log) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(kPersistedLogMagic), kPersistedLogMagicBits);
    cb.store_bytes(log.address.bytes, 20);
    auto count = static_cast<unsigned>(log.topics.size());
    if (count > 4) count = 4;  // EVM caps at LOG4
    cb.store_long(count, 4);

    auto topics_cell = encode_topic_array(log.topics);
    if (topics_cell.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(topics_cell);
    } else {
        cb.store_long(0, 1);
    }

    store_maybe_bytes(cb, td::Slice{reinterpret_cast<const char*>(log.data.data()), log.data.size()});
    return cb.finalize();
}

bool decode_one_log(td::Ref<vm::Cell> cell, silkworm::Log& out) {
    if (cell.is_null()) return false;
    vm::CellSlice cs;
    if (!load_ordinary_slice(cell, cs)) return false;
    long long magic = 0;
    if (!cs.fetch_long_bool(kPersistedLogMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kPersistedLogMagic) {
        return false;
    }
    if (!cs.fetch_bytes(out.address.bytes, 20)) return false;
    long long count = 0;
    if (!cs.fetch_long_bool(4, count) || count < 0 || count > 4) return false;

    long long has_topics = 0;
    if (!cs.fetch_long_bool(1, has_topics)) return false;
    td::Ref<vm::Cell> topics_cell;
    if (has_topics) {
        if (!cs.fetch_ref_to(topics_cell)) return false;
    }
    if (!decode_topic_array(topics_cell, static_cast<unsigned>(count), out.topics)) return false;

    if (!load_maybe_bytes(cs, out.data)) return false;
    return cs.size() == 0 && cs.size_refs() == 0;
}

// ---------------------------------------------------------------------------
// PersistedLogList cell.  Encoded as a chain of cells, each holding up to 3
// log refs + 1 ref to the next chunk.  Total log count is stored in the
// head cell (16 bits → 65535 logs per receipt, well above any realistic
// limit).  An empty list is just one cell with count=0 and no continuation.
// ---------------------------------------------------------------------------

constexpr size_t kLogsPerListChunk = 3;  // 4 refs - 1 for next = 3 logs

td::Ref<vm::Cell> encode_log_list(const std::vector<silkworm::Log>& logs) {
    auto count = static_cast<unsigned>(logs.size());
    if (count > 0xffffu) count = 0xffffu;

    // Pre-encode each log into its own cell.
    std::vector<td::Ref<vm::Cell>> log_cells;
    log_cells.reserve(count);
    for (unsigned i = 0; i < count; ++i) {
        log_cells.push_back(encode_one_log(logs[i]));
    }

    // Empty list: one cell with count=0 and no continuation.
    if (log_cells.empty()) {
        vm::CellBuilder cb;
        cb.store_long(0, 16);
        cb.store_long(0, 1);
        return cb.finalize();
    }

    // Build the chain tail-first.  Continuation chunks carry 0 in the count
    // slot (decoder reads count from the head only).  The head chunk gets
    // the real count.  Each chunk holds up to `kLogsPerListChunk` log refs
    // plus an optional continuation ref (max 4 refs total).
    td::Ref<vm::Cell> next;
    size_t i = log_cells.size();
    while (i > 0) {
        size_t take = std::min<size_t>(kLogsPerListChunk, i);
        size_t start = i - take;
        bool is_head = (start == 0);

        vm::CellBuilder cb;
        cb.store_long(is_head ? count : 0u, 16);
        for (size_t k = 0; k < take; ++k) {
            cb.store_ref(log_cells[start + k]);
        }
        if (next.not_null()) {
            cb.store_long(1, 1);
            cb.store_ref(next);
        } else {
            cb.store_long(0, 1);
        }
        next = cb.finalize();
        i = start;
    }
    return next;
}

bool decode_log_list(td::Ref<vm::Cell> root, std::vector<silkworm::Log>& out) {
    out.clear();
    if (root.is_null()) return false;

    long long total = -1;
    auto cell = root;
    constexpr size_t kMaxChunks = 4096;  // bound for safety
    for (size_t step = 0; step < kMaxChunks; ++step) {
        if (cell.is_null()) return false;
        vm::CellSlice cs;
        if (!load_ordinary_slice(cell, cs)) return false;
        long long count_field = 0;
        if (!cs.fetch_long_bool(16, count_field)) return false;
        if (total < 0) {
            total = count_field;
            out.reserve(static_cast<size_t>(total));
        }

        // Determine continuation: peek the trailing Maybe bit.  Refs come
        // first in the cell layout, so we need to figure out which refs are
        // logs vs continuation.  Approach: read all refs except possibly
        // the last as logs; then read the trailing 1 bit; if it's 1, the
        // last ref was the continuation.
        unsigned nrefs = cs.size_refs();
        if (nrefs == 0) {
            // No refs at all → empty list (only valid when total == 0).
            // Still need to consume the Maybe bit.
            long long has_next = 0;
            if (!cs.fetch_long_bool(1, has_next)) return false;
            if (has_next) return false;  // would need a ref but has none
            break;
        }

        // Sniff the Maybe bit by looking at the slice end.  We can clone
        // the cs to peek without disturbing it.  Easier: compute logs-in-
        // chunk = nrefs - has_next, where has_next is the trailing bit.
        // But we don't yet know has_next.  Trick: read it now (we've
        // already consumed the count), then walk refs.
        long long has_next = 0;
        if (!cs.fetch_long_bool(1, has_next)) return false;
        if (cs.size() != 0) return false;
        unsigned cont_refs = (has_next != 0) ? 1u : 0u;
        if (cont_refs > nrefs) return false;
        unsigned log_refs = nrefs - cont_refs;
        if (log_refs > kLogsPerListChunk) return false;

        for (unsigned r = 0; r < log_refs; ++r) {
            silkworm::Log lg;
            if (!decode_one_log(cs.prefetch_ref(r), lg)) return false;
            out.push_back(std::move(lg));
        }
        if (!has_next) break;
        cell = cs.prefetch_ref(log_refs);
    }
    if (total < 0) return false;
    return out.size() == static_cast<size_t>(total);
}

}  // namespace

// ---------------------------------------------------------------------------
// uint256 (big-endian 32-byte) helpers.
// ---------------------------------------------------------------------------

void store_uint256(vm::CellBuilder& cb, const intx::uint256& v) {
    auto be = intx::be::store<evmc::uint256be>(v);
    cb.store_bytes(be.bytes, 32);
}

bool load_uint256(vm::CellSlice& cs, intx::uint256& out) {
    evmc::uint256be be{};
    if (!cs.fetch_bytes(be.bytes, 32)) return false;
    out = intx::be::load<intx::uint256>(be);
    return true;
}

// ---------------------------------------------------------------------------
// PersistedTransaction (StoredTransaction round-trip).
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> encode_persisted_transaction_impl(const StoredTransaction& txn) {
    // Total scalar bits would be 32 (magic) + 160 (from) + 162 (to opt)
    // + 256 (value) + 64 (nonce) + 64 (gas_limit) + 256 (gas_price)
    // + 64 (block_number) + 32 (tx_index) = 1090 — overflows 1023.
    // Split into a head with the address fields + a meta-ref cell with
    // the integer fields.
    vm::CellBuilder meta;
    store_uint256(meta, txn.value);
    store_uint256(meta, txn.gas_price);
    meta.store_long(static_cast<long long>(txn.nonce), 64);
    meta.store_long(static_cast<long long>(txn.gas_limit), 64);
    meta.store_long(static_cast<long long>(txn.block_number), 64);
    meta.store_long(static_cast<long long>(txn.tx_index), 32);

    vm::CellBuilder head;
    head.store_long(static_cast<long long>(kPersistedTransactionMagic),
                    kPersistedTransactionMagicBits);
    head.store_bytes(txn.from.bytes, 20);
    store_optional_address(head, txn.to);
    head.store_ref(meta.finalize());
    store_maybe_bytes(head, td::Slice{reinterpret_cast<const char*>(txn.data.data()),
                                       txn.data.size()});
    store_maybe_bytes(head, td::Slice{reinterpret_cast<const char*>(txn.raw_rlp.data()),
                                       txn.raw_rlp.size()});
    return head.finalize();
}

bool decode_persisted_transaction_impl(td::Ref<vm::Cell> cell, StoredTransaction& out) {
    out = StoredTransaction{};
    if (cell.is_null()) return false;
    vm::CellSlice cs;
    if (!load_ordinary_slice(cell, cs)) return false;
    long long magic = 0;
    if (!cs.fetch_long_bool(kPersistedTransactionMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kPersistedTransactionMagic) {
        return false;
    }
    if (!cs.fetch_bytes(out.from.bytes, 20)) return false;
    if (!load_optional_address(cs, out.to)) return false;

    if (cs.size_refs() == 0) return false;
    auto meta_cell = cs.fetch_ref();
    vm::CellSlice meta_cs;
    if (!load_ordinary_slice(meta_cell, meta_cs)) return false;
    if (!load_uint256(meta_cs, out.value)) return false;
    if (!load_uint256(meta_cs, out.gas_price)) return false;
    long long nonce = 0, gas_limit = 0, block_number = 0, tx_index = 0;
    if (!meta_cs.fetch_long_bool(64, nonce)) return false;
    if (!meta_cs.fetch_long_bool(64, gas_limit)) return false;
    if (!meta_cs.fetch_long_bool(64, block_number)) return false;
    if (!meta_cs.fetch_long_bool(32, tx_index)) return false;
    out.nonce = static_cast<uint64_t>(nonce);
    out.gas_limit = static_cast<uint64_t>(gas_limit);
    out.block_number = static_cast<uint64_t>(block_number);
    out.tx_index = static_cast<uint32_t>(tx_index);
    if (meta_cs.size() != 0 || meta_cs.size_refs() != 0) return false;

    if (!load_maybe_bytes(cs, out.data)) return false;
    if (!load_maybe_bytes(cs, out.raw_rlp)) return false;
    return cs.size() == 0 && cs.size_refs() == 0;
}

// ---------------------------------------------------------------------------
// PersistedBlock (StoredBlock round-trip).
//
// transaction_hashes encoded as a chunked chain (4 hashes per cell head + 1
// continuation ref), parallel to the log-list pattern.
// ---------------------------------------------------------------------------

constexpr size_t kHashesPerListChunk = 3;  // 4 refs - 1 for next = 3 hashes

td::Ref<vm::Cell> encode_hash32(const evmc::bytes32& h) {
    vm::CellBuilder cb;
    cb.store_bytes(h.bytes, 32);
    return cb.finalize();
}

bool decode_hash32(td::Ref<vm::Cell> cell, evmc::bytes32& out) {
    if (cell.is_null()) return false;
    vm::CellSlice cs;
    if (!load_ordinary_slice(cell, cs)) return false;
    if (!cs.fetch_bytes(out.bytes, 32)) return false;
    return cs.size() == 0 && cs.size_refs() == 0;
}

td::Ref<vm::Cell> encode_hash_list(const std::vector<evmc::bytes32>& hashes) {
    auto count = static_cast<unsigned>(hashes.size());
    if (count > 0xffffffu) count = 0xffffffu;  // 24-bit cap, plenty

    if (count == 0) {
        vm::CellBuilder cb;
        cb.store_long(0, 24);
        cb.store_long(0, 1);
        return cb.finalize();
    }

    std::vector<td::Ref<vm::Cell>> leaves;
    leaves.reserve(count);
    for (unsigned i = 0; i < count; ++i) {
        leaves.push_back(encode_hash32(hashes[i]));
    }

    td::Ref<vm::Cell> next;
    size_t i = leaves.size();
    while (i > 0) {
        size_t take = std::min<size_t>(kHashesPerListChunk, i);
        size_t start = i - take;
        bool is_head = (start == 0);

        vm::CellBuilder cb;
        cb.store_long(is_head ? count : 0u, 24);
        for (size_t k = 0; k < take; ++k) {
            cb.store_ref(leaves[start + k]);
        }
        if (next.not_null()) {
            cb.store_long(1, 1);
            cb.store_ref(next);
        } else {
            cb.store_long(0, 1);
        }
        next = cb.finalize();
        i = start;
    }
    return next;
}

bool decode_hash_list(td::Ref<vm::Cell> root, std::vector<evmc::bytes32>& out) {
    out.clear();
    if (root.is_null()) return false;

    long long total = -1;
    auto cell = root;
    constexpr size_t kMaxChunks = 1 << 20;
    for (size_t step = 0; step < kMaxChunks; ++step) {
        if (cell.is_null()) return false;
        vm::CellSlice cs;
        if (!load_ordinary_slice(cell, cs)) return false;
        long long count_field = 0;
        if (!cs.fetch_long_bool(24, count_field)) return false;
        if (total < 0) {
            total = count_field;
            out.reserve(static_cast<size_t>(total));
        }
        unsigned nrefs = cs.size_refs();
        long long has_next = 0;
        if (!cs.fetch_long_bool(1, has_next)) return false;
        if (cs.size() != 0) return false;
        unsigned cont_refs = (has_next != 0) ? 1u : 0u;
        if (cont_refs > nrefs) return false;
        unsigned hash_refs = nrefs - cont_refs;
        if (hash_refs > kHashesPerListChunk) return false;
        for (unsigned r = 0; r < hash_refs; ++r) {
            evmc::bytes32 h{};
            if (!decode_hash32(cs.prefetch_ref(r), h)) return false;
            out.push_back(h);
        }
        if (!has_next) break;
        cell = cs.prefetch_ref(hash_refs);
    }
    if (total < 0) return false;
    return out.size() == static_cast<size_t>(total);
}

td::Ref<vm::Cell> encode_persisted_block_impl(const StoredBlock& block) {
    // Body cell holds the scalar fields (under the 1023-bit cell limit) and
    // points at side cells for the bloom + hash list.
    //
    // Scalar bits: 32 (magic) + 64 (number) + 32 (timestamp lo, see below)
    // + 32 (timestamp hi) + 64 (gas_limit) + 64 (gas_used) + 160 (miner)
    // + 256 (base_fee) + 256 (state_root) + 256 (tx_root) + 256 (receipts_root)
    // = 1472 bits — exceeds one cell. Split: scalars in head, with a child
    // cell holding the four 256-bit roots + base_fee.
    vm::CellBuilder head;
    head.store_long(static_cast<long long>(kPersistedBlockMagic),
                    kPersistedBlockMagicBits);
    head.store_long(static_cast<long long>(block.number), 64);
    head.store_long(static_cast<long long>(block.timestamp), 64);
    head.store_long(static_cast<long long>(block.gas_limit), 64);
    head.store_long(static_cast<long long>(block.gas_used), 64);
    head.store_bytes(block.hash.bytes, 32);
    head.store_bytes(block.parent_hash.bytes, 32);
    head.store_bytes(block.miner.bytes, 20);
    // Now: 32 + 4*64 + 32 + 32 + 20 = 32 + 256 + 64 + 20 = 372 bytes
    // wait: 32 bits + 256 bits + (32+32+20) bytes = 288 bits + 84 bytes
    // = 288 + 672 = 960 bits — under 1023. OK.

    // Roots cell: base_fee (256) + state_root (256) + tx_root (256)
    // + receipts_root (256) = 1024 bits — overflows by 1. Split base_fee
    // into the head cell (head was 960 bits + 256 base_fee = 1216, also
    // overflow). Use two ref cells: roots_a (base_fee + state_root = 512)
    // and roots_b (tx_root + receipts_root = 512).
    vm::CellBuilder roots_a;
    store_uint256(roots_a, block.base_fee_per_gas);
    roots_a.store_bytes(block.state_root.bytes, 32);
    head.store_ref(roots_a.finalize());

    vm::CellBuilder roots_b;
    roots_b.store_bytes(block.transactions_root.bytes, 32);
    roots_b.store_bytes(block.receipts_root.bytes, 32);
    head.store_ref(roots_b.finalize());

    // Bloom (256 bytes = 2048 bits) needs its own ref cell. 2048 > 1023
    // → chain into 2 cells: 1016 bits each + continuation. Use a bytes
    // chunk via encode_evm_bytecode (already chunks at 127 bytes).
    auto bloom_cell = encode_evm_bytecode(
        td::Slice{reinterpret_cast<const char*>(block.logs_bloom), 256});
    head.store_ref(bloom_cell);

    // Transaction-hash list as its own ref.
    head.store_ref(encode_hash_list(block.transaction_hashes));

    return head.finalize();
}

bool decode_persisted_block_impl(td::Ref<vm::Cell> cell, StoredBlock& out) {
    out = StoredBlock{};
    if (cell.is_null()) return false;
    vm::CellSlice cs;
    if (!load_ordinary_slice(cell, cs)) return false;

    long long magic = 0;
    if (!cs.fetch_long_bool(kPersistedBlockMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kPersistedBlockMagic) {
        return false;
    }
    long long number = 0, timestamp = 0, gas_limit = 0, gas_used = 0;
    if (!cs.fetch_long_bool(64, number)) return false;
    if (!cs.fetch_long_bool(64, timestamp)) return false;
    if (!cs.fetch_long_bool(64, gas_limit)) return false;
    if (!cs.fetch_long_bool(64, gas_used)) return false;
    out.number = static_cast<uint64_t>(number);
    out.timestamp = static_cast<uint64_t>(timestamp);
    out.gas_limit = static_cast<uint64_t>(gas_limit);
    out.gas_used = static_cast<uint64_t>(gas_used);
    if (!cs.fetch_bytes(out.hash.bytes, 32)) return false;
    if (!cs.fetch_bytes(out.parent_hash.bytes, 32)) return false;
    if (!cs.fetch_bytes(out.miner.bytes, 20)) return false;

    if (cs.size_refs() < 4) return false;
    auto roots_a = cs.fetch_ref();
    auto roots_b = cs.fetch_ref();
    auto bloom_cell = cs.fetch_ref();
    auto hashes_cell = cs.fetch_ref();
    if (cs.size() != 0 || cs.size_refs() != 0) return false;

    vm::CellSlice cs_a;
    if (!load_ordinary_slice(roots_a, cs_a)) return false;
    if (!load_uint256(cs_a, out.base_fee_per_gas)) return false;
    if (!cs_a.fetch_bytes(out.state_root.bytes, 32)) return false;
    if (cs_a.size() != 0 || cs_a.size_refs() != 0) return false;

    vm::CellSlice cs_b;
    if (!load_ordinary_slice(roots_b, cs_b)) return false;
    if (!cs_b.fetch_bytes(out.transactions_root.bytes, 32)) return false;
    if (!cs_b.fetch_bytes(out.receipts_root.bytes, 32)) return false;
    if (cs_b.size() != 0 || cs_b.size_refs() != 0) return false;

    auto bloom_bytes = decode_evm_bytecode(bloom_cell);
    if (bloom_bytes.size() != 256) return false;
    std::memcpy(out.logs_bloom, bloom_bytes.data(), 256);

    if (!decode_hash_list(hashes_cell, out.transaction_hashes)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> encode_persisted_transaction(const StoredTransaction& txn) {
    return encode_persisted_transaction_impl(txn);
}
bool decode_persisted_transaction(td::Ref<vm::Cell> cell, StoredTransaction& out) {
    return decode_persisted_transaction_impl(cell, out);
}
td::Ref<vm::Cell> encode_persisted_block(const StoredBlock& block) {
    return encode_persisted_block_impl(block);
}
bool decode_persisted_block(td::Ref<vm::Cell> cell, StoredBlock& out) {
    return decode_persisted_block_impl(cell, out);
}

// ---------------------------------------------------------------------------
// PersistedLogsForBlock — chunked chain of IndexedLog cells (eth_getLogs).
//
//   indexed_log#494c4f47
//     block_number:uint64
//     tx_hash:bits256
//     log_index:uint32
//     tx_index:uint32
//     log:^PersistedLog
//     = IndexedLog;
//
//   indexed_log_list_chunk#_
//     count:uint32              // populated only on the head chunk
//     entries:(n * ^IndexedLog) // n in [0, 3]
//     next:(Maybe ^Chunk)
//     = IndexedLogListChunk;
// ---------------------------------------------------------------------------

namespace {
constexpr size_t kIndexedLogsPerChunk = 3;

td::Ref<vm::Cell> encode_one_indexed_log(const IndexedLog& il) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(kPersistedIndexedLogMagic),
                  kPersistedIndexedLogMagicBits);
    cb.store_long(static_cast<long long>(il.block_number), 64);
    cb.store_bytes(il.tx_hash.bytes, 32);
    cb.store_long(static_cast<long long>(il.log_index), 32);
    cb.store_long(static_cast<long long>(il.tx_index), 32);
    cb.store_ref(encode_one_log(il.log));
    return cb.finalize();
}

bool decode_one_indexed_log(td::Ref<vm::Cell> cell, IndexedLog& out) {
    if (cell.is_null()) return false;
    vm::CellSlice cs;
    if (!load_ordinary_slice(cell, cs)) return false;
    long long magic = 0;
    if (!cs.fetch_long_bool(kPersistedIndexedLogMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kPersistedIndexedLogMagic) {
        return false;
    }
    long long block_number = 0, log_index = 0, tx_index = 0;
    if (!cs.fetch_long_bool(64, block_number)) return false;
    if (!cs.fetch_bytes(out.tx_hash.bytes, 32)) return false;
    if (!cs.fetch_long_bool(32, log_index)) return false;
    if (!cs.fetch_long_bool(32, tx_index)) return false;
    out.block_number = static_cast<uint64_t>(block_number);
    out.log_index = static_cast<uint32_t>(log_index);
    out.tx_index = static_cast<uint32_t>(tx_index);
    if (cs.size_refs() == 0) return false;
    auto log_ref = cs.fetch_ref();
    if (cs.size() != 0 || cs.size_refs() != 0) return false;
    return decode_one_log(log_ref, out.log);
}

td::Ref<vm::Cell> encode_indexed_log_list(const std::vector<IndexedLog>& logs) {
    auto count = static_cast<unsigned>(logs.size());
    if (count > 0xffffffffu) count = 0xffffffffu;

    if (logs.empty()) {
        vm::CellBuilder cb;
        cb.store_long(0, 32);
        cb.store_long(0, 1);
        return cb.finalize();
    }

    std::vector<td::Ref<vm::Cell>> il_cells;
    il_cells.reserve(logs.size());
    for (const auto& il : logs) {
        il_cells.push_back(encode_one_indexed_log(il));
    }

    td::Ref<vm::Cell> next;
    size_t i = il_cells.size();
    while (i > 0) {
        size_t take = std::min<size_t>(kIndexedLogsPerChunk, i);
        size_t start = i - take;
        bool is_head = (start == 0);

        vm::CellBuilder cb;
        cb.store_long(is_head ? count : 0u, 32);
        for (size_t k = 0; k < take; ++k) {
            cb.store_ref(il_cells[start + k]);
        }
        if (next.not_null()) {
            cb.store_long(1, 1);
            cb.store_ref(next);
        } else {
            cb.store_long(0, 1);
        }
        next = cb.finalize();
        i = start;
    }
    return next;
}

bool decode_indexed_log_list(td::Ref<vm::Cell> root, std::vector<IndexedLog>& out) {
    out.clear();
    if (root.is_null()) return false;

    long long total = -1;
    auto cell = root;
    constexpr size_t kMaxChunks = 1 << 20;
    for (size_t step = 0; step < kMaxChunks; ++step) {
        if (cell.is_null()) return false;
        vm::CellSlice cs;
        if (!load_ordinary_slice(cell, cs)) return false;
        long long count_field = 0;
        if (!cs.fetch_long_bool(32, count_field)) return false;
        if (total < 0) {
            total = count_field;
            out.reserve(static_cast<size_t>(total));
        }
        unsigned nrefs = cs.size_refs();
        long long has_next = 0;
        if (!cs.fetch_long_bool(1, has_next)) return false;
        if (cs.size() != 0) return false;
        unsigned cont_refs = (has_next != 0) ? 1u : 0u;
        if (cont_refs > nrefs) return false;
        unsigned log_refs = nrefs - cont_refs;
        if (log_refs > kIndexedLogsPerChunk) return false;
        for (unsigned r = 0; r < log_refs; ++r) {
            IndexedLog il;
            if (!decode_one_indexed_log(cs.prefetch_ref(r), il)) return false;
            out.push_back(std::move(il));
        }
        if (!has_next) break;
        cell = cs.prefetch_ref(log_refs);
    }
    if (total < 0) return false;
    return out.size() == static_cast<size_t>(total);
}
}  // anonymous namespace (Phase F.6 indexed-log helpers)

td::Ref<vm::Cell> encode_persisted_logs_for_block(const std::vector<IndexedLog>& logs) {
    return encode_indexed_log_list(logs);
}
bool decode_persisted_logs_for_block(td::Ref<vm::Cell> cell, std::vector<IndexedLog>& out) {
    return decode_indexed_log_list(cell, out);
}

td::Ref<vm::Cell> encode_persisted_receipt(const StoredReceipt& receipt) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(kPersistedReceiptMagic), kPersistedReceiptMagicBits);
    cb.store_long(static_cast<long long>(receipt.type), 8);
    cb.store_long(receipt.success ? 1 : 0, 1);
    cb.store_long(static_cast<long long>(receipt.gas_used), 64);
    cb.store_long(static_cast<long long>(receipt.cumulative_gas_used), 64);
    cb.store_long(static_cast<long long>(receipt.block_number), 64);
    cb.store_long(static_cast<long long>(receipt.tx_index), 32);
    cb.store_bytes(receipt.from.bytes, 20);
    store_optional_address(cb, receipt.to);
    store_optional_address(cb, receipt.contract_address);
    store_maybe_bytes(cb, td::Slice{reinterpret_cast<const char*>(receipt.return_data.data()),
                                    receipt.return_data.size()});

    auto logs_cell = encode_log_list(receipt.logs);
    cb.store_ref(logs_cell);

    return cb.finalize();
}

bool decode_persisted_receipt(td::Ref<vm::Cell> cell, StoredReceipt& out) {
    out = StoredReceipt{};
    if (cell.is_null()) return false;
    vm::CellSlice cs;
    if (!load_ordinary_slice(cell, cs)) return false;

    long long magic = 0;
    if (!cs.fetch_long_bool(kPersistedReceiptMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kPersistedReceiptMagic) {
        return false;
    }

    long long tx_type = 0;
    if (!cs.fetch_long_bool(8, tx_type)) return false;
    switch (static_cast<uint8_t>(tx_type)) {
        case static_cast<uint8_t>(silkworm::TransactionType::kLegacy):
        case static_cast<uint8_t>(silkworm::TransactionType::kAccessList):
        case static_cast<uint8_t>(silkworm::TransactionType::kDynamicFee):
        case static_cast<uint8_t>(silkworm::TransactionType::kBlob):
        case static_cast<uint8_t>(silkworm::TransactionType::kSetCode):
        case static_cast<uint8_t>(silkworm::TransactionType::kSystem):
            out.type = static_cast<silkworm::TransactionType>(tx_type);
            break;
        default:
            return false;
    }

    long long succ = 0;
    if (!cs.fetch_long_bool(1, succ)) return false;
    out.success = (succ != 0);

    long long gas_used = 0, cum_gas = 0, block_num = 0, tx_idx = 0;
    if (!cs.fetch_long_bool(64, gas_used)) return false;
    if (!cs.fetch_long_bool(64, cum_gas)) return false;
    if (!cs.fetch_long_bool(64, block_num)) return false;
    if (!cs.fetch_long_bool(32, tx_idx)) return false;
    out.gas_used = static_cast<uint64_t>(gas_used);
    out.cumulative_gas_used = static_cast<uint64_t>(cum_gas);
    out.block_number = static_cast<uint64_t>(block_num);
    out.tx_index = static_cast<uint32_t>(tx_idx);

    if (!cs.fetch_bytes(out.from.bytes, 20)) return false;
    if (!load_optional_address(cs, out.to)) return false;
    if (!load_optional_address(cs, out.contract_address)) return false;
    if (!load_maybe_bytes(cs, out.return_data)) return false;

    if (cs.size_refs() == 0) return false;
    auto logs_root = cs.fetch_ref();
    if (!decode_log_list(logs_root, out.logs)) return false;

    return cs.size() == 0 && cs.size_refs() == 0;
}

}  // namespace evm_workchain
