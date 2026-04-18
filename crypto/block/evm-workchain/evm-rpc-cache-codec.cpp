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
#include "evm-rpc-cache-codec.h"

#include "evm-cell-codec.h"  // encode_evm_bytecode / decode_evm_bytecode

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include <cstring>

namespace evm_workchain {

namespace {

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
    auto cs = vm::load_cell_slice(cell);
    if (cs.size_refs() < count) return false;
    out.resize(count);
    for (unsigned i = 0; i < count; ++i) {
        auto leaf = cs.prefetch_ref(i);
        if (leaf.is_null()) return false;
        auto ls = vm::load_cell_slice(leaf);
        if (!ls.fetch_bytes(out[i].bytes, 32)) return false;
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
    auto cs = vm::load_cell_slice(cell);
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

    return load_maybe_bytes(cs, out.data);
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
        auto cs = vm::load_cell_slice(cell);
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
        unsigned cont_refs = (has_next == 1) ? 1u : 0u;
        if (cont_refs > nrefs) return false;
        unsigned log_refs = nrefs - cont_refs;

        for (unsigned r = 0; r < log_refs; ++r) {
            silkworm::Log lg;
            if (!decode_one_log(cs.prefetch_ref(r), lg)) return false;
            out.push_back(std::move(lg));
        }
        if (has_next == 0) break;
        cell = cs.prefetch_ref(log_refs);
    }
    if (total < 0) return false;
    return out.size() == static_cast<size_t>(total);
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> encode_persisted_receipt(const StoredReceipt& receipt) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(kPersistedReceiptMagic), kPersistedReceiptMagicBits);
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
    auto cs = vm::load_cell_slice(cell);

    long long magic = 0;
    if (!cs.fetch_long_bool(kPersistedReceiptMagicBits, magic) ||
        static_cast<unsigned long long>(magic) != kPersistedReceiptMagic) {
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

    return true;
}

}  // namespace evm_workchain
