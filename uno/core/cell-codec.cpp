/*
    Uno Workchain — cell / TLV helpers implementation.
    Source: TOS-specific adapter.
*/
#include "uno/core/cell-codec.h"

#include <algorithm>
#include <cstring>

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Chunk chain
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> encode_chunk_chain(td::Slice bytes) noexcept {
    if (bytes.empty()) return {};
    td::Ref<vm::Cell> next;
    const size_t total = bytes.size();
    const size_t n_chunks = (total + kChunkInlineBytes - 1) / kChunkInlineBytes;
    for (size_t i = n_chunks; i-- > 0;) {
        size_t start = i * kChunkInlineBytes;
        size_t end = std::min(start + size_t{kChunkInlineBytes}, total);
        size_t len = end - start;
        vm::CellBuilder cb;
        cb.store_bytes(bytes.data() + start, len);
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

std::string decode_chunk_chain(td::Ref<vm::Cell> root) noexcept {
    if (root.is_null()) return {};
    std::string out;
    auto cell = root;
    for (size_t i = 0; i < kChunkChainWalkLimit; ++i) {
        if (cell.is_null()) break;
        auto cs = vm::load_cell_slice(cell);
        unsigned bits = cs.size();
        if (bits < 1 || (bits - 1) % 8 != 0) return {};
        unsigned data_bytes = (bits - 1) / 8;
        if (data_bytes > 0) {
            size_t off = out.size();
            out.resize(off + data_bytes);
            cs.fetch_bytes(reinterpret_cast<unsigned char*>(out.data() + off), data_bytes);
        }
        unsigned has_next = static_cast<unsigned>(cs.fetch_ulong(1));
        if (has_next == 0) return out;
        if (cs.size_refs() == 0) return {};
        cell = cs.prefetch_ref(0);
    }
    return {};
}

size_t chunk_chain_byte_length(td::Ref<vm::Cell> root) noexcept {
    if (root.is_null()) return 0;
    size_t total = 0;
    auto cell = root;
    for (size_t i = 0; i < kChunkChainWalkLimit; ++i) {
        if (cell.is_null()) break;
        auto cs = vm::load_cell_slice(cell);
        unsigned bits = cs.size();
        if (bits < 1 || (bits - 1) % 8 != 0) return total;
        total += (bits - 1) / 8;
        auto tmp = cs;
        if (!tmp.advance(bits - 1)) return total;
        unsigned has_next = static_cast<unsigned>(tmp.fetch_ulong(1));
        if (has_next == 0) break;
        if (cs.size_refs() == 0) break;
        cell = cs.prefetch_ref(0);
    }
    return total;
}

// ---------------------------------------------------------------------------
// TLV helpers
// ---------------------------------------------------------------------------

td::Status store_tlv(vm::CellBuilder& cb, uint8_t tag, td::Slice value) noexcept {
    if (value.size() > 0xFFFFu) {
        return td::Status::Error("tlv value too large (> 65535 bytes)");
    }
    const unsigned needed_bits = 8 + 16 + static_cast<unsigned>(value.size()) * 8;
    if (cb.remaining_bits() < needed_bits) {
        return td::Status::Error("tlv does not fit into current cell; caller must chain");
    }
    cb.store_long(tag, 8);
    cb.store_long(static_cast<long long>(value.size()), 16);
    cb.store_bytes(value.data(), value.size());
    return td::Status::OK();
}

bool fetch_tlv(vm::CellSlice& cs, TlvField& out) noexcept {
    if (!cs.have(8 + 16)) return false;
    out.tag = static_cast<uint8_t>(cs.fetch_ulong(8));
    uint16_t len = static_cast<uint16_t>(cs.fetch_ulong(16));
    if (!cs.have(static_cast<unsigned>(len) * 8u)) return false;
    out.value.resize(len);
    return cs.fetch_bytes(reinterpret_cast<unsigned char*>(out.value.data()), len);
}

// ---------------------------------------------------------------------------
// Big-endian int helpers
// ---------------------------------------------------------------------------

void store_be_u16(vm::CellBuilder& cb, uint16_t v) { cb.store_long(v, 16); }
void store_be_u32(vm::CellBuilder& cb, uint32_t v) { cb.store_long(v, 32); }
void store_be_u64(vm::CellBuilder& cb, uint64_t v) { cb.store_long(static_cast<long long>(v), 64); }

bool fetch_be_u16(vm::CellSlice& cs, uint16_t& out) {
    if (!cs.have(16)) return false;
    out = static_cast<uint16_t>(cs.fetch_ulong(16));
    return true;
}

bool fetch_be_u32(vm::CellSlice& cs, uint32_t& out) {
    if (!cs.have(32)) return false;
    out = static_cast<uint32_t>(cs.fetch_ulong(32));
    return true;
}

bool fetch_be_u64(vm::CellSlice& cs, uint64_t& out) {
    if (!cs.have(64)) return false;
    out = cs.fetch_ulong(64);
    return true;
}

}  // namespace uno_workchain
