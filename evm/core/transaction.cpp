/*
    EVM Workchain — canonical transaction envelope implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/transaction.h"
#include "evm/core/cell-codec.h"

#include <silkworm/core/rlp/decode.hpp>

namespace evm_workchain {

std::variant<DecodedTransaction, TxDecodeError>
decode_evm_transaction(silkworm::ByteView raw_rlp) noexcept {
    silkworm::Transaction txn;

    // Decode the RLP-encoded signed transaction.
    // We accept both bare typed-transaction bytes and RLP-string-wrapped
    // forms (Eip2718Wrapping::kBoth) for maximum compatibility.
    silkworm::ByteView view = raw_rlp;
    auto result = silkworm::rlp::decode_transaction(
        view, txn,
        silkworm::rlp::Eip2718Wrapping::kBoth);

    if (!result.has_value()) {
        return TxDecodeError{"RLP decode failed"};
    }

    // Recover sender from the ECDSA signature.
    auto sender_opt = txn.sender();
    if (!sender_opt.has_value()) {
        return TxDecodeError{"sender recovery failed"};
    }

    DecodedTransaction decoded;
    decoded.txn = std::move(txn);
    decoded.sender = *sender_opt;
    return decoded;
}

std::optional<silkworm::Bytes>
extract_evm_payload(vm::CellSlice& body) noexcept {
    // `body` is the inbound message body slice as prepared by the
    // collator (transaction.cpp:1046): already past the ext_in_msg
    // init:(Maybe …) body:(Either X ^X) TLB, positioned at the
    // contents of the body cell itself. For EVM external messages,
    // build_evm_external_message stores those contents as the first
    // cell of an EvmBytecodeChunk chain:
    //
    //   bytes:(n * Bit) { n <= 1016 }
    //   next:(Maybe ^EvmBytecodeChunk)
    //
    // Walk the chain: read the inline data bytes, read the Maybe tag,
    // if set recurse into the next chunk via decode_evm_bytecode.

    unsigned bits = body.size();
    if (bits < 1) return std::nullopt;
    // Data bits are everything except the last (Maybe-tag) bit.
    if ((bits - 1) % 8 != 0) return std::nullopt;
    unsigned data_bytes = (bits - 1) / 8;

    silkworm::Bytes out;
    out.resize(data_bytes);
    if (data_bytes > 0 && !body.fetch_bytes(out.data(), data_bytes)) {
        return std::nullopt;
    }
    unsigned has_next = static_cast<unsigned>(body.fetch_ulong(1));
    // Round 72 MEDIUM fix: enforce exact-shape after the
    // Maybe-tag.  Pre-fix `extract_evm_payload` accepted trailing
    // refs (and trailing bits via the relaxed `have_refs()` check)
    // in both branches: with `has_next == 0` it ignored any refs;
    // with `has_next == 1` it read only the first ref and ignored
    // subsequent refs.  This let an attacker pad an external EVM
    // message body with arbitrary cell subtrees that the host
    // sized + validated under the same Ethereum tx hash, an
    // unmetered DoS / canonicality surface.
    //
    // Canonical shape per `build_evm_external_message`:
    //   has_next == 0  →  no trailing bits, no refs.
    //   has_next == 1  →  exactly one ref (the next chunk), no
    //                     trailing bits.
    if (has_next == 0) {
        if (body.size() != 0 || body.size_refs() != 0) {
            return std::nullopt;
        }
    } else {
        if (body.size() != 0 || body.size_refs() != 1) {
            return std::nullopt;
        }
        // Round 73 MEDIUM fix: enforce canonical chunk size on the
        // FIRST (head) chunk too.  Pre-fix `extract_evm_payload`
        // checked only trailing bits/refs but did not require the
        // head's `data_bytes == kEvmBytecodeChunkBytes` for
        // non-final chunks — the canonical encoder always packs
        // non-final cells with exactly 127 bytes, but a non-canonical
        // head with `data_bytes == 0` or `1..126` could chain to a
        // canonical tail and still parse to the same EVM tx bytes.
        // Two distinct cell-tree roots → same Ethereum tx hash;
        // collator dedupes by root hash, so the same tx could be
        // submitted twice with different cell shapes.  The
        // round-72 `decode_evm_bytecode` gate already covered this
        // for the recursive tail; this mirror covers the head
        // parsed inline by `extract_evm_payload`.
        if (data_bytes != kEvmBytecodeChunkBytes) {
            return std::nullopt;
        }
        auto next = body.fetch_ref();
        auto more = decode_evm_bytecode(next);
        if (more.empty()) return std::nullopt;
        out.insert(out.end(), more.begin(), more.end());
    }
    if (out.empty()) return std::nullopt;
    return out;
}

}  // namespace evm_workchain
