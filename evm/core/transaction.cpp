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
    if (has_next == 1) {
        if (!body.have_refs()) return std::nullopt;
        auto next = body.fetch_ref();
        auto more = decode_evm_bytecode(next);
        if (more.empty()) return std::nullopt;
        out.insert(out.end(), more.begin(), more.end());
    }
    if (out.empty()) return std::nullopt;
    return out;
}

}  // namespace evm_workchain
