/*
    EVM Workchain — canonical transaction envelope implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-transaction.h"

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
    // Convention: the message body contains the raw RLP bytes directly
    // as the remaining data bits of the cell slice, packed as 8-bit bytes.
    //
    // For the first slice we read all remaining bits as a byte string.
    // A more robust version would support multi-cell payloads via references.

    unsigned bits = body.size();
    if (bits == 0 || (bits % 8) != 0) {
        return std::nullopt;
    }

    unsigned byte_count = bits / 8;
    silkworm::Bytes out(byte_count, 0);
    if (!body.fetch_bytes(out.data(), byte_count)) {
        return std::nullopt;
    }
    return out;
}

}  // namespace evm_workchain
