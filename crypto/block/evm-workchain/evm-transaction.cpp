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
    // The message body follows TLB: init:(Maybe ...) body:(Either X ^X)
    // After ext_in_msg_info is parsed, the remaining slice contains:
    //   init_bit(1) [+ init if 1] + either_bit(1) + inline_or_ref
    //
    // For EVM messages built by build_evm_external_message():
    //   init = nothing$0 (1 bit)
    //   body = right$1 ^X (1 bit + reference)
    //
    // But when called from the compute phase, the body CellSlice may
    // already be positioned at the raw body content (after TLB unpacking).
    // We handle both cases.

    // Case 1: body has references — try reading from reference
    // (This is the standard TLB format from build_evm_external_message)
    if (body.size() >= 2 && body.have_refs()) {
        unsigned init_bit = static_cast<unsigned>(body.fetch_ulong(1));
        if (init_bit == 0) {
            // init = nothing, next bit is either tag
            unsigned either_bit = static_cast<unsigned>(body.fetch_ulong(1));
            if (either_bit == 1 && body.have_refs()) {
                // body is in reference cell
                auto ref = body.fetch_ref();
                auto ref_cs = vm::load_cell_slice(ref);
                unsigned bits = ref_cs.size();
                if (bits == 0 || (bits % 8) != 0) return std::nullopt;
                unsigned byte_count = bits / 8;
                silkworm::Bytes out(byte_count, 0);
                if (!ref_cs.fetch_bytes(out.data(), byte_count)) return std::nullopt;
                return out;
            }
            // either_bit == 0: inline body, fall through to inline read
        }
        // init_bit == 1: has init, not our format — try inline read of remaining
    }

    // Case 2: raw bytes directly in the cell slice (legacy / direct call)
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
