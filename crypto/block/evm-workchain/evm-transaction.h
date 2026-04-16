/*
    EVM Workchain — canonical transaction envelope.

    This module bridges the host-chain inbound message format to the Silkworm
    Transaction type used by the EVM executor.

    Canonical transaction path:
      1. External message arrives targeting the EVM workchain.
      2. The message body contains an RLP-encoded Ethereum transaction.
      3. This module decodes the RLP payload, recovers the sender, and
         produces a silkworm::Transaction ready for execution.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "vm/cells/CellSlice.h"  // host-chain cell types

namespace evm_workchain {

/// Result of decoding an EVM transaction from a host-chain message body.
struct DecodedTransaction {
    silkworm::Transaction txn;
    evmc::address sender;
};

/// Error descriptor returned when transaction decoding fails.
struct TxDecodeError {
    std::string reason;
};

/// Decode an RLP-encoded Ethereum transaction from raw bytes.
///
/// The caller provides the raw bytes extracted from the host-chain message
/// body.  On success the returned DecodedTransaction contains a fully
/// populated silkworm::Transaction with the recovered sender address.
///
/// @param raw_rlp  Raw RLP bytes of a signed Ethereum transaction.
/// @return         Decoded transaction on success, error on failure.
std::variant<DecodedTransaction, TxDecodeError>
decode_evm_transaction(silkworm::ByteView raw_rlp) noexcept;

/// Extract the raw EVM transaction bytes from a host-chain CellSlice.
///
/// The convention is that the first reference in the message body cell
/// contains the raw RLP bytes of the Ethereum transaction.  This helper
/// reads those bytes into a Bytes buffer.
///
/// @param body  The body CellSlice of the inbound host-chain message.
/// @return      Raw RLP bytes, or std::nullopt if extraction failed.
std::optional<silkworm::Bytes>
extract_evm_payload(vm::CellSlice& body) noexcept;

}  // namespace evm_workchain
