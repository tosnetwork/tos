/*
    EVM Workchain — external message builder.

    Wraps RLP-encoded Ethereum transactions into host-chain external message
    cells that can be submitted to the validator-manager's external message pool.

    The external message format follows block.tlb ext_in_msg_info:
      ext_in_msg_info$10 src:MsgAddressExt dest:MsgAddressInt
        import_fee:Grams = CommonMsgInfo;

    For EVM workchain messages:
      - src: addr_none (external source)
      - dest: descriptor-selected EVM workchain, singleton executor address
      - body: raw RLP bytes of the signed Ethereum transaction

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include "vm/cells.h"
#include "tos/tos-types.h"
#include <evmc/evmc.hpp>

namespace evm_workchain {

/// Build a host-chain external message cell from an RLP-encoded Ethereum transaction.
///
/// @param raw_rlp       Raw RLP bytes of the signed Ethereum transaction.
/// @param rlp_size      Size of the raw_rlp buffer.
/// @param sender_addr   Recovered Ethereum sender address (20 bytes).
/// @return              A cell containing the external message, or null on error.
td::Ref<vm::Cell> build_evm_external_message(
    const uint8_t* raw_rlp, size_t rlp_size,
    const evmc::address& sender_addr,
    tos::WorkchainId workchain_id);

/// Convenience overload for tests and genesis tooling that still use the
/// default EVM workchain id from evm/core/workchain.h. Consensus and RPC paths
/// should pass the descriptor-resolved workchain id explicitly.
td::Ref<vm::Cell> build_evm_external_message(
    const uint8_t* raw_rlp, size_t rlp_size,
    const evmc::address& sender_addr);

/// Convert an Ethereum 20-byte address to a 256-bit host-chain account address.
/// The lower 160 bits contain the Ethereum address, upper 96 bits are zero.
td::Bits256 eth_addr_to_internal(const evmc::address& addr);

}  // namespace evm_workchain
