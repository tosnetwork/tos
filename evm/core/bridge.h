/*
    EVM Workchain — cross-workchain asset bridge.

    Defines the interface for moving native assets between the basechain
    (workchain 0) and the EVM workchain (workchain 1).

    Bridge operations:
      Deposit:  basechain → EVM workchain
        1. User sends native tokens to a bridge contract on basechain
        2. Bridge mints equivalent balance on EVM workchain to the
           user's Ethereum address
        3. The minted balance is directly usable as native gas/value

      Withdraw: EVM workchain → basechain
        1. User calls the bridge contract on EVM workchain with amount
        2. Bridge burns the balance on EVM workchain
        3. Bridge releases equivalent tokens on basechain to the user's
           basechain address

    For the first implementation:
      - Deposit is a simple credit operation (admin-initiated)
      - Withdraw records an intent (to be processed by a relayer)
      - No trust-minimised proof verification yet

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include "evm/core/state.h"

namespace evm_workchain {

/// A pending withdrawal request from EVM workchain to basechain.
struct WithdrawalRequest {
    evmc::address evm_sender;       // sender on EVM workchain
    std::string basechain_dest;     // destination address on basechain (base64 or raw)
    intx::uint256 amount;           // amount in wei
    uint64_t block_number;          // block when the withdrawal was requested
    evmc::bytes32 tx_hash;          // originating transaction hash
};

/// Deposit native tokens from basechain into the EVM workchain.
///
/// Credits the specified EVM address with the given amount.
/// In a full implementation this would be triggered by observing a
/// deposit transaction on the basechain.  For the first slice it is
/// an administrative operation.
///
/// @param state   EVM workchain state.
/// @param to      Ethereum address to credit.
/// @param amount  Amount in wei to credit.
/// @return        true on success.
bool bridge_deposit(EvmState& state,
                    const evmc::address& to,
                    const intx::uint256& amount);

/// Get a snapshot of pending withdrawal requests.
std::vector<WithdrawalRequest> get_pending_withdrawals();

/// Record a withdrawal request.
/// Called when a user burns tokens on the EVM workchain side.
void record_withdrawal(const evmc::address& evm_sender,
                       const std::string& basechain_dest,
                       const intx::uint256& amount,
                       uint64_t block_number,
                       const evmc::bytes32& tx_hash);

/// Clear processed withdrawals (called after relayer confirms).
void clear_withdrawals();

}  // namespace evm_workchain
