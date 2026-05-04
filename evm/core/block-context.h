/*
    EVM Workchain — block context adapter.

    Maps host-chain block metadata (timestamp, logical time, random seed, etc.)
    into a silkworm::Block / silkworm::BlockHeader suitable for EVM execution.

    The EVM executor needs:
      - block number
      - timestamp
      - gas limit
      - coinbase / beneficiary
      - base fee (simplified: 0 for first slice)
      - difficulty / prevrandao (mapped from host-chain random seed)
      - block hash callback

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/chain/config.hpp>

#include "evm/core/workchain.h"

namespace evm_workchain {

/// Build a minimal silkworm::Block from host-chain block context fields.
///
/// @param block_seqno   Host-chain block sequence number (maps to EVM block number).
/// @param timestamp     Unix timestamp of the block.
/// @param rand_seed     256-bit block random seed (maps to EVM prevrandao).
/// @param gas_limit     Block gas limit for the EVM workchain.
/// @param beneficiary   Coinbase / fee recipient address.
/// @return              A silkworm::Block ready for use with ExecutionProcessor.
silkworm::Block make_evm_block(
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    uint64_t gas_limit = 30'000'000,
    const evmc::address& beneficiary = {});

/// Build a minimal ChainConfig for the EVM workchain with an explicit
/// consensus chain id.
silkworm::ChainConfig make_evm_chain_config(uint64_t chain_id);

/// Legacy process-local ChainConfig accessor.
///
/// Consensus compute must receive an explicit chain id from the active
/// WorkchainDescr and use make_evm_chain_config(chain_id). This singleton is
/// retained for non-consensus RPC/helpers and old test paths.
const silkworm::ChainConfig& evm_chain_config() noexcept;

// --- EIP-1559 base fee calculation ---

/// EIP-1559 constants for the EVM workchain.
constexpr uint64_t kInitialBaseFee = 1'000'000'000;         // 1 gwei
constexpr uint64_t kBaseFeeMaxChangeDenominator = 8;
constexpr uint64_t kElasticityMultiplier = 2;

/// Calculate the expected base fee for the next block given the parent block's
/// gas usage. Follows the EIP-1559 formula.
///
/// @param parent_base_fee   Base fee of the parent block (0 for genesis).
/// @param parent_gas_used   Gas used in the parent block.
/// @param parent_gas_limit  Gas limit of the parent block.
/// @return                  Expected base fee for the next block.
intx::uint256 calc_base_fee(
    const intx::uint256& parent_base_fee,
    uint64_t parent_gas_used,
    uint64_t parent_gas_limit);

}  // namespace evm_workchain
