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

#include "evm-workchain.h"

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

/// Build a minimal ChainConfig for the EVM workchain.
///
/// Uses Shanghai rules (the latest pre-Cancun stable fork) with the
/// EVM workchain's chain id.  No PoW, no beacon chain — the host
/// chain provides finality.
const silkworm::ChainConfig& evm_chain_config() noexcept;

}  // namespace evm_workchain
