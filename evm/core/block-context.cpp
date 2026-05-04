/*
    EVM Workchain — block context adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/block-context.h"

#include <cstring>

namespace evm_workchain {

silkworm::Block make_evm_block(
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    uint64_t gas_limit,
    const evmc::address& beneficiary) {

    silkworm::Block block;

    block.header.number = block_seqno;
    block.header.timestamp = timestamp;
    block.header.gas_limit = gas_limit;
    block.header.beneficiary = beneficiary;

    // Map host-chain random seed to EVM's prevrandao (post-merge field).
    std::memcpy(block.header.prev_randao.bytes, rand_seed, 32);

    // Base fee: 0 for the first slice (simple gas model).
    block.header.base_fee_per_gas = 0;

    // Difficulty: 0 (post-merge semantics).
    block.header.difficulty = 0;

    return block;
}

silkworm::ChainConfig make_evm_chain_config(uint64_t chain_id) {
    silkworm::ChainConfig c;
    c.chain_id = chain_id;

    // All forks active from block 0 (Cancun-equivalent).
    c.homestead_block   = 0;
    c.tangerine_whistle_block = 0;
    c.spurious_dragon_block = 0;
    c.byzantium_block   = 0;
    c.constantinople_block = 0;
    c.petersburg_block  = 0;
    c.istanbul_block    = 0;
    c.berlin_block      = 0;
    c.london_block      = 0;

    // Shanghai (EIP-3651, 3855, 3860, 4895) active from time 0.
    c.shanghai_time     = 0;
    // Cancun (EIP-1153/4788/4844/5656/6780/7516) active from time 0.
    c.cancun_time       = 0;
    // Pectra/Prague (EIP-2537/2935/6110/7002/7251/7549/7623/7685/7702)
    // active from time 0. Mainnet activated 2025-05-07. Pre-fork prep
    // landed earlier (2026-04-18).
    c.prague_time       = 0;
    // Osaka/Fusaka active from time 0 for this workchain profile.
    c.osaka_time        = 0;

    // PoW -> PoS terminal difficulty set to 0 (merged from genesis).
    c.terminal_total_difficulty = 0;

    return c;
}

const silkworm::ChainConfig& evm_chain_config() noexcept {
    // Legacy singleton config for non-consensus paths. Consensus compute
    // passes descriptor.vm_mode explicitly to make_evm_chain_config().
    static const silkworm::ChainConfig config = make_evm_chain_config(current_evm_chain_id());
    return config;
}

intx::uint256 calc_base_fee(
    const intx::uint256& parent_base_fee,
    uint64_t parent_gas_used,
    uint64_t parent_gas_limit) {

    if (parent_base_fee == 0) {
        return intx::uint256{kInitialBaseFee};
    }

    const uint64_t parent_gas_target = parent_gas_limit / kElasticityMultiplier;
    if (parent_gas_target == 0) {
        return parent_base_fee;  // avoid division by zero on zero-limit blocks
    }

    if (parent_gas_used == parent_gas_target) {
        return parent_base_fee;
    }

    if (parent_gas_used > parent_gas_target) {
        const intx::uint256 gas_used_delta{parent_gas_used - parent_gas_target};
        intx::uint256 delta = parent_base_fee * gas_used_delta / parent_gas_target / kBaseFeeMaxChangeDenominator;
        if (delta < 1) delta = 1;
        return parent_base_fee + delta;
    }

    // parent_gas_used < parent_gas_target
    const intx::uint256 gas_used_delta{parent_gas_target - parent_gas_used};
    intx::uint256 delta = parent_base_fee * gas_used_delta / parent_gas_target / kBaseFeeMaxChangeDenominator;
    if (parent_base_fee > delta) {
        return parent_base_fee - delta;
    }
    return 0;
}

}  // namespace evm_workchain
