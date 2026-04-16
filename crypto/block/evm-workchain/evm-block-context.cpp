/*
    EVM Workchain — block context adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-block-context.h"

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

const silkworm::ChainConfig& evm_chain_config() noexcept {
    // Singleton config for the EVM workchain.
    // Uses Shanghai rules — the latest stable fork before Cancun/blob txns.
    // All fork blocks set to 0 so that all rules are active from genesis.
    static const silkworm::ChainConfig config = [] {
        silkworm::ChainConfig c;
        c.chain_id = kEvmChainId;

        // All forks active from block 0 (Shanghai-equivalent).
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

        // PoW → PoS terminal difficulty set to 0 (merged from genesis).
        c.terminal_total_difficulty = 0;

        return c;
    }();

    return config;
}

}  // namespace evm_workchain
