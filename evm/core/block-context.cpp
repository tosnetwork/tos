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

const silkworm::ChainConfig& evm_chain_config() noexcept {
    // Singleton config for the EVM workchain.
    // **Cancun-rules**: all forks active from genesis. Per the user
    // decision on 2026-04-18, `cancun_time = 0` so BLOBHASH, BLOBBASEFEE,
    // TLOAD/TSTORE, MCOPY, EIP-6780 SELFDESTRUCT, KZG point-evaluation
    // precompile (0x0a), and EIP-4788 beacon-roots system call all
    // activate from block 0.
    //
    // Pre-fork prep (commits 6d311e8e + bb56f43e + ca8cc59b) wired:
    //  - KZG canary in init_evm_workchain (verifies evmone's bundled
    //    trusted setup is loaded before any tx executes)
    //  - EIP-4788 beacon-roots predeploy at the magic address
    //    0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02 with the canonical
    //    97-byte runtime
    //  - blob-tx (type-3) admission rejection at eth_sendRawTransaction —
    //    we have no blob mempool, so blob txs would otherwise stall in
    //    the collator
    //
    // The chain_id is captured on first call (via current_evm_chain_id()).
    // Production builds must bind it through chain configuration rather than
    // process-local environment. Once captured the config is frozen because
    // silkworm caches the pointer for the rest of the process.
    static const silkworm::ChainConfig config = [] {
        silkworm::ChainConfig c;
        c.chain_id = current_evm_chain_id();

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
        // active from time 0. Mainnet activated 2025-05-07. Pre-fork
        // prep landed earlier (2026-04-18):
        //   - EIP-2935 history-storage predeploy seeded at startup
        //     (seed_eip2935_predeploy in evm-init.cpp)
        //   - EIP-2935 system call hook in compute-phase, gated on
        //     revision() >= EVMC_PRAGUE
        //   - EIP-7702 set-code (type-4) tx admission already supported
        //     by silkworm; passes through transparently
        //   - EIP-2537 BLS12-381 precompiles (0x0b–0x11) wired into
        //     silkworm dispatch via evmone's bls.cpp (Phase B).
        c.prague_time       = 0;
        // Osaka/Fusaka (EIPs 7825/7883/7823/7939/7951/7935). Mainnet
        // activated 2025-12-03. Code changes landed today (2026-04-18)
        // across silkworm + evmone:
        //   - EIP-7939 CLZ opcode (0x1e) in evmone.
        //   - EIP-7951 secp256r1 P-256 precompile at 0x100 via OpenSSL.
        //   - EIP-7823 MODEXP input cap 8192 B / parameter.
        //   - EIP-7883 MODEXP gas increase (min 500, 16×/2× multipliers).
        //   - EIP-7825 per-tx gas cap 2^24 = 16,777,216.
        //   - EIP-7935 default block gas limit 60M — operational (set
        //     per genesis/runtime gas_limit), no silkworm change needed.
        c.osaka_time        = 0;

        // PoW → PoS terminal difficulty set to 0 (merged from genesis).
        c.terminal_total_difficulty = 0;

        return c;
    }();

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
