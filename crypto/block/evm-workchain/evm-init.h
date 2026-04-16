/*
    EVM Workchain — module initialisation.

    Call init_evm_workchain() once at node startup to register the EVM
    compute phase handler with the host-chain transaction pipeline.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <string>

namespace evm_workchain {

class EvmState;
class IncrementalTrieCalculator;

/// Register the EVM compute phase handler with the host chain.
void init_evm_workchain(const std::string& db_root = "");

/// Access the global EVM workchain state singleton.
EvmState& global_evm_state();

/// Access the global incremental trie calculator.
IncrementalTrieCalculator& global_trie_calculator();

}  // namespace evm_workchain
