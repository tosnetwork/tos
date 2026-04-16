/*
    EVM Workchain — module initialisation implementation.

    Registers the EVM compute phase handler with the host-chain dispatch
    mechanism defined in evm-workchain-dispatch.h.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-init.h"
#include "evm-workchain.h"

#include "block/evm-workchain-dispatch.h"
#include "evm-compute-phase.h"
#include "evm-state.h"
#include "evm-cell-state.h"
#include "evm-incremental-trie.h"

#include "vm/boc.h"

#include <fstream>

#include "td/utils/logging.h"

namespace evm_workchain {

static std::unique_ptr<EvmState> g_evm_state;
static std::unique_ptr<IncrementalTrieCalculator> g_trie_calc;

EvmState& global_evm_state() {
    return *g_evm_state;
}

IncrementalTrieCalculator& global_trie_calculator() {
    return *g_trie_calc;
}

void init_evm_workchain(const std::string& db_root) {
    LOG(WARNING) << "evm-workchain: initialising (workchain_id=2, chain_id="
                 << kEvmChainId << ")";

    // Cell-native state. The dictionary lives entirely in cells; the root
    // can be serialized to / loaded from a BoC file at {db_root}/evm-state.boc
    // for development persistence. Production persistence will route through
    // the collator's ShardAccounts → CellDb (single atomic WriteBatch).
    auto cell_state = std::make_unique<CellEvmState>();

    if (!db_root.empty()) {
        std::string boc_path = db_root + "/evm-state.boc";
        std::ifstream in(boc_path, std::ios::binary);
        if (in.good()) {
            std::string data((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
            auto cell_r = vm::std_boc_deserialize(td::Slice{data});
            if (cell_r.is_ok()) {
                cell_state->load_from_cell(cell_r.move_as_ok());
                LOG(WARNING) << "evm-workchain: loaded cell-native state from " << boc_path;
            } else {
                LOG(WARNING) << "evm-workchain: failed to deserialize "
                             << boc_path << ", starting empty";
            }
        } else {
            LOG(WARNING) << "evm-workchain: no existing state at " << boc_path
                         << ", starting empty";
        }
    } else {
        LOG(WARNING) << "evm-workchain: in-memory state only (no db_root)";
    }

    g_evm_state = std::make_unique<EvmState>(std::move(cell_state));

    evm_workchain_dispatch::set_evm_compute_handler(
        [](block::ComputePhase& cp,
           vm::CellSlice& in_msg_body,
           uint64_t gas_limit,
           uint64_t block_seqno,
           uint64_t timestamp,
           const uint8_t rand_seed[32]) -> bool {
            return run_evm_compute_phase(
                cp, in_msg_body, gas_limit,
                *g_evm_state,
                block_seqno, timestamp, rand_seed);
        });

    g_trie_calc = std::make_unique<IncrementalTrieCalculator>();

    LOG(WARNING) << "evm-workchain: handler registered";
}

}  // namespace evm_workchain
