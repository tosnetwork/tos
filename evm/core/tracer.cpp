/*
    EVM Workchain — transaction tracer implementation.

    Uses silkworm::EvmTracer (from ~/s/silkworm/core/execution/evm.hpp)
    to collect EVM instruction-level traces.

    Source: TOS-specific adapter.
*/
#include "evm/core/tracer.h"
#include "evm/core/executor.h"

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <evmone/execution_state.hpp>

namespace evm_workchain {

void StructLogTracer::on_execution_start(evmc_revision /*rev*/,
                                          const evmc_message& msg,
                                          evmone::bytes_view code) noexcept {
    code_ = code;
    depth_ = static_cast<uint32_t>(msg.depth + 1);
}

void StructLogTracer::on_instruction_start(uint32_t pc,
                                            const intx::uint256* stack_top,
                                            int stack_height,
                                            int64_t gas,
                                            const evmone::ExecutionState& /*state*/,
                                            const silkworm::IntraBlockState& /*ibs*/) noexcept {
    TraceStep step;
    step.pc = pc;
    step.op = (pc < code_.size()) ? code_[pc] : 0;
    step.gas = gas;
    step.stack_height = stack_height;
    step.depth = depth_;

    // Gas cost = previous gas - current gas (for the previous instruction)
    if (!steps_.empty()) {
        steps_.back().gas_cost = steps_.back().gas - gas;
    }

    // Capture top 16 stack values (or fewer)
    int capture = std::min(stack_height, 16);
    step.stack.resize(static_cast<size_t>(capture));
    for (int i = 0; i < capture; ++i) {
        // stack_top points to the top; stack_top[-1] is second, etc.
        step.stack[static_cast<size_t>(capture - 1 - i)] = stack_top[-i];
    }

    steps_.push_back(std::move(step));
    prev_gas_ = gas;
}

void StructLogTracer::on_execution_end(const evmc_result& /*result*/,
                                        const silkworm::IntraBlockState& /*ibs*/) noexcept {
    // Set gas_cost for the last instruction
    if (!steps_.empty()) {
        steps_.back().gas_cost = steps_.back().gas;  // remaining gas consumed
    }
}

ExecutionTrace trace_evm_transaction(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    const EvmState& evm_state,
    const silkworm::ChainConfig& config) {

    ExecutionTrace trace;

    auto sender_opt = txn.sender();
    if (!sender_opt) {
        return trace;
    }

    // Create a read-only state for tracing
    std::unique_lock lock(evm_state.mutex());
    auto& mutable_state = const_cast<silkworm::State&>(evm_state.state());
    silkworm::IntraBlockState ibs(mutable_state);
    silkworm::EVM evm(block, ibs, config);

    // Add the tracer
    StructLogTracer tracer;
    evm.add_tracer(tracer);

    auto rev = evm.revision();
    auto intrinsic = silkworm::protocol::intrinsic_gas(txn, rev);
    uint64_t execution_gas = txn.gas_limit - static_cast<uint64_t>(intrinsic);

    // Warm up access lists
    ibs.access_account(*sender_opt);
    if (txn.to) ibs.access_account(*txn.to);
    ibs.access_account(block.header.beneficiary);

    auto call_result = evm.execute(txn, execution_gas);

    trace.success = (call_result.status == EVMC_SUCCESS);
    trace.gas_used = txn.gas_limit - call_result.gas_left;
    trace.return_data = std::move(call_result.data);
    trace.steps = tracer.steps();

    return trace;
}

}  // namespace evm_workchain
