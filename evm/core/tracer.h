/*
    EVM Workchain — transaction tracer for debug_traceTransaction.

    Implements the silkworm::EvmTracer interface to collect a structured
    execution trace of an EVM transaction.  The trace includes:
      - opcode at each step
      - program counter
      - remaining gas
      - stack depth
      - top stack values

    This matches the Ethereum debug_traceTransaction "structLog" format.

    Source: TOS-specific adapter, uses EvmTracer interface from
            ~/s/silkworm/core/execution/evm.hpp
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <silkworm/core/execution/evm.hpp>

#include "evm/core/state.h"

namespace evm_workchain {

/// A single step in the execution trace.
struct TraceStep {
    uint32_t pc{0};
    uint8_t op{0};
    int64_t gas{0};
    int64_t gas_cost{0};
    int stack_height{0};
    std::vector<intx::uint256> stack;  // top N values
    uint32_t depth{1};
};

/// Collected execution trace.
struct ExecutionTrace {
    bool success{false};
    uint64_t gas_used{0};
    silkworm::Bytes return_data;
    std::vector<TraceStep> steps;
    bool truncated{false};
};

/// EVM tracer that collects structured logs for debug_traceTransaction.
class StructLogTracer : public silkworm::EvmTracer {
  public:
    explicit StructLogTracer(size_t max_steps) noexcept : max_steps_(max_steps) {}

    void on_execution_start(evmc_revision rev, const evmc_message& msg,
                            evmone::bytes_view code) noexcept override;

    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top,
                              int stack_height, int64_t gas,
                              const evmone::ExecutionState& state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override;

    void on_execution_end(const evmc_result& result,
                          const silkworm::IntraBlockState& intra_block_state) noexcept override;

    /// Get the collected trace.
    const std::vector<TraceStep>& steps() const noexcept { return steps_; }
    std::vector<TraceStep> consume_steps() noexcept { return std::move(steps_); }
    bool truncated() const noexcept { return truncated_; }

  private:
    size_t max_steps_{0};
    std::vector<TraceStep> steps_;
    evmone::bytes_view code_;
    uint32_t depth_{1};
    bool truncated_{false};
};

/// Execute a transaction with tracing enabled and return the trace.
ExecutionTrace trace_evm_transaction(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    const EvmState& evm_state,
    const silkworm::ChainConfig& config,
    size_t max_steps);

}  // namespace evm_workchain
