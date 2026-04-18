/*
    EVM Workchain — AccessListTracer (EIP-2930 access list generation).

    Implements silkworm::EvmTracer to record every account/storage slot
    accessed during EVM execution. Used by eth_createAccessList.

    Source: ported from ~/s/silkworm/rpc/core/evm_access_list_tracer.{hpp,cpp}.
    Apache-2.0.
*/
#pragma once

#include <map>
#include <vector>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace evm_workchain {

class AccessListTracer : public silkworm::EvmTracer {
  public:
    AccessListTracer() = default;
    AccessListTracer(const AccessListTracer&) = delete;
    AccessListTracer& operator=(const AccessListTracer&) = delete;

    const std::vector<silkworm::AccessListEntry>& get_access_list() const noexcept { return access_list_; }

    void on_instruction_start(uint32_t pc,
                              const intx::uint256* stack_top,
                              int stack_height,
                              int64_t gas,
                              const evmone::ExecutionState& execution_state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override;

    void reset_access_list() noexcept { access_list_.clear(); }

    /// Per EIP-2930: drop addresses from access list when their savings
    /// don't outweigh kTxAccessListAddressGas.
    void optimize_gas(const evmc::address& from,
                      const evmc::address& to,
                      const evmc::address& coinbase) noexcept;

  private:
    static bool exclude(const evmc::address& address, evmc_revision rev) noexcept;
    static bool is_storage_opcode(int opcode) noexcept;
    static bool is_contract_opcode(int opcode) noexcept;
    static bool is_call_opcode(int opcode) noexcept;

    void add_storage(const evmc::address& address, const evmc::bytes32& storage);
    void add_address(const evmc::address& address);
    bool is_created_contract(const evmc::address& address) const;
    void add_contract(const evmc::address& address);
    void use_address_on_old_contract(const evmc::address& address);
    void optimize_warm_address_in_access_list(const evmc::address& address);

    std::map<evmc::address, bool> created_contracts_;
    std::map<evmc::address, bool> used_before_creation_;
    std::vector<silkworm::AccessListEntry> access_list_;
};

}  // namespace evm_workchain
