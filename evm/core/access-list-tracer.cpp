/*
    EVM Workchain — AccessListTracer implementation.
    Ported from ~/s/silkworm/rpc/core/evm_access_list_tracer.cpp (Apache-2.0).
*/
#include "evm/core/access-list-tracer.h"

#include <ethash/keccak.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <evmone/instructions_traits.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/types/address.hpp>

namespace evm_workchain {

// Per EIP-2930
static constexpr size_t kTxAccessListStorageKeyGas = 1900;
static constexpr size_t kTxAccessListAddressGas    = 2400;

void AccessListTracer::on_instruction_start(
    uint32_t pc,
    const intx::uint256* stack_top,
    int stack_height,
    int64_t /*gas*/,
    const evmone::ExecutionState& execution_state,
    const silkworm::IntraBlockState& intra_block_state) noexcept {

    if (!execution_state.msg) return;
    const evmc::address recipient(execution_state.msg->recipient);
    const auto opcode = execution_state.original_code[pc];

    if (is_storage_opcode(opcode) && stack_height >= 1) {
        evmc::bytes32 slot;
        intx::be::store(slot.bytes, stack_top[0]);
        if (!exclude(recipient, execution_state.rev)) {
            add_storage(recipient, slot);
            if (!is_created_contract(recipient)) {
                use_address_on_old_contract(recipient);
            }
        }
    } else if (is_call_opcode(opcode) && stack_height >= 5) {
        evmc::address addr;
        intx::be::trunc(addr.bytes, stack_top[-1]);
        if (!exclude(addr, execution_state.rev)) {
            add_address(addr);
            if (!is_created_contract(addr)) use_address_on_old_contract(addr);
        }
    } else if (is_contract_opcode(opcode) && stack_height >= 1) {
        evmc::address addr;
        intx::be::trunc(addr.bytes, stack_top[0]);
        if (!exclude(addr, execution_state.rev)) {
            add_address(addr);
            if (!is_created_contract(addr)) use_address_on_old_contract(addr);
        }
    } else if (opcode == evmc_opcode::OP_CREATE) {
        const uint64_t nonce = intra_block_state.get_nonce(execution_state.msg->recipient);
        const auto contract_addr = silkworm::create_address(execution_state.msg->recipient, nonce);
        add_contract(contract_addr);
    } else if (opcode == evmc_opcode::OP_CREATE2) {
        if (stack_height < 4) return;
        const auto init_code_offset = static_cast<size_t>(stack_top[-1]);
        if (init_code_offset >= execution_state.memory.size()) return;
        const auto init_code_size = static_cast<size_t>(stack_top[-2]);
        const evmc::bytes32 salt2 = intx::be::store<evmc::bytes32>(stack_top[-3]);
        auto init_code_hash =
            init_code_size > 0
                ? ethash::keccak256(&execution_state.memory.data()[init_code_offset], init_code_size)
                : ethash_hash256{};
        const auto contract_addr =
            silkworm::create2_address(execution_state.msg->recipient, salt2, init_code_hash.bytes);
        add_contract(contract_addr);
    }
}

bool AccessListTracer::is_storage_opcode(int opcode) noexcept {
    return opcode == evmc_opcode::OP_SLOAD || opcode == evmc_opcode::OP_SSTORE;
}

bool AccessListTracer::is_contract_opcode(int opcode) noexcept {
    return opcode == evmc_opcode::OP_EXTCODECOPY ||
           opcode == evmc_opcode::OP_EXTCODEHASH ||
           opcode == evmc_opcode::OP_EXTCODESIZE ||
           opcode == evmc_opcode::OP_BALANCE ||
           opcode == evmc_opcode::OP_SELFDESTRUCT;
}

bool AccessListTracer::is_call_opcode(int opcode) noexcept {
    return opcode == evmc_opcode::OP_DELEGATECALL ||
           opcode == evmc_opcode::OP_CALL ||
           opcode == evmc_opcode::OP_STATICCALL ||
           opcode == evmc_opcode::OP_CALLCODE;
}

bool AccessListTracer::exclude(const evmc::address& address, evmc_revision rev) noexcept {
    return silkworm::precompile::is_precompile(address, rev);
}

void AccessListTracer::add_storage(const evmc::address& address, const evmc::bytes32& storage) {
    for (auto& entry : access_list_) {
        if (entry.account == address) {
            for (const auto& key : entry.storage_keys) {
                if (key == storage) return;
            }
            entry.storage_keys.push_back(storage);
            return;
        }
    }
    silkworm::AccessListEntry item;
    item.account = address;
    item.storage_keys.push_back(storage);
    access_list_.push_back(std::move(item));
}

void AccessListTracer::add_address(const evmc::address& address) {
    for (const auto& entry : access_list_) {
        if (entry.account == address) return;
    }
    silkworm::AccessListEntry item;
    item.account = address;
    access_list_.push_back(std::move(item));
}

bool AccessListTracer::is_created_contract(const evmc::address& address) const {
    return created_contracts_.find(address) != created_contracts_.end();
}

void AccessListTracer::add_contract(const evmc::address& address) {
    created_contracts_[address] = false;
}

void AccessListTracer::use_address_on_old_contract(const evmc::address& address) {
    used_before_creation_[address] = true;
}

void AccessListTracer::optimize_gas(const evmc::address& from,
                                     const evmc::address& to,
                                     const evmc::address& coinbase) noexcept {
    optimize_warm_address_in_access_list(from);
    optimize_warm_address_in_access_list(to);
    optimize_warm_address_in_access_list(coinbase);
    for (const auto& [address, _] : created_contracts_) {
        if (used_before_creation_.find(address) == used_before_creation_.end()) {
            optimize_warm_address_in_access_list(address);
        }
    }
}

void AccessListTracer::optimize_warm_address_in_access_list(const evmc::address& address) {
    for (auto it = access_list_.begin(); it != access_list_.end(); ++it) {
        if (it->account == address) {
            // EIP-2930: only worth listing if storage savings outweigh address gas
            const size_t saving_per_slot =
                evmone::instr::cold_sload_cost -
                evmone::instr::warm_storage_read_cost -
                kTxAccessListStorageKeyGas;
            if (saving_per_slot * it->storage_keys.size() <= kTxAccessListAddressGas) {
                access_list_.erase(it);
                return;
            }
        }
    }
}

}  // namespace evm_workchain
