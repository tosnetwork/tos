#pragma once
#include <cstddef>
#include <cstdint>

#include "tos/tos-types.h"
namespace vm {
class OpcodeTable;
inline constexpr unsigned validator_auth_chksign_opcode = 0xf917;
inline constexpr unsigned validator_auth_state_opcode = 0xf918;
inline constexpr unsigned validator_auth_apply_opcode = 0xf919;
inline constexpr int validator_auth_min_version = 16;
inline constexpr std::uint64_t validator_auth_capability = tos::capValidatorAuth;
inline constexpr std::size_t validator_auth_max_message = 65536;
inline constexpr long long validator_auth_base_gas = 50000;
void register_validator_auth_ops(OpcodeTable&);
}  // namespace vm
