#pragma once
#include <cstddef>
#include <cstdint>

#include "tos/tos-types.h"
namespace vm {
class OpcodeTable;
inline constexpr unsigned p0_chksign_opcode = 0xf917;
inline constexpr unsigned p0_state_opcode = 0xf918;
inline constexpr unsigned p0_apply_opcode = 0xf919;
inline constexpr int p0_chksign_min_version = 16;
inline constexpr std::uint64_t p0_capability = tos::capValidatorAuth;
inline constexpr std::size_t p0_chksign_max_message = 65536;
inline constexpr long long p0_chksign_base_gas = 50000;
void register_validator_auth_ops(OpcodeTable&);
}  // namespace vm
