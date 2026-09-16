#pragma once
#include <cstddef>
#include <cstdint>

#include "tos/tos-types.h"
namespace vm {
class OpcodeTable;
inline constexpr unsigned validator_auth_chksign_opcode = 0xf917;
inline constexpr unsigned validator_auth_state_opcode = 0xf918;
inline constexpr unsigned validator_auth_apply_opcode = 0xf919;
inline constexpr unsigned validator_auth_bind_opcode = 0xf91a;
inline constexpr int validator_auth_min_version = 16;
inline constexpr std::uint64_t validator_auth_capability = tos::capValidatorAuth;
inline constexpr std::size_t validator_auth_max_message = 65536;
inline constexpr long long validator_auth_base_gas = 50000;
// The signature suites the machine publishes a tariff for, so that a host
// reporting verification work can be charged at a price that already exists
// rather than at one invented beside it. A suite with no tariff is refused
// instead of charged at another suite's price: an unpriced verification is a
// free one, and free verification is the question the charge exists to answer.
inline constexpr std::uint16_t validator_auth_suite_ed25519 = 1;
inline constexpr std::uint16_t validator_auth_suite_mldsa44 = 2;
void register_validator_auth_ops(OpcodeTable&);
}  // namespace vm
