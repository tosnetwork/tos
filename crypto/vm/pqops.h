/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
namespace vm {
class OpcodeTable;
inline constexpr unsigned pq_mldsa44_opcode = 0xf93100;
inline constexpr int pq_mldsa44_min_version = 16;
inline constexpr long long pq_mldsa44_base_gas = 50000;
inline constexpr long long pq_mldsa44_byte_gas = 1;
void register_pq_ops(OpcodeTable& table);
}  // namespace vm
