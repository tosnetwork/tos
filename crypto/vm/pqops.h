/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
namespace vm {
class OpcodeTable;
inline constexpr unsigned pq_mldsa44_opcode = 0xf93100;
inline constexpr int pq_mldsa44_min_version = 16;
inline constexpr long long pq_mldsa44_base_gas = 50000;
inline constexpr long long pq_mldsa44_byte_gas = 1;
// Candidate allocation for disposable development execution; no network activation.
inline constexpr unsigned pq_falcon512_opcode = 0xf93101;
inline constexpr int pq_falcon512_min_version = 19;
inline constexpr long long pq_falcon512_base_gas = 20000;
inline constexpr long long pq_falcon512_byte_gas = 1;
// PROTOTYPE generic instruction: message context signature public_key suite -> bool.
// Suite 1 = ML-DSA-44 and suite 2 = Falcon-512 padded behave as F93100/F93101; suite 4 is the
// rescue fee gate's one-level HSS/LMS verifier. Opcode, version and tariff are not allocated.
inline constexpr unsigned pq_suite_opcode = 0xf93102;
inline constexpr int pq_suite_min_version = 19;
inline constexpr int pq_suite_mldsa44 = 1;
inline constexpr int pq_suite_falcon512 = 2;
inline constexpr int pq_suite_slhdsa128s = 3;
inline constexpr int pq_suite_lms_fee = 4;
// Rescue root, Pure SLH-DSA-SHA2-128s. The design's unapproved estimate, charged flat before
// verification so that false and true results cost the same; the tariff is an R1 deliverable.
inline constexpr long long pq_slhdsa128s_base_gas = 750000;
inline constexpr long long pq_slhdsa128s_byte_gas = 1;
// Interpreter-rate pricing: about 0.12-0.14 us per SHA-256 compression with SHA-NI, at about
// 48 ns per gas for ordinary instructions on the measuring host, gives ~3 gas per compression.
inline constexpr long long pq_lms_fee_base_gas = 500;
inline constexpr long long pq_lms_fee_gas_per_compression = 3;
// The bytes are already paid for twice over: every chain cell costs a cell load, and every byte
// that is hashed is inside a counted compression. A per-byte charge would bill them a third time.
inline constexpr long long pq_lms_fee_byte_gas = 0;
void register_pq_ops(OpcodeTable& table);
}  // namespace vm
