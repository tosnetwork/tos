/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <string>

#include "pq/falcon512.h"
#include "pq/lms-fee.h"
#include "pq/mldsa44.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"
#include "vm/log.h"
#include "vm/opctable.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

#include "pqops.h"

namespace vm {
namespace {
// A canonical chunk cannot exceed one cell's capacity. The parser enforces that
// locally so the fixed decoding buffer never depends on a limit declared elsewhere.
constexpr std::size_t max_chunk_bytes = 127;

// Canonical byte chain: full 127-byte non-final cells, at most one reference,
// nonempty final cell (except the sole root of an empty string), level zero.
std::string read_pq_bytes(VmState* st, td::Ref<Cell> cell, std::size_t limit,
                          long long byte_gas = pq_mldsa44_byte_gas) {
  std::string result;
  while (true) {
    if (cell->get_level() != 0) {
      throw VmError{Excno::cell_und, "PQ byte chains must have level zero"};
    }
    bool special = false;
    auto cs = load_cell_slice_special(cell, special);  // ordinary VM load gas applies
    if (special || cs.get_cell_level() != 0 || cs.get_level() != 0 ||
        (cs.size() & 7) != 0 || cs.size_refs() > 1) {
      throw VmError{Excno::cell_und, "non-canonical PQ byte chain"};
    }
    const std::size_t size = cs.size() / 8;
    // Structural rejection precedes metering: an oversized chunk is never charged for.
    if (size > max_chunk_bytes) {
      throw VmError{Excno::cell_und, "PQ byte chain chunk exceeds cell capacity"};
    }
    if ((cs.size_refs() && size != max_chunk_bytes) ||
        (size == 0 && (!result.empty() || cs.size_refs())) || size > limit - result.size()) {
      throw VmError{Excno::cell_und, "invalid PQ byte chain size"};
    }
    // Checked deduction precedes copying; limit bounds both memory and work.
    st->consume_gas_chk(static_cast<long long>(size) * byte_gas);
    unsigned char bytes[max_chunk_bytes];
    if (size && !cs.prefetch_bytes(bytes, static_cast<unsigned>(size))) {
      throw VmError{Excno::cell_und, "truncated PQ byte chain"};
    }
    result.append(reinterpret_cast<const char*>(bytes), size);
    if (!cs.size_refs()) {
      return result;
    }
    cell = cs.prefetch_ref();
  }
}

int exec_pq_mldsa44(VmState* st) {
  VM_LOG(st) << "execute PQCHECKSIG_MLDSA44";
  auto& stack = st->get_stack();
  stack.check_underflow(4);
  // Charge on every call; do not inherit the classic signature free allowance.
  st->consume_gas_chk(pq_mldsa44_base_gas);
  auto public_key_cell = stack.pop_cell();
  auto signature_cell = stack.pop_cell();
  auto context_cell = stack.pop_cell();
  auto message_cell = stack.pop_cell();
  const auto public_key = read_pq_bytes(st, public_key_cell, tos::pq::mldsa44_public_key_bytes);
  const auto signature = read_pq_bytes(st, signature_cell, tos::pq::mldsa44_signature_bytes);
  const auto context = read_pq_bytes(st, context_cell, tos::pq::mldsa44_max_context_bytes);
  const auto message = read_pq_bytes(st, message_cell, tos::pq::mldsa44_max_message_bytes);
  switch (tos::pq::verify_mldsa44(message, context, signature, public_key)) {
    case tos::pq::VerifyResult::valid:
      stack.push_bool(true);
      return 0;
    case tos::pq::VerifyResult::invalid:
      stack.push_bool(false);
      return 0;
    case tos::pq::VerifyResult::malformed_input:
      throw VmError{Excno::cell_und, "incorrect ML-DSA-44 key or signature size"};
    case tos::pq::VerifyResult::backend_error:
      throw VmError{Excno::fatal, "ML-DSA-44 verifier backend failure"};
  }
  throw VmError{Excno::fatal, "invalid verifier result"};
}
int exec_pq_falcon512(VmState* st) {
  VM_LOG(st) << "execute PQCHECKSIG_FALCON512_PADDED";
  auto& stack = st->get_stack();
  stack.check_underflow(3);
  st->consume_gas_chk(pq_falcon512_base_gas);
  auto key_cell = stack.pop_cell();
  auto signature_cell = stack.pop_cell();
  auto message_cell = stack.pop_cell();
  const auto key = read_pq_bytes(st, key_cell, tos::pq::falcon512_public_key_bytes, pq_falcon512_byte_gas);
  const auto signature = read_pq_bytes(st, signature_cell, tos::pq::falcon512_signature_bytes, pq_falcon512_byte_gas);
  const auto message = read_pq_bytes(st, message_cell, tos::pq::falcon512_max_message_bytes, pq_falcon512_byte_gas);
  switch (tos::pq::verify_falcon512_padded(message, signature, key)) {
    case tos::pq::VerifyResult::valid:
      stack.push_bool(true);
      return 0;
    case tos::pq::VerifyResult::invalid:
      stack.push_bool(false);
      return 0;
    case tos::pq::VerifyResult::malformed_input:
      throw VmError{Excno::cell_und, "incorrect Falcon-512 padded length"};
    case tos::pq::VerifyResult::backend_error:
      throw VmError{Excno::fatal, "Falcon-512 verifier backend failure"};
  }
  throw VmError{Excno::fatal, "invalid verifier result"};
}

void push_verify_result(Stack& stack, tos::pq::VerifyResult result, const char* name) {
  switch (result) {
    case tos::pq::VerifyResult::valid:
      stack.push_bool(true);
      return;
    case tos::pq::VerifyResult::invalid:
      stack.push_bool(false);
      return;
    case tos::pq::VerifyResult::malformed_input:
      throw VmError{Excno::cell_und, std::string{"malformed "} + name + " input"};
    case tos::pq::VerifyResult::backend_error:
      throw VmError{Excno::fatal, std::string{name} + " verifier backend failure"};
  }
  throw VmError{Excno::fatal, "invalid verifier result"};
}

int exec_pq_suite(VmState* st) {
  VM_LOG(st) << "execute PQCHECKSIG_SUITE";
  auto& stack = st->get_stack();
  stack.check_underflow(5);
  const int suite = stack.pop_smallint_range(255);
  auto public_key_cell = stack.pop_cell();
  auto signature_cell = stack.pop_cell();
  auto context_cell = stack.pop_cell();
  auto message_cell = stack.pop_cell();
  switch (suite) {
    case pq_suite_mldsa44: {
      st->consume_gas_chk(pq_mldsa44_base_gas);
      const auto public_key = read_pq_bytes(st, public_key_cell, tos::pq::mldsa44_public_key_bytes);
      const auto signature = read_pq_bytes(st, signature_cell, tos::pq::mldsa44_signature_bytes);
      const auto context = read_pq_bytes(st, context_cell, tos::pq::mldsa44_max_context_bytes);
      const auto message = read_pq_bytes(st, message_cell, tos::pq::mldsa44_max_message_bytes);
      push_verify_result(stack, tos::pq::verify_mldsa44(message, context, signature, public_key), "ML-DSA-44");
      return 0;
    }
    case pq_suite_falcon512: {
      st->consume_gas_chk(pq_falcon512_base_gas);
      // Falcon has no context parameter; only the empty context is accepted.
      read_pq_bytes(st, context_cell, 0, pq_falcon512_byte_gas);
      const auto key = read_pq_bytes(st, public_key_cell, tos::pq::falcon512_public_key_bytes, pq_falcon512_byte_gas);
      const auto signature =
          read_pq_bytes(st, signature_cell, tos::pq::falcon512_signature_bytes, pq_falcon512_byte_gas);
      const auto message = read_pq_bytes(st, message_cell, tos::pq::falcon512_max_message_bytes, pq_falcon512_byte_gas);
      push_verify_result(stack, tos::pq::verify_falcon512_padded(message, signature, key), "Falcon-512");
      return 0;
    }
    case pq_suite_lms_fee: {
      read_pq_bytes(st, context_cell, 0, pq_lms_fee_byte_gas);
      const auto key = read_pq_bytes(st, public_key_cell, tos::pq::lms_fee_public_key_bytes, pq_lms_fee_byte_gas);
      const auto message = read_pq_bytes(st, message_cell, tos::pq::lms_fee_max_message_bytes, pq_lms_fee_byte_gas);
      const auto worst = tos::pq::lms_fee_worst_compressions(key, message.size());
      if (!worst) {
        throw VmError{Excno::cell_und, "unsupported LMS fee profile"};
      }
      // Charge the worst case for this profile before reading or verifying the signature.
      st->consume_gas_chk(pq_lms_fee_base_gas + pq_lms_fee_gas_per_compression * static_cast<long long>(*worst));
      const auto signature =
          read_pq_bytes(st, signature_cell, tos::pq::lms_fee_max_signature_bytes, pq_lms_fee_byte_gas);
      push_verify_result(stack, tos::pq::verify_lms_fee(message, signature, key), "LMS fee");
      return 0;
    }
    default:
      throw VmError{Excno::range_chk, "unknown PQ suite"};
  }
}
}  // namespace

void register_pq_ops(OpcodeTable& table) {
  table.insert(OpcodeInstr::mksimple(pq_suite_opcode, 24, "PQCHECKSIG_SUITE", exec_pq_suite)
                   ->require_version(pq_suite_min_version));
  table.insert(OpcodeInstr::mksimple(pq_falcon512_opcode, 24, "PQCHECKSIG_FALCON512_PADDED", exec_pq_falcon512)
                   ->require_version(pq_falcon512_min_version));
  table.insert(OpcodeInstr::mksimple(pq_mldsa44_opcode, 24, "PQCHECKSIG_MLDSA44", exec_pq_mldsa44)
                   ->require_version(pq_mldsa44_min_version));
}
}  // namespace vm
