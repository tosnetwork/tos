#include <algorithm>
#include <memory>
#include <sodium.h>
#include <string>

#include "validator-auth/ed25519.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"
#include "vm/log.h"
#include "vm/opctable.h"
#include "vm/pqops.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

#include "authops.h"

namespace vm {
namespace {
CellSlice ordinary(td::Ref<Cell> cell) {
  if (cell->get_level() != 0)
    throw VmError{Excno::cell_und, "P0 AuthBytes must have level zero"};
  bool special = false;
  auto slice = load_cell_slice_special(cell, special);
  if (special || !slice.is_valid() || slice.get_cell_level() != 0 || slice.get_level() != 0)
    throw VmError{Excno::cell_und, "P0 AuthBytes must use ordinary cells"};
  return slice;
}
std::size_t capacity(std::size_t size) {
  std::size_t cap = 120;
  while (size > 4 * cap)
    cap *= 4;
  return cap;
}
void read_node(VmState* st, td::Ref<Cell> cell, std::size_t expected, std::string& out) {
  auto cs = ordinary(std::move(cell));
  if (cs.size() < 1)
    throw VmError{Excno::cell_und, "missing P0 byte node"};
  auto branch = cs.fetch_ulong(1);
  if (expected <= 120) {
    if (branch != 0 || cs.size() < 7)
      throw VmError{Excno::cell_und, "invalid P0 byte leaf"};
    auto length = cs.fetch_ulong(7);
    if (length != expected || length == 0 || cs.size() != length * 8 || cs.size_refs() != 0)
      throw VmError{Excno::cell_und, "noncanonical P0 byte leaf"};
    st->consume_gas_chk(static_cast<long long>(length));
    char data[120];
    if (!cs.fetch_bytes(td::MutableSlice(data, length)))
      throw VmError{Excno::cell_und, "truncated P0 byte leaf"};
    out.append(data, length);
    return;
  }
  if (branch != 1 || cs.size() != 35)
    throw VmError{Excno::cell_und, "invalid P0 byte branch"};
  auto count = cs.fetch_ulong(3), length = cs.fetch_ulong(32);
  auto cap = capacity(expected);
  if (length != expected || count != (expected + cap - 1) / cap || count < 2 || count > 4 || cs.size_refs() != count)
    throw VmError{Excno::cell_und, "noncanonical P0 byte partition"};
  // Canonical partitions strictly decrease the expected length. The admitted
  // root length therefore bounds recursion, cell occurrences and output size.
  for (std::size_t offset = 0; offset < expected; offset += cap)
    read_node(st, cs.fetch_ref(), std::min(cap, expected - offset), out);
}
std::string read_message(VmState* st, td::Ref<Cell> cell) {
  auto cs = ordinary(std::move(cell));
  if (cs.size() != 336 || cs.size_refs() != 1 || cs.fetch_ulong(32) != 0x76616231 || cs.fetch_ulong(16) != 1)
    throw VmError{Excno::cell_und, "invalid P0 AuthBytes root"};
  auto length = cs.fetch_ulong(32);
  if (length == 0 || length > validator_auth_max_message)
    throw VmError{Excno::cell_und, "P0 message bound"};
  std::array<unsigned char, 32> expected{}, actual{};
  if (!cs.fetch_bytes(td::MutableSlice(expected.data(), expected.size())))
    throw VmError{Excno::cell_und, "P0 message hash"};
  std::string result;
  result.reserve(length);
  read_node(st, cs.fetch_ref(), length, result);
  if (crypto_hash_sha256(actual.data(), reinterpret_cast<const unsigned char*>(result.data()), result.size()) != 0)
    throw VmError{Excno::fatal, "P0 hash backend failure"};
  if (actual != expected)
    throw VmError{Excno::cell_und, "P0 message hash mismatch"};
  return result;
}
int exec_validator_auth_chksign(VmState* st) {
  VM_LOG(st) << "execute VAUTH_CHKSIGN";
  auto& stack = st->get_stack();
  stack.check_underflow(3);
  // Every invocation pays, including invalid signatures. No free-call allowance
  // or ignore-signatures test switch supplies validator authorization.
  st->consume_gas_chk(validator_auth_base_gas);
  auto key = stack.pop_int();
  auto signature = stack.pop_cellslice();
  auto message = stack.pop_cell();
  std::array<unsigned char, 32> public_key{};
  std::array<unsigned char, 64> sig{};
  if (!key->export_bytes(public_key.data(), public_key.size(), false))
    throw VmError{Excno::range_chk, "P0 public key must fit an unsigned 256-bit integer"};
  if (signature->size() != 512 || signature->size_refs() != 0 || !signature->prefetch_bytes(sig.data(), sig.size()))
    throw VmError{Excno::cell_und, "P0 signature must be exactly 512 bits without references"};
  auto bytes = read_message(st, std::move(message));
  using tos::auth::c0::AdmittedKey;
  using tos::auth::c0::Error;
  auto admitted = AdmittedKey::admit({reinterpret_cast<const char*>(public_key.data()), public_key.size()});
  if (auto* error = std::get_if<Error>(&admitted)) {
    if (*error == Error::backend)
      throw VmError{Excno::fatal, "P0 verifier backend failure"};
    stack.push_bool(false);
    return 0;
  }
  auto result = std::get<AdmittedKey>(admitted).verify(bytes, {reinterpret_cast<const char*>(sig.data()), sig.size()});
  if (std::holds_alternative<Error>(result))
    throw VmError{Excno::fatal, "P0 verifier backend failure"};
  stack.push_bool(std::get<bool>(result));
  return 0;
}
void charge_native(VmState* st, long long gas) {
  if (gas < 0)
    throw VmError{Excno::range_chk, "negative native charge"};
  st->consume_gas_chk(gas);
}
// One signature verification a host is about to perform, priced where this
// machine already prices that primitive.
//
// The classical suite goes through the schedule and the counter CHKSIGNU uses,
// so a contract's own signature checks and the host's draw on one allowance
// rather than each receiving a separate one. The post-quantum suite pays the
// tariff its instruction pays. Neither price is restated here.
void charge_signature(VmState* st, std::uint16_t suite) {
  if (suite == validator_auth_suite_ed25519) {
    st->register_chksgn_call();
    return;
  }
  if (suite == validator_auth_suite_mldsa44) {
    st->consume_gas_chk(pq_mldsa44_base_gas);
    return;
  }
  throw VmError{Excno::cell_und, "unpriced signature suite"};
}
ValidatorAuthHost::Charge native_charge(VmState* st) {
  return {[st](long long gas) { charge_native(st, gas); },
          [st](std::uint16_t suite) { charge_signature(st, suite); }};
}
int exec_validator_auth_state(VmState* st) {
  VM_LOG(st) << "execute VAUTH_STATE";
  auto host = st->get_validator_auth_host();
  if (!host)
    throw VmError{Excno::inv_opcode, "P0 native transaction context required"};
  auto result = host->checkpoint(native_charge(st));
  st->get_stack().push_cell(std::move(result));
  return 0;
}
int exec_validator_auth_apply(VmState* st) {
  VM_LOG(st) << "execute VAUTH_APPLY";
  auto host = st->get_validator_auth_host();
  if (!host)
    throw VmError{Excno::inv_opcode, "P0 native transaction context required"};
  auto& stack = st->get_stack();
  stack.check_underflow(2);
  auto evidence = stack.pop_cell();
  auto update = stack.pop_cell();
  auto result = host->apply(std::move(update), std::move(evidence), native_charge(st));
  stack.push_cell(std::move(result));
  return 0;
}

int exec_validator_auth_bind(VmState* st) {
  VM_LOG(st) << "execute VAUTH_BIND";
  auto host = st->get_validator_auth_host();
  if (!host)
    throw VmError{Excno::inv_opcode, "P0 native transaction context required"};
  auto& stack = st->get_stack();
  stack.check_underflow(2);
  auto bindings = stack.pop_cell();
  auto elected = stack.pop_cell();
  auto result = host->bind(std::move(elected), std::move(bindings), native_charge(st));
  stack.push_cell(std::move(result));
  return 0;
}
class CapabilityGated final : public OpcodeInstr {
  std::unique_ptr<OpcodeInstr> inner_;

 public:
  explicit CapabilityGated(OpcodeInstr* inner)
      : OpcodeInstr(inner->get_opcode_min(), inner->get_opcode_max()), inner_(inner) {
  }
  int dispatch(VmState* st, CellSlice& cs, unsigned opcode, unsigned bits) const override {
    if (st->get_global_version() < validator_auth_min_version || !(st->get_global_capabilities() & validator_auth_capability)) {
      st->consume_gas(gas_per_instr);
      throw VmError{Excno::inv_opcode, "invalid opcode", opcode};
    }
    return inner_->dispatch(st, cs, opcode, bits);
  }
  std::string dump(CellSlice& cs, unsigned opcode, unsigned bits) const override {
    return inner_->dump(cs, opcode, bits);
  }
  int instr_len(const CellSlice& cs, unsigned opcode, unsigned bits) const override {
    return inner_->instr_len(cs, opcode, bits);
  }
};
}  // namespace
void register_validator_auth_ops(OpcodeTable& table) {
  table.insert(new CapabilityGated(OpcodeInstr::mksimple(validator_auth_chksign_opcode, 16, "VAUTH_CHKSIGN", exec_validator_auth_chksign)));
  table.insert(new CapabilityGated(OpcodeInstr::mksimple(validator_auth_state_opcode, 16, "VAUTH_STATE", exec_validator_auth_state)));
  table.insert(new CapabilityGated(OpcodeInstr::mksimple(validator_auth_apply_opcode, 16, "VAUTH_APPLY", exec_validator_auth_apply)));
  table.insert(new CapabilityGated(OpcodeInstr::mksimple(validator_auth_bind_opcode, 16, "VAUTH_BIND", exec_validator_auth_bind)));
}
}  // namespace vm
