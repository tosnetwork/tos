/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstring>
#include <tuple>
#include <vector>

#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"
#include "vm/log.h"
#include "vm/opctable.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

#include "blst.h"
#include "poseidon2-params.h"
#include "poseidon2ops.h"

namespace vm {
namespace poseidon2 {
namespace {

using Fr = blst_fr;

Fr fr_from_be(const unsigned char be[32]) {
  blst_scalar scalar;
  blst_scalar_from_bendian(&scalar, be);
  Fr value;
  blst_fr_from_scalar(&value, &scalar);
  return value;
}

void fr_to_be(unsigned char out[32], const Fr& value) {
  blst_scalar scalar;
  blst_scalar_from_fr(&scalar, &value);
  blst_bendian_from_scalar(out, &scalar);
}

// The constants are stored canonically and converted once. Doing it per call
// would be the same arithmetic repeated, not a different result.
struct Tables {
  Fr diag[state_width];
  Fr rc[rounds_total][state_width];
};

const Tables& tables() {
  static const Tables loaded = [] {
    Tables t{};
    for (int i = 0; i < state_width; ++i) {
      t.diag[i] = fr_from_be(mat_diag8_be[i]);
    }
    for (int r = 0; r < rounds_total; ++r) {
      for (int i = 0; i < state_width; ++i) {
        t.rc[r][i] = fr_from_be(rc8_be[r][i]);
      }
    }
    return t;
  }();
  return loaded;
}

void sbox(Fr& x) {  // x^alpha, alpha = 5
  static_assert(sbox_alpha == 5, "the S-box below is written for alpha = 5");
  Fr squared, quartic, result;
  blst_fr_sqr(&squared, &x);
  blst_fr_sqr(&quartic, &squared);
  blst_fr_mul(&result, &quartic, &x);
  x = result;
}

void doubled(Fr& out, const Fr& x) {
  blst_fr_add(&out, &x, &x);
}

// The cheap 4x4 MDS block, applied to each quarter of the state.
void matmul_m4(Fr* x) {
  Fr t0, t1, t2, t3, t4, t5, t6, t7;
  blst_fr_add(&t0, &x[0], &x[1]);
  blst_fr_add(&t1, &x[2], &x[3]);
  doubled(t2, x[1]);
  blst_fr_add(&t2, &t2, &t1);
  doubled(t3, x[3]);
  blst_fr_add(&t3, &t3, &t0);
  doubled(t4, t1);
  doubled(t4, t4);
  blst_fr_add(&t4, &t4, &t3);
  doubled(t5, t0);
  doubled(t5, t5);
  blst_fr_add(&t5, &t5, &t2);
  blst_fr_add(&t6, &t3, &t5);
  blst_fr_add(&t7, &t2, &t4);
  x[0] = t6;
  x[1] = t5;
  x[2] = t7;
  x[3] = t4;
}

void matmul_external(Fr* s) {
  matmul_m4(s);
  matmul_m4(s + 4);
  Fr stored[4];
  for (int l = 0; l < 4; ++l) {
    blst_fr_add(&stored[l], &s[l], &s[4 + l]);
  }
  for (int i = 0; i < state_width; ++i) {
    blst_fr_add(&s[i], &s[i], &stored[i % 4]);
  }
}

void matmul_internal(Fr* s) {
  const Tables& t = tables();
  Fr sum = s[0];
  for (int i = 1; i < state_width; ++i) {
    blst_fr_add(&sum, &sum, &s[i]);
  }
  for (int i = 0; i < state_width; ++i) {
    Fr scaled;
    blst_fr_mul(&scaled, &s[i], &t.diag[i]);
    blst_fr_add(&s[i], &scaled, &sum);
  }
}

}  // namespace

void permute(unsigned char state[8][32]) {
  const Tables& t = tables();
  Fr s[state_width];
  for (int i = 0; i < state_width; ++i) {
    s[i] = fr_from_be(state[i]);
  }

  matmul_external(s);
  const int partial_end = rounds_f_beginning + rounds_p;
  for (int r = 0; r < rounds_f_beginning; ++r) {
    for (int i = 0; i < state_width; ++i) {
      blst_fr_add(&s[i], &s[i], &t.rc[r][i]);
      sbox(s[i]);
    }
    matmul_external(s);
  }
  for (int r = rounds_f_beginning; r < partial_end; ++r) {
    blst_fr_add(&s[0], &s[0], &t.rc[r][0]);
    sbox(s[0]);
    matmul_internal(s);
  }
  for (int r = partial_end; r < rounds_total; ++r) {
    for (int i = 0; i < state_width; ++i) {
      blst_fr_add(&s[i], &s[i], &t.rc[r][i]);
      sbox(s[i]);
    }
    matmul_external(s);
  }

  for (int i = 0; i < state_width; ++i) {
    fr_to_be(state[i], s[i]);
  }
}

std::string manifest_bytes() {
  std::string out;
  // sizeof() carries the literal's trailing NUL, which the stream includes.
  out.append(manifest_tag, sizeof(manifest_tag));
  out.append(reinterpret_cast<const char*>(modulus_be), 32);
  out.push_back(static_cast<char>(state_width));
  out.push_back(static_cast<char>(sbox_alpha));
  out.push_back(static_cast<char>(rounds_f));
  out.push_back(static_cast<char>(rounds_p));
  for (int i = 0; i < state_width; ++i) {
    out.append(reinterpret_cast<const char*>(mat_diag8_be[i]), 32);
  }
  for (int row = 0; row < state_width; ++row) {
    for (int col = 0; col < state_width; ++col) {
      out.append(reinterpret_cast<const char*>(mat_internal8_be[row][col]), 32);
    }
  }
  for (int r = 0; r < rounds_total; ++r) {
    for (int i = 0; i < state_width; ++i) {
      out.append(reinterpret_cast<const char*>(rc8_be[r][i]), 32);
    }
  }
  return out;
}

}  // namespace poseidon2

namespace {

// Fail closed: anything that is not already a canonical field element is
// refused. Nothing is reduced, because a silent reduction would let two
// different stack values hash the same.
void pop_field_element(Stack& stack, unsigned char out[32]) {
  auto value = stack.pop_int_finite();
  if (value->sgn() < 0) {
    throw VmError{Excno::range_chk, "Poseidon2 input is negative"};
  }
  if (!value->export_bytes(out, 32, false)) {
    throw VmError{Excno::range_chk, "Poseidon2 input does not fit in 256 bits"};
  }
  if (std::memcmp(out, poseidon2::modulus_be, 32) >= 0) {
    throw VmError{Excno::range_chk, "Poseidon2 input is not below the field modulus"};
  }
}

void push_field_element(Stack& stack, const unsigned char value[32]) {
  td::RefInt256 result{true};
  if (!result.write().import_bytes(value, 32, false)) {
    throw VmError{Excno::fatal, "cannot represent a Poseidon2 output"};
  }
  stack.push_int(std::move(result));
}

// Both instructions consume a full state; they differ only in what they return.
void pop_state(Stack& stack, unsigned char state[8][32]) {
  for (int i = poseidon2::state_width - 1; i >= 0; --i) {
    pop_field_element(stack, state[i]);
  }
}

int exec_poseidon2_perm8(VmState* st) {
  VM_LOG(st) << "execute POSEIDON2_PERM8";
  auto& stack = st->get_stack();
  stack.check_underflow(poseidon2::state_width);
  st->consume_gas_chk(poseidon2_perm8_gas_price);
  unsigned char state[8][32];
  pop_state(stack, state);
  poseidon2::permute(state);
  for (int i = 0; i < poseidon2::state_width; ++i) {
    push_field_element(stack, state[i]);
  }
  return 0;
}

int exec_poseidon2_hash7(VmState* st) {
  VM_LOG(st) << "execute POSEIDON2_HASH7";
  auto& stack = st->get_stack();
  stack.check_underflow(poseidon2::state_width);
  st->consume_gas_chk(poseidon2_hash7_gas_price);
  // The domain constant sits in lane 0 and the result is lane 0: no capacity
  // element and no padding rule beyond that.
  unsigned char state[8][32];
  pop_state(stack, state);
  poseidon2::permute(state);
  push_field_element(stack, state[0]);
  return 0;
}

// One level's six siblings, which section 7.2 of the shielded pool profile
// lays out as two cells of three field elements each: the first carrying a
// reference to the second, the second to the next level, except at the last
// level where it carries none.
//
// Everything this reads is supplied by the sender, so everything is checked.
// The cell is loaded through load_cell_slice rather than parsed by hand,
// because that is what refuses a pruned branch or a library cell -- the FunC
// this replaces depends on exactly that, and a forged path built out of
// pruned branches would otherwise be an attack on every caller of this
// instruction at once.
Ref<Cell> read_siblings(const Ref<Cell>& cell, bool last, unsigned char out[6][32]) {
  if (cell.is_null()) {
    throw VmError{Excno::cell_und, "Poseidon2 path ends before its depth"};
  }
  // The cell load is charged by `load_cell_slice` itself, which calls
  // `register_cell_load` through the VM state interface -- the same
  // first-load and reload prices and the same set of already-loaded cells as
  // every other cell the VM reads.
  //
  // Registering it here as well was this function's second bug: the cell was
  // charged 100 for the first load and then 25 again as a reload, 50 a level
  // more than the Rust VM, which was found by putting a withdrawal through a
  // real node and comparing.
  CellSlice cs = load_cell_slice(cell);
  if (cs.size() != 768) {
    throw VmError{Excno::cell_und, "a Poseidon2 path cell is not three field elements"};
  }
  if (cs.size_refs() != (last ? 0u : 1u)) {
    throw VmError{Excno::cell_und, "a Poseidon2 path cell has the wrong reference count"};
  }
  for (int i = 0; i < 3; ++i) {
    if (!cs.fetch_bytes(out[i], 32)) {
      throw VmError{Excno::cell_und, "a Poseidon2 path cell is short"};
    }
    // Rejected, never reduced. A silent reduction here would accept paths the
    // contract refuses today, for every caller that ever adopts this.
    if (std::memcmp(out[i], poseidon2::modulus_be, 32) >= 0) {
      throw VmError{Excno::range_chk, "a Poseidon2 path sibling is not below the field modulus"};
    }
  }
  return last ? Ref<Cell>{} : cs.prefetch_ref();
}

int exec_poseidon2_path7(VmState* st) {
  VM_LOG(st) << "execute POSEIDON2_PATH7";
  auto& stack = st->get_stack();
  stack.check_underflow(5);
  st->consume_gas_chk(poseidon2_path7_base_gas_price);

  auto depth_int = stack.pop_int_finite();
  if (!depth_int->fits_bits(32, false) || depth_int->sgn() < 0) {
    throw VmError{Excno::range_chk, "Poseidon2 path depth is not a small non-negative integer"};
  }
  int depth = static_cast<int>(depth_int->to_long());
  if (depth < 1 || depth > poseidon2_path7_max_depth) {
    throw VmError{Excno::range_chk, "Poseidon2 path depth is outside the permitted range"};
  }
  auto index = stack.pop_int_finite();
  if (index->sgn() < 0) {
    throw VmError{Excno::range_chk, "Poseidon2 path index is negative"};
  }
  auto path = stack.pop_cell();

  unsigned char state[8][32];
  // The domain goes into lane 0 at every level, exactly as HASH7 places it.
  //
  // It is kept in a variable of its own because `poseidon2::permute` works in
  // place: the permutation's own output lands in lane 0, so a domain written
  // once before the loop is gone from the second level onwards. That was this
  // function's first bug, and nothing caught it -- the contract tests run in
  // the Rust VM, which writes the domain each level, and the C++ path was not
  // executed by anything until a pool was deployed on a node.
  unsigned char domain[32];
  pop_field_element(stack, domain);
  unsigned char carry[32];
  pop_field_element(stack, carry);

  // The index, decided before any level is charged.
  //
  // Whether an index fits the depth is a question about two integers. It needs
  // no cell, no hash and no level, so it is answered before any of those are
  // paid for: refusing after twelve levels of work bills a caller for a
  // permutation whose result was going to be thrown away, and lets one
  // malformed operand cost as much as a real path.
  //
  // This ordering is also what the Rust VM does. It did not used to be what
  // this one did, and the two charged differently for the same input --
  // 500 gas against 500 plus twelve levels -- which is a divergence between
  // two implementations of one public instruction. The shared vectors did not
  // catch it because they are all *well-formed* paths, and a malformed one
  // was only ever checked for its exception, never for its price.
  td::RefInt256 remaining = std::move(index);
  const td::RefInt256 arity = td::make_refint(7);
  std::vector<int> digits;
  digits.reserve(static_cast<std::size_t>(depth));
  for (int level = 0; level < depth; ++level) {
    td::RefInt256 quotient, digit;
    std::tie(quotient, digit) = td::divmod(std::move(remaining), arity);
    digits.push_back(static_cast<int>(digit->to_long()));
    remaining = std::move(quotient);
  }
  if (remaining->sgn() != 0) {
    throw VmError{Excno::range_chk, "Poseidon2 path index is past the depth given"};
  }

  Ref<Cell> node = std::move(path);
  unsigned char siblings[6][32];
  for (int level = 0; level < depth; ++level) {
    // Charged as the level is read, so an oversized *path* is paid for on the
    // way in rather than after it fails. An oversized *index* is a different
    // case and was already refused above, without charging anything for it.
    st->consume_gas_chk(poseidon2_path7_level_gas_price);

    Ref<Cell> next = read_siblings(node, false, siblings);
    unsigned char rest[6][32];
    Ref<Cell> after = read_siblings(next, level == depth - 1, rest);
    for (int i = 0; i < 3; ++i) {
      std::memcpy(siblings[3 + i], rest[i], 32);
    }

    const int d = digits[static_cast<std::size_t>(level)];

    // The carry goes back into position d and the six siblings fill the rest
    // in ascending child position, which is what makes a reordered witness
    // produce a different root.
    std::memcpy(state[0], domain, 32);
    int taken = 0;
    for (int slot = 0; slot < 7; ++slot) {
      if (slot == d) {
        std::memcpy(state[1 + slot], carry, 32);
      } else {
        std::memcpy(state[1 + slot], siblings[taken++], 32);
      }
    }
    poseidon2::permute(state);
    std::memcpy(carry, state[0], 32);
    node = std::move(after);
  }
  // The index was decided before the loop, so nothing about it is left to
  // check here. A path *longer* than its depth still is: that is a property of
  // the cells, and the cells are only known as they are read.
  if (node.not_null()) {
    throw VmError{Excno::cell_und, "Poseidon2 path is longer than its depth"};
  }
  push_field_element(stack, carry);
  return 0;
}

}  // namespace

void register_poseidon2_ops(OpcodeTable& table) {
  table.insert(OpcodeInstr::mksimple(poseidon2_perm8_opcode, 24, "POSEIDON2_PERM8", exec_poseidon2_perm8)
                   ->require_version(poseidon2_min_version));
  table.insert(OpcodeInstr::mksimple(poseidon2_hash7_opcode, 24, "POSEIDON2_HASH7", exec_poseidon2_hash7)
                   ->require_version(poseidon2_min_version));
  table.insert(OpcodeInstr::mksimple(poseidon2_path7_opcode, 24, "POSEIDON2_PATH7", exec_poseidon2_path7)
                   ->require_version(poseidon2_path7_min_version));
}

}  // namespace vm
