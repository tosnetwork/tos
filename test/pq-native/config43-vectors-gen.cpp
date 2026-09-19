/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Configuration parameter 43 encodings, as whole cells rather than as descriptions to be
// rebuilt. Two implementations read these same bytes; one that refuses a version the
// other accepts, or reads a different limit out of it, is a split in how much state an
// account may hold.
//
// Every line carries the parsed values both sides must reach, so agreement is checked
// against a stated answer rather than against each other, which two implementations that
// are wrong in the same way would also satisfy.
#include <cstdio>
#include <string>

#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"

namespace {

struct Values {
  unsigned max_msg_bits = 1u << 21;
  unsigned max_msg_cells = 1u << 13;
  unsigned max_library_cells = 1000;
  unsigned max_vm_data_depth = 512;
  unsigned max_ext_msg_size = 65535;
  unsigned max_ext_msg_depth = 512;
  unsigned max_acc_state_cells = 1u << 16;
  unsigned max_mc_acc_state_cells = 1u << 11;
  unsigned max_acc_public_libraries = 256;
  unsigned defer_out_queue_size_limit = 256;
  unsigned max_msg_extra_currencies = 2;
  unsigned max_acc_fixed_prefix_length = 8;
  unsigned acc_state_cells_for_storage_dict = 26;
  long long max_transaction_library_loads = -1;  // -1 means absent, which means unlimited
  unsigned max_total_msg_bits = (1u << 21) * 5 / 2;
  unsigned max_total_msg_cells = (1u << 13) * 5 / 2;
};

void store_v1_fields(vm::CellBuilder& cb, const Values& v) {
  cb.store_long(v.max_msg_bits, 32);
  cb.store_long(v.max_msg_cells, 32);
  cb.store_long(v.max_library_cells, 32);
  cb.store_long(v.max_vm_data_depth, 16);
  cb.store_long(v.max_ext_msg_size, 32);
  cb.store_long(v.max_ext_msg_depth, 16);
}

void store_v2_fields(vm::CellBuilder& cb, const Values& v) {
  cb.store_long(v.max_acc_state_cells, 32);
  cb.store_long(v.max_mc_acc_state_cells, 32);
  cb.store_long(v.max_acc_public_libraries, 32);
  cb.store_long(v.defer_out_queue_size_limit, 32);
  cb.store_long(v.max_msg_extra_currencies, 32);
  cb.store_long(v.max_acc_fixed_prefix_length, 8);
  cb.store_long(v.acc_state_cells_for_storage_dict, 32);
}

td::Ref<vm::Cell> v1(const Values& v) {
  vm::CellBuilder cb;
  cb.store_long(0x01, 8);
  store_v1_fields(cb, v);
  return cb.finalize();
}

td::Ref<vm::Cell> v2(const Values& v) {
  vm::CellBuilder cb;
  cb.store_long(0x02, 8);
  store_v1_fields(cb, v);
  store_v2_fields(cb, v);
  return cb.finalize();
}

td::Ref<vm::Cell> v3(const Values& v) {
  vm::CellBuilder cb;
  cb.store_long(0x03, 8);
  store_v1_fields(cb, v);
  store_v2_fields(cb, v);
  if (v.max_transaction_library_loads < 0) {
    cb.store_long(0, 1);
  } else {
    cb.store_long(1, 1);
    cb.store_long(v.max_transaction_library_loads, 32);
  }
  cb.store_long(v.max_total_msg_bits, 32);
  cb.store_long(v.max_total_msg_cells, 32);
  return cb.finalize();
}

// A version-1 record says nothing about the later fields, so both sides must fall back to
// exactly the same defaults rather than to whatever each considers reasonable.
Values v1_expectation(const Values& written) {
  Values expected;
  expected.max_msg_bits = written.max_msg_bits;
  expected.max_msg_cells = written.max_msg_cells;
  expected.max_library_cells = written.max_library_cells;
  expected.max_vm_data_depth = written.max_vm_data_depth;
  expected.max_ext_msg_size = written.max_ext_msg_size;
  expected.max_ext_msg_depth = written.max_ext_msg_depth;
  return expected;
}

// A version-2 record carries everything but the version-3 fields.
Values v2_expectation(const Values& written) {
  Values expected = written;
  Values defaults;
  expected.max_transaction_library_loads = defaults.max_transaction_library_loads;
  expected.max_total_msg_bits = defaults.max_total_msg_bits;
  expected.max_total_msg_cells = defaults.max_total_msg_cells;
  return expected;
}

void emit(const char* name, const char* verdict, const td::Ref<vm::Cell>& cell, const Values& e) {
  std::string loads = e.max_transaction_library_loads < 0 ? "-" : std::to_string(e.max_transaction_library_loads);
  std::printf("%s\t%s\t%s\t%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%u,%u\n", name, verdict,
              td::hex_encode(vm::std_boc_serialize(cell, 31).move_as_ok().as_slice()).c_str(), e.max_msg_bits,
              e.max_msg_cells, e.max_library_cells, e.max_vm_data_depth, e.max_ext_msg_size, e.max_ext_msg_depth,
              e.max_acc_state_cells, e.max_mc_acc_state_cells, e.max_acc_public_libraries, e.defer_out_queue_size_limit,
              e.max_msg_extra_currencies, e.max_acc_fixed_prefix_length, e.acc_state_cells_for_storage_dict,
              loads.c_str(), e.max_total_msg_bits, e.max_total_msg_cells);
}

void emit_reject(const char* name, const td::Ref<vm::Cell>& cell) {
  std::printf("%s\treject\t%s\t-\n", name,
              td::hex_encode(vm::std_boc_serialize(cell, 31).move_as_ok().as_slice()).c_str());
}

}  // namespace

int main() {
  std::printf("# Configuration parameter 43, one encoding per line, with the values both\n");
  std::printf("# implementations must read out of it.\n");
  std::printf(
      "# name\tverdict\tboc_hex\tmax_msg_bits,max_msg_cells,max_library_cells,max_vm_data_depth,"
      "max_ext_msg_size,max_ext_msg_depth,max_acc_state_cells,max_mc_acc_state_cells,"
      "max_acc_public_libraries,defer_out_queue_size_limit,max_msg_extra_currencies,"
      "max_acc_fixed_prefix_length,acc_state_cells_for_storage_dict,max_transaction_library_loads,"
      "max_total_msg_bits,max_total_msg_cells\n");

  Values defaults;
  emit("v1-defaults", "accept", v1(defaults), v1_expectation(defaults));

  Values distinct;
  distinct.max_msg_bits = 1234567;
  distinct.max_msg_cells = 4321;
  distinct.max_library_cells = 999;
  distinct.max_vm_data_depth = 511;
  distinct.max_ext_msg_size = 60000;
  distinct.max_ext_msg_depth = 300;
  distinct.max_acc_state_cells = 70000;
  distinct.max_mc_acc_state_cells = 3000;
  distinct.max_acc_public_libraries = 128;
  distinct.defer_out_queue_size_limit = 64;
  distinct.max_msg_extra_currencies = 5;
  distinct.max_acc_fixed_prefix_length = 7;
  distinct.acc_state_cells_for_storage_dict = 31;
  emit("v1-distinct", "accept", v1(distinct), v1_expectation(distinct));
  emit("v2-distinct", "accept", v2(distinct), v2_expectation(distinct));

  // Version 3 with the optional library-load limit absent, which means unlimited and is
  // not the same statement as a limit that happens to be large.
  Values v3_absent = distinct;
  v3_absent.max_transaction_library_loads = -1;
  v3_absent.max_total_msg_bits = 7000000;
  v3_absent.max_total_msg_cells = 20000;
  emit("v3-library-loads-absent", "accept", v3(v3_absent), v3_absent);

  Values v3_present = v3_absent;
  v3_present.max_transaction_library_loads = 17;
  emit("v3-library-loads-present", "accept", v3(v3_present), v3_present);

  // Zero is a real bound, not an absent one, and must survive the round trip as zero.
  Values v3_zero = v3_absent;
  v3_zero.max_transaction_library_loads = 0;
  emit("v3-library-loads-zero", "accept", v3(v3_zero), v3_zero);

  {  // An unknown constructor is refused rather than read as the nearest known one.
    vm::CellBuilder cb;
    cb.store_long(0x04, 8);
    store_v1_fields(cb, defaults);
    store_v2_fields(cb, defaults);
    emit_reject("unknown-tag", cb.finalize());
  }
  {  // A version-2 record that stops early is refused rather than defaulted.
    vm::CellBuilder cb;
    cb.store_long(0x02, 8);
    store_v1_fields(cb, defaults);
    cb.store_long(defaults.max_acc_state_cells, 32);
    emit_reject("v2-truncated", cb.finalize());
  }
  return 0;
}
