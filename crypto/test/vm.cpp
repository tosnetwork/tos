/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include <random>
#include <vector>

#include "common/bigint.hpp"
#include "fift/utils.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/tests.h"
#include "vm/cp0.h"
#include "vm/dict.h"
#include "vm/vm.h"

std::string run_vm(td::Ref<vm::Cell> cell) {
  vm::init_vm().ensure();
  vm::DictionaryBase::get_empty_dictionary();

  class Logger : public td::LogInterface {
   public:
    void append(td::CSlice slice) override {
      res.append(slice.data(), slice.size());
    }
    std::string res;
  };
  static Logger logger;
  logger.res = "";
  td::set_log_fatal_error_callback([](td::CSlice message) { td::default_log_interface->append(logger.res); });
  vm::VmLog log{&logger, td::LogOptions::plain()};
  log.log_options.level = 4;
  log.log_options.fix_newlines = true;
  log.log_mask |= vm::VmLog::DumpStack;

  auto total_data_cells_before = vm::DataCell::get_total_data_cells();
  SCOPE_EXIT {
    auto total_data_cells_after = vm::DataCell::get_total_data_cells();
    ASSERT_EQ(total_data_cells_before, total_data_cells_after);
  };

  vm::Stack stack;
  try {
    vm::GasLimits gas_limit(1000, 1000);

    vm::run_vm_code(vm::load_cell_slice_ref(cell), stack, 0 /*flags*/, nullptr /*data*/, std::move(log) /*VmLog*/,
                    nullptr, &gas_limit);
  } catch (...) {
    LOG(FATAL) << "catch unhandled exception";
  }
  return logger.res;  // must be a copy
}

td::Ref<vm::Cell> to_cell(const unsigned char *buff, int bits) {
  return vm::CellBuilder().store_bits(buff, bits, 0).finalize();
}
void test_run_vm(td::Ref<vm::Cell> code) {
  auto a = run_vm(code);
  auto b = run_vm(code);
  ASSERT_EQ(a, b);
  REGRESSION_VERIFY(a);
}

void test_run_vm(td::Slice code_hex) {
  unsigned char buff[128];
  int bits = (int)td::bitstring::parse_bitstring_hex_literal(buff, sizeof(buff), code_hex.begin(), code_hex.end());
  CHECK(bits >= 0);
  test_run_vm(to_cell(buff, bits));
}

void test_run_vm_raw(td::Slice code64) {
  auto code = td::base64_decode(code64).move_as_ok();
  if (code.size() > 127) {
    code.resize(127);
  }
  test_run_vm(vm::CellBuilder().store_bytes(code).finalize());
}

TEST(VM, simple) {
  test_run_vm("ABCBABABABA");
}

TEST(VM, sha256_canonical_snake) {
  vm::init_vm().ensure();
  std::string first(120, 'a');
  std::string second(120, 'b');
  auto tail = vm::CellBuilder().store_bytes(second).finalize();
  auto snake = vm::CellBuilder().store_bytes(first).store_ref(tail).finalize();
  unsigned char opcode[] = {0xf9, 0x03};
  auto code = to_cell(opcode, 16);
  vm::Stack stack;
  stack.push_cell(snake);
  vm::GasLimits gas_limit(100000, 100000);
  auto result = vm::run_vm_code(vm::load_cell_slice_ref(code), stack, 0, nullptr, {}, nullptr, &gas_limit,
                                {}, {}, nullptr, 14);
  ASSERT_EQ(result, 0);
  auto actual = stack.pop_int_finite();
  auto bytes = first + second;
  auto hash = td::sha256(bytes);
  td::BigInt256 expected;
  ASSERT_TRUE(expected.import_bytes(reinterpret_cast<const unsigned char *>(hash.data()), hash.size(), false));
  ASSERT_EQ(actual->cmp_un(expected), 0);
}

TEST(VM, sha256_canonical_snake_rejects_aliases_and_old_versions) {
  vm::init_vm().ensure();
  unsigned char opcode[] = {0xf9, 0x03};
  auto code = to_cell(opcode, 16);
  auto run = [&](td::Ref<vm::Cell> input, int global_version) {
    vm::Stack stack;
    stack.push_cell(std::move(input));
    vm::GasLimits gas_limit(100000, 100000);
    return vm::run_vm_code(vm::load_cell_slice_ref(code), stack, 0, nullptr, {}, nullptr, &gas_limit,
                           {}, {}, nullptr, global_version);
  };

  auto valid = vm::CellBuilder().store_long(0x41, 8).finalize();
  ASSERT_TRUE(run(valid, 13) != 0);  // SHA256C is activated only at protocol version 14.

  auto non_byte_aligned = vm::CellBuilder().store_long(1, 1).finalize();
  ASSERT_TRUE(run(non_byte_aligned, 14) != 0);

  auto tail = vm::CellBuilder().store_long(0x42, 8).finalize();
  auto two_references = vm::CellBuilder().store_ref(tail).store_ref(tail).finalize();
  ASSERT_TRUE(run(two_references, 14) != 0);
}

TEST(VM, memory_leak_old) {
  test_run_vm("90787FDB3B");
}

TEST(VM, memory_leak) {
  test_run_vm("90707FDB3B");
}

TEST(VM, bug_div_short_any) {
  test_run_vm("6883FF73A98D");
}
TEST(VM, assert_pfx_dict_lookup) {
  test_run_vm("778B04216D73F43E018B04591277F473");
}

TEST(VM, assert_lookup_prefix) {
  test_run_vm("78E58B008B028B04010000016D90ED5272F43A755D77F4A8");
}

TEST(VM, assert_code_not_null) {
  test_run_vm("76ED40DE");
}

TEST(VM, bug_exec_dict_getnear) {
  test_run_vm("8B048B00006D72F47573655F6D656D6D656D8B007F");
}

TEST(VM, bug_stack_overflow) {
  test_run_vm("72A93AF8");
}

TEST(VM, assert_extract_minmax_key) {
  test_run_vm("6D6DEB21807AF49C2180EB21807AF41C");
}

TEST(VM, memory_leak_new) {
  test_run_vm("72E5ED40DB3603");
}

TEST(VM, unhandled_exception_1) {
  test_run_vm("70EDA2ED00");
}

TEST(VM, unhandled_exception_2) {
  // infinite loop now
  test_run_vm("EBEDB4");
}

TEST(VM, unhandled_exception_3) {
  // infinite loop now
  test_run_vm("EBEDC0");
}

TEST(VM, unhandled_exception_4) {
  test_run_vm("7F853EA1C8CB3E");
}

TEST(VM, unhandled_exception_5) {
  test_run_vm("738B04016D21F41476A721F49F");
}

TEST(VM, infinity_loop_1) {
  test_run_vm_raw("f3r4AJGQ6rDraIQ=");
}
TEST(VM, infinity_loop_2) {
  test_run_vm_raw("kpTt7ZLrig==");
}

TEST(VM, oom_1) {
  test_run_vm_raw("bXflX/BvDw==");
}

TEST(VM, bigint) {
  td::StringBuilder sb({}, true);

  using word_t = td::BigIntInfo::word_t;
  std::vector<word_t> numbers{1,
                              -1,
                              2,
                              -2,
                              100,
                              -100,
                              std::numeric_limits<word_t>::max(),
                              std::numeric_limits<word_t>::min(),
                              std::numeric_limits<word_t>::max() - 1,
                              std::numeric_limits<word_t>::min() + 1};
  for (auto x : numbers) {
    for (auto y : numbers) {
      word_t a;
      word_t b;
      td::BigIntInfo::set_mul(&a, &b, x, y);
      sb << "set_mul " << x << " * " << y << " = " << a << " " << b << "\n";
      td::BigIntInfo::add_mul(&a, &b, x, y);
      sb << "add_mul " << x << " " << y << " = " << a << " " << b << "\n";
      td::BigIntInfo::sub_mul(&a, &b, x, y);
      sb << "sub_mul " << x << " " << y << " = " << a << " " << b << "\n";
    }
  }
  auto base = td::BigIntInfo::Base;
  std::vector<word_t> lo_numbers{1, -1, 2, -2, 100, -100, base - 1, base - 2, -base + 1, -base + 2};
  for (auto x : numbers) {
    for (auto y : lo_numbers) {
      for (auto z : numbers) {
        word_t a;
        word_t b;
        td::BigIntInfo::dbl_divmod(&a, &b, x, y, z);
        sb << "dbl_divmod " << x << " " << y << " / " << z << " = " << a << " " << b << "\n";
      }
    }
  }

  REGRESSION_VERIFY(sb.as_cslice());
}

TEST(VM, report3_1) {
  //WA: expect (1, 2, 6, 3)
  td::Slice test1 =
      R"A(
CONT:<{
DEPTH
}>
3 SETNUMARGS
c0 POPCTR
1 INT
2 INT
3 INT
4 INT
5 INT
6 INT
4 RETURNARGS
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_2) {
  td::Slice test1 =
      R"A(
CONT:<{
DEPTH
}>
2 SETNUMARGS
c0 POPCTR
1 INT
2 INT
3 INT
4 INT
2 RETARGS
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_3) {
  // WA: expect (9)
  td::Slice test1 =
      R"A(
CONT:<{
 8 INT
}>
c0 POPCTR
CONT:<{
 9 INT
}>
c1 POPCTR
0 INT
BRANCH
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_4) {
  td::Slice test1 =
      R"A(
CONT:<{
1 INT
2 INT
3 INT
2 RETARGS
}>
CALLX
ADD
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_6) {
  // WA: expect StackOverflow
  td::Slice test1 =
      R"A(
10 INT
20 INT
30 INT
CONT:<{
  DEPTH
  40 INT
  SWAP
}>
2 SETNUMARGS
3 1 CALLXARGS
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

//TEST(VM, report3_ce) {
//td::Slice test1 =
//R"A(
//s16 POP
//s16 PUSH
//s0 s16 XCHG
//)A";
//test_run_vm(fift::compile_asm(test1).move_as_ok());
//}

TEST(VM, report3_int_overflow_1) {
  td::Slice test1 =
      R"A(
4 INT
16 INT
-115792089237316195423570985008687907853269984665640564039457584007913129639936 INT
MULDIVMOD
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}
TEST(VM, report3_int_overflow_2) {
  td::Slice test1 =
      R"A(
4 INT
16 INT
-115792089237316195423570985008687907853269984665640564039457584007913129639936 INT
MULDIVR
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_qnot) {
  td::Slice test1 =
      R"A(
PUSHNAN
QNOT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_1) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  2 INT
}>
ATEXITALT
CONT:<{
 1 INT
 RETALT
 -1 INT
}>
AGAIN
3 INT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_2) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  2 INT
}>
ATEXITALT
CONT:<{
 1 INT
 RETALT
 -1 INT
}>
UNTIL
3 INT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_3) {
  //WA
  td::Slice test1 =
      R"A(
1 INT
CONT:<{
  UNTILEND
  RET
  -1 INT
}>
CALLX
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_4) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  2 INT
}>
ATEXITALT
CONT:<{
  1 INT
  RETALT
  -1 PUSHINT
}>
CONT:<{
  -1 INT
}>
WHILE
3 INT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}
TEST(VM, report3_loop_5) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  1 INT
  2 INT
}>
ATEXITALT
3 INT
AGAINEND
DEC
DUP
IFRET
DROP
RETALT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

TEST(VM, report3_loop_6) {
  //WA
  td::Slice test1 =
      R"A(
CONT:<{
  1 INT
  2 INT
}>
3 INT
AGAINEND
DEC
DUP
IFRET
DROP
ATEXITALT
RETALT
)A";
  test_run_vm(fift::compile_asm(test1).move_as_ok());
}

namespace {

// Leaf cell for an 8-bit key whose label is encoded in an explicitly chosen form.
enum class LabelForm { ShortUnary, Long, Same };

td::Ref<vm::Cell> make_leaf_with_label(unsigned key, LabelForm form) {
  constexpr int key_bits = 8;
  constexpr int len_bits = 4;  // 32 - clz(8)
  vm::CellBuilder cb;
  switch (form) {
    case LabelForm::ShortUnary:
      CHECK(cb.store_long_bool(0, 1));
      CHECK(cb.store_long_bool(-2, key_bits + 1));  // eight ones, then a zero
      CHECK(cb.store_long_bool(key, key_bits));
      break;
    case LabelForm::Long:
      CHECK(cb.store_long_bool(2, 2));
      CHECK(cb.store_long_bool(key_bits, len_bits));
      CHECK(cb.store_long_bool(key, key_bits));
      break;
    case LabelForm::Same:
      CHECK(key == 0 || key == 0xff);
      CHECK(cb.store_long_bool(6 + (key != 0), 3));
      CHECK(cb.store_long_bool(key_bits, len_bits));
      break;
  }
  CHECK(cb.store_long_bool(0x5a, 8));
  return cb.finalize();
}

td::Ref<vm::Cell> make_canonical_leaf(unsigned key) {
  vm::Dictionary dict{8};
  td::BitArray<8> k;
  k.bits().store_uint(key, 8);
  vm::CellBuilder value;
  CHECK(value.store_long_bool(0x5a, 8));
  CHECK(dict.set_builder(k.cbits(), 8, value));
  return dict.get_root_cell();
}

bool label_parses(td::Ref<vm::Cell> cell, bool check_canonical) {
  try {
    vm::dict::LabelParser label{std::move(cell), 8, vm::dict::LabelParser::chk_all, check_canonical};
    return label.l_bits == 8;
  } catch (vm::VmError &) {
    return false;
  }
}

// Returns the number of changed keys reported, or -1 if the scan threw.
int count_diff(td::Ref<vm::Cell> old_root, td::Ref<vm::Cell> new_root, int key_bits, int mode) {
  vm::Dictionary old_dict{std::move(old_root), key_bits};
  vm::Dictionary new_dict{std::move(new_root), key_bits};
  int changed = 0;
  try {
    bool ok = old_dict.scan_diff(
        new_dict,
        [&](td::ConstBitPtr, int, td::Ref<vm::CellSlice>, td::Ref<vm::CellSlice>) {
          ++changed;
          return true;
        },
        mode);
    CHECK(ok);
  } catch (vm::VmError &) {
    return -1;
  }
  return changed;
}

}  // namespace

TEST(VM, dict_label_canonical_check_is_opt_in) {
  // The encoder picks the long form for a mixed 8-bit label and the same-bit form for 0x00 / 0xff.
  ASSERT_EQ(make_canonical_leaf(0xb2)->get_hash(), make_leaf_with_label(0xb2, LabelForm::Long)->get_hash());
  ASSERT_EQ(make_canonical_leaf(0xff)->get_hash(), make_leaf_with_label(0xff, LabelForm::Same)->get_hash());
  ASSERT_EQ(make_canonical_leaf(0x00)->get_hash(), make_leaf_with_label(0x00, LabelForm::Same)->get_hash());

  struct Case {
    unsigned key;
    LabelForm form;
    bool canonical;
  };
  const Case cases[] = {
      {0xb2, LabelForm::Long, true},  {0xb2, LabelForm::ShortUnary, false}, {0xff, LabelForm::Same, true},
      {0xff, LabelForm::Long, false}, {0xff, LabelForm::ShortUnary, false}, {0x00, LabelForm::Same, true},
      {0x00, LabelForm::Long, false},
  };
  for (const auto &c : cases) {
    auto cell = make_leaf_with_label(c.key, c.form);
    // Default mode (used by every TVM dictionary operation) accepts every valid encoding.
    ASSERT_TRUE(label_parses(cell, false));
    ASSERT_EQ(c.canonical, label_parses(cell, true));
  }
}

TEST(VM, dict_scan_diff_rejects_non_canonical_new_labels) {
  const int strict = vm::DictionaryFixed::check_new_aug | vm::DictionaryFixed::check_new_canonical_labels;
  auto canonical = make_canonical_leaf(0xb2);
  auto aliased = make_leaf_with_label(0xb2, LabelForm::ShortUnary);
  ASSERT_TRUE(canonical->get_hash() != aliased->get_hash());

  // Empty old dictionary: the new entry is reported, unless its label is not canonical.
  ASSERT_EQ(1, count_diff({}, canonical, 8, strict));
  ASSERT_EQ(1, count_diff({}, aliased, 8, vm::DictionaryFixed::check_new_aug));
  ASSERT_EQ(-1, count_diff({}, aliased, 8, strict));

  // Same content under a different encoding: no key changes, so only the label check can refuse it.
  ASSERT_EQ(0, count_diff(canonical, aliased, 8, vm::DictionaryFixed::check_new_aug));
  ASSERT_EQ(-1, count_diff(canonical, aliased, 8, strict));
  // Only the new side is checked.
  ASSERT_EQ(0, count_diff(aliased, canonical, 8, strict));
}

TEST(VM, dict_scan_diff_canonical_check_accepts_encoder_output) {
  const int strict = vm::DictionaryFixed::check_new_aug | vm::DictionaryFixed::check_new_canonical_labels;
  std::mt19937_64 rng(20261022);
  for (int key_bits : {1, 2, 3, 7, 8, 16, 64, 352}) {
    vm::Dictionary old_dict{key_bits};
    vm::Dictionary new_dict{key_bits};
    std::vector<td::BitArray<352>> keys;
    for (int i = 0; i < 300; i++) {
      td::BitArray<352> key;
      for (int b = 0; b < key_bits; b++) {
        // Sparse ones give long runs of equal bits, so the same-bit label form is exercised too.
        key.bits()[b] = (rng() % 8) == 0;
      }
      if (i % 50 == 0) {
        key.bits().fill(i % 100 == 0, key_bits);
      }
      vm::CellBuilder value;
      CHECK(value.store_long_bool((long long)(rng() & 0xff), 8));
      new_dict.set_builder(key.cbits(), key_bits, value);
      if (i % 3 == 0) {
        old_dict.set_builder(key.cbits(), key_bits, value);
      }
      keys.push_back(key);
    }
    for (std::size_t i = 0; i < keys.size(); i += 7) {
      new_dict.lookup_delete(keys[i].cbits(), key_bits);
    }
    ASSERT_TRUE(count_diff({}, new_dict.get_root_cell(), key_bits, strict) >= 0);
    ASSERT_TRUE(count_diff(old_dict.get_root_cell(), new_dict.get_root_cell(), key_bits, strict) >= 0);
  }
}
