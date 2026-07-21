/*
    Copyright (C) 2025-2026 TOS Network.

    ConfigParam 43's max_transaction_library_loads end-to-end through the
    real transaction-execution path (Codex review follow-up, 2026-07-21).

    emulator/test/vm-library-loads-fixture.cpp already pins the VmState-level
    counting mechanism (ported from ton-c b647a8d5) and tvm-v14-v15-
    transaction-fixture.cpp already pins the TL-B parse of ConfigParam 43 v3.
    What neither covers is the wiring in between: does a real
    block::transaction::Transaction, given a ComputePhaseConfig whose
    size_limits.max_transaction_library_loads is set, actually thread that
    value into vm.set_max_library_loads() (crypto/block/transaction.cpp,
    ~line 2459) and have the VM enforce it while running real TVM code that
    performs library loads via XLOAD (crypto/vm/cellops.cpp)?

    This drives block::transaction::Transaction directly (bypassing
    TransactionEmulator's full block::Config/FetchConfigParams machinery,
    which needs a full synthetic genesis-style config) with a hand-built
    ComputePhaseConfig and a minimal active account whose code performs
    ACCEPT then two XLOADs against two distinct account-independent
    "global" libraries (via ComputePhaseConfig::libraries, the same
    cfg.get_lib_root() path real masterchain-published libraries use).
*/

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"
#include "vm/vm.h"

namespace {

void ensure_vm_ready() {
  static const bool once = [] {
    vm::init_vm(false).ensure();
    return true;
  }();
  (void)once;
}

td::Ref<vm::Cell> leaf_cell(td::uint32 tag) {
  vm::CellBuilder cb;
  cb.store_long(tag, 32);
  return cb.finalize();
}

// A special "Library" cell (CellTraits::SpecialType::Library = 2) referencing
// `content` by hash -- what XLOAD expects on the stack (crypto/vm/cellops.cpp
// exec_load_special_cell): 8-bit special-type tag + 256-bit content hash.
td::Ref<vm::Cell> library_ref_cell(const td::Ref<vm::Cell>& content) {
  vm::CellBuilder cb;
  cb.store_long(2, 8);
  cb.store_bits(content->get_hash().bits(), 256);
  return cb.finalize(/*special=*/true);
}

// Code: ACCEPT; PUSHREF lib1; XLOAD; DROP; PUSHREF lib2; XLOAD; DROP.
// Mirrors the F2.2 "ACCEPT taken before a later throw" shape from
// slice-1-failure-phase-fixtures.cpp -- msg is accepted, then the second,
// distinct library load either succeeds (no cap / cap >= 2) or throws
// (cap == 1), which is exactly the enforcement point under test.
td::Ref<vm::Cell> build_two_library_load_code(const td::Ref<vm::Cell>& lib1, const td::Ref<vm::Cell>& lib2) {
  vm::CellBuilder cb;
  cb.store_long(0xf800, 16);  // ACCEPT
  cb.store_long(0x88, 8);     // PUSHREF (ref 0 = lib1)
  cb.store_long(0xd73a, 16);  // XLOAD
  cb.store_long(0x30, 8);     // DROP
  cb.store_long(0x88, 8);     // PUSHREF (ref 1 = lib2)
  cb.store_long(0xd73a, 16);  // XLOAD
  cb.store_long(0x30, 8);     // DROP
  cb.store_ref(library_ref_cell(lib1));
  cb.store_ref(library_ref_cell(lib2));
  return cb.finalize();
}

// Builds a minimal, real int_msg_info$0 message with a genuine addr_std
// src (GenericAccount::store_int_message leaves src as addr_none$00, which
// is valid for an outbound message the collator fills in later, but fails
// block::gen::t_MsgAddressInt's strict addr_std$10/addr_var$11 check when
// fed straight into Transaction::unpack_input_msg as an inbound message).
td::Ref<vm::Cell> build_internal_message(const block::StdAddress& src, const block::StdAddress& dest,
                                         td::int64 tomis) {
  vm::CellBuilder cb;
  CHECK(cb.store_zeroes_bool(1));                 // int_msg_info$0
  CHECK(cb.store_ones_bool(1));                   // ihr_disabled = true
  CHECK(cb.store_long_bool(dest.bounceable, 1));  // bounce
  CHECK(cb.store_zeroes_bool(1));                 // bounced = false
  // src, dest: addr_std$10 anycast:none workchain:int8 address:bits256
  for (const auto& addr : {src, dest}) {
    CHECK(cb.store_long_bool(2, 2));  // addr_std$10
    CHECK(cb.store_zeroes_bool(1));   // anycast: none
    CHECK(cb.store_long_bool(addr.workchain, 8));
    CHECK(cb.store_bits_bool(addr.addr.cbits(), 256));
  }
  // value:CurrencyCollection = Grams + Maybe ^ExtraCurrencyCollection(none)
  CHECK(block::tlb::t_Tomis.store_integer_value(cb, td::BigInt256(tomis)));
  CHECK(cb.store_maybe_ref({}));
  // extra_flags:Grams(0) fwd_fee:Grams(0) created_lt:uint64(0) created_at:uint32(0)
  CHECK(cb.store_zeroes_bool(8 + 64 + 32));
  CHECK(cb.store_zeroes_bool(1));  // init:(Maybe ...) = nothing$0
  CHECK(cb.store_zeroes_bool(1));  // body:(Either X ^X) = left$0 (inline, empty)
  return cb.finalize();
}

struct RunResult {
  bool success;
  int exit_code;
  bool accepted;
};

// Constructs a fresh active account with `code`, drives a real
// block::transaction::Transaction through storage phase + compute phase
// (skipping credit/action/serialize -- irrelevant to library-load
// enforcement), and returns the compute-phase outcome.
RunResult run_compute(const td::Ref<vm::Cell>& code, td::optional<td::uint32> max_transaction_library_loads,
                      vm::Dictionary& global_libraries) {
  ensure_vm_ready();

  const tos::UnixTime now = 1750000000;
  const tos::LogicalTime lt = 1000;

  td::Bits256 addr_bits;
  addr_bits.set_zero();
  addr_bits.as_slice().ubegin()[0] = 0x42;

  block::Account acc(tos::basechainId, addr_bits.cbits());
  CHECK(acc.init_new(now));
  acc.status = acc.orig_status = block::Account::acc_active;
  acc.balance = block::CurrencyCollection(10'000'000'000LL);
  acc.code = code;
  acc.data = vm::CellBuilder().finalize();

  td::Bits256 sender_bits;
  sender_bits.set_zero();
  sender_bits.as_slice().ubegin()[0] = 0x99;
  block::StdAddress src(tos::basechainId, sender_bits.cbits());
  block::StdAddress dest(tos::basechainId, addr_bits.cbits());
  auto in_msg = build_internal_message(src, dest, 1'000'000'000LL);

  block::transaction::Transaction trans(acc, block::transaction::Transaction::tr_ord, lt, now, in_msg);

  block::ActionPhaseConfig action_cfg;
  action_cfg.global_version = 15;
  CHECK(trans.unpack_input_msg(/*ihr_delivered=*/false, &action_cfg));

  std::vector<block::StoragePrices> storage_prices;
  block::StoragePhaseConfig storage_cfg(&storage_prices);
  storage_cfg.global_version = 15;
  CHECK(trans.prepare_storage_phase(storage_cfg, /*force_collect=*/true));

  block::ComputePhaseConfig cfg;
  cfg.gas_limit = 1'000'000;
  cfg.special_gas_limit = cfg.gas_limit;
  cfg.gas_credit = 10'000;
  cfg.set_gas_price(1000);
  cfg.global_version = 15;
  cfg.max_vm_data_depth = 512;
  cfg.block_rand_seed.set_zero();
  cfg.libraries = std::make_unique<vm::Dictionary>(global_libraries);
  cfg.size_limits.max_transaction_library_loads = max_transaction_library_loads;

  CHECK(trans.prepare_compute_phase(cfg));
  CHECK(trans.compute_phase != nullptr);
  return RunResult{trans.compute_phase->success, trans.compute_phase->exit_code, trans.compute_phase->accepted};
}

}  // namespace

TEST(ConfigParam43Transaction, UnsetLimitAllowsTwoDistinctLibraryLoads) {
  auto lib1 = leaf_cell(1), lib2 = leaf_cell(2);
  vm::Dictionary global_libraries{256};
  CHECK(global_libraries.set_ref(lib1->get_hash().bits(), 256, lib1));
  CHECK(global_libraries.set_ref(lib2->get_hash().bits(), 256, lib2));

  auto code = build_two_library_load_code(lib1, lib2);
  auto result = run_compute(code, /*max_transaction_library_loads=*/{}, global_libraries);
  CHECK(result.accepted);
  CHECK(result.success);
  CHECK(result.exit_code == 0);
}

TEST(ConfigParam43Transaction, LimitOfOneRejectsSecondDistinctLibraryLoad) {
  auto lib1 = leaf_cell(10), lib2 = leaf_cell(20);
  vm::Dictionary global_libraries{256};
  CHECK(global_libraries.set_ref(lib1->get_hash().bits(), 256, lib1));
  CHECK(global_libraries.set_ref(lib2->get_hash().bits(), 256, lib2));

  auto code = build_two_library_load_code(lib1, lib2);
  auto result = run_compute(code, /*max_transaction_library_loads=*/1u, global_libraries);
  // ACCEPT already ran before the second, over-the-cap XLOAD throws --
  // matches the F2.2 "compute-phase exception under execute" shape.
  CHECK(result.accepted);
  CHECK(!result.success);
  CHECK(result.exit_code == (int)vm::Excno::cell_und);
}

TEST(ConfigParam43Transaction, LimitOfTwoAllowsBothDistinctLibraryLoads) {
  auto lib1 = leaf_cell(100), lib2 = leaf_cell(200);
  vm::Dictionary global_libraries{256};
  CHECK(global_libraries.set_ref(lib1->get_hash().bits(), 256, lib1));
  CHECK(global_libraries.set_ref(lib2->get_hash().bits(), 256, lib2));

  auto code = build_two_library_load_code(lib1, lib2);
  auto result = run_compute(code, /*max_transaction_library_loads=*/2u, global_libraries);
  CHECK(result.accepted);
  CHECK(result.success);
  CHECK(result.exit_code == 0);
}
