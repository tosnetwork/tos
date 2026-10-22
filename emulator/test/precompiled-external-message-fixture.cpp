/*
    Copyright (C) 2025-2026 TOS Network.

    Compute-phase gas for messages to a contract whose code hash ConfigParam 45
    lists as precompiled, driven through a real block::transaction::Transaction.

    An external message has no gas limit until the contract accepts it, only a
    credit; what the account can pay for is gas_max. So the precompiled gas
    usage of an external message is compared with gas_max, and when the VM runs
    in place of a missing implementation, an unaccepted external runs on the
    credit alone, exactly as an ordinary compute phase does.

    No precompiled implementation is registered in this build, so every case
    takes the VM path whether or not dont_run_precompiled is set; both settings
    are checked.
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

constexpr td::uint64 kGasLimit = 1'000'000;
constexpr td::uint64 kGasCredit = 10'000;

void ensure_vm_ready() {
  static const bool once = [] {
    vm::init_vm(false).ensure();
    return true;
  }();
  (void)once;
}

// ACCEPT
td::Ref<vm::Cell> accept_code() {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0xf800, 16));
  return cb.finalize();
}

// Returns without accepting.
td::Ref<vm::Cell> no_accept_code() {
  return vm::CellBuilder().finalize();
}

// UNTIL:<{ GASCONSUMED; 2^pow2 PUSHPOW2; GREATER }>
// Burns just over 2^pow2 gas without accepting.
td::Ref<vm::Cell> burn_code(int pow2) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0x95, 8));      // PUSHCONT, 5 bytes
  CHECK(cb.store_long_bool(0xf807, 16));   // GASCONSUMED
  CHECK(cb.store_long_bool(0x83, 8));      // PUSHPOW2
  CHECK(cb.store_long_bool(pow2 - 1, 8));  //   2^pow2
  CHECK(cb.store_long_bool(0xbc, 8));      // GREATER
  CHECK(cb.store_long_bool(0xe6, 8));      // UNTIL
  return cb.finalize();
}

// The same, then ACCEPT.
td::Ref<vm::Cell> burn_then_accept_code(int pow2) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0x95, 8));      // PUSHCONT, 5 bytes
  CHECK(cb.store_long_bool(0xf807, 16));   // GASCONSUMED
  CHECK(cb.store_long_bool(0x83, 8));      // PUSHPOW2
  CHECK(cb.store_long_bool(pow2 - 1, 8));  //   2^pow2
  CHECK(cb.store_long_bool(0xbc, 8));      // GREATER
  CHECK(cb.store_long_bool(0xe6, 8));      // UNTIL
  CHECK(cb.store_long_bool(0xf800, 16));   // ACCEPT
  return cb.finalize();
}

void store_std_address(vm::CellBuilder& cb, const block::StdAddress& addr) {
  CHECK(cb.store_long_bool(2, 2));  // addr_std$10
  CHECK(cb.store_zeroes_bool(1));   // anycast: none
  CHECK(cb.store_long_bool(addr.workchain, 8));
  CHECK(cb.store_bits_bool(addr.addr.cbits(), 256));
}

td::Ref<vm::Cell> build_external_message(const block::StdAddress& dest) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(2, 2));  // ext_in_msg_info$10
  CHECK(cb.store_long_bool(0, 2));  // src: addr_none$00
  store_std_address(cb, dest);
  CHECK(block::tlb::t_Tomis.store_integer_value(cb, td::BigInt256(0)));  // import_fee
  CHECK(cb.store_zeroes_bool(1));                                        // init: nothing
  CHECK(cb.store_zeroes_bool(1));                                        // body: inline, empty
  return cb.finalize();
}

td::Ref<vm::Cell> build_internal_message(const block::StdAddress& src, const block::StdAddress& dest, td::int64 tomis) {
  vm::CellBuilder cb;
  CHECK(cb.store_zeroes_bool(1));  // int_msg_info$0
  CHECK(cb.store_ones_bool(1));    // ihr_disabled
  CHECK(cb.store_zeroes_bool(1));  // bounce
  CHECK(cb.store_zeroes_bool(1));  // bounced
  store_std_address(cb, src);
  store_std_address(cb, dest);
  CHECK(block::tlb::t_Tomis.store_integer_value(cb, td::BigInt256(tomis)));
  CHECK(cb.store_maybe_ref({}));
  CHECK(cb.store_zeroes_bool(8 + 64 + 32));  // extra_flags, fwd_fee, created_lt, created_at
  CHECK(cb.store_zeroes_bool(1));            // init: nothing
  CHECK(cb.store_zeroes_bool(1));            // body: inline, empty
  return cb.finalize();
}

struct Outcome {
  // False when the VM in place of a precompiled contract ran out of gas, which no block may contain.
  bool prepared;
  bool out_of_gas;
  bool skipped;
  int skip_reason;
  bool accepted;
  bool success;
  td::uint64 gas_used;
};

Outcome run_case(const td::Ref<vm::Cell>& code, td::optional<td::uint64> precompiled_gas, bool external,
                 bool dont_run_precompiled, td::int64 balance = 100'000'000'000LL, td::uint64 gas_limit = kGasLimit) {
  ensure_vm_ready();
  const tos::UnixTime now = 1750000000;
  const tos::LogicalTime lt = 1000;

  td::Bits256 addr_bits;
  addr_bits.set_zero();
  addr_bits.as_slice().ubegin()[0] = 0x45;
  block::Account acc(tos::basechainId, addr_bits.cbits());
  CHECK(acc.init_new(now));
  acc.status = acc.orig_status = block::Account::acc_active;
  acc.balance = block::CurrencyCollection(balance);
  acc.code = code;
  acc.data = vm::CellBuilder().finalize();

  td::Bits256 sender_bits;
  sender_bits.set_zero();
  sender_bits.as_slice().ubegin()[0] = 0x99;
  block::StdAddress src(tos::basechainId, sender_bits.cbits());
  block::StdAddress dest(tos::basechainId, addr_bits.cbits());
  auto in_msg = external ? build_external_message(dest) : build_internal_message(src, dest, 1'000'000'000LL);

  block::transaction::Transaction trans(acc, block::transaction::Transaction::tr_ord, lt, now, in_msg);
  block::ActionPhaseConfig action_cfg;
  action_cfg.global_version = 16;
  // Free import, so the external message is not refused before the compute phase.
  action_cfg.fwd_std = action_cfg.fwd_mc = block::MsgPrices(0, 0, 0, 0, 0, 0);
  CHECK(trans.unpack_input_msg(/*ihr_delivered=*/false, &action_cfg));

  std::vector<block::StoragePrices> storage_prices;
  block::StoragePhaseConfig storage_cfg(&storage_prices);
  storage_cfg.global_version = 16;
  CHECK(trans.prepare_storage_phase(storage_cfg, /*force_collect=*/true));

  block::ComputePhaseConfig cfg;
  cfg.gas_limit = gas_limit;
  cfg.special_gas_limit = gas_limit;
  cfg.gas_credit = kGasCredit;
  cfg.set_gas_price(1000);
  cfg.global_version = 16;
  cfg.max_vm_data_depth = 512;
  cfg.block_rand_seed.set_zero();
  cfg.libraries = std::make_unique<vm::Dictionary>(256);
  cfg.dont_run_precompiled_ = dont_run_precompiled;
  if (precompiled_gas) {
    vm::CellBuilder smc;
    CHECK(smc.store_long_bool(0xb0, 8) && smc.store_long_bool(precompiled_gas.value(), 64));  // precompiled_smc#b0
    CHECK(cfg.precompiled_contracts.list.set_builder(code->get_hash().bits(), 256, smc));
  }

  bool prepared = trans.prepare_compute_phase(cfg);
  CHECK(trans.compute_phase != nullptr);
  const auto& cp = *trans.compute_phase;
  return Outcome{prepared,
                 cp.out_of_gas,
                 cp.skip_reason != block::ComputePhase::sk_none,
                 cp.skip_reason,
                 cp.accepted,
                 cp.success,
                 static_cast<td::uint64>(cp.gas_used)};
}

}  // namespace

TEST(PrecompiledExternalMessage, AcceptedAndChargedThePrecompiledGas) {
  for (bool dont_run : {false, true}) {
    auto r = run_case(accept_code(), td::uint64{5000}, /*external=*/true, dont_run);
    CHECK(r.prepared);
    CHECK(!r.skipped);
    CHECK(r.accepted);
    CHECK(r.success);
    CHECK(r.gas_used == 5000);
  }
}

TEST(PrecompiledExternalMessage, UsageAboveGasMaxIsSkipped) {
  for (bool dont_run : {false, true}) {
    auto r = run_case(accept_code(), td::uint64{kGasLimit + 1}, /*external=*/true, dont_run);
    CHECK(r.skipped);
    CHECK(r.skip_reason == block::ComputePhase::sk_no_gas);
    CHECK(!r.accepted);
  }
  // gas_max is what the balance can buy: gas_price 1000 is 1000/65536 tomis per gas, so 50 tomis buy 3276 gas.
  auto r = run_case(accept_code(), td::uint64{5000}, /*external=*/true, false, /*balance=*/50);
  CHECK(r.skipped);
  CHECK(r.skip_reason == block::ComputePhase::sk_no_gas);
}

TEST(PrecompiledExternalMessage, NotAcceptedWithoutAccept) {
  auto r = run_case(no_accept_code(), td::uint64{5000}, /*external=*/true, false);
  CHECK(!r.skipped);
  CHECK(!r.accepted);
  CHECK(!r.success);
}

TEST(PrecompiledExternalMessage, CreditAboveUint32StillRequiresAccept) {
  for (td::uint64 limit : {(td::uint64{1} << 32) - 1, td::uint64{1} << 32, (td::uint64{1} << 32) + 1}) {
    for (bool dont_run : {false, true}) {
      auto unaccepted = run_case(no_accept_code(), td::uint64{5000}, true, dont_run, 100'000'000'000LL, limit);
      CHECK(unaccepted.prepared);
      CHECK(!unaccepted.skipped);
      CHECK(!unaccepted.accepted);
      CHECK(!unaccepted.success);
      auto accepted = run_case(accept_code(), td::uint64{5000}, true, dont_run, 100'000'000'000LL, limit);
      CHECK(accepted.prepared);
      CHECK(!accepted.skipped);
      CHECK(accepted.accepted);
      CHECK(accepted.success);
      CHECK(accepted.gas_used == 5000);
    }
  }
}

TEST(PrecompiledExternalMessage, UnacceptedExternalRunsOnCreditOnly) {
  // The credit for a precompiled contract is the full gas limit. Burning less than that before ACCEPT is fine.
  auto under = run_case(burn_then_accept_code(19), td::uint64{0}, /*external=*/true, false);
  CHECK(under.prepared);
  CHECK(!under.skipped);
  CHECK(under.accepted);
  CHECK(under.success);
  // Burning more than the credit runs out of gas before ACCEPT. Granting the gas limit on top of the credit would
  // let it reach ACCEPT.
  auto over = run_case(burn_then_accept_code(20), td::uint64{0}, /*external=*/true, false);
  CHECK(!over.prepared);
  CHECK(over.out_of_gas);
  CHECK(!over.accepted);
  // Without ACCEPT, the unaccepted run is still cut off at the credit rather than finishing on twice the limit.
  auto unaccepted = run_case(burn_code(20), td::uint64{0}, /*external=*/true, false);
  CHECK(!unaccepted.prepared);
  CHECK(unaccepted.out_of_gas);
  CHECK(!unaccepted.accepted);
}

TEST(PrecompiledExternalMessage, InternalMessagesAreUnchanged) {
  // The 1e9 tomis the message carries buy more than the gas limit, so gas_limit is the full limit.
  auto r = run_case(accept_code(), td::uint64{5000}, /*external=*/false, false);
  CHECK(r.prepared);
  CHECK(!r.skipped);
  CHECK(r.accepted);
  CHECK(r.success);
  CHECK(r.gas_used == 5000);
  auto over = run_case(accept_code(), td::uint64{kGasLimit + 1}, /*external=*/false, false);
  CHECK(over.skipped);
  CHECK(over.skip_reason == block::ComputePhase::sk_no_gas);
}
