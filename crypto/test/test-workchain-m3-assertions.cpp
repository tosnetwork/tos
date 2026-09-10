// TEST SUPPORT. Synthetic post-states test the asserter, not host execution.
#include <iostream>

#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/vm.h"

#include "workchain-m3-assertions.h"
using namespace block;
namespace {
td::Bits256 number(unsigned n) {
  td::Bits256 x = td::Bits256::zero();
  x.as_slice()[31] = static_cast<char>(n);
  return x;
}
template <class R>
auto pack(const R& r) {
  return confidential_state_detail::pack(r).move_as_ok();
}
// Structural block fixture only; no live execution is claimed.
td::Ref<vm::Cell> structural_block(const td::Ref<vm::Cell>& candidate) {
  using namespace block;
  auto empty = vm::CellBuilder().finalize();
  auto absent = vm::CellBuilder().store_long(0, 1).as_cellslice_ref();
  auto fees = vm::CellBuilder().store_zeroes(5).as_cellslice_ref();
  auto domain = pack(gen::UnoV2HostDomain::Record{3, number(1), number(2), 2, 0x8000000000000000ULL});
  auto policy = pack(gen::UnoV2HostPolicy::Record{number(3), false, 0x554e4f32, 0, 1, 4});
  auto context = pack(gen::UnoV2HostContext::Record{number(4), 1, 1, 1, empty});
  auto identity = pack(gen::UnoV2HostIdentity::Record{domain, policy, context});
  auto access = pack(gen::UnoV2HostAccess::Record{absent, absent});
  auto input = pack(gen::UnoV2HostInput::Record{identity, access, candidate, absent});
  auto native = pack(gen::UnoV2NativeEffects::Record_uno_v2_native_effects{absent, absent});
  auto effects = pack(gen::UnoV2HostEffects::Record{absent, native, absent, absent, 0, 0, 0});
  auto binding = pack(gen::UnoV2HostRecord::Record{input->get_hash().bits(), effects->get_hash().bits(), number(1), 0});
  auto descr = pack(gen::TransactionDescr::Record_trans_workchain_entry_v3{binding, input, effects});
  auto update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  gen::Transaction::Record tx;
  tx.account_addr = number(1);
  tx.lt = 1;
  tx.prev_trans_hash = number(0);
  tx.prev_trans_lt = 0;
  tx.now = 1;
  tx.outmsg_cnt = 0;
  tx.orig_status = 0;
  tx.end_status = 0;
  tx.r1.in_msg = absent;
  tx.r1.out_msgs = absent;
  tx.total_fees = fees;
  tx.state_update = update;
  tx.description = descr;
  vm::AugmentedDictionary transactions(64, block::tlb::aug_AccountTransactions);
  CHECK(transactions.set_ref(td::BitArray<64>{1LL}, pack(tx)));
  auto account =
      pack(gen::AccountBlock::Record{number(1), vm::load_cell_slice_ref(transactions.get_root_cell()), update});
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccountBlocks);
  CHECK(accounts.set(number(1), vm::load_cell_slice(account)));
  auto extra =
      pack(gen::BlockExtra::Record{empty, empty, accounts.get_wrapped_dict_root(), number(0), number(0), absent});
  return pack(gen::Block::Record{3, empty, empty, empty, extra});
}

auto root(std::string path) {
  return vm::std_boc_deserialize(td::read_file_str(M3_VECTOR_DIR + path).move_as_ok()).move_as_ok();
}
auto encoded(const WorkchainConfidentialAccount& a) {
  return encode_workchain_confidential_account(a).move_as_ok();
}
m3_test::Point secret(unsigned n) {
  m3_test::Point s{};
  CHECK(n <= 255);
  s[0] = static_cast<unsigned char>(n);
  return s;
}

// Synthetic source-side artifacts test the assertion, not Native execution or
// recipient delivery. The live backend supplies these from its actual overlay.
m3_test::RefundObserved refund_artifacts(const m3_test::Root& before_data, const m3_test::Root& after_data,
                                         const WorkchainRegistrationFunding& historical,
                                         std::uint64_t emitted, std::uint64_t retained_operating = 4800) {
  vm::init_vm().ensure();
  const auto coordinator = number(77);
  auto native = [&](const m3_test::Root& data, std::uint64_t balance, std::uint64_t lt) {
    vm::CellBuilder storage;
    storage.store_long(lt, 64);
    CHECK(m3_test::refund_assertion_detail::amount(balance).store(storage));
    storage.store_long(1, 1).store_long(0, 1).store_long(0, 1);
    CHECK(storage.store_maybe_ref(vm::CellBuilder().finalize()));
    CHECK(storage.store_maybe_ref(data));
    storage.store_long(0, 1);
    vm::CellBuilder account;
    account.store_long(1, 1).store_long(4, 3).store_long(2, 8).store_bits(coordinator.bits(), 256);
    CHECK(store_UInt7(account, 0)); CHECK(store_UInt7(account, 0));
    account.store_long(0, 3).store_long(0, 32).store_long(0, 1)
        .append_cellslice(vm::load_cell_slice(storage.finalize()));
    return m3_test::Root{account.finalize()};
  };
  auto before = native(before_data, m3_test::checked_sum(historical.paid_deposit, 5000).move_as_ok(), 0);
  auto after = native(after_data, retained_operating, 101);
  vm::CellBuilder msg;
  msg.store_long(6, 4).store_long(4, 3).store_long(2, 8).store_bits(coordinator.bits(), 256)
      .store_long(4, 3).store_long(historical.refund_workchain, 8).store_bits(historical.refund_account.bits(), 256);
  CHECK(m3_test::refund_assertion_detail::amount(emitted).store(msg));
  CHECK(block::tlb::t_Tomis.store_integer_ref(msg, td::make_refint(0)));
  CHECK(block::tlb::t_Tomis.store_integer_ref(msg, td::make_refint(150)));
  msg.store_long(100, 64).store_long(1234, 32).store_long(0, 1).store_long(0, 1);
  m3_test::Root message = msg.finalize();
  vm::Dictionary outputs(15); CHECK(outputs.set_ref(td::BitArray<15>{0LL}, message));
  gen::Transaction::Record tx;
  tx.account_addr = coordinator; tx.lt = 100; tx.prev_trans_hash = number(0); tx.prev_trans_lt = 0;
  tx.now = 1234; tx.outmsg_cnt = 1; tx.orig_status = -2; tx.end_status = -2; // Signed two-bit encoding of active (10).
  tx.r1.in_msg = vm::CellBuilder().store_long(0, 1).as_cellslice_ref();
  tx.r1.out_msgs = outputs.get_root();
  vm::CellBuilder fees; CHECK(CurrencyCollection(50).store(fees)); tx.total_fees = fees.as_cellslice_ref();
  tx.state_update = vm::CellBuilder().store_long(0x72, 8).store_bits(before->get_hash().bits(), 256)
      .store_bits(after->get_hash().bits(), 256).finalize();
  tx.description = vm::CellBuilder().finalize(); // assertion does not claim valid execution.
  auto transaction = pack(tx);
  auto dictionary = [&](const m3_test::Root& account, const td::Bits256& hash, std::uint64_t lt) {
    vm::CellBuilder shard; shard.store_ref(account).store_bits(hash.bits(), 256).store_long(lt, 64);
    vm::AugmentedDictionary dict(256, block::tlb::aug_ShardAccounts); CHECK(dict.set_builder(coordinator, shard));
    return dict.get_wrapped_dict_root();
  };
  return {transaction, message, dictionary(before, number(0), 0),
      dictionary(after, transaction->get_hash().bits(), 100), coordinator, 2, 1234};
}
}  // namespace
TEST(M3Assertions, FormalTransfersAndPending) {
  for (auto name : {"collect1", "collect3"}) {
    std::string dir = std::string("/") + name;
    auto candidate = root(dir + "/candidate-1.boc"), before = root(dir + "/bob.boc");
    auto input = decode_workchain_transfer_input(candidate).move_as_ok();
    const auto& collect = std::get<WorkchainCollectData>(input.data);
    auto after = decode_workchain_confidential_account(before).move_as_ok();
    after.available = collect.available;
    after.pending.erase(std::remove_if(after.pending.begin(), after.pending.end(),
                                       [&](const auto& p) {
                                         return std::any_of(
                                             collect.selected.begin(), collect.selected.end(),
                                             [&](const auto& s) { return s.receipt_id == p.receipt_id; });
                                       }),
                        after.pending.end());
    auto result = m3_test::assert_transfer(candidate, before, encoded(after), secret(223), 1000000, 3107,
                                           std::string(name) == "collect1" ? 3227 : 3567);
    if (result.is_error())
      std::cerr << result.error().message().str() << std::endl;
    ASSERT_TRUE(result.is_ok());
    ASSERT_EQ(result.ok().retained_pending, 4 - collect.selected.size());
  }
  auto candidate = root("/send/candidate-1.boc"), before = root("/send/alice.boc"), db = root("/send/bob.boc");
  auto input = decode_workchain_transfer_input(candidate).move_as_ok();
  auto send = std::get<WorkchainSendData>(input.data);
  auto after = decode_workchain_confidential_account(before).move_as_ok();
  after.available = send.available;
  auto dest = decode_workchain_confidential_account(db).move_as_ok();
  auto id = derive_workchain_receipt_id(after.address.instance, input.claimed_operation_id, 0).move_as_ok();
  dest.pending.push_back({id,
                          after.address,
                          send.claims.auth_nonce,
                          dest.address.instance,
                          dest.key_epoch,
                          dest.bindings.asset,
                          {send.transfer.commitment, send.transfer.recipient_handle},
                          input.claimed_operation_id,
                          0,
                          0});
  auto result = m3_test::assert_transfer(candidate, before, encoded(after), secret(101), 1000000, 50000, 49852, db,
                                         encoded(dest), secret(223));
  if (result.is_error())
    std::cerr << result.error().message().str() << std::endl;
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(result.ok().transferred, 137u);
  // Same real decryption and same balance verdict, only the expected number is wrong.
  auto wrong = m3_test::assert_transfer(candidate, before, encoded(after), secret(101), 1000000, 50000, 49853, db,
                                        encoded(dest), secret(223));
  ASSERT_TRUE(wrong.is_error());
  ASSERT_EQ(wrong.error().message(), "decrypted balance mismatch");
}
TEST(M3Assertions, PlaintextAlarm) {
  auto account = root("/send/alice.boc");
  ASSERT_TRUE(m3_test::assert_private_account(account).is_ok());
  // Deliberately persist a plaintext amount beside the formal state.
  auto fake = vm::CellBuilder().append_cellslice(vm::load_cell_slice(account)).store_long(137, 64).finalize();
  auto status = m3_test::assert_private_account(fake);
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.message(), "plaintext/noncanonical account layout alarm");
  auto candidate = root("/send/candidate-1.boc");
  auto leaked = vm::CellBuilder().append_cellslice(vm::load_cell_slice(candidate)).store_long(137, 64).finalize();
  ASSERT_TRUE(m3_test::assert_private_input(leaked).is_error());
}
TEST(M3Assertions, RegistrationClosureAndClosedObservation) {
  auto account = decode_workchain_confidential_account(root("/send/alice.boc")).move_as_ok();
  WorkchainCoordinatorState old{2, {1, 1, 5, 0}, 0};
  auto next = old;
  next.system.registered_accounts = 6;
  next.refundable_deposits = account.funding.paid_deposit;
  auto c0 = encode_workchain_coordinator_state(old).move_as_ok(),
       c1 = encode_workchain_coordinator_state(next).move_as_ok();
  ASSERT_TRUE(m3_test::assert_registration(c0, c1, encoded(account)).is_ok());
  auto closed = account;
  closed.available = {td::Bits256::zero(), td::Bits256::zero()};
  closed.pending.clear();
  closed.lifecycle = WorkchainAccountClosed{};
  auto end = next;
  end.refundable_deposits = 0;
  auto end_data = encode_workchain_coordinator_state(end).move_as_ok();
  const auto paid = account.funding.paid_deposit;
  auto refund = refund_artifacts(c1, end_data, account.funding, paid);
  auto check = [&](const m3_test::Root& data, const m3_test::RefundObserved& observation) {
    return m3_test::assert_closure(c1, data, encoded(account), encoded(closed), secret(101), 1000000, observation);
  };
  ASSERT_TRUE(check(end_data, refund).is_ok());
  auto missing = refund; missing.message.clear();
  auto absent_message = check(end_data, missing);
  ASSERT_TRUE(absent_message.is_error()); ASSERT_EQ(absent_message.message(), "refund enqueue observation missing");
  auto no_debit = check(c1, refund_artifacts(c1, c1, account.funding, paid));
  ASSERT_TRUE(no_debit.is_error());
  ASSERT_TRUE(paid > 0);
  auto wrong_value = check(end_data, refund_artifacts(c1, end_data, account.funding, paid - 1));
  ASSERT_TRUE(wrong_value.is_error());
  ASSERT_EQ(wrong_value.message(), "refund outbound value differs from historical deposit");
  auto unpaid_fees = check(end_data, refund_artifacts(c1, end_data, account.funding, paid, 5000));
  ASSERT_TRUE(unpaid_fees.is_error()); ASSERT_EQ(unpaid_fees.message(), "refund fees were not paid by operating budget");
  auto unrelated = refund;
  unrelated.message = refund_artifacts(c1, end_data, account.funding, paid - 1).message;
  auto detached_message = check(end_data, unrelated);
  ASSERT_TRUE(detached_message.is_error());
  ASSERT_EQ(detached_message.message(), "refund message absent from transaction outputs");
  auto observed = m3_test::assert_closed({true, "test.activation.site", 0, 0}, "test.activation.site");
  ASSERT_TRUE(observed.is_ok());
  std::cout << observed.ok() << std::endl;
  ASSERT_TRUE(m3_test::assert_closed({false, "", std::nullopt, std::nullopt}, "test.activation.site").is_error());
}

TEST(M3Assertions, PermanentInputPath) {
  auto candidate = root("/send/candidate-1.boc");
  auto block = structural_block(candidate);
  // Roundtrip the block itself, then obtain the candidate through its transaction.
  auto persisted = vm::std_boc_deserialize(vm::std_boc_serialize(block, 0).move_as_ok()).move_as_ok();
  auto recovered = m3_test::input_from_block(persisted, number(1), 1);
  if (recovered.is_error())
    std::cerr << recovered.error().message().str() << std::endl;
  ASSERT_TRUE(recovered.is_ok());
  ASSERT_EQ(recovered.ok()->get_hash(), candidate->get_hash());
  auto leaked = vm::CellBuilder().append_cellslice(vm::load_cell_slice(candidate)).store_long(137, 64).finalize();
  auto bad = m3_test::input_from_block(structural_block(leaked), number(1), 1);
  ASSERT_TRUE(bad.is_error());
  ASSERT_EQ(bad.error().message(), "plaintext/noncanonical replay input layout alarm");
}
