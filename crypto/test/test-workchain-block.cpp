#include <limits>
#include "workchain-counter-engine.h"

#include "block/workchain-block-execution.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "emulator/transaction-emulator.h"

namespace {

td::Ref<vm::Cell> number(std::uint64_t value) {
  return vm::CellBuilder().store_long(value, 64).finalize();
}

using CounterEngine = block::test::CounterEngine;

td::Ref<vm::Cell> shard_fixture(int shard_wc = 2, int account_wc = 2, bool active = true,
                              unsigned account_count = 1, bool before_split = false, unsigned prefix_bits = 0,
                              std::uint64_t counter_value = 40, bool wrong_dictionary_key = false,
                              std::uint64_t operating_balance = 0) {
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  for (unsigned i = 0; i < account_count; ++i) {
    td::Bits256 address = td::Bits256::zero();
    if (i != 0) address = number(i)->get_hash().bits();
    vm::CellBuilder account;
    account.store_long(1, 1).store_long(4, 3).store_long(account_wc, 8).store_bits(address.bits(), 256)
        .store_zeroes(42).store_long(2, 64);
    ASSERT_TRUE(block::CurrencyCollection(td::make_refint(operating_balance)).store(account));
    if (active) {
      auto executor = block::encode_workchain_executor_state({number(counter_value), {}, {}}).move_as_ok();
      account.store_long(1, 1).store_zeroes(3).store_long(1, 1).store_ref(executor).store_long(0, 1);
    } else {
      account.store_long(0, 2);
    }
    auto root = account.finalize();
    ASSERT_TRUE(block::gen::t_Account.validate_ref(10000, root));
    vm::CellBuilder entry;
    entry.store_ref(root).store_zeroes(256).store_long(1, 64);
    auto dictionary_address = address;
    if (wrong_dictionary_key) dictionary_address = number(99)->get_hash().bits();
    ASSERT_TRUE(accounts.set_builder(dictionary_address, entry));
  }
  auto queue = vm::CellBuilder().store_zeroes(67).finalize();
  // Funded fixtures have one account; keep the public shard balance consistent.
  ASSERT_TRUE(operating_balance == 0 || account_count == 1);
  vm::CellBuilder aux_builder;
  aux_builder.store_zeroes(128);
  ASSERT_TRUE(block::CurrencyCollection(td::make_refint(operating_balance)).store(aux_builder));
  auto aux = aux_builder.store_zeroes(7).finalize();
  auto root = vm::CellBuilder().store_long(0x9023afe2, 32).store_long(1, 32)
      .store_long(0, 2).store_long(prefix_bits, 6).store_long(shard_wc, 32).store_long(0, 64)
      .store_long(1, 32).store_long(0, 32).store_long(1, 32).store_long(2, 64).store_long(0, 32)
      .store_ref(queue).store_long(before_split, 1).store_ref(accounts.get_wrapped_dict_root())
      .store_ref(aux).store_long(0, 1).finalize();
  ASSERT_TRUE(block::gen::t_ShardStateUnsplit.validate_ref(10000, root));
  return root;
}

block::WorkchainBlockInput input() {
  return {shard_fixture(), number(2), number(1), number(1)};
}

}  // namespace

TEST(WorkchainBlock, ExtractExecutorFromShardState) {
  auto root = shard_fixture();
  auto bytes = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
  auto data = block::extract_workchain_engine_state(restored, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(data).fetch_ulong(64), 40u);
  ASSERT_TRUE(root->get_hash() == restored->get_hash());
  auto reject = [&](td::Ref<vm::Cell> state, td::Slice expected) {
    auto result = block::extract_workchain_engine_state(state, 2, td::Bits256::zero());
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), expected);
  };
  reject(shard_fixture(3), "block engine requires its own unsplit shard state");
  reject(shard_fixture(2, 2, true, 1, true), "block engine requires its own unsplit shard state");
  reject(shard_fixture(2, 2, true, 1, false, 1), "block engine requires its own unsplit shard state");
  reject(shard_fixture(2, 2, true, 0), "block workchain must contain exactly its executor account");
  reject(shard_fixture(2, 2, true, 2), "block workchain must contain exactly its executor account");
  reject(shard_fixture(2, 2, true, 1, false, 0, 40, true),
         "block workchain must contain exactly its executor account");
  reject(shard_fixture(2, 3), "invalid block executor account");
  reject(shard_fixture(2, 2, false), "block executor requires active state data without address rewriting");
  reject({}, "missing or invalid block workchain state identity");
  reject(number(0), "invalid block workchain shard state");
  auto wrong_address = block::extract_workchain_engine_state(root, 2, number(99)->get_hash().bits());
  ASSERT_TRUE(wrong_address.is_error());
  ASSERT_EQ(wrong_address.error().message(), "block workchain must contain exactly its executor account");
}

TEST(WorkchainBlock, CounterReplay) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(produced.new_engine_state).fetch_ulong(64), 42u);
  auto validated = block::replay_workchain_block(engine, in, produced).move_as_ok();
  ASSERT_TRUE(validated.new_engine_state->get_hash() == produced.new_engine_state->get_hash());
  auto previous = block::extract_workchain_engine_state(in.previous_shard_state, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(previous).fetch_ulong(64), 40u);
}

TEST(WorkchainBlock, ExecutorWitnessEncoding) {
  CounterEngine engine;
  auto in = input();
  auto effects = engine.execute_block(in).move_as_ok();
  auto encoded_effects = block::encode_workchain_block_result(effects).move_as_ok();
  block::WorkchainExecutorState state{effects.new_engine_state, in.candidate, encoded_effects};
  auto root = block::encode_workchain_executor_state(state).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainExecutorState.validate_ref(10000, root));
  auto wire = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto decoded = block::decode_workchain_executor_state(restored).move_as_ok();
  ASSERT_TRUE(decoded.engine_state->get_hash() == state.engine_state->get_hash());
  ASSERT_TRUE(decoded.candidate->get_hash() == state.candidate->get_hash());
  ASSERT_TRUE(decoded.effects->get_hash() == state.effects->get_hash());
  auto missing = state;
  missing.candidate = {};
  ASSERT_TRUE(block::encode_workchain_executor_state(missing).is_error());
  auto bad = vm::CellBuilder().store_long(0x57424531, 32).store_long(1, 1).store_ref(number(99))
      .store_ref(vm::load_cell_slice(root).prefetch_ref(1)).finalize();
  ASSERT_TRUE(block::gen::t_WorkchainExecutorState.validate_ref(10000, bad));
  auto mismatch = block::decode_workchain_executor_state(bad);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "executor state differs from stored batch effects");
  auto missing_witness = vm::CellBuilder().store_long(0x57424531, 32).store_long(1, 1)
      .store_ref(state.engine_state).finalize();
  auto absent = block::decode_workchain_executor_state(missing_witness);
  ASSERT_TRUE(absent.is_error());
  ASSERT_EQ(absent.error().message(), "invalid workchain executor state references");
  auto initial = block::encode_workchain_executor_state({number(40), {}, {}}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainExecutorState.validate_ref(10000, initial));
  ASSERT_TRUE(block::decode_workchain_executor_state(initial).move_as_ok().candidate.is_null());
}

TEST(WorkchainBlock, BatchAccountCommitAndReload) {
  CounterEngine engine;
  auto in = input();
  auto effects = engine.execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto load = [&]() {
    block::Account account(2, td::Bits256::zero().bits());
    ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
    return account;
  };
  block::SerializeConfig cfg;
  auto account = load();
  auto old_account = account.total_state;
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(account.total_state->get_hash() == old_account->get_hash());
  block::gen::Transaction::Record record;
  ASSERT_TRUE(tlb::unpack_cell(tx.root, record));
  ASSERT_EQ(record.lt, 10u);
  ASSERT_EQ(record.now, 10u);
  ASSERT_EQ(record.outmsg_cnt, 0);
  ASSERT_TRUE(block::replay_workchain_batch(engine, in, record.description).is_ok());
  auto replayed_account = block::replay_workchain_batch_transaction(
      engine, in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(replayed_account->get_hash() == tx.new_total_state->get_hash());
  ASSERT_TRUE(account.total_state->get_hash() == old_account->get_hash());
  for (int mutation = 0; mutation < 8; ++mutation) {
    auto changed = record;
    if (mutation == 0) changed.prev_trans_hash = number(99)->get_hash().bits();
    if (mutation == 1) changed.prev_trans_lt = 5;
    if (mutation == 2) changed.now = 11;
    if (mutation == 3) changed.lt = 11;
    if (mutation == 4) changed.total_fees = vm::CellBuilder().store_long(1, 4).store_long(1, 8)
        .store_long(0, 1).as_cellslice_ref();
    if (mutation == 5) changed.orig_status = block::gen::AccountStatus::acc_state_frozen;
    if (mutation == 6) changed.state_update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
    if (mutation == 7) changed.account_addr = number(99)->get_hash().bits();
    td::Ref<vm::Cell> messages;
    ASSERT_TRUE(tlb::pack_cell(messages, changed.r1));
    auto altered = vm::CellBuilder().store_long(7, 4).store_bits(changed.account_addr.bits(), 256)
        .store_long(changed.lt, 64).store_bits(changed.prev_trans_hash.bits(), 256)
        .store_long(changed.prev_trans_lt, 64).store_long(changed.now, 32).store_long(changed.outmsg_cnt, 15)
        .store_long(changed.orig_status, 2).store_long(changed.end_status, 2).store_ref(messages)
        .append_cellslice(changed.total_fees).store_ref(changed.state_update).store_ref(changed.description).finalize();
    ASSERT_TRUE(block::gen::t_Transaction.validate_ref(4096, altered));
    auto rejected = block::replay_workchain_batch_transaction(
        engine, in, altered, 2, td::Bits256::zero(), 10, 10, cfg);
    ASSERT_TRUE(rejected.is_error());
    auto expected = mutation == 2 || mutation == 3 || mutation == 7
        ? td::Slice("batch transaction identity or time differs from host context")
        : td::Slice("batch transaction wrapper differs from replay");
    ASSERT_EQ(rejected.error().message(), expected);
  }
  auto committed = tx.commit(account);
  ASSERT_TRUE(committed.not_null());
  ASSERT_TRUE(account.balance.is_zero());
  ASSERT_TRUE(account.storage_used.cells > 0);
  ASSERT_EQ(account.last_trans_lt_, 10u);
  ASSERT_EQ(account.last_trans_end_lt_, 11u);
  auto stored = block::decode_workchain_executor_state(account.data).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(stored.engine_state).fetch_ulong(64), 42u);
  ASSERT_TRUE(stored.candidate->get_hash() == in.candidate->get_hash());
  ASSERT_TRUE(stored.effects->get_hash() == block::encode_workchain_block_result(effects).move_as_ok()->get_hash());
  vm::CellBuilder account_block;
  ASSERT_TRUE(account.create_account_block(account_block));
  auto block_root = account_block.finalize();
  ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(10000, block_root));
  ASSERT_TRUE(block::tlb::t_AccountBlock.validate_ref(10000, block_root));
  vm::CellBuilder entry;
  entry.store_ref(account.total_state).store_bits(account.last_trans_hash_.bits(), 256)
      .store_long(account.last_trans_lt_, 64);
  ASSERT_TRUE(accounts.set_builder(td::Bits256::zero(), entry));
  state.accounts = accounts.get_wrapped_dict_root();
  state.seq_no = 2;
  state.gen_lt = 11;
  state.gen_utime = 10;
  td::Ref<vm::Cell> next;
  ASSERT_TRUE(tlb::pack_cell(next, state));
  auto wire = vm::std_boc_serialize(next).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto new_data = block::extract_workchain_engine_state(restored, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(new_data).fetch_ulong(64), 42u);
  block::gen::ShardStateUnsplit::Record recovered_state;
  ASSERT_TRUE(tlb::unpack_cell(restored, recovered_state));
  vm::AugmentedDictionary recovered_accounts(vm::load_cell_slice_ref(recovered_state.accounts), 256,
                                              block::tlb::aug_ShardAccounts);
  block::Account recovered_account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(recovered_account.unpack(recovered_accounts.lookup(td::Bits256::zero()), 10, false));
  auto recovered_witness = block::decode_workchain_executor_state(recovered_account.data).move_as_ok();
  auto recovered_input = in;
  recovered_input.candidate = recovered_witness.candidate;
  auto replayed_from_storage = block::replay_workchain_batch_transaction(
      engine, recovered_input, committed, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(replayed_from_storage->get_hash() == recovered_account.total_state->get_hash());
  ASSERT_TRUE(recovered_witness.effects->get_hash() == stored.effects->get_hash());
  block::WorkchainBlockReplayContext context{in.previous_shard_state, in.configuration, in.finality_context};
  auto state_replay = block::replay_workchain_batch_state(
      engine, context, restored, committed, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(state_replay->get_hash() == recovered_account.total_state->get_hash());
  block::Config configuration(0);
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  auto resolved = registry.resolve_block(descriptor, configuration).move_as_ok();
  ASSERT_TRUE(block::replay_resolved_workchain_batch_state(
      resolved, context, restored, committed, 10, 10, cfg).is_ok());
  ASSERT_TRUE(block::replay_resolved_workchain_account_block(
      resolved, context, restored, block_root, 10, cfg).is_ok());
  for (int mutation = 0; mutation < 3; ++mutation) {
    block::gen::AccountBlock::Record altered;
    ASSERT_TRUE(tlb::unpack_cell(block_root, altered));
    if (mutation == 0) altered.account_addr = number(99)->get_hash().bits();
    if (mutation == 1) altered.state_update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
    if (mutation == 2) {
      vm::AugmentedDictionary transactions(vm::DictNonEmpty(), altered.transactions, 64,
                                             block::tlb::aug_AccountTransactions);
      ASSERT_TRUE(transactions.set_ref(td::BitArray<64>{11LL}, committed, vm::Dictionary::SetMode::Add));
      altered.transactions = vm::load_cell_slice_ref(transactions.get_root_cell());
    }
    td::Ref<vm::Cell> altered_root;
    ASSERT_TRUE(tlb::pack_cell(altered_root, altered));
    ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(4096, altered_root));
    auto rejected = block::replay_resolved_workchain_account_block(
        resolved, context, restored, altered_root, 10, cfg);
    ASSERT_TRUE(rejected.is_error());
    const td::Slice expected[] = {"AccountBlock differs from configured executor identity",
                                  "AccountBlock state update differs from its batch transaction",
                                  "block executor requires exactly one batch transaction"};
    ASSERT_EQ(rejected.error().message(), expected[mutation]);
  }
  resolved.policy.limits.wire_bytes = 7;
  auto limited = block::replay_resolved_workchain_batch_state(
      resolved, context, restored, committed, 10, 10, cfg);
  ASSERT_TRUE(limited.is_error());
  ASSERT_EQ(limited.error().message(), "block execution exceeds configured resource limits");
  block::gen::ShardStateUnsplit::Record original_state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, original_state));
  vm::AugmentedDictionary original_accounts(vm::load_cell_slice_ref(original_state.accounts), 256,
                                             block::tlb::aug_ShardAccounts);
  for (int mutation = 0; mutation < 3; ++mutation) {
    block::Account altered_account(2, td::Bits256::zero().bits());
    ASSERT_TRUE(altered_account.unpack(original_accounts.lookup(td::Bits256::zero()), 10, false));
    auto altered_effects = effects;
    auto altered_input = in;
    if (mutation == 1) altered_effects.receipts = number(99);
    if (mutation == 2) altered_input.candidate = number(3);
    block::transaction::Transaction altered_tx(
        altered_account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
    auto prepared = altered_tx.prepare_workchain_batch(altered_input, altered_effects, cfg);
    ASSERT_TRUE(prepared.is_ok());
    ASSERT_TRUE(altered_tx.serialize(cfg));
    vm::CellBuilder altered_entry;
    altered_entry.store_ref(altered_tx.new_total_state)
        .store_bits((mutation == 0 ? number(99)->get_hash() : committed->get_hash()).bits(), 256)
        .store_long(10, 64);
    vm::AugmentedDictionary altered_accounts(256, block::tlb::aug_ShardAccounts);
    ASSERT_TRUE(altered_accounts.set_builder(td::Bits256::zero(), altered_entry));
    auto altered_state = recovered_state;
    altered_state.accounts = altered_accounts.get_wrapped_dict_root();
    td::Ref<vm::Cell> altered_root;
    ASSERT_TRUE(tlb::pack_cell(altered_root, altered_state));
    auto rejected = block::replay_workchain_batch_state(
        engine, context, altered_root, committed, 2, td::Bits256::zero(), 10, 10, cfg);
    ASSERT_TRUE(rejected.is_error());
    const td::Slice expected[] = {"claimed executor transaction link differs from batch",
                                  "claimed executor account differs from batch replay",
                                  "batch transaction input commitment differs from authenticated context"};
    ASSERT_EQ(rejected.error().message(), expected[mutation]);
  }
}

TEST(WorkchainBlock, ResolvedBatchStaging) {
  auto in = input();
  block::Config configuration(0);
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  auto resolved = registry.resolve_block(descriptor, configuration).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  auto original = account.total_state;
  block::SerializeConfig cfg;
  auto staged = block::prepare_resolved_workchain_batch_transaction(resolved, in, account, 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(staged->root.not_null());
  ASSERT_TRUE(account.total_state->get_hash() == original->get_hash());
  ASSERT_TRUE(account.transactions.empty());
  auto replayed = block::replay_workchain_batch_transaction(
      *resolved.executor, in, staged->root, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(replayed->get_hash() == staged->new_total_state->get_hash());
  auto early = block::prepare_resolved_workchain_batch_transaction(resolved, in, account, 1, 10, cfg);
  ASSERT_TRUE(early.is_error());
  ASSERT_EQ(early.error().message(), "batch staging logical time differs from requested time");
  block::Account other(2, number(99)->get_hash().bits());
  auto wrong = block::prepare_resolved_workchain_batch_transaction(resolved, in, other, 10, 10, cfg);
  ASSERT_TRUE(wrong.is_error());
  ASSERT_EQ(wrong.error().message(), "batch staging account differs from configured executor");
  resolved.policy.limits.wire_bytes = 7;
  auto limited = block::prepare_resolved_workchain_batch_transaction(resolved, in, account, 10, 10, cfg);
  ASSERT_TRUE(limited.is_error());
  ASSERT_EQ(limited.error().message(), "block execution exceeds configured resource limits");
  ASSERT_TRUE(account.total_state->get_hash() == original->get_hash());
  ASSERT_TRUE(account.transactions.empty());
}

TEST(WorkchainBlock, BatchPreparationRejectsUnsettledState) {
  CounterEngine engine;
  auto in = input();
  auto effects = engine.execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  block::SerializeConfig cfg;
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  auto altered = effects;
  altered.outbound_messages = number(0);
  auto unsettled = tx.prepare_workchain_batch(in, altered, cfg);
  ASSERT_TRUE(unsettled.is_error());
  ASSERT_EQ(unsettled.error().message(), "batch native message settlement is not implemented");
  tx.balance = block::CurrencyCollection(1);
  auto value = tx.prepare_workchain_batch(in, effects, cfg);
  ASSERT_TRUE(value.is_error());
  ASSERT_EQ(value.error().message(), "batch state preparation cannot mix account phases or native value flow");
  tx.balance = account.balance;
  auto previous_hash = account.last_trans_hash_;
  account.last_trans_hash_ = number(99)->get_hash().bits();
  auto wrapper = tx.prepare_workchain_batch(in, effects, cfg);
  ASSERT_TRUE(wrapper.is_error());
  ASSERT_EQ(wrapper.error().message(), "batch account wrapper differs from committed input state");
  account.last_trans_hash_ = previous_hash;
  auto limited_cfg = cfg;
  limited_cfg.size_limits.max_acc_state_cells = 0;
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, limited_cfg).is_error());
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(tx.new_data->get_hash() == account.data->get_hash());
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  tx.new_data = number(99);
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(account.total_state->get_hash() == account.orig_total_state->get_hash());
}

TEST(WorkchainBlock, BatchNativeMessageSettlement) {
  CounterEngine engine;
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000);
  auto effects = engine.execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  auto previous = account.total_state->get_hash();
  block::SerializeConfig cfg;
  block::WorkchainSet workchains;
  block::ActionPhaseConfig messages_cfg;
  messages_cfg.workchains = &workchains;
  messages_cfg.fwd_mc.lump_price = 100;
  messages_cfg.fwd_mc.first_frac = 32768;
  auto message = [&](int wc) {
    vm::CellBuilder cb;
    cb.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(wc, 8).store_zeroes(256);
    ASSERT_TRUE(block::CurrencyCollection(100).store(cb));
    cb.store_zeroes(8).store_zeroes(96).store_zeroes(2);
    auto result = cb.finalize();
    ASSERT_TRUE(block::gen::t_MessageRelaxed_Any.validate_ref(4096, result));
    return result;
  };
  auto requests = [&](unsigned count, bool invalid_last = false, unsigned first = 0) {
    vm::Dictionary dict(15);
    for (unsigned i = 0; i < count; ++i) {
      ASSERT_TRUE(dict.set_ref(td::BitArray<15>(i + first), message(invalid_last && i + 1 == count ? 9 : -1)));
    }
    vm::CellBuilder cb;
    ASSERT_TRUE(std::move(dict).append_dict_to_bool(cb));
    return cb.finalize();
  };
  using Transaction = block::transaction::Transaction;
  effects.outbound_messages = requests(2);
  Transaction tx(account, Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg, &messages_cfg).is_ok());
  ASSERT_TRUE(!tx.compute_phase && !tx.action_phase);
  ASSERT_EQ(tx.balance.tomis->to_long(), 600);
  ASSERT_EQ(tx.total_fees.tomis->to_long(), 100);
  ASSERT_EQ(tx.end_lt, 13u);
  ASSERT_EQ(tx.out_msgs.size(), 2u);
  for (unsigned i = 0; i < 2; ++i) {
    block::gen::Message::Record msg;
    block::gen::CommonMsgInfo::Record_int_msg_info info;
    ASSERT_TRUE(tlb::type_unpack_cell(tx.out_msgs[i], block::gen::t_Message_Any, msg));
    ASSERT_TRUE(tlb::csr_unpack(msg.info, info));
    block::CurrencyCollection value;
    ASSERT_TRUE(value.unpack(info.value));
    ASSERT_EQ(value.tomis->to_long(), 100);
    ASSERT_EQ(block::tlb::t_Tomis.as_integer(info.fwd_fee)->to_long(), 50);
    ASSERT_EQ(info.created_lt, 11u + i);
    ASSERT_EQ(info.created_at, 10u);
    ASSERT_TRUE(info.src->contents_equal(*account.my_addr));
  }
  ASSERT_EQ(account.balance.tomis->to_long(), 1000);
  ASSERT_TRUE(account.total_state->get_hash() == previous);
  // Serialization must not accept public-field changes after fee settlement.
  tx.balance = block::CurrencyCollection(601);
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.balance = block::CurrencyCollection(600);
  tx.total_fees = block::CurrencyCollection(101);
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.total_fees = block::CurrencyCollection(100);
  tx.end_lt = 14;
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.end_lt = 13;
  auto first_message = tx.out_msgs[0];
  tx.out_msgs[0] = message(-1);
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.out_msgs[0] = first_message;
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(10000, tx.root));
  class MessageEngine final : public block::WorkchainBlockEngine {
   public:
    td::Ref<vm::Cell> requests;
    td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput& input) const override {
      TRY_RESULT(result, CounterEngine().execute_block(input));
      result.outbound_messages = requests;
      return result;
    }
  } replay_engine;
  replay_engine.requests = effects.outbound_messages;
  auto replayed = block::replay_workchain_batch_transaction(
      replay_engine, in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg, &messages_cfg);
  ASSERT_TRUE(replayed.is_ok());
  ASSERT_TRUE(replayed.ok()->get_hash() == tx.new_total_state->get_hash());
  auto different_prices = messages_cfg;
  different_prices.fwd_mc.lump_price = 102;
  auto wrong_fees = block::replay_workchain_batch_transaction(
      replay_engine, in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg, &different_prices);
  ASSERT_TRUE(wrong_fees.is_error());
  ASSERT_EQ(wrong_fees.error().message(), "batch transaction wrapper differs from replay");
  auto reject = [&](td::Ref<vm::Cell> outbound, const block::ActionPhaseConfig& pricing, td::Slice expected) {
    Transaction rejected(account, Transaction::tr_workchain_batch, 10, 10);
    auto altered = effects;
    altered.outbound_messages = std::move(outbound);
    auto status = rejected.prepare_workchain_batch(in, altered, cfg, &pricing);
    ASSERT_TRUE(status.is_error());
    ASSERT_EQ(status.message(), expected);
    ASSERT_TRUE(rejected.out_msgs.empty());
    ASSERT_EQ(rejected.balance.tomis->to_long(), 1000);
    ASSERT_TRUE(rejected.total_fees.is_zero());
    ASSERT_EQ(rejected.end_lt, 11u);
    ASSERT_TRUE(rejected.new_data->get_hash() == account.data->get_hash());
    ASSERT_TRUE(!rejected.serialize(cfg));
  };
  reject(requests(2, true), messages_cfg, "batch native message send failed");
  reject(requests(6), messages_cfg, "batch native message send failed");
  reject(requests(1, false, 1), messages_cfg, "invalid batch outbound requests");
  reject(number(0), messages_cfg, "invalid batch outbound dictionary");
  auto limited = messages_cfg;
  limited.max_actions = 1;
  reject(requests(2), limited, "invalid batch outbound requests");
  limited = messages_cfg;
  limited.workchains = nullptr;
  reject(requests(1), limited, "missing batch native message configuration");
  Transaction overflow(account, Transaction::tr_workchain_batch,
                       std::numeric_limits<std::uint64_t>::max() - 1, 10);
  auto no_lt = overflow.prepare_workchain_batch(in, effects, cfg, &messages_cfg);
  ASSERT_TRUE(no_lt.is_error());
  ASSERT_EQ(no_lt.message(), "invalid batch outbound requests");
  ASSERT_TRUE(overflow.out_msgs.empty());
}

TEST(WorkchainBlock, BatchCommitmentReplay) {
  CounterEngine engine;
  auto in = input();
  in.configuration = number(17);
  in.finality_context = number(19);
  auto produced = engine.execute_block(in).move_as_ok();
  auto context = block::encode_workchain_block_input(in).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBlockInput.validate_ref(10000, context));
  block::gen::WorkchainBlockInput::Record generated;
  ASSERT_TRUE(tlb::unpack_cell(context, generated));
  ASSERT_TRUE(generated.previous_shard_state->get_hash() == in.previous_shard_state->get_hash());
  ASSERT_TRUE(generated.candidate->get_hash() == in.candidate->get_hash());
  ASSERT_TRUE(generated.configuration->get_hash() == in.configuration->get_hash());
  ASSERT_TRUE(generated.finality_context->get_hash() == in.finality_context->get_hash());
  auto commitments = block::make_workchain_batch_description(in, produced).move_as_ok();
  auto description = block::encode_workchain_batch_description(commitments);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, description));
  auto wire = vm::std_boc_serialize(description).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto replayed = block::replay_workchain_batch(engine, in, restored).move_as_ok();
  ASSERT_TRUE(replayed.new_engine_state->get_hash() == produced.new_engine_state->get_hash());
  td::Ref<vm::Cell> block::WorkchainBlockInput::* fields[] = {
      &block::WorkchainBlockInput::previous_shard_state, &block::WorkchainBlockInput::candidate,
      &block::WorkchainBlockInput::configuration, &block::WorkchainBlockInput::finality_context};
  for (auto field : fields) {
    auto changed = in;
    changed.*field = number(99);
    auto result = block::replay_workchain_batch(engine, changed, description);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "batch transaction input commitment differs from authenticated context");
    changed.*field = {};
    auto missing = block::replay_workchain_batch(engine, changed, description);
    ASSERT_TRUE(missing.is_error());
    ASSERT_EQ(missing.error().message(), "batch commitment requires state, candidate, configuration and finality");
  }
}

TEST(WorkchainBlock, BatchCommitmentRejectsEffectMutations) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  td::Ref<vm::Cell> block::WorkchainBlockResult::* fields[] = {
      &block::WorkchainBlockResult::new_engine_state, &block::WorkchainBlockResult::outbound_messages,
      &block::WorkchainBlockResult::actions, &block::WorkchainBlockResult::receipts,
      &block::WorkchainBlockResult::events, &block::WorkchainBlockResult::data_availability};
  for (auto field : fields) {
    auto changed = produced;
    changed.*field = number(99);
    auto claimed = block::make_workchain_batch_description(in, changed).move_as_ok();
    auto result = block::replay_workchain_batch(engine, in, block::encode_workchain_batch_description(claimed));
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "batch transaction commitments differ from replay");
    changed.*field = {};
    ASSERT_TRUE(block::make_workchain_batch_description(in, changed).is_error());
  }
  for (int i = 0; i < 3; ++i) {
    auto claimed = block::make_workchain_batch_description(in, produced).move_as_ok();
    if (i == 0) claimed.usage.wire_bytes = 99;
    if (i == 1) claimed.usage.verification_units = 99;
    if (i == 2) claimed.usage.written_cells = 99;
    auto result = block::replay_workchain_batch(engine, in, block::encode_workchain_batch_description(claimed));
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "batch transaction commitments differ from replay");
  }
}

TEST(WorkchainBlock, BatchDescriptionParsersAndScope) {
  block::WorkchainBatchDescription description;
  description.input_hash = number(11)->get_hash().bits();
  description.effects_hash = number(12)->get_hash().bits();
  description.usage = {13, 14, std::numeric_limits<std::uint64_t>::max()};
  auto root = block::encode_workchain_batch_description(description);
  ASSERT_EQ(vm::load_cell_slice(root).size(), 708u);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, root));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, root));
  block::gen::TransactionDescr::Record_trans_workchain_batch_v1 generated;
  ASSERT_TRUE(tlb::unpack_cell(root, generated));
  ASSERT_TRUE(generated.input_hash == description.input_hash);
  ASSERT_TRUE(generated.effects_hash == description.effects_hash);
  ASSERT_EQ(generated.wire_bytes, description.usage.wire_bytes);
  ASSERT_EQ(generated.verification_units, description.usage.verification_units);
  ASSERT_EQ(generated.written_cells, description.usage.written_cells);
  auto decoded = block::decode_workchain_batch_description(root).move_as_ok();
  ASSERT_TRUE(decoded.input_hash == description.input_hash);
  ASSERT_TRUE(decoded.effects_hash == description.effects_hash);
  ASSERT_TRUE(decoded.usage == description.usage);
  auto cs = vm::load_cell_slice(root);
  ASSERT_EQ(block::tlb::t_TransactionDescr.get_tag(cs), block::tlb::TransactionDescr::trans_workchain_batch_v1);
  ASSERT_TRUE(block::tlb::t_TransactionDescr.skip(cs));
  ASSERT_TRUE(cs.empty_ext());
  td::RefInt256 storage_fees;
  ASSERT_TRUE(block::tlb::t_TransactionDescr.get_storage_fees(root, storage_fees));
  ASSERT_EQ(td::sgn(storage_fees), 0);
  ASSERT_TRUE(block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::BlockTransition).is_ok());
  auto wrong_scope = block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::AccountCompute);
  ASSERT_TRUE(wrong_scope.is_error());
  ASSERT_EQ(wrong_scope.error().message(), "transaction description does not match execution scope");
  // Storage-only transaction: zero collected fees, no due fees, unchanged status.
  auto account = vm::CellBuilder().store_long(1, 4).store_long(0, 6).finalize();
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, account));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, account));
  ASSERT_TRUE(block::validate_transaction_execution_scope(account, block::WorkchainExecutionScope::AccountCompute).is_ok());
  ASSERT_TRUE(block::validate_transaction_execution_scope(account, block::WorkchainExecutionScope::BlockTransition).is_error());
  for (unsigned tag = 9; tag < 16; ++tag) {
    auto future = vm::CellBuilder().store_long(tag, 4).finalize();
    ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, future));
    ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, future));
    auto scope = block::validate_transaction_execution_scope(future, block::WorkchainExecutionScope::AccountCompute);
    ASSERT_TRUE(scope.is_error());
    ASSERT_EQ(scope.error().message(), "unknown transaction description for execution scope");
  }
}

TEST(WorkchainBlock, RejectMalformedBatchDescription) {
  for (int mutation = 0; mutation < 3; ++mutation) {
    vm::CellBuilder cb;
    cb.store_long(8, 4).store_zeroes(mutation == 0 ? 703 : mutation == 1 ? 705 : 704);
    if (mutation == 2) cb.store_ref(number(0));
    auto root = cb.finalize();
    ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, root));
    ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, root));
    auto decoded = block::decode_workchain_batch_description(root);
    ASSERT_TRUE(decoded.is_error());
    ASSERT_EQ(decoded.error().message(), "invalid batch transaction description");
  }
}

TEST(WorkchainBlock, AccountEmulatorRejectsBatchTransaction) {
  block::WorkchainBatchDescription description;
  description.input_hash.set_zero();
  description.effects_hash.set_zero();
  auto messages = vm::CellBuilder().store_long(0, 2).finalize();
  auto update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  auto transaction = vm::CellBuilder().store_long(7, 4).store_zeroes(256).store_long(1, 64)
      .store_zeroes(256).store_long(0, 64).store_long(1, 32).store_long(0, 15)
      .store_long(0, 4).store_ref(messages).store_long(0, 5).store_ref(update)
      .store_ref(block::encode_workchain_batch_description(description)).finalize();
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(10000, transaction));
  ASSERT_TRUE(block::tlb::t_Transaction.validate_ref(10000, transaction));
  emulator::TransactionEmulator emulator(std::make_shared<block::Config>(0));
  block::Account account(2, td::Bits256::zero().bits());
  account.now_ = 17;
  auto result = emulator.emulate_transaction(std::move(account), transaction);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().message(), "transaction description does not match execution scope");
  ASSERT_EQ(account.now_, 17u);
}

TEST(WorkchainBlock, ResultWireRoundTrip) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  auto root = block::encode_workchain_block_result(produced).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBlockResult.validate_ref(10000, root));
  auto bytes = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
  auto validated = block::replay_workchain_block(engine, in, restored).move_as_ok();
  auto encoded = block::encode_workchain_block_result(validated).move_as_ok();
  ASSERT_TRUE(encoded->get_hash() == root->get_hash());
  td::Ref<vm::Cell> block::WorkchainBlockResult::* fields[] = {
      &block::WorkchainBlockResult::new_engine_state,
      &block::WorkchainBlockResult::outbound_messages, &block::WorkchainBlockResult::actions,
      &block::WorkchainBlockResult::receipts, &block::WorkchainBlockResult::events,
      &block::WorkchainBlockResult::data_availability};
  std::uint64_t value = 100;
  for (auto field : fields) produced.*field = number(value++);
  auto distinct = block::encode_workchain_block_result(produced).move_as_ok();
  auto decoded = block::decode_workchain_block_result(distinct).move_as_ok();
  for (auto field : fields) {
    ASSERT_TRUE((decoded.*field)->get_hash() == (produced.*field)->get_hash());
  }
  produced = engine.execute_block(in).move_as_ok();
  produced.usage = {std::numeric_limits<std::uint64_t>::max(), 0,
                    std::numeric_limits<std::uint64_t>::max()};
  auto extreme = block::encode_workchain_block_result(produced).move_as_ok();
  ASSERT_TRUE(block::decode_workchain_block_result(extreme).move_as_ok().usage == produced.usage);
  auto mismatch = block::replay_workchain_block(engine, in, extreme);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "block execution replay differs from claimed result");
  produced.receipts = {};
  ASSERT_TRUE(block::encode_workchain_block_result(produced).is_error());
}

TEST(WorkchainBlock, RejectNonCanonicalResultWire) {
  CounterEngine engine;
  auto produced = engine.execute_block(input()).move_as_ok();
  auto valid = block::encode_workchain_block_result(produced).move_as_ok();
  auto cs = vm::load_cell_slice(valid);
  auto outputs = cs.prefetch_ref(1);
  auto envelope = [&](std::uint32_t tag, td::Ref<vm::Cell> out, unsigned extra_bits, unsigned refs) {
    vm::CellBuilder cb;
    cb.store_long(tag, 32).store_long(8, 64).store_long(1, 64).store_long(3, 64);
    if (extra_bits) cb.store_long(0, extra_bits);
    td::Ref<vm::Cell> children[] = {produced.new_engine_state, out,
                                  produced.data_availability, number(99)};
    for (unsigned i = 0; i < refs; ++i) cb.store_ref(children[i]);
    return cb.finalize();
  };
  auto reject = [&](td::Ref<vm::Cell> root, td::Slice expected) {
    auto decoded = block::decode_workchain_block_result(root);
    ASSERT_TRUE(decoded.is_error());
    ASSERT_EQ(decoded.error().message(), expected);
    ASSERT_TRUE(!block::gen::t_WorkchainBlockResult.validate_ref(10000, root));
  };
  auto absent = block::decode_workchain_block_result({});
  ASSERT_TRUE(absent.is_error());
  ASSERT_EQ(absent.error().message(), "missing block result envelope");
  auto proof = vm::MerkleProof::generate(valid, [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  reject(proof, "invalid block result envelope");
  auto output_proof = vm::MerkleProof::generate(outputs, [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  reject(envelope(0x57425232, output_proof, 0, 3), "invalid block output envelope");
  reject(envelope(0x57425231, outputs, 0, 3), "invalid block result envelope");
  reject(envelope(0x57425232, outputs, 1, 3), "invalid block result envelope");
  reject(envelope(0x57425232, outputs, 0, 2), "invalid block result envelope");
  reject(envelope(0x57425232, outputs, 0, 4), "invalid block result envelope");
  for (int mutation = 0; mutation < 3; ++mutation) {
    vm::CellBuilder cb;
    cb.store_long(mutation == 0 ? 0x57424f30 : 0x57424f31, 32);
    if (mutation == 1) cb.store_long(0, 1);
    cb.store_ref(produced.outbound_messages).store_ref(produced.actions).store_ref(produced.receipts);
    if (mutation != 2) cb.store_ref(produced.events);
    reject(envelope(0x57425232, cb.finalize(), 0, 3), "invalid block output envelope");
  }
}

TEST(WorkchainBlock, RejectEveryResultMutation) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  td::Ref<vm::Cell> block::WorkchainBlockResult::* fields[] = {
      &block::WorkchainBlockResult::new_engine_state,
      &block::WorkchainBlockResult::outbound_messages, &block::WorkchainBlockResult::actions,
      &block::WorkchainBlockResult::receipts, &block::WorkchainBlockResult::events,
      &block::WorkchainBlockResult::data_availability};
  for (auto field : fields) {
    auto altered = produced;
    altered.*field = number(99);
    auto result = block::replay_workchain_block(engine, in, altered);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "block execution replay differs from claimed result");
    altered.*field = {};
    ASSERT_TRUE(block::replay_workchain_block(engine, in, altered).is_error());
  }
  for (int i = 0; i < 3; ++i) {
    auto altered = produced;
    if (i == 0) altered.usage.wire_bytes = 99;
    if (i == 1) altered.usage.verification_units = 99;
    if (i == 2) altered.usage.written_cells = 99;
    ASSERT_TRUE(block::replay_workchain_block(engine, in, altered).is_error());
  }
}

TEST(WorkchainBlock, RejectOverflowAndMissingContext) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, std::numeric_limits<std::uint64_t>::max());
  auto overflow = block::replay_workchain_block(engine, in, produced);
  ASSERT_TRUE(overflow.is_error());
  ASSERT_EQ(overflow.error().message(), "counter overflow");
  in = input();
  in.finality_context = {};
  auto missing = block::replay_workchain_block(engine, in, produced);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "block replay requires state, candidate, configuration and finality");
}

TEST(WorkchainBlock, CollationCandidateScope) {
  using Scope = block::WorkchainExecutionScope;
  ASSERT_TRUE(block::validate_workchain_candidate_scope({}, Scope::AccountCompute).is_ok());
  ASSERT_TRUE(block::validate_workchain_candidate_scope(number(2), Scope::BlockTransition).is_ok());
  auto missing = block::validate_workchain_candidate_scope({}, Scope::BlockTransition);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "workchain candidate does not match configured execution scope");
  auto unexpected = block::validate_workchain_candidate_scope(number(2), Scope::AccountCompute);
  ASSERT_TRUE(unexpected.is_error());
  ASSERT_EQ(unexpected.error().message(), missing.error().message());
  ASSERT_TRUE(block::validate_workchain_candidate_scope({}, static_cast<Scope>(255)).is_error());
}

TEST(WorkchainBlock, RegistryScopeIsolation) {
  block::WorkchainExecutionRegistry registry;
  CounterEngine counter;
  const auto key = counter.engine_key();
  ASSERT_TRUE(!registry.execution_scope(key).has_value());
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  ASSERT_TRUE(registry.has_engine(key));
  ASSERT_TRUE(registry.execution_scope(key) == block::WorkchainExecutionScope::BlockTransition);
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_error());
  ASSERT_TRUE(registry.register_block_engine(nullptr).is_error());
  block::Config configuration(0);
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = static_cast<std::int32_t>(key.selector);
  auto resolved = registry.resolve_block(descriptor, configuration).move_as_ok();
  auto scoped = registry.resolve_scoped(descriptor, configuration).move_as_ok();
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainBlockExecution>(scoped));
  ASSERT_TRUE(std::get<block::ResolvedWorkchainBlockExecution>(scoped).executor == resolved.executor);
  auto in = input();
  auto produced = block::execute_resolved_workchain_block(resolved, in).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(produced.new_engine_state).fetch_ulong(64), 42u);
  auto account = registry.resolve(descriptor, configuration);
  ASSERT_TRUE(account.is_error());
  ASSERT_EQ(account.error().message(), "block engine cannot execute through account compute");
  descriptor.max_split = 1;
  auto split = registry.resolve_block(descriptor, configuration);
  ASSERT_TRUE(split.is_error());
  ASSERT_EQ(split.error().message(), "counter requires an unsplit workchain");
  descriptor.max_split = 0;
  descriptor.vm_mode = 1;
  auto null_config = registry.resolve_block(descriptor, configuration);
  ASSERT_TRUE(null_config.is_error());
  ASSERT_EQ(null_config.error().message(), "block engine returned null configuration");
  descriptor.active = false;
  auto inactive = registry.resolve_block(descriptor, configuration);
  ASSERT_TRUE(inactive.is_error());
  ASSERT_EQ(inactive.error().message(), "block workchain is inactive");
  descriptor.active = true;
  descriptor.vm_version = -1;
  auto missing = registry.resolve_block(descriptor, configuration);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "descriptor has no registered block engine");
  auto& native_registry = block::default_workchain_execution_registry();
  descriptor.vm_mode = 0;
  ASSERT_TRUE(native_registry.execution_scope(block::tvm_workchain_engine_key()) ==
              block::WorkchainExecutionScope::AccountCompute);
  ASSERT_TRUE(native_registry.resolve(descriptor, configuration).is_ok());
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainExecution>(
      native_registry.resolve_scoped(descriptor, configuration).move_as_ok()));
}

TEST(WorkchainBlock, ResolvedBlockResourcePolicy) {
  block::Config configuration(0);
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  const block::WorkchainBlockResourceUsage limits[] = {
      {8, 2, 3}, {9, 3, 4}, {7, 2, 3}, {8, 2, 2}, {8, 1, 3}, {0, 2, 3}, {8, 0, 3}, {8, 2, 0}};
  for (unsigned i = 0; i < std::size(limits); ++i) {
    block::WorkchainExecutionRegistry registry;
    ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>(limits[i], 2)).is_ok());
    auto resolved = registry.resolve_block(descriptor, configuration);
    if (i >= 5) {
      ASSERT_TRUE(resolved.is_error());
      ASSERT_EQ(resolved.error().message(), "block execution policy requires explicit nonzero resource limits");
      continue;
    }
    ASSERT_TRUE(resolved.is_ok());
    ASSERT_TRUE(resolved.ok().policy.limits == limits[i]);
    auto result = block::execute_resolved_workchain_block(resolved.ok(), input());
    if (i >= 2) {
      ASSERT_TRUE(result.is_error());
      ASSERT_EQ(result.error().message(), "block execution exceeds configured resource limits");
      continue;
    }
    ASSERT_TRUE(result.is_ok());
    auto wrong_identity = resolved.ok();
    wrong_identity.policy.executor_address = number(99)->get_hash().bits();
    auto rejected = block::execute_resolved_workchain_block(wrong_identity, input());
    ASSERT_TRUE(rejected.is_error());
    ASSERT_EQ(rejected.error().message(), "block workchain must contain exactly its executor account");
  }
}

TEST(WorkchainBlock, ScopedWorkchainConfigurationResolution) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  block::Config configuration(0);
  td::Ref<block::WorkchainInfo> info{true};
  auto& value = info.write();
  value.workchain = 2;
  value.enabled_since = 0;
  value.monitor_min_split = value.min_split = value.max_split = 0;
  value.basic = value.active = value.accept_msgs = true;
  value.flags = value.version = 0;
  value.zerostate_root_hash.set_zero();
  value.zerostate_file_hash.set_zero();
  value.vm_version = 0x434e5431;
  value.min_addr_len = value.max_addr_len = 256;
  value.addr_len_step = 0;
  block::WorkchainSet workchains{{2, std::move(info)}};
  auto scoped = registry.resolve_scoped_workchain(workchains, 2, configuration).move_as_ok();
  ASSERT_TRUE(scoped.has_value());
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainBlockExecution>(*scoped));
  ASSERT_TRUE(!registry.resolve_scoped_workchain(workchains, tos::masterchainId, configuration).move_as_ok().has_value());
  ASSERT_TRUE(!registry.resolve_scoped_workchain(workchains, 99, configuration).move_as_ok().has_value());
  auto account = registry.resolve_workchain(workchains, 2, configuration);
  ASSERT_TRUE(account.is_error());
  ASSERT_EQ(account.error().message(), "block engine cannot execute through account compute");
  block::LocalWorkchainRoleSet roles;
  roles.required_workchains.insert(2);
  ASSERT_TRUE(registry.validate_required_workchains(workchains, configuration, roles).is_ok());
  block::WorkchainExecutionRegistry unsupported;
  ASSERT_TRUE(unsupported.validate_required_workchains(workchains, configuration, {}).is_ok());
  ASSERT_TRUE(unsupported.validate_required_workchains(workchains, configuration, roles).is_error());
  ASSERT_TRUE(block::default_workchain_execution_registry()
                  .validate_required_workchains(workchains, configuration, roles).is_error());
  workchains[2].write().max_split = 1;
  auto split = registry.resolve_scoped_workchain(workchains, 2, configuration);
  ASSERT_TRUE(split.is_error());
  ASSERT_EQ(split.error().message(), "counter requires an unsplit workchain");
  auto invalid_required = registry.validate_required_workchains(workchains, configuration, roles);
  ASSERT_TRUE(invalid_required.is_error());
  ASSERT_EQ(invalid_required.error().message(), "counter requires an unsplit workchain");
  workchains[2].write().max_split = 0;
  workchains[2].write().workchain = 3;
  auto mismatch = registry.resolve_scoped_workchain(workchains, 2, configuration);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "workchain descriptor identity differs from configuration key");
  workchains[2].write().workchain = 2;
  workchains[2].write().vm_version = static_cast<std::int32_t>(block::tvm_workchain_engine_key().selector);
  ASSERT_TRUE(block::default_workchain_execution_registry()
                  .validate_required_workchains(workchains, configuration, roles).is_ok());
}
