#include <limits>
#include <random>
#include "workchain-counter-engine.h"

#include "block/workchain-block-execution.h"
#include "block/workchain-input-preflight.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/MerkleUpdate.h"
#include "vm/cells/UsageCell.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "emulator/transaction-emulator.h"
#include "uno/core/used-nullifiers.h"

namespace {

class PreflightObservedCell final : public vm::Cell {
 public:
  PreflightObservedCell(td::Ref<vm::Cell> cell, unsigned* loads, bool unavailable = false)
      : cell_(std::move(cell)), loads_(loads), unavailable_(unavailable) {
  }
  td::Status set_data_cell(td::Ref<vm::DataCell>&& cell) const override {
    return cell_->set_data_cell(std::move(cell));
  }
  td::Result<LoadedCell> load_cell() const override {
    ++*loads_;
    if (unavailable_) return td::Status::Error("test input unavailable");
    return cell_->load_cell();
  }
  bool is_virtualized() const override { return cell_->is_virtualized(); }
  vm::CellUsageTree::NodePtr get_tree_node() const override { return {}; }
  bool is_loaded() const override { return !unavailable_; }
  LevelMask get_level_mask() const override { return cell_->get_level_mask(); }

 private:
  const Hash do_get_hash(td::uint32 level) const override { return cell_->get_hash(level); }
  td::uint16 do_get_depth(td::uint32 level) const override { return cell_->get_depth(level); }
  td::Ref<vm::Cell> cell_;
  unsigned* loads_;
  bool unavailable_;
};

td::Ref<vm::Cell> number(std::uint64_t value) {
  return vm::CellBuilder().store_long(value, 64).finalize();
}

using CounterEngine = block::test::CounterEngine;

std::unique_ptr<block::Config> block_configuration(int version = block::kBlockTransitionMinGlobalVersion,
                                                 td::uint64 capabilities = tos::capBlockTransition,
                                                 td::uint64 vm_mode = 0, bool include_ingress = true) {
  vm::CellBuilder param;
  CHECK(block::gen::t_GlobalVersion.pack_capabilities(param, version, capabilities));
  vm::Dictionary config(32);
  CHECK(config.set_ref(td::BitArray<32>(8u), param.finalize()));
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.vm_mode = vm_mode;
  policy.executor_address.set_zero();
  policy.engine_configuration = vm::CellBuilder().finalize();
  if (include_ingress) {
    CHECK(config.set_ref(td::BitArray<32>(84u), block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
  }
  return block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
                                     block::Config::needCapabilities).move_as_ok();
}

td::Ref<vm::Cell> shard_fixture(int shard_wc = 2, int account_wc = 2, bool active = true,
                              unsigned account_count = 1, bool before_split = false, unsigned prefix_bits = 0,
                              std::uint64_t counter_value = 40, bool wrong_dictionary_key = false,
                              std::uint64_t operating_balance = 0, td::Ref<vm::Cell> payload = {},
                              td::Ref<vm::Cell> engine_override = {}) {
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  for (unsigned i = 0; i < account_count; ++i) {
    td::Bits256 address = td::Bits256::zero();
    if (i != 0) address = number(i)->get_hash().bits();
    vm::CellBuilder account;
    account.store_long(1, 1).store_long(4, 3).store_long(account_wc, 8).store_bits(address.bits(), 256)
        .store_zeroes(42).store_long(2, 64);
    ASSERT_TRUE(block::CurrencyCollection(td::make_refint(operating_balance)).store(account));
    if (active) {
      vm::CellBuilder engine;
      engine.store_long(counter_value, 64);
      if (payload.not_null()) engine.store_ref(payload);
      auto executor = block::encode_workchain_executor_state(
          {engine_override.not_null() ? engine_override : engine.finalize(), {}, {}}).move_as_ok();
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

td::Ref<vm::Cell> inbound_envelope(std::uint64_t lt, std::uint64_t nonce = 0,
                                  td::optional<tos::LogicalTime> emitted = {}) {
  vm::CellBuilder cb;
  cb.store_long(4, 4).store_long(4, 3).store_long(0, 8).store_zeroes(255).store_long(1, 1)
      .store_long(4, 3).store_long(2, 8).store_zeroes(256);
  ASSERT_TRUE(block::CurrencyCollection(100).store(cb));
  cb.store_long(0, 4).store_long(1, 4).store_long(67, 8).store_long(lt, 64)
      .store_long(1, 32).store_zeroes(2).store_long(nonce, 64);
  auto message = cb.finalize();
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(4096, message));
  block::tlb::MsgEnvelope::Record_std record{0x60, 0x60, td::make_refint(67), message, emitted, {}};
  td::Ref<vm::Cell> envelope;
  ASSERT_TRUE(tlb::pack_cell(envelope, record));
  return envelope;
}

td::Ref<vm::Cell> inbound_transaction(td::Ref<vm::Cell> description, td::Ref<vm::Cell> ordinary_input = {}) {
  vm::CellBuilder messages;
  ASSERT_TRUE(messages.store_maybe_ref(ordinary_input));
  messages.store_long(0, 1);
  auto update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  return vm::CellBuilder().store_long(7, 4).store_zeroes(256).store_long(10, 64)
      .store_zeroes(256).store_long(0, 64).store_long(10, 32).store_zeroes(15)
      .store_long(2, 2).store_long(2, 2).store_ref(messages.finalize()).store_zeroes(5)
      .store_ref(update).store_ref(description).finalize();
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

TEST(WorkchainBlock, CounterPayloadSurvivesBatchReplay) {
  // Wide unique leaves model account-cell storage, not private-note semantics.
  std::vector<td::Ref<vm::Cell>> layer;
  for (unsigned i = 0; i < (1u << 14); ++i) {
    layer.push_back(vm::CellBuilder().store_long(i, 64).store_zeroes(896).finalize());
  }
  while (layer.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(layer[i]).store_ref(layer[i + 1]).finalize());
    }
    layer = std::move(next);
  }
  auto payload = layer.front();
  std::size_t payload_loads = 0;
  auto usage = std::make_shared<vm::CellUsageTree>();
  usage->set_cell_load_callback([&](const vm::LoadedCell&) { ++payload_loads; });
  auto observed_payload = vm::UsageCell::create(payload, usage->root_ptr());
  // Prove the instrument observes loads, but neither hashing nor taking a
  // reference counts as reading the payload. Use a fresh tree for each phase.
  ASSERT_TRUE(observed_payload->get_hash() == payload->get_hash());
  ASSERT_EQ(payload_loads, 0u);
  vm::load_cell_slice(observed_payload);
  ASSERT_EQ(payload_loads, 1u);
  auto reset_observation = [&] {
    payload_loads = 0;
    usage = std::make_shared<vm::CellUsageTree>();
    usage->set_cell_load_callback([&](const vm::LoadedCell&) { ++payload_loads; });
    observed_payload = vm::UsageCell::create(payload, usage->root_ptr());
  };
  reset_observation();
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, observed_payload);
  const auto previous_hash = in.previous_shard_state->get_hash();
  CounterEngine engine({8, 1, 3}, 1, 2, CounterEngine::PayloadMode::PreserveReference);
  ASSERT_TRUE(CounterEngine().execute_block(in).is_error());
  ASSERT_TRUE(engine.execute_block(input()).is_error());
  auto effects = engine.execute_block(in).move_as_ok();
  auto result_state = vm::load_cell_slice(effects.new_engine_state);
  ASSERT_EQ(result_state.fetch_ulong(64), 42u);
  ASSERT_EQ(result_state.size_refs(), 1u);
  ASSERT_TRUE(result_state.fetch_ref()->get_hash() == payload->get_hash());
  ASSERT_EQ(payload_loads, 0u);

  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
  ASSERT_EQ(payload_loads, 0u);
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  ASSERT_EQ(cfg.size_limits.max_acc_state_cells, 65536u);
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  // Diagnostic only: do not require a future storage-stat optimization to
  // retain today's traversal cost. This fixture has no cached storage index.
  LOG(INFO) << "Counter payload reads: phase=prepare unique_tree_nodes=" << payload_loads;
  ASSERT_TRUE(tx.serialize(cfg));
  reset_observation();
  auto replay_input = in;
  replay_input.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, observed_payload);
  ASSERT_TRUE(replay_input.previous_shard_state->get_hash() == previous_hash);
  ASSERT_EQ(payload_loads, 0u);
  auto replayed = block::replay_workchain_batch_transaction(
      engine, replay_input, tx.root, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  LOG(INFO) << "Counter payload reads: phase=replay unique_tree_nodes=" << payload_loads;
  ASSERT_TRUE(replayed->get_hash() == tx.new_total_state->get_hash());
  auto wire = vm::std_boc_serialize(tx.new_data).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  ASSERT_TRUE(restored->get_hash() == tx.new_data->get_hash());
  vm::CellStorageStat stat;
  ASSERT_TRUE(stat.compute_used_storage(restored).is_ok());
  ASSERT_TRUE(stat.cells > 32767u);
  ASSERT_TRUE(stat.cells < cfg.size_limits.max_acc_state_cells);
  ASSERT_TRUE(wire.size() > (1u << 20));
  ASSERT_TRUE(in.previous_shard_state->get_hash() == previous_hash);
  LOG(INFO) << "Counter payload batch: wrapper cells=" << stat.cells << " boc bytes=" << wire.size();
}

TEST(WorkchainBlock, ReplayStorageCachePreservesValidation) {
  std::vector<td::Ref<vm::Cell>> layer;
  for (unsigned i = 0; i < 256; ++i) layer.push_back(number(i));
  while (layer.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(layer[i]).store_ref(layer[i + 1]).finalize());
    }
    layer = std::move(next);
  }
  auto payload = layer.front();
  CounterEngine engine({8, 1, 3}, 1, 2, CounterEngine::PayloadMode::PreserveReference);
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  cfg.extra_currency_v2 = true;
  cfg.store_storage_dict_hash = true;
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, payload);
  auto unpack_account = [&](const td::Ref<vm::Cell>& root, block::Account& account) {
    block::gen::ShardStateUnsplit::Record state;
    ASSERT_TRUE(tlb::unpack_cell(root, state));
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
  };
  block::Account first_account(2, td::Bits256::zero().bits());
  unpack_account(in.previous_shard_state, first_account);
  block::transaction::Transaction first(first_account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(first.prepare_workchain_batch(in, engine.execute_block(in).move_as_ok(), cfg).is_ok());
  ASSERT_TRUE(first.serialize(cfg));
  ASSERT_TRUE(first.new_storage_dict_hash);
  auto previous_index = first.new_account_storage_stat.value().get_dict_root().move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  vm::CellBuilder entry;
  entry.store_ref(first.new_total_state).store_bits(first.root->get_hash().bits(), 256).store_long(first.start_lt, 64);
  ASSERT_TRUE(accounts.set_builder(td::Bits256::zero(), entry));
  state.accounts = accounts.get_wrapped_dict_root();
  state.gen_lt = first.end_lt;
  state.gen_utime = 10;
  ASSERT_TRUE(tlb::pack_cell(in.previous_shard_state, state));
  block::Account second_account(2, td::Bits256::zero().bits());
  unpack_account(in.previous_shard_state, second_account);
  block::transaction::Transaction second(second_account, block::transaction::Transaction::tr_workchain_batch, 20, 10);
  ASSERT_TRUE(second.prepare_workchain_batch(in, engine.execute_block(in).move_as_ok(), cfg).is_ok());
  ASSERT_TRUE(second.serialize(cfg));

  auto run = [&](td::Ref<vm::Cell> cached, bool expect_hit, bool valid_claim) {
    std::size_t loads = 0, lookups = 0, remembered = 0;
    auto usage = std::make_shared<vm::CellUsageTree>();
    usage->set_cell_load_callback([&](const vm::LoadedCell&) { ++loads; });
    auto observed = in;
    observed.previous_shard_state = vm::UsageCell::create(in.previous_shard_state, usage->root_ptr());
    block::WorkchainReplayStorageCache cache{
        [&](const td::Bits256& hash) {
          ++lookups;
          ASSERT_TRUE(hash == first.new_storage_dict_hash.value());
          return cached;
        },
        [&](td::Ref<vm::Cell> root, td::uint32 cells) {
          ++remembered;
          ASSERT_TRUE(td::Bits256(root->get_hash().bits()) == second.new_storage_dict_hash.value());
          ASSERT_EQ(cells, second.new_storage_used.cells);
        }};
    auto claimed = second.root;
    if (!valid_claim) {
      block::gen::Transaction::Record wrong;
      ASSERT_TRUE(tlb::unpack_cell(claimed, wrong));
      wrong.prev_trans_hash.set_zero();
      td::Ref<vm::Cell> messages;
      ASSERT_TRUE(tlb::pack_cell(messages, wrong.r1));
      claimed = vm::CellBuilder().store_long(7, 4).store_bits(wrong.account_addr.bits(), 256)
          .store_long(wrong.lt, 64).store_bits(wrong.prev_trans_hash.bits(), 256)
          .store_long(wrong.prev_trans_lt, 64).store_long(wrong.now, 32).store_long(wrong.outmsg_cnt, 15)
          .store_long(wrong.orig_status, 2).store_long(wrong.end_status, 2).store_ref(messages)
          .append_cellslice(wrong.total_fees).store_ref(wrong.state_update).store_ref(wrong.description).finalize();
      ASSERT_TRUE(block::gen::t_Transaction.validate_ref(4096, claimed));
    }
    auto replayed = block::replay_workchain_batch_transaction(
        engine, observed, claimed, 2, td::Bits256::zero(), 20, 10, cfg, nullptr, &cache);
    ASSERT_EQ(lookups, 1u);
    ASSERT_EQ(remembered, valid_claim ? 1u : 0u);
    ASSERT_EQ(replayed.is_ok(), valid_claim);
    if (valid_claim) ASSERT_TRUE(replayed.ok()->get_hash() == second.new_total_state->get_hash());
    LOG(INFO) << "Replay storage cache: hit=" << expect_hit << " valid_claim=" << valid_claim << " reads=" << loads;
    // A hit must avoid the 511-node payload; a miss remains the reference path.
    if (expect_hit) ASSERT_TRUE(loads < 100u);
    return loads;
  };
  auto cold_loads = run({}, false, true);
  ASSERT_TRUE(run(previous_index, true, true) < cold_loads);
  ASSERT_EQ(run(number(999), false, true), cold_loads);
  run(previous_index, true, false);
}

TEST(WorkchainBlock, CanonicalInboundList) {
  auto first = inbound_envelope(3);
  auto second = inbound_envelope(4);
  auto encoded = block::encode_workchain_batch_inbound({first, second}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBatchInbound.validate_ref(10000, encoded));
  auto wire = vm::std_boc_serialize(encoded).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto decoded = block::decode_workchain_batch_inbound(restored).move_as_ok();
  ASSERT_EQ(decoded.size(), 2u);
  ASSERT_TRUE(decoded[0]->get_hash() == first->get_hash());
  ASSERT_TRUE(decoded[1]->get_hash() == second->get_hash());
  auto reversed = block::encode_workchain_batch_inbound({second, first}).move_as_ok();
  ASSERT_TRUE(reversed->get_hash() == encoded->get_hash());
  // Increasing emitted LT must not disguise a duplicate original message.
  auto duplicate = block::encode_workchain_batch_inbound({first, inbound_envelope(3, 0, 5)});
  ASSERT_TRUE(duplicate.is_error());
  ASSERT_EQ(duplicate.error().message(), "duplicate batch inbound message");
  ASSERT_TRUE(block::encode_workchain_batch_inbound({number(0)}).is_error());
  ASSERT_TRUE(block::encode_workchain_batch_inbound({}).is_error());
  ASSERT_TRUE(block::encode_workchain_batch_inbound({{}}).is_error());
  auto delayed = inbound_envelope(1, 0, 5);
  auto delayed_root = block::encode_workchain_batch_inbound({delayed, second}).move_as_ok();
  auto delayed_list = block::decode_workchain_batch_inbound(delayed_root).move_as_ok();
  ASSERT_TRUE(delayed_list[0]->get_hash() == second->get_hash());
  ASSERT_TRUE(delayed_list[1]->get_hash() == delayed->get_hash());
  auto same_lt = inbound_envelope(3, 1);
  block::tlb::MsgEnvelope::Record_std a, b;
  ASSERT_TRUE(tlb::unpack_cell(first, a) && tlb::unpack_cell(same_lt, b));
  auto equal_root = block::encode_workchain_batch_inbound({first, same_lt}).move_as_ok();
  auto equal_list = block::decode_workchain_batch_inbound(equal_root).move_as_ok();
  ASSERT_TRUE(equal_list[0]->get_hash() == (a.msg->get_hash() < b.msg->get_hash() ? first : same_lt)->get_hash());
  auto mismatched_count = vm::CellBuilder().store_long(0x57494e31, 32).store_long(3, 15)
      .store_long(1, 1).store_ref(vm::load_cell_slice(encoded).prefetch_ref()).finalize();
  auto mismatch = block::decode_workchain_batch_inbound(mismatched_count);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "invalid or noncanonical batch inbound entries");
  vm::Dictionary gap(256);
  ASSERT_TRUE(gap.set_ref(number(99)->get_hash().bits(), 256, first));
  vm::CellBuilder gap_root;
  gap_root.store_long(0x57494e31, 32).store_long(1, 15);
  ASSERT_TRUE(std::move(gap).append_dict_to_bool(gap_root));
  auto gap_result = block::decode_workchain_batch_inbound(gap_root.finalize());
  ASSERT_TRUE(gap_result.is_error());
  ASSERT_EQ(gap_result.error().message(), "invalid or noncanonical batch inbound entries");
}

TEST(WorkchainBlock, InboundCommitmentAndMembership) {
  auto in = input();
  auto first = inbound_envelope(3);
  auto second = inbound_envelope(4);
  in.inbound_messages = block::encode_workchain_batch_inbound({first, second}).move_as_ok();
  auto encoded_input = block::encode_workchain_block_input(in).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBlockInput.validate_ref(10000, encoded_input));
  block::gen::WorkchainBlockInput::Record_workchain_block_input_v2 input_record;
  ASSERT_TRUE(tlb::unpack_cell(encoded_input, input_record));
  ASSERT_TRUE(input_record.inbound_messages->get_hash() == in.inbound_messages->get_hash());
  CounterEngine engine;
  auto effects = engine.execute_block(in).move_as_ok();
  auto description = block::make_workchain_batch_description(in, effects).move_as_ok();
  auto root = block::encode_workchain_batch_description(description);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, root));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, root));
  ASSERT_TRUE(block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::BlockTransition).is_ok());
  ASSERT_TRUE(block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::AccountCompute).is_error());
  auto decoded = block::decode_workchain_batch_description(root).move_as_ok();
  ASSERT_TRUE(decoded.inbound_messages->get_hash() == in.inbound_messages->get_hash());
  ASSERT_TRUE(block::replay_workchain_batch(engine, in, root).is_ok());
  auto forged = description;
  forged.inbound_messages = block::encode_workchain_batch_inbound({inbound_envelope(5)}).move_as_ok();
  auto wrong = block::replay_workchain_batch(engine, in, block::encode_workchain_batch_description(forged));
  ASSERT_TRUE(wrong.is_error());
  ASSERT_EQ(wrong.error().message(), "batch transaction commitments differ from replay");
  auto altered_input = in;
  altered_input.inbound_messages = forged.inbound_messages;
  auto wrong_input = block::replay_workchain_batch(engine, altered_input, root);
  ASSERT_TRUE(wrong_input.is_error());
  ASSERT_EQ(wrong_input.error().message(), "batch transaction input commitment differs from authenticated context");
  auto transaction = inbound_transaction(root);
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(10000, transaction));
  ASSERT_TRUE(block::tlb::t_Transaction.validate_ref(10000, transaction));
  block::tlb::MsgEnvelope::Record_std first_record, second_record, other;
  ASSERT_TRUE(tlb::unpack_cell(first, first_record));
  ASSERT_TRUE(tlb::unpack_cell(second, second_record));
  ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(5), other));
  ASSERT_TRUE(block::is_transaction_in_msg(transaction, first_record.msg));
  ASSERT_TRUE(block::is_transaction_in_msg(transaction, second_record.msg));
  ASSERT_TRUE(!block::is_transaction_in_msg(transaction, other.msg));
  ASSERT_TRUE(!block::is_transaction_in_msg(transaction, {}));
  ASSERT_TRUE(!block::is_transaction_in_msg(inbound_transaction(root, first_record.msg), first_record.msg));
  auto malformed = forged;
  malformed.inbound_messages = number(0);
  auto bad = block::encode_workchain_batch_description(malformed);
  ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, bad));
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, bad));
  ASSERT_TRUE(!block::is_transaction_in_msg(inbound_transaction(bad), other.msg));
  // A membership query is not acceptance: native credit requires host version.
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  auto status = tx.prepare_workchain_batch(in, effects, block::SerializeConfig{});
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.message(), "batch incoming credit requires activated host version");
  ASSERT_TRUE(account.balance.is_zero());
  ASSERT_TRUE(!tx.serialize(block::SerializeConfig{}));
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
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
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
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
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

TEST(WorkchainBlock, UsedNullifierGrowthReachesNativeAccountLimit) {
  std::mt19937 random(91);
  std::vector<td::Bits256> keys(32768);
  for (auto& key : keys) {
    for (auto& byte : key.as_slice()) {
      byte = static_cast<char>(random());
    }
  }
  auto in = input();
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  ASSERT_EQ(cfg.size_limits.max_acc_state_cells, 65536u);
  auto fits = [&](std::size_t count) {
    auto used = uno_workchain::UsedNullifiers{}.with_used(
        std::vector<td::Bits256>(keys.begin(), keys.begin() + count)).move_as_ok();
    auto effects = CounterEngine().execute_block(in).move_as_ok();
    // Use the real persistent used-set representation as host payload. This
    // measures account admission, not a complete private-transfer execution.
    effects.new_engine_state = used.root();
    block::gen::ShardStateUnsplit::Record state;
    ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    block::Account account(2, td::Bits256::zero().bits());
    ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
    const auto original = account.total_state->get_hash();
    block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
    auto result = tx.prepare_workchain_batch(in, effects, cfg);
    ASSERT_TRUE(account.total_state->get_hash() == original);
    if (result.is_error()) {
      ASSERT_EQ(result.error().code(), block::AccountStorageStat::errorcode_limits_exceeded);
      ASSERT_TRUE(tx.new_data->get_hash() == account.data->get_hash());
      ASSERT_TRUE(!tx.serialize(cfg));
      return false;
    }
    ASSERT_TRUE(tx.serialize(cfg));
    return true;
  };
  std::size_t lower = 32000, upper = keys.size();
  ASSERT_TRUE(fits(lower));
  ASSERT_TRUE(!fits(upper));
  while (upper - lower > 1) {
    auto middle = lower + (upper - lower) / 2;
    if (fits(middle)) lower = middle;
    else upper = middle;
  }
  ASSERT_TRUE(fits(lower));
  ASSERT_TRUE(!fits(upper));
  LOG(INFO) << "Used-nullifier host capacity: accepted=" << lower << " rejected=" << upper
            << " account_cell_limit=" << cfg.size_limits.max_acc_state_cells
            << " scope=used-set-only payload plus host wrapper; not complete UNO state";
}

TEST(WorkchainBlock, BatchExecutorCellBudgetIncludesFullWrapper) {
  auto in = input();
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  // A balanced, uniquely labelled tree avoids both depth-limit rejection and
  // accidental deduplication. This is host test state, not a private-note tree.
  std::vector<td::Ref<vm::Cell>> layer;
  for (unsigned i = 0; i < (1u << 15); ++i) {
    layer.push_back(number(i));
  }
  while (layer.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(layer[i]).store_ref(layer[i + 1]).finalize());
    }
    layer = std::move(next);
  }
  effects.new_engine_state = layer.front();
  vm::CellStorageStat payload_stat;
  ASSERT_TRUE(payload_stat.compute_used_storage(effects.new_engine_state).is_ok());
  ASSERT_EQ(payload_stat.cells, 65535u);
  auto encoded = block::encode_workchain_block_result(effects).move_as_ok();
  auto wrapper = block::encode_workchain_executor_state({effects.new_engine_state, in.candidate, encoded}).move_as_ok();
  vm::CellStorageStat wrapper_stat;
  ASSERT_TRUE(wrapper_stat.compute_used_storage(wrapper).is_ok());
  ASSERT_TRUE(wrapper_stat.cells > 65536u);
  ASSERT_TRUE(wrapper_stat.cells < std::numeric_limits<td::uint32>::max());

  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  ASSERT_EQ(cfg.size_limits.max_acc_state_cells, 65536u);
  const auto original = account.total_state->get_hash();
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  auto rejected = tx.prepare_workchain_batch(in, effects, cfg);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.error().code(), block::AccountStorageStat::errorcode_limits_exceeded);
  ASSERT_TRUE(tx.new_data->get_hash() == account.data->get_hash());
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(tx.out_msgs.empty());
  ASSERT_TRUE(account.total_state->get_hash() == original);

  const auto required = static_cast<td::uint32>(wrapper_stat.cells);
  cfg.size_limits.max_acc_state_cells = required - 1;
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_error());
  cfg.size_limits.max_acc_state_cells = required;
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(tx.new_data->get_hash() == wrapper->get_hash());
  ASSERT_TRUE(account.total_state->get_hash() == original);
  LOG(INFO) << "Batch executor cell budget: payload=" << payload_stat.cells << " wrapper=" << required;
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
  account.is_special = true;
  block::transaction::Transaction special(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(special.prepare_workchain_batch(in, effects, cfg).is_error());
  ASSERT_TRUE(special.out_msgs.empty());
  ASSERT_TRUE(special.total_fees.is_zero());
  ASSERT_TRUE(!special.serialize(cfg));
  account.is_special = false;
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
  block::gen::WorkchainBlockInput::Record_workchain_block_input_v1 generated;
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

TEST(WorkchainBlock, NativeQueueViewIsBoundToInput) {
  auto in = input();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  auto queue = block::extract_workchain_native_queue_state(in).move_as_ok();
  ASSERT_TRUE(queue->get_hash() == state.out_msg_queue_info->get_hash());
  auto before = block::encode_workchain_block_input(in).move_as_ok();
  // Empty queue with explicit dispatch metadata, rather than absent metadata.
  auto changed_queue = vm::CellBuilder().store_zeroes(66).store_long(1, 1)
      .store_zeroes(4 + 65).store_long(1, 1).store_zeroes(48).finalize();
  ASSERT_TRUE(block::gen::t_OutMsgQueueInfo.validate_ref(10000, changed_queue));
  state.out_msg_queue_info = changed_queue;
  auto changed = in;
  ASSERT_TRUE(tlb::pack_cell(changed.previous_shard_state, state));
  ASSERT_TRUE(block::gen::t_ShardStateUnsplit.validate_ref(10000, changed.previous_shard_state));
  ASSERT_TRUE(block::extract_workchain_native_queue_state(changed).move_as_ok()->get_hash() == changed_queue->get_hash());
  ASSERT_TRUE(block::encode_workchain_block_input(changed).move_as_ok()->get_hash() != before->get_hash());
  auto invalid = in;
  invalid.previous_shard_state = {};
  ASSERT_TRUE(block::extract_workchain_native_queue_state(invalid).is_error());
  invalid.previous_shard_state = number(0);
  ASSERT_TRUE(block::extract_workchain_native_queue_state(invalid).is_error());
}

TEST(WorkchainBlock, UnmatchedBatchInputDoesNotInvokeEngine) {
  class CountingEngine final : public block::WorkchainBlockEngine {
   public:
    mutable unsigned calls = 0;
    td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput& in) const override {
      ++calls;
      return CounterEngine().execute_block(in);
    }
  } engine;
  auto in = input();
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  auto claim = block::make_workchain_batch_description(in, effects).move_as_ok();
  auto description = block::encode_workchain_batch_description(claim);
  auto matched = block::replay_workchain_batch(engine, in, description);
  ASSERT_TRUE(matched.is_ok());
  ASSERT_EQ(engine.calls, 1u);

  td::Ref<vm::Cell> block::WorkchainBlockInput::* fields[] = {
      &block::WorkchainBlockInput::previous_shard_state, &block::WorkchainBlockInput::candidate,
      &block::WorkchainBlockInput::configuration, &block::WorkchainBlockInput::finality_context};
  for (auto field : fields) {
    auto changed = in;
    changed.*field = number(99);
    engine.calls = 0;
    auto rejected = block::replay_workchain_batch(engine, changed, description);
    ASSERT_EQ(engine.calls, 0u);
    ASSERT_TRUE(rejected.is_error());
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
  ASSERT_EQ(vm::load_cell_slice(root).size(), 709u);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, root));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, root));
  block::gen::TransactionDescr::Record_trans_workchain_batch_v2 generated;
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
  ASSERT_EQ(block::tlb::t_TransactionDescr.get_tag(cs), block::tlb::TransactionDescr::trans_workchain_batch_v2);
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
  for (unsigned tag = 10; tag < 16; ++tag) {
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
    cb.store_long(9, 4).store_zeroes(mutation == 0 ? 704 : mutation == 1 ? 706 : 705);
    if (mutation == 2) cb.store_ref(number(0));
    auto root = cb.finalize();
    ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, root));
    ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, root));
    auto decoded = block::decode_workchain_batch_description(root);
    ASSERT_TRUE(decoded.is_error());
    ASSERT_EQ(decoded.error().message(), "invalid batch transaction description");
  }
}

TEST(WorkchainBlock, ScopeClassifiesEveryConstructorPrefix) {
  // Prefix classification is separate from full TL-B payload validation.
  // Both fourth-bit values of the three-bit tick/tock tag must classify alike.
  for (unsigned tag = 0; tag < 16; ++tag) {
    auto prefix = vm::CellBuilder().store_long(tag, 4).finalize();
    bool account = block::validate_transaction_execution_scope(
        prefix, block::WorkchainExecutionScope::AccountCompute).is_ok();
    bool batch = block::validate_transaction_execution_scope(
        prefix, block::WorkchainExecutionScope::BlockTransition).is_ok();
    ASSERT_EQ(account, tag < 8);
    ASSERT_EQ(batch, tag == 9);
  }
}

TEST(WorkchainBlock, RetiredBatchDescriptorRejected) {
  auto retired = vm::CellBuilder().store_long(8, 4).store_zeroes(704).finalize();
  ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, retired));
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, retired));
  ASSERT_TRUE(block::decode_workchain_batch_description(retired).is_error());
  auto cs = vm::load_cell_slice(retired);
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.skip(cs));
  cs = vm::load_cell_slice(retired);
  bool found = false;
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.skip_to_storage_phase(cs, found));
  ASSERT_TRUE(block::validate_transaction_execution_scope(
      retired, block::WorkchainExecutionScope::BlockTransition).is_error());

  block::WorkchainBatchDescription empty;
  auto current = block::encode_workchain_batch_description(empty);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, current));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, current));
  auto transaction = inbound_transaction(current);
  ASSERT_TRUE(block::is_transaction_in_msg(transaction, {}));
  block::tlb::MsgEnvelope::Record_std envelope;
  ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(3), envelope));
  ASSERT_TRUE(!block::is_transaction_in_msg(transaction, envelope.msg));
}

TEST(WorkchainBlock, BatchTimeFollowsEveryInputAndLeavesEndSpace) {
  ASSERT_EQ(block::workchain_batch_start_lt(10).move_as_ok(), 11u);
  auto inbox = block::encode_workchain_batch_inbound(
      {inbound_envelope(20), inbound_envelope(3, 1, 30)}).move_as_ok();
  ASSERT_EQ(block::workchain_batch_start_lt(10, inbox).move_as_ok(), 31u);
  ASSERT_EQ(block::workchain_batch_start_lt(40, inbox).move_as_ok(), 41u);
  // Even an inconsistent old emission time cannot hide the creation LT.
  auto created = block::encode_workchain_batch_inbound({inbound_envelope(50, 0, 2)}).move_as_ok();
  ASSERT_EQ(block::workchain_batch_start_lt(10, created).move_as_ok(), 51u);
  auto maximum = std::numeric_limits<std::uint64_t>::max();
  ASSERT_EQ(block::workchain_batch_start_lt(maximum - 2).move_as_ok(), maximum - 1);
  ASSERT_TRUE(block::workchain_batch_start_lt(maximum - 1).is_error());
  ASSERT_TRUE(block::workchain_batch_start_lt(maximum).is_error());
  auto exhausted = block::encode_workchain_batch_inbound({inbound_envelope(maximum - 1)}).move_as_ok();
  ASSERT_TRUE(block::workchain_batch_start_lt(0, exhausted).is_error());
  ASSERT_TRUE(block::workchain_batch_start_lt(0, number(0)).is_error());
}

TEST(WorkchainBlock, InboxReconstructedFromNativeImports) {
  auto first = inbound_envelope(3);
  auto second = inbound_envelope(4);
  auto expected = block::encode_workchain_batch_inbound({first, second}).move_as_ok();
  block::WorkchainBatchDescription description;
  description.input_hash.set_zero();
  description.effects_hash.set_zero();
  description.inbound_messages = expected;
  auto transaction = inbound_transaction(block::encode_workchain_batch_description(description));
  auto final = vm::CellBuilder().store_long(4, 3).store_ref(first).store_ref(transaction)
      .store_long(1, 4).store_long(67, 8).finalize();
  auto deferred = vm::CellBuilder().store_long(4, 5).store_ref(second).store_ref(transaction)
      .store_long(1, 4).store_long(67, 8).finalize();
  auto transit = vm::CellBuilder().store_long(5, 5).store_ref(first).store_ref(first).finalize();
  auto routed = vm::CellBuilder().store_long(5, 3).store_ref(first).store_ref(first).store_long(0, 4).finalize();
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, final));
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, deferred));
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, transit));
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, routed));
  auto rebuilt = block::workchain_batch_inbound_from_imports({deferred, transit, routed, final}).move_as_ok();
  ASSERT_TRUE(rebuilt->get_hash() == expected->get_hash());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({transit}).move_as_ok().is_null());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({}).move_as_ok().is_null());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({final, final}).is_error());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({{}}).is_error());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({number(0)}).is_error());
  // A well-formed discarded message is not a final delivery to the engine.
  auto discarded = vm::CellBuilder().store_long(6, 3).store_ref(first).store_long(10, 64)
      .store_long(1, 4).store_long(67, 8).finalize();
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, discarded));
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({discarded}).is_error());
}

TEST(WorkchainBlock, NativeBatchCreditIsAtomicAndReplayable) {
  auto in = input();
  in.inbound_messages = block::encode_workchain_batch_inbound(
      {inbound_envelope(3), inbound_envelope(4)}).move_as_ok();
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  auto old_hash = account.total_state->get_hash();
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  using Transaction = block::transaction::Transaction;
  Transaction tx(account, Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  ASSERT_TRUE(tx.balance == block::CurrencyCollection(200));
  ASSERT_TRUE(tx.total_fees.is_zero());
  ASSERT_TRUE(account.balance.is_zero());
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(block::replay_workchain_batch_transaction(
      CounterEngine(), in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg).is_ok());
  ASSERT_TRUE(account.total_state->get_hash() == old_hash);

  for (auto late : {inbound_envelope(10), inbound_envelope(3, 0, 10)}) {
    auto changed = in;
    changed.inbound_messages = block::encode_workchain_batch_inbound({late}).move_as_ok();
    Transaction rejected(account, Transaction::tr_workchain_batch, 10, 10);
    ASSERT_TRUE(rejected.prepare_workchain_batch(changed, effects, cfg).is_error());
    ASSERT_TRUE(rejected.balance.is_zero());
    ASSERT_TRUE(!rejected.serialize(cfg));
  }
  vm::CellBuilder message;
  message.store_long(4, 4).store_zeroes(2)
      .store_long(4, 3).store_long(-1, 8).store_zeroes(256);
  ASSERT_TRUE(block::CurrencyCollection(100).store(message));
  message.store_zeroes(8).store_zeroes(96).store_zeroes(2);
  auto outbound = message.finalize();
  vm::Dictionary requests(15);
  for (unsigned i = 0; i < 2; ++i) {
    ASSERT_TRUE(requests.set_ref(td::BitArray<15>(i), outbound));
  }
  vm::CellBuilder encoded_requests;
  ASSERT_TRUE(std::move(requests).append_dict_to_bool(encoded_requests));
  auto costly = effects;
  costly.outbound_messages = encoded_requests.finalize();
  block::WorkchainSet workchains;
  block::ActionPhaseConfig message_cfg;
  message_cfg.workchains = &workchains;
  message_cfg.global_version = cfg.global_version;
  message_cfg.fwd_mc.lump_price = 100;
  message_cfg.fwd_mc.first_frac = 32768;
  vm::Dictionary one_request(15);
  unsigned first_index = 0;
  ASSERT_TRUE(one_request.set_ref(td::BitArray<15>(first_index), outbound));
  vm::CellBuilder one_encoded;
  ASSERT_TRUE(std::move(one_request).append_dict_to_bool(one_encoded));
  auto funded_input = in;
  funded_input.candidate = vm::CellBuilder().store_long(2, 64).store_ref(one_encoded.finalize()).finalize();
  auto funded_effects = CounterEngine().execute_block(funded_input).move_as_ok();
  Transaction funded(account, Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(funded.prepare_workchain_batch(funded_input, funded_effects, cfg, &message_cfg).is_ok());
  ASSERT_TRUE(funded.balance.is_zero());
  ASSERT_EQ(funded.out_msgs.size(), 1u);
  ASSERT_TRUE(funded.serialize(cfg));
  ASSERT_TRUE(block::replay_workchain_batch_transaction(
      CounterEngine(), funded_input, funded.root, 2, td::Bits256::zero(), 10, 10, cfg, &message_cfg).is_ok());
  Transaction insufficient(account, Transaction::tr_workchain_batch, 10, 10);
  auto failure = insufficient.prepare_workchain_batch(in, costly, cfg, &message_cfg);
  ASSERT_TRUE(failure.is_error());
  ASSERT_EQ(failure.message(), "batch native message send failed");
  ASSERT_TRUE(insufficient.balance.is_zero());
  ASSERT_TRUE(insufficient.out_msgs.empty());
  ASSERT_TRUE(insufficient.total_fees.is_zero());
  ASSERT_TRUE(account.total_state->get_hash() == old_hash);
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

TEST(WorkchainBlock, InputPreflightUnionAndExactLimits) {
  auto shared = vm::CellBuilder().store_long(5, 3).finalize();
  auto first = vm::CellBuilder().store_long(0, 1).store_ref(shared).store_ref(shared).finalize();
  auto second = vm::CellBuilder().store_long(1, 2).store_ref(shared).finalize();
  block::WorkchainInputPreflight gate({3, 6, 3});
  ASSERT_TRUE(gate.add(first).is_ok());
  ASSERT_EQ(gate.usage().cells, 2u);
  ASSERT_EQ(gate.usage().bits, 4u);
  ASSERT_TRUE(gate.add(second).is_ok());
  ASSERT_TRUE(gate.add(first).is_ok());
  ASSERT_EQ(gate.usage().cells, 3u);
  ASSERT_EQ(gate.usage().bits, 6u);
  ASSERT_EQ(gate.usage().roots, 3u);
  ASSERT_TRUE(gate.add(first).is_error());
  block::WorkchainInputPreflight cells({2, 6, 2});
  ASSERT_TRUE(cells.add(first).is_ok());
  ASSERT_TRUE(cells.add(second).is_error());
  block::WorkchainInputPreflight bits({3, 5, 2});
  ASSERT_TRUE(bits.add(first).is_ok());
  ASSERT_TRUE(bits.add(second).is_error());
  ASSERT_TRUE(bits.add(first).is_error());
}

TEST(WorkchainBlock, InputPreflightStopsBeforeOverLimitLoad) {
  unsigned root_loads = 0, child_loads = 0;
  td::Ref<PreflightObservedCell> child{true, number(1), &child_loads};
  auto raw_root = vm::CellBuilder().store_long(1, 1).store_ref(child).finalize();
  td::Ref<PreflightObservedCell> root{true, raw_root, &root_loads};
  block::WorkchainInputPreflight gate({1, 65, 1});
  auto rejected = gate.add(root);
  ASSERT_EQ(root_loads, 1u);
  ASSERT_EQ(child_loads, 0u);
  ASSERT_TRUE(rejected.is_error());
  block::WorkchainInputPreflight accepted({2, 65, 1});
  ASSERT_TRUE(accepted.add(root).is_ok());
  ASSERT_EQ(root_loads, 2u);
  ASSERT_EQ(child_loads, 1u);
  block::WorkchainInputPreflight bits({2, 0, 1});
  ASSERT_TRUE(bits.add(root).is_error());
  ASSERT_EQ(root_loads, 3u);
  ASSERT_EQ(child_loads, 1u);
}

TEST(WorkchainBlock, InputPreflightDeepSharedGraph) {
  auto cell = vm::CellBuilder().finalize();
  for (unsigned i = 0; i < vm::CellTraits::max_depth; ++i) {
    cell = vm::CellBuilder().store_ref(cell).store_ref(cell).store_ref(cell).store_ref(cell).finalize();
  }
  block::WorkchainInputPreflight gate({vm::CellTraits::max_depth + 1, 0, 1});
  ASSERT_TRUE(gate.add(cell).is_ok());
  ASSERT_EQ(gate.usage().cells, vm::CellTraits::max_depth + 1u);
  ASSERT_EQ(gate.usage().bits, 0u);
}

TEST(WorkchainBlock, InputPreflightUnavailableAndSpecial) {
  unsigned loads = 0;
  td::Ref<PreflightObservedCell> absent{true, number(1), &loads, true};
  block::WorkchainInputPreflight unavailable({10, 1024, 2});
  ASSERT_TRUE(unavailable.add(absent).is_error());
  ASSERT_EQ(loads, 1u);
  ASSERT_TRUE(unavailable.add(number(1)).is_error());
  auto proof = vm::MerkleProof::generate(number(1), [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  block::WorkchainInputPreflight special({10, 1024, 1});
  ASSERT_TRUE(special.add(proof).is_error());
  block::WorkchainInputPreflight missing({1, 1, 1});
  ASSERT_TRUE(missing.add({}).is_error());
}

TEST(WorkchainBlock, EngineSpecialInputClassification) {
  const td::Ref<vm::Cell> special_cells[] = {
      vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true),
      vm::CellBuilder::do_create_pruned_branch(number(2), 1, 0),
      vm::CellBuilder::create_merkle_proof(number(2))};
  ASSERT_TRUE(CounterEngine().execute_block(input()).is_ok());
  for (const auto& special : special_cells) {
    bool is_special = false;
    vm::load_cell_slice_special(special, is_special);
    ASSERT_TRUE(is_special);
    auto in = input();
    in.candidate = special;
    auto result = CounterEngine().execute_block(in);
    ASSERT_TRUE(result.is_error());
    ASSERT_TRUE(!block::workchain_execution_requires_local_failure(result.error()));
  }

  // Native state/update transport permits library cells below account data;
  // transport authentication does not enforce an engine-specific state schema.
  auto before = shard_fixture();
  auto after = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, {}, special_cells[0]);
  auto update = vm::CellBuilder::create_merkle_update(before, after);
  ASSERT_TRUE(vm::MerkleUpdate::validate(update).is_ok());
  auto applied = vm::MerkleUpdate::apply(before, update).move_as_ok();
  ASSERT_TRUE(applied->get_hash() == after->get_hash());
  auto in = input();
  in.previous_shard_state = applied;
  auto state = block::extract_workchain_engine_state(applied, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_TRUE(state->get_hash() == special_cells[0]->get_hash());
  auto result = CounterEngine().execute_block(in);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().code(), static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(result.error()));
}

TEST(WorkchainBlock, EngineExceptionIsNotCandidateInvalid) {
  class ThrowingEngine final : public block::RegisteredWorkchainBlockEngine {
   public:
    explicit ThrowingEngine(unsigned kind) : kind_(kind) {}
    block::WorkchainEngineKey engine_key() const override { return CounterEngine().engine_key(); }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& d, const block::Config& c,
        const td::Ref<vm::Cell>& root) const override {
      return CounterEngine().validate_and_resolve_config(d, c, root);
    }
    td::Result<block::WorkchainBlockPolicy> block_policy(
        const block::WorkchainExecutionDescriptor& d, const block::WorkchainEngineConfig& c) const override {
      return CounterEngine().block_policy(d, c);
    }
    td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput&) const override {
      ++calls;
      switch (kind_) {
        case 0: throw vm::VmError(vm::Excno::cell_und);
        case 1: throw vm::VmVirtError();
        case 2: throw vm::VmNoGas();
        case 3: throw vm::CellBuilder::CellCreateError();
        default: throw vm::CellBuilder::CellWriteError();
      }
    }
    mutable unsigned calls = 0;
   private:
    unsigned kind_;
  };
  for (unsigned kind = 0; kind < 5; ++kind) {
    ThrowingEngine engine(kind);
    block::ResolvedWorkchainBlockExecution execution;
    execution.executor = &engine;
    execution.descriptor.workchain_id = 2;
    execution.engine_config = std::make_shared<block::WorkchainEngineConfig>();
    execution.policy.limits = {8, 1, 3};
    auto result = block::execute_resolved_workchain_block(execution, input());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    auto prefixed = result.move_as_error().move_as_error_prefix("replay: ");
    ASSERT_TRUE(block::workchain_execution_requires_local_failure(prefixed));
  }
  ASSERT_TRUE(!block::workchain_execution_requires_local_failure(td::Status::Error("invalid candidate")));
  ASSERT_TRUE(!block::workchain_execution_requires_local_failure(td::Status::OK()));
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
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
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
  ASSERT_EQ(split.error().message(), "native ingress policy differs from execution descriptor");
  descriptor.max_split = 0;
  descriptor.vm_mode = 1;
  auto mode_configuration = block_configuration(block::kBlockTransitionMinGlobalVersion, tos::capBlockTransition, 1);
  auto null_config = registry.resolve_block(descriptor, *mode_configuration);
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
  descriptor.workchain_id = 0;
  ASSERT_TRUE(native_registry.execution_scope(block::tvm_workchain_engine_key()) ==
              block::WorkchainExecutionScope::AccountCompute);
  ASSERT_TRUE(native_registry.resolve(descriptor, configuration).is_ok());
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainExecution>(
      native_registry.resolve_scoped(descriptor, configuration).move_as_ok()));
}

TEST(WorkchainBlock, IngressProtocolScopeDoesNotDependOnRegistry) {
  block::WorkchainNativeIngressPolicy ingress;
  ingress.workchain_id = 2;
  ingress.engine_key = block::tvm_workchain_engine_key();
  ingress.engine_configuration = vm::CellBuilder().finalize();
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = static_cast<std::int32_t>(ingress.engine_key.selector);
  block::WorkchainExecutionRegistry empty;
  ASSERT_TRUE(!empty.has_engine(ingress.engine_key));
  ASSERT_TRUE(block::reserved_workchain_engine_scope(ingress.engine_key) ==
              block::WorkchainExecutionScope::AccountCompute);
  ASSERT_TRUE(block::validate_workchain_native_ingress_binding(ingress, descriptor).is_error());
  ingress.engine_key = CounterEngine().engine_key();
  descriptor.vm_version = static_cast<std::int32_t>(ingress.engine_key.selector);
  ASSERT_TRUE(!empty.has_engine(ingress.engine_key));
  ASSERT_TRUE(block::validate_workchain_native_ingress_binding(ingress, descriptor).is_ok());
}

TEST(WorkchainBlock, DeclaredScopePreventsLocalComputeFallback) {
  class WrongLocalEngine final : public block::WorkchainEngine {
   public:
    explicit WrongLocalEngine(unsigned* calls) : calls_(calls) {}
    block::WorkchainEngineKey engine_key() const override { return CounterEngine().engine_key(); }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&) const override {
      ++*calls_;
      return std::shared_ptr<const block::WorkchainEngineConfig>(std::make_shared<block::WorkchainEngineConfig>());
    }
    block::AccountExecutionPolicy account_policy(const block::WorkchainExecutionDescriptor&,
        const block::WorkchainEngineConfig&) const override { return {}; }
    td::Result<block::WorkchainComputeOutput> run_compute(const block::WorkchainComputeInput&,
        const block::WorkchainComputeContext&) const override { return td::Status::Error("not invoked"); }
   private:
    unsigned* calls_;
  };
  unsigned calls = 0;
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<WrongLocalEngine>(&calls));
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = static_cast<std::int32_t>(CounterEngine().engine_key().selector);
  auto declared = block_configuration();
  auto scoped = registry.resolve_scoped(descriptor, *declared);
  auto direct = registry.resolve(descriptor, *declared);
  ASSERT_EQ(calls, 0u);
  ASSERT_TRUE(scoped.is_error());
  ASSERT_TRUE(direct.is_error());
  auto ordinary = block_configuration(block::kBlockTransitionMinGlobalVersion, tos::capBlockTransition, 0, false);
  ASSERT_TRUE(registry.resolve_scoped(descriptor, *ordinary).is_ok());
  ASSERT_EQ(calls, 1u);
}

TEST(WorkchainBlock, RegistryRequiresConsensusActivation) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  auto activated = block_configuration();
  ASSERT_TRUE(registry.resolve_block(descriptor, *activated).is_ok());
  for (int version : {block::kBlockTransitionMinGlobalVersion - 1,
                      block::kBlockTransitionMinGlobalVersion}) {
    for (td::uint64 capabilities : {td::uint64{0}, td::uint64{tos::capBlockTransition}}) {
      auto config = block_configuration(version, capabilities);
      bool expected = version >= block::kBlockTransitionMinGlobalVersion && capabilities != 0;
      ASSERT_EQ(registry.resolve_block(descriptor, *config).is_ok(), expected);
      ASSERT_EQ(registry.resolve_scoped(descriptor, *config).is_ok(), expected);
    }
  }
  block::Config unavailable(0);
  ASSERT_TRUE(registry.resolve_block(descriptor, unavailable).is_error());
}

TEST(WorkchainBlock, PublicIngressPolicyCodecAndDescriptorBinding) {
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x554e4f32};
  policy.vm_mode = 17;
  policy.descriptor_version = 2;
  policy.executor_address = number(9)->get_hash().bits();
  policy.engine_configuration = number(42);
  auto root = block::encode_workchain_native_ingress_policy(policy).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressPolicy.validate_ref(10000, root));
  auto wire = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto decoded = block::decode_workchain_native_ingress_policy(restored).move_as_ok();
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(decoded).move_as_ok()->get_hash() == root->get_hash());
  ASSERT_TRUE(decoded.executor_address == policy.executor_address);
  ASSERT_TRUE(decoded.engine_configuration->get_hash() == policy.engine_configuration->get_hash());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x554e4f32;
  descriptor.vm_mode = 17;
  descriptor.version = 2;
  ASSERT_TRUE(block::validate_workchain_native_ingress_binding(decoded, descriptor).is_ok());
  for (int mutation = 0; mutation < 6; ++mutation) {
    auto changed = descriptor;
    if (mutation == 0) changed.workchain_id = 3;
    if (mutation == 1) changed.vm_version = 1;
    if (mutation == 2) changed.vm_mode = 18;
    if (mutation == 3) changed.version = 3;
    if (mutation == 4) changed.active = false;
    if (mutation == 5) changed.max_split = 1;
    ASSERT_TRUE(block::validate_workchain_native_ingress_binding(decoded, changed).is_error());
  }
  auto invalid = policy;
  invalid.engine_key.selector = std::numeric_limits<std::int64_t>::max();
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(invalid).is_error());
  invalid = policy;
  invalid.workchain_id = -1;
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(invalid).is_error());
  invalid = policy;
  invalid.engine_configuration = {};
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(invalid).is_error());
  auto extended = policy;
  extended.engine_key = {block::WorkchainFormat::Extended, std::numeric_limits<std::uint32_t>::max()};
  extended.vm_mode = 0;
  auto extended_root = block::encode_workchain_native_ingress_policy(extended).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressPolicy.validate_ref(10000, extended_root));
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(extended_root).move_as_ok().engine_key == extended.engine_key);
  extended.vm_mode = 1;
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(extended).is_error());
  auto wide_mode = policy;
  wide_mode.vm_mode = std::numeric_limits<std::uint64_t>::max();
  auto wide_root = block::encode_workchain_native_ingress_policy(wide_mode).move_as_ok();
  ASSERT_EQ(block::decode_workchain_native_ingress_policy(wide_root).move_as_ok().vm_mode, wide_mode.vm_mode);
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy({}).is_error());
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(number(0)).is_error());
  auto extra = vm::CellBuilder().append_cellslice(vm::load_cell_slice(root)).store_long(0, 1).finalize();
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(extra).is_error());
}

TEST(WorkchainBlock, PublicIngressRequiresStandardWorkchainRange) {
  block::WorkchainNativeIngressPolicy policy;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address.set_zero();
  policy.engine_configuration = number(0);
  for (int id : {0, 127, 128, std::numeric_limits<std::int32_t>::max()}) {
    policy.workchain_id = id;
    ASSERT_EQ(block::encode_workchain_native_ingress_policy(policy).is_ok(), id <= 127);
    auto raw = vm::CellBuilder().store_long(0x57495031, 32).store_long(id, 32).store_long(0, 1)
        .store_long(policy.engine_key.selector, 64).store_zeroes(64 + 32 + 256)
        .store_ref(policy.engine_configuration).finalize();
    ASSERT_TRUE(block::gen::t_WorkchainNativeIngressPolicy.validate_ref(10000, raw));
    ASSERT_EQ(block::decode_workchain_native_ingress_policy(raw).is_ok(), id <= 127);
  }
}

TEST(WorkchainBlock, PublicIngressTableCanonicalKeys) {
  block::WorkchainNativeIngressPolicy first;
  first.workchain_id = 2;
  first.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  first.executor_address.set_zero();
  first.engine_configuration = number(1);
  auto second = first;
  second.workchain_id = 3;
  second.engine_configuration = number(2);
  auto encoded = block::encode_workchain_native_ingress_table({first, second}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressTable.validate_ref(10000, encoded));
  auto reversed = block::encode_workchain_native_ingress_table({second, first}).move_as_ok();
  ASSERT_TRUE(encoded->get_hash() == reversed->get_hash());
  auto wire = vm::std_boc_serialize(encoded).move_as_ok();
  auto decoded = block::decode_workchain_native_ingress_table(vm::std_boc_deserialize(wire.as_slice()).move_as_ok())
      .move_as_ok();
  ASSERT_EQ(decoded.size(), 2u);
  ASSERT_TRUE(decoded.at(3).engine_configuration->get_hash() == second.engine_configuration->get_hash());
  auto empty = block::encode_workchain_native_ingress_table({}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressTable.validate_ref(10000, empty));
  ASSERT_TRUE(block::decode_workchain_native_ingress_table(empty).move_as_ok().empty());
  ASSERT_TRUE(block::encode_workchain_native_ingress_table({first, first}).is_error());
  vm::Dictionary wrong(32);
  ASSERT_TRUE(wrong.set_ref(td::BitArray<32>(3u), block::encode_workchain_native_ingress_policy(first).move_as_ok()));
  vm::CellBuilder cb;
  cb.store_long(0x57495431, 32);
  ASSERT_TRUE(std::move(wrong).append_dict_to_bool(cb));
  auto wrong_key = cb.finalize();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressTable.validate_ref(10000, wrong_key));
  ASSERT_TRUE(block::decode_workchain_native_ingress_table(wrong_key).is_error());
  ASSERT_TRUE(block::decode_workchain_native_ingress_table({}).is_error());
  ASSERT_TRUE(block::decode_workchain_native_ingress_table(number(0)).is_error());
}

TEST(WorkchainBlock, NativeSenderEnforcesPublicExecutorAddress) {
  td::Ref<block::WorkchainInfo> info{true};
  info.write().workchain = 2;
  info.write().basic = info.write().active = info.write().accept_msgs = true;
  info.write().min_addr_len = info.write().max_addr_len = 256;
  info.write().addr_len_step = 0;
  block::WorkchainSet workchains{{2, info}};
  info.clear();
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000);
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account sender(2, td::Bits256::zero().bits());
  ASSERT_TRUE(sender.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  block::ActionPhaseConfig cfg;
  cfg.workchains = &workchains;
  cfg.native_ingress_destinations.emplace(2, td::Bits256::zero());
  auto address = [](bool wrong) {
    return vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(2, 8)
        .store_zeroes(255).store_long(wrong, 1).finalize());
  };
  auto send = [&](td::Ref<vm::CellSlice> dest, bool accepted) {
    vm::CellBuilder cb;
    cb.store_long(6, 4).store_zeroes(2);
    ASSERT_TRUE(cb.append_cellslice_bool(dest));
    ASSERT_TRUE(block::CurrencyCollection(100).store(cb));
    cb.store_zeroes(8).store_zeroes(96).store_zeroes(2);
    auto message = cb.finalize();
    ASSERT_TRUE(block::gen::t_MessageRelaxed_Any.validate_ref(4096, message));
    vm::Dictionary requests(15);
    unsigned index = 0;
    ASSERT_TRUE(requests.set_ref(td::BitArray<15>(index), message));
    vm::CellBuilder root;
    ASSERT_TRUE(std::move(requests).append_dict_to_bool(root));
    effects.outbound_messages = root.finalize();
    using Transaction = block::transaction::Transaction;
    Transaction tx(sender, Transaction::tr_workchain_batch, 10, 10);
    block::SerializeConfig serialization;
    auto status = tx.prepare_workchain_batch(in, effects, serialization, &cfg);
    ASSERT_EQ(status.is_ok(), accepted);
    ASSERT_EQ(tx.out_msgs.size(), accepted ? 1u : 0u);
    ASSERT_EQ(tx.balance.tomis->to_long(), accepted ? 900 : 1000);
    ASSERT_EQ(sender.balance.tomis->to_long(), 1000);
    return accepted ? tx.out_msgs.front() : td::Ref<vm::Cell>{};
  };
  auto canonical_message = send(address(false), true);
  send(address(true), false);
  auto variable_address = [](bool wrong) {
    return vm::load_cell_slice_ref(vm::CellBuilder().store_long(6, 3).store_long(256, 9)
        .store_long(2, 32).store_zeroes(255).store_long(wrong, 1).finalize());
  };
  auto normalized_message = send(variable_address(false), true);
  ASSERT_TRUE(normalized_message->get_hash() == canonical_message->get_hash());
  send(variable_address(true), false);
  workchains.at(2).write().accept_msgs = false;
  send(address(false), false);
  send(variable_address(false), false);
  workchains.at(2).write().accept_msgs = true;
  send(address(false), true);
  auto anycast = vm::load_cell_slice_ref(vm::CellBuilder().store_long(2, 2).store_long(1, 1)
      .store_long(1, 5).store_long(0, 1).store_long(2, 8).store_zeroes(256).finalize());
  send(anycast, false);
  cfg.native_ingress_destinations.clear();
  send(address(true), true);
  send(anycast, true);
}

TEST(WorkchainBlock, ActivatedHostWithoutIngressPolicyIsIdle) {
  vm::Dictionary dictionary(32);
  vm::CellBuilder version;
  ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(version, 15, tos::capBlockTransition));
  ASSERT_TRUE(dictionary.set_ref(td::BitArray<32>{8}, version.finalize()));
  ASSERT_TRUE(block::validate_native_ingress_presence(dictionary).is_ok());
  auto config = block::Config::unpack_config(dictionary.get_root_cell(), td::Bits256::zero(),
                                             block::Config::needCapabilities).move_as_ok();
  ASSERT_TRUE(block::load_workchain_native_ingress_table(*config).move_as_ok().empty());
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*config).move_as_ok().empty());
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  auto execution = registry.resolve_block(descriptor, *config);
  ASSERT_TRUE(execution.is_error());
  ASSERT_EQ(execution.error().message(), "block workchain has no public native ingress policy");
  ASSERT_TRUE(dictionary.set_ref(td::BitArray<32>{84}, number(0)));
  config = block::Config::unpack_config(dictionary.get_root_cell(), td::Bits256::zero(),
                                       block::Config::needCapabilities).move_as_ok();
  ASSERT_TRUE(block::load_workchain_native_ingress_table(*config).is_error());
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*config).is_error());
}

TEST(WorkchainBlock, NativeIngressParameterPresenceRequiresActivation) {
  for (int version : {14, 15}) {
    for (td::uint64 capabilities : {td::uint64{0}, td::uint64{tos::capBlockTransition}}) {
      vm::Dictionary config(32);
      vm::CellBuilder param;
      ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(param, version, capabilities));
      ASSERT_TRUE(config.set_ref(td::BitArray<32>{8}, param.finalize()));
      ASSERT_TRUE(block::validate_native_ingress_presence(config).is_ok());
      auto table = block::encode_workchain_native_ingress_table({}).move_as_ok();
      ASSERT_TRUE(config.set_ref(td::BitArray<32>{84}, table));
      ASSERT_EQ(block::validate_native_ingress_presence(config).is_ok(), version >= 15 && capabilities != 0);
    }
  }
  vm::Dictionary missing_version(32);
  ASSERT_TRUE(missing_version.set_ref(td::BitArray<32>{84},
      block::encode_workchain_native_ingress_table({}).move_as_ok()));
  ASSERT_TRUE(block::validate_native_ingress_presence(missing_version).is_error());
  ASSERT_TRUE(missing_version.set_ref(td::BitArray<32>{8}, number(0)));
  ASSERT_TRUE(block::validate_native_ingress_presence(missing_version).is_error());
}

TEST(WorkchainBlock, ResolvedBlockResourcePolicy) {
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
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

TEST(WorkchainBlock, ReceiverRequiresMatchingPublicIngressPolicy) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  auto configuration = [](td::Ref<vm::Cell> table) {
    vm::Dictionary config(32);
    vm::CellBuilder version;
    CHECK(block::gen::t_GlobalVersion.pack_capabilities(version, 15, tos::capBlockTransition));
    CHECK(config.set_ref(td::BitArray<32>{8}, version.finalize()));
    if (table.not_null()) {
      CHECK(config.set_ref(td::BitArray<32>{84}, table));
    }
    return block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
                                       block::Config::needCapabilities).move_as_ok();
  };
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address.set_zero();
  policy.engine_configuration = vm::CellBuilder().finalize();
  auto resolve = [&](std::vector<block::WorkchainNativeIngressPolicy> policies) {
    auto cfg = configuration(block::encode_workchain_native_ingress_table(policies).move_as_ok());
    return registry.resolve_block(descriptor, *cfg);
  };
  ASSERT_TRUE(resolve({policy}).is_ok());
  auto missing = configuration({});
  ASSERT_TRUE(registry.resolve_block(descriptor, *missing).is_error());
  ASSERT_TRUE(resolve({}).is_error());
  auto wrong = policy;
  wrong.workchain_id = 3;
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong = policy;
  wrong.descriptor_version = 1;
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong = policy;
  wrong.executor_address = td::Bits256::ones();
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong = policy;
  wrong.engine_configuration = number(0);
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong.engine_configuration = vm::CellBuilder().store_ref(policy.engine_configuration).finalize();
  ASSERT_TRUE(resolve({wrong}).is_error());
  auto malformed = configuration(number(0));
  ASSERT_TRUE(registry.resolve_block(descriptor, *malformed).is_error());
  ASSERT_TRUE(resolve({policy}).is_ok());
}

TEST(WorkchainBlock, SenderResolvesIngressWithoutForeignEngine) {
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address = td::Bits256::ones();
  policy.engine_configuration = number(0);
  auto configuration = [&](td::Ref<vm::Cell> table, bool include_descriptor, unsigned descriptor_version = 0) {
    vm::Dictionary config(32);
    vm::CellBuilder version;
    CHECK(block::gen::t_GlobalVersion.pack_capabilities(version, 15, tos::capBlockTransition));
    CHECK(config.set_ref(td::BitArray<32>{8}, version.finalize()));
    if (table.not_null()) {
      CHECK(config.set_ref(td::BitArray<32>{84}, table));
    }
    vm::Dictionary workchains(32);
    if (include_descriptor) {
      vm::CellBuilder descriptor;
      descriptor.store_long(0xa6, 8).store_zeroes(32 + 24).store_long(7, 3).store_zeroes(13)
          .store_zeroes(512).store_long(descriptor_version, 32).store_long(1, 4)
          .store_long(0x434e5431, 32).store_zeroes(64);
      auto encoded = descriptor.finalize();
      CHECK(block::gen::t_WorkchainDescr.validate_ref(10000, encoded));
      CHECK(workchains.set(td::BitArray<32>{2}, vm::load_cell_slice_ref(encoded)));
    }
    vm::CellBuilder list;
    CHECK(std::move(workchains).append_dict_to_bool(list));
    CHECK(config.set_ref(td::BitArray<32>{12}, list.finalize()));
    return block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
        block::Config::needCapabilities | block::Config::needWorkchainInfo).move_as_ok();
  };
  auto table = block::encode_workchain_native_ingress_table({policy}).move_as_ok();
  auto good = configuration(table, true);
  ASSERT_TRUE(!block::default_workchain_execution_registry().execution_scope(policy.engine_key).has_value());
  auto destinations = block::resolve_native_ingress_destinations(*good).move_as_ok();
  ASSERT_EQ(destinations.size(), 1u);
  ASSERT_TRUE(destinations.at(2) == policy.executor_address);
  auto missing_descriptor = configuration(table, false);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*missing_descriptor).is_error());
  auto wrong_version = configuration(table, true, 1);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*wrong_version).is_error());
  auto missing_table = configuration({}, true);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*missing_table).move_as_ok().empty());
  auto empty = configuration(block::encode_workchain_native_ingress_table({}).move_as_ok(), true);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*empty).move_as_ok().empty());
}

TEST(WorkchainBlock, ScopedWorkchainConfigurationResolution) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
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
  ASSERT_EQ(split.error().message(), "native ingress policy differs from execution descriptor");
  auto invalid_required = registry.validate_required_workchains(workchains, configuration, roles);
  ASSERT_TRUE(invalid_required.is_error());
  ASSERT_EQ(invalid_required.error().message(), "native ingress policy differs from execution descriptor");
  workchains[2].write().max_split = 0;
  workchains[2].write().workchain = 3;
  auto mismatch = registry.resolve_scoped_workchain(workchains, 2, configuration);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "workchain descriptor identity differs from configuration key");
  workchains[2].write().workchain = 2;
  workchains[2].write().vm_version = static_cast<std::int32_t>(block::tvm_workchain_engine_key().selector);
  ASSERT_TRUE(block::default_workchain_execution_registry()
                  .validate_required_workchains(workchains, configuration, roles).is_error());
}
