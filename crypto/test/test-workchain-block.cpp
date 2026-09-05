#include <limits>

#include "block/workchain-block-execution.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "block/block-auto.h"

namespace {

td::Ref<vm::Cell> number(std::uint64_t value) {
  return vm::CellBuilder().store_long(value, 64).finalize();
}

class CounterEngine final : public block::RegisteredWorkchainBlockEngine {
 public:
  block::WorkchainEngineKey engine_key() const override {
    return {block::WorkchainFormat::Basic, 0x434e5431};
  }

  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor, const block::Config&) const override {
    if (descriptor.min_split != 0 || descriptor.max_split != 0) {
      return td::Status::Error("counter requires an unsplit workchain");
    }
    if (descriptor.vm_mode != 0) {
      return std::shared_ptr<const block::WorkchainEngineConfig>{};
    }
    return std::shared_ptr<const block::WorkchainEngineConfig>(std::make_shared<block::WorkchainEngineConfig>());
  }

  td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput& input) const override {
    auto state = vm::load_cell_slice(input.previous_shard_state);
    auto candidate = vm::load_cell_slice(input.candidate);
    if (state.size() != 64 || state.size_refs() != 0 || candidate.size() != 64 || candidate.size_refs() != 0) {
      return td::Status::Error("counter input shape");
    }
    const auto value = state.fetch_ulong(64);
    const auto increment = candidate.fetch_ulong(64);
    if (increment > std::numeric_limits<std::uint64_t>::max() - value) {
      return td::Status::Error("counter overflow");
    }
    block::WorkchainBlockResult result;
    result.new_shard_state = number(value + increment);
    result.batch_transaction = vm::CellBuilder().store_ref(input.previous_shard_state)
                                   .store_ref(result.new_shard_state).store_ref(input.candidate).finalize();
    result.outbound_messages = number(0);
    result.actions = input.candidate;
    result.receipts = result.new_shard_state;
    result.events = number(increment);
    result.data_availability = input.candidate;
    result.usage = {8, 1, 3};
    return result;
  }
};

block::WorkchainBlockInput input() {
  return {number(40), number(2), number(1), number(1)};
}

}  // namespace

TEST(WorkchainBlock, CounterReplay) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(produced.new_shard_state).fetch_ulong(64), 42u);
  auto validated = block::replay_workchain_block(engine, in, produced).move_as_ok();
  ASSERT_TRUE(validated.new_shard_state->get_hash() == produced.new_shard_state->get_hash());
  ASSERT_EQ(vm::load_cell_slice(in.previous_shard_state).fetch_ulong(64), 40u);
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
      &block::WorkchainBlockResult::new_shard_state, &block::WorkchainBlockResult::batch_transaction,
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
  auto outputs = cs.prefetch_ref(2);
  auto envelope = [&](std::uint32_t tag, td::Ref<vm::Cell> out, unsigned extra_bits, unsigned refs) {
    vm::CellBuilder cb;
    cb.store_long(tag, 32).store_long(8, 64).store_long(1, 64).store_long(3, 64);
    if (extra_bits) cb.store_long(0, extra_bits);
    td::Ref<vm::Cell> children[] = {produced.new_shard_state, produced.batch_transaction, out,
                                  produced.data_availability};
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
  reject(envelope(0x57425231, output_proof, 0, 4), "invalid block output envelope");
  reject(envelope(0x57425230, outputs, 0, 4), "invalid block result envelope");
  reject(envelope(0x57425231, outputs, 1, 4), "invalid block result envelope");
  reject(envelope(0x57425231, outputs, 0, 3), "invalid block result envelope");
  for (int mutation = 0; mutation < 3; ++mutation) {
    vm::CellBuilder cb;
    cb.store_long(mutation == 0 ? 0x57424f30 : 0x57424f31, 32);
    if (mutation == 1) cb.store_long(0, 1);
    cb.store_ref(produced.outbound_messages).store_ref(produced.actions).store_ref(produced.receipts);
    if (mutation != 2) cb.store_ref(produced.events);
    reject(envelope(0x57425231, cb.finalize(), 0, 4), "invalid block output envelope");
  }
}

TEST(WorkchainBlock, RejectEveryResultMutation) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  td::Ref<vm::Cell> block::WorkchainBlockResult::* fields[] = {
      &block::WorkchainBlockResult::new_shard_state, &block::WorkchainBlockResult::batch_transaction,
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
  in.previous_shard_state = number(std::numeric_limits<std::uint64_t>::max());
  auto overflow = block::replay_workchain_block(engine, in, produced);
  ASSERT_TRUE(overflow.is_error());
  ASSERT_EQ(overflow.error().message(), "counter overflow");
  in = input();
  in.finality_context = {};
  auto missing = block::replay_workchain_block(engine, in, produced);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "block replay requires state, candidate, configuration and finality");
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
  auto in = input();
  auto produced = resolved.executor->execute_block(in).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(produced.new_shard_state).fetch_ulong(64), 42u);
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
}
