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
*/
#include "block/block-auto.h"
#include "block/evm-workchain-dispatch.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "uno/core/dispatch-engine.h"
#include "evm/core/dispatch-engine.h"
#include "evm/core/workchain.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"

#include <cstdint>
#include <functional>
#include <memory>

namespace {

constexpr std::int32_t kEvmVmVersion = 0x45564D;
constexpr std::int32_t kUnoVmVersion = 0x554E4F31;
constexpr std::int32_t kDummyVmVersion = 0x44554D59;  // "DUMY"
constexpr std::uint32_t kDummyExtendedType = 0x00ABCDEF;

struct DummyEngineConfig final : public block::WorkchainEngineConfig {
};

struct CountingEngineConfig final : public block::WorkchainEngineConfig {
  int resolve_number{0};
};

class DummyEngine final : public block::WorkchainEngine {
 public:
  explicit DummyEngine(block::WorkchainEngineKey key, bool reject_config = false)
      : key_(key), reject_config_(reject_config) {
  }

  block::WorkchainEngineKey engine_key() const override {
    return key_;
  }

  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor,
      const block::Config& /*block_transition_config*/) const override {
    if (block::workchain_engine_key_from_descriptor(descriptor) != key_) {
      return td::Status::Error("dummy engine received the wrong descriptor key");
    }
    if (reject_config_) {
      return td::Status::Error("dummy engine rejected descriptor config");
    }
    std::shared_ptr<const block::WorkchainEngineConfig> result = std::make_shared<DummyEngineConfig>();
    return result;
  }

  block::AccountExecutionPolicy account_policy(
      const block::WorkchainExecutionDescriptor& /*descriptor*/,
      const block::WorkchainEngineConfig& /*engine_config*/) const override {
    return {};
  }

  td::Result<block::WorkchainComputeOutput> run_compute(
      const block::WorkchainComputeInput& /*input*/,
      const block::WorkchainComputeContext& /*context*/) const override {
    return td::Status::Error("dummy engine is not executable");
  }

 private:
  block::WorkchainEngineKey key_;
  bool reject_config_{false};
};

class CountingEngine final : public block::WorkchainEngine {
 public:
  explicit CountingEngine(block::WorkchainEngineKey key, int& resolve_count)
      : key_(key), resolve_count_(resolve_count) {
  }

  block::WorkchainEngineKey engine_key() const override {
    return key_;
  }

  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor,
      const block::Config& /*block_transition_config*/) const override {
    if (block::workchain_engine_key_from_descriptor(descriptor) != key_) {
      return td::Status::Error("counting engine received the wrong descriptor key");
    }
    auto config = std::make_shared<CountingEngineConfig>();
    config->resolve_number = ++resolve_count_;
    std::shared_ptr<const block::WorkchainEngineConfig> result = config;
    return result;
  }

  block::AccountExecutionPolicy account_policy(
      const block::WorkchainExecutionDescriptor& /*descriptor*/,
      const block::WorkchainEngineConfig& /*engine_config*/) const override {
    return {};
  }

  td::Result<block::WorkchainComputeOutput> run_compute(
      const block::WorkchainComputeInput& /*input*/,
      const block::WorkchainComputeContext& /*context*/) const override {
    return td::Status::Error("counting engine is not executable");
  }

 private:
  block::WorkchainEngineKey key_;
  int& resolve_count_;
};

block::WorkchainExecutionDescriptor make_basic_descriptor(
    tos::WorkchainId workchain_id, std::int32_t vm_version, std::uint64_t vm_mode) {
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = workchain_id;
  descriptor.active = true;
  descriptor.accept_msgs = true;
  descriptor.format = block::WorkchainFormat::Basic;
  descriptor.vm_version = vm_version;
  descriptor.vm_mode = vm_mode;
  descriptor.min_addr_len = descriptor.max_addr_len = 256;
  return descriptor;
}

td::Ref<block::WorkchainInfo> make_basic_workchain_info(
    tos::WorkchainId workchain_id, std::int32_t vm_version, std::uint64_t vm_mode) {
  td::Ref<block::WorkchainInfo> info{true};
  auto& w = info.unique_write();
  w.workchain = workchain_id;
  w.enabled_since = 1;
  w.monitor_min_split = 0;
  w.min_split = 0;
  w.max_split = 0;
  w.basic = true;
  w.active = true;
  w.accept_msgs = true;
  w.flags = 0;
  w.version = 0;
  w.vm_version = vm_version;
  w.vm_mode = vm_mode;
  w.workchain_type_id = 0;
  w.min_addr_len = w.max_addr_len = 256;
  w.addr_len_step = 0;
  return info;
}

td::Ref<vm::Cell> build_extended_workchain_descr(std::uint32_t workchain_type_id) {
  vm::CellBuilder cb;
  cb.store_long(0xa6, 8);      // workchain#a6
  cb.store_long(1, 32);        // enabled_since
  cb.store_long(0, 8);         // monitor_min_split
  cb.store_long(0, 8);         // min_split
  cb.store_long(0, 8);         // max_split
  cb.store_long(0x6000, 16);   // basic=false, active=true, accept_msgs=true, flags=0
  cb.store_zeroes(512);        // zerostate hashes
  cb.store_long(0, 32);        // version
  cb.store_long(0, 4);         // wfmt_ext#0
  cb.store_long(64, 12);       // min_addr_len
  cb.store_long(256, 12);      // max_addr_len
  cb.store_long(8, 12);        // addr_len_step
  cb.store_long(workchain_type_id, 32);
  auto cell = cb.finalize();
  CHECK(block::gen::t_WorkchainDescr.validate_ref(cell));
  return cell;
}

block::Config make_empty_config() {
  return block::Config{0};
}

td::Ref<vm::Cell> make_marker_cell(std::uint8_t value) {
  vm::CellBuilder cb;
  cb.store_long(value, 8);
  return cb.finalize();
}

tos::StdSmcAddress singleton_executor_address() {
  tos::StdSmcAddress addr;
  addr.set_zero();
  addr.data()[31] = 1;
  return addr;
}

td::Ref<vm::Cell> build_external_message(tos::WorkchainId workchain_id,
                                         const tos::StdSmcAddress& dest,
                                         td::Ref<vm::Cell> body) {
  vm::CellBuilder cb;
  bool ok = cb.store_long_bool(0b10, 2)       // ext_in_msg_info$10
            && cb.store_long_bool(0b00, 2)    // src:addr_none$00
            && cb.store_long_bool(0b100, 3)   // dest:addr_std$10, anycast=0
            && cb.store_long_bool(workchain_id, 8)
            && cb.store_bits_bool(dest)
            && cb.store_long_bool(0, 4)       // import_fee:Grams = 0
            && cb.store_long_bool(0, 1)       // init:Nothing
            && cb.store_long_bool(1, 1)       // body in ref
            && cb.store_ref_bool(std::move(body));
  CHECK(ok);
  auto cell = cb.finalize();
  CHECK(block::gen::t_Message_Any.validate_ref(cell));
  return cell;
}

// Mock EVM engine for tests that need to inject a fake compute function.
// Wraps a lambda with the same signature as the old EvmComputeHandler but
// without the chain_id parameter (chain_id is extracted from the engine config
// and passed in separately so tests can assert on it).
using MockEvmComputeFn = std::function<bool(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> account_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t chain_id,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32])>;

struct MockEvmEngineConfig final : public block::WorkchainEngineConfig {
  std::uint64_t chain_id{0};
};

class MockEvmEngine final : public block::WorkchainEngine {
 public:
  explicit MockEvmEngine(MockEvmComputeFn fn) : fn_(std::move(fn)) {}

  block::WorkchainEngineKey engine_key() const override {
    return block::evm_workchain_engine_key();
  }

  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor,
      const block::Config& /*block_transition_config*/) const override {
    if (!block::workchain_engine_key_is_evm(
            block::workchain_engine_key_from_descriptor(descriptor))) {
      return td::Status::Error("MockEvmEngine received non-EVM descriptor");
    }
    if (descriptor.vm_mode == 0) {
      return td::Status::Error("MockEvmEngine: legacy vm_mode=0; expected chain id");
    }
    auto cfg = std::make_shared<MockEvmEngineConfig>();
    cfg->chain_id = descriptor.vm_mode;
    std::shared_ptr<const block::WorkchainEngineConfig> result = cfg;
    return result;
  }

  block::AccountExecutionPolicy account_policy(
      const block::WorkchainExecutionDescriptor& /*descriptor*/,
      const block::WorkchainEngineConfig& /*engine_config*/) const override {
    block::AccountExecutionPolicy policy;
    policy.kind = block::AccountExecutionPolicyKind::SingletonExecutor;
    tos::StdSmcAddress addr;
    addr.set_zero();
    addr.data()[31] = 1;
    policy.singleton_address = addr;
    policy.accepts_external_inbound = true;
    policy.accepts_internal_inbound = true;
    policy.may_activate_uninitialized_account = true;
    policy.activation_code = evm_workchain_dispatch::get_evm_code_marker_cell();
    return policy;
  }

  td::Result<block::WorkchainComputeOutput> run_compute(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& context) const override {
    auto* cfg = dynamic_cast<const MockEvmEngineConfig*>(context.engine_config.get());
    if (cfg == nullptr || cfg->chain_id == 0) {
      return td::Status::Error("MockEvmEngine missing resolved chain id");
    }
    if (input.inbound_body.is_null()) {
      block::WorkchainComputeOutput out;
      out.completed = true;
      out.skip_reason = block::ComputePhase::sk_bad_state;
      return out;
    }
    block::ComputePhase cp{};
    vm::CellSlice body_cs{*input.inbound_body};
    bool ok = fn_(cp, input.current_data, body_cs, input.gas_limit,
                  cfg->chain_id, context.block_seqno, context.now,
                  context.rand_seed.data(), context.parent_block_hash.data());
    if (!ok) {
      return td::Status::Error("MockEvmEngine compute fn failed");
    }
    block::WorkchainComputeOutput out;
    out.skip_reason = cp.skip_reason;
    out.completed = true;
    out.accepted = cp.accepted;
    out.committed = cp.accepted && cp.new_data.not_null();
    out.engine_success = cp.success;
    out.msg_state_used = cp.msg_state_used;
    out.account_activated = cp.account_activated;
    out.out_of_gas = cp.out_of_gas;
    out.mode = cp.mode;
    out.exit_code = cp.exit_code;
    out.exit_arg = cp.exit_arg;
    out.vm_steps = cp.vm_steps;
    out.vm_init_state_hash = cp.vm_init_state_hash;
    out.vm_final_state_hash = cp.vm_final_state_hash;
    out.gas_used = cp.gas_used;
    out.gas_fees = cp.gas_fees.not_null() ? cp.gas_fees : td::zero_refint();
    out.new_data = cp.new_data;
    out.action_list = cp.actions;
    out.vm_log = cp.vm_log;
    return out;
  }

 private:
  MockEvmComputeFn fn_;
};

// Mock Uno engine for tests that need to inject a fake compute function.
// Tests that need a mock compute handler register a MockUnoEngine directly
// with a local WorkchainExecutionRegistry.
using MockUnoComputeFn = std::function<bool(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> state_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32])>;

struct MockUnoEngineConfig final : public block::WorkchainEngineConfig {
};

class MockUnoEngine final : public block::WorkchainEngine {
 public:
  explicit MockUnoEngine(MockUnoComputeFn fn,
                         bool may_activate_uninitialized_account = true,
                         block::AccountExecutionPolicyKind policy_kind =
                             block::AccountExecutionPolicyKind::SingletonExecutor)
      : fn_(std::move(fn))
      , may_activate_uninitialized_account_(may_activate_uninitialized_account)
      , policy_kind_(policy_kind) {}

  block::WorkchainEngineKey engine_key() const override {
    return block::uno_workchain_engine_key();
  }

  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor,
      const block::Config& /*block_transition_config*/) const override {
    if (!block::workchain_engine_key_is_uno(
            block::workchain_engine_key_from_descriptor(descriptor))) {
      return td::Status::Error("MockUnoEngine received non-Uno descriptor");
    }
    if (descriptor.vm_mode != 0) {
      return td::Status::Error("MockUnoEngine: Uno v1 requires vm_mode=0");
    }
    std::shared_ptr<const block::WorkchainEngineConfig> result =
        std::make_shared<MockUnoEngineConfig>();
    return result;
  }

  block::AccountExecutionPolicy account_policy(
      const block::WorkchainExecutionDescriptor& /*descriptor*/,
      const block::WorkchainEngineConfig& /*engine_config*/) const override {
    block::AccountExecutionPolicy policy;
    policy.kind = policy_kind_;
    tos::StdSmcAddress addr;
    addr.set_zero();
    addr.data()[31] = 1;
    if (policy.kind == block::AccountExecutionPolicyKind::SingletonExecutor) {
      policy.singleton_address = addr;
    }
    policy.accepts_external_inbound = true;
    policy.accepts_internal_inbound = true;
    policy.may_activate_uninitialized_account = may_activate_uninitialized_account_;
    // Build the 0x55 'U' marker cell inline (same as UnoNativeEngine).
    vm::CellBuilder cb;
    cb.store_long(0x55, 8);
    policy.activation_code = cb.finalize();
    return policy;
  }

  td::Result<block::WorkchainComputeOutput> run_compute(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& context) const override {
    if (input.inbound_body.is_null()) {
      block::WorkchainComputeOutput out;
      out.completed = true;
      out.skip_reason = block::ComputePhase::sk_bad_state;
      return out;
    }
    block::ComputePhase cp{};
    vm::CellSlice body_cs{*input.inbound_body};
    bool ok = fn_(cp, input.current_data, body_cs, input.gas_limit,
                  context.block_seqno, context.now,
                  context.rand_seed.data());
    if (!ok) {
      return td::Status::Error("MockUnoEngine compute fn failed");
    }
    block::WorkchainComputeOutput out;
    out.skip_reason = cp.skip_reason;
    out.completed = true;
    out.accepted = cp.accepted;
    out.committed = cp.accepted && cp.new_data.not_null();
    out.engine_success = cp.success;
    out.msg_state_used = cp.msg_state_used;
    out.account_activated = cp.account_activated;
    out.out_of_gas = cp.out_of_gas;
    out.mode = cp.mode;
    out.exit_code = cp.exit_code;
    out.exit_arg = cp.exit_arg;
    out.vm_steps = cp.vm_steps;
    out.vm_init_state_hash = cp.vm_init_state_hash;
    out.vm_final_state_hash = cp.vm_final_state_hash;
    out.gas_used = cp.gas_used;
    out.gas_fees = cp.gas_fees.not_null() ? cp.gas_fees : td::zero_refint();
    out.new_data = cp.new_data;
    out.action_list = cp.actions;
    out.vm_log = cp.vm_log;
    return out;
  }

 private:
  MockUnoComputeFn fn_;
  bool may_activate_uninitialized_account_;
  block::AccountExecutionPolicyKind policy_kind_;
};

}  // namespace

TEST(WorkchainExecutionRegistry, NormalizesBasicAndExtendedSelectors) {
  auto basic_info = make_basic_workchain_info(7, kDummyVmVersion, 123);
  auto basic_descriptor = block::normalize_workchain_descriptor(*basic_info).move_as_ok();
  CHECK(basic_descriptor.format == block::WorkchainFormat::Basic);
  CHECK(basic_descriptor.vm_version == kDummyVmVersion);
  CHECK(basic_descriptor.vm_mode == 123);
  CHECK(basic_descriptor.workchain_type_id == 0);
  auto basic_key = block::workchain_engine_key_from_descriptor(basic_descriptor);
  CHECK(basic_key.format == block::WorkchainFormat::Basic);
  CHECK(basic_key.selector == kDummyVmVersion);
  CHECK(!block::workchain_engine_key_is_tvm(basic_key));
  CHECK(!block::workchain_engine_key_is_evm(basic_key));
  CHECK(!block::workchain_engine_key_is_uno(basic_key));

  auto ext_cell = build_extended_workchain_descr(kDummyExtendedType);
  auto ext_cs = vm::load_cell_slice(ext_cell);
  td::Ref<block::WorkchainInfo> ext_info{true};
  CHECK(ext_info.unique_write().unpack(8, ext_cs));
  auto ext_descriptor = block::normalize_workchain_descriptor(*ext_info).move_as_ok();
  CHECK(ext_descriptor.format == block::WorkchainFormat::Extended);
  CHECK(ext_descriptor.vm_version == 0);
  CHECK(ext_descriptor.vm_mode == 0);
  CHECK(ext_descriptor.workchain_type_id == kDummyExtendedType);
  CHECK(ext_descriptor.min_addr_len == 64);
  CHECK(ext_descriptor.max_addr_len == 256);
  CHECK(ext_descriptor.addr_len_step == 8);
  auto ext_key = block::workchain_engine_key_from_descriptor(ext_descriptor);
  CHECK(ext_key.format == block::WorkchainFormat::Extended);
  CHECK(ext_key.selector == kDummyExtendedType);
  CHECK(!block::workchain_engine_key_is_tvm(ext_key));
  CHECK(!block::workchain_engine_key_is_evm(ext_key));
  CHECK(!block::workchain_engine_key_is_uno(ext_key));

  CHECK(block::tvm_workchain_engine_key() ==
        (block::WorkchainEngineKey{block::WorkchainFormat::Basic, -1}));
  CHECK(block::evm_workchain_engine_key() ==
        (block::WorkchainEngineKey{block::WorkchainFormat::Basic, kEvmVmVersion}));
  CHECK(block::uno_workchain_engine_key() ==
        (block::WorkchainEngineKey{block::WorkchainFormat::Basic, kUnoVmVersion}));
  CHECK(block::workchain_engine_key_is_tvm(block::tvm_workchain_engine_key()));
  CHECK(block::workchain_engine_key_is_evm(block::evm_workchain_engine_key()));
  CHECK(block::workchain_engine_key_is_uno(block::uno_workchain_engine_key()));
}

TEST(WorkchainExecutionRegistry, ResolveFailsClosedForMissingAndRejectedEngines) {
  auto config = make_empty_config();
  auto descriptor = make_basic_descriptor(7, kDummyVmVersion, 0);

  block::WorkchainExecutionRegistry registry;
  auto missing = registry.resolve(descriptor, config);
  CHECK(missing.is_error());

  registry.register_engine_if_absent(std::make_unique<DummyEngine>(
      block::WorkchainEngineKey{block::WorkchainFormat::Basic, kDummyVmVersion}, true));
  auto rejected = registry.resolve(descriptor, config);
  CHECK(rejected.is_error());
}

TEST(WorkchainExecutionRegistry, RegisterIfAbsentAndPreflightRequiredWorkchains) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(7, make_basic_workchain_info(7, kDummyVmVersion, 0));

  block::LocalWorkchainRoleSet roles;
  roles.required_workchains.insert(7);

  block::WorkchainExecutionRegistry registry;
  CHECK(registry.validate_required_workchains(workchains, config, roles).is_error());

  CHECK(registry.register_engine_if_absent(std::make_unique<DummyEngine>(
      block::WorkchainEngineKey{block::WorkchainFormat::Basic, kDummyVmVersion})));
  CHECK(!registry.register_engine_if_absent(std::make_unique<DummyEngine>(
      block::WorkchainEngineKey{block::WorkchainFormat::Basic, kDummyVmVersion})));
  CHECK(registry.validate_required_workchains(workchains, config, roles).is_ok());
}

TEST(WorkchainExecutionRegistry, ResolveRevalidatesConfigForEachSnapshot) {
  auto config = make_empty_config();
  auto descriptor = make_basic_descriptor(7, kDummyVmVersion, 0);
  int resolve_count = 0;

  block::WorkchainExecutionRegistry registry;
  CHECK(registry.register_engine_if_absent(std::make_unique<CountingEngine>(
      block::WorkchainEngineKey{block::WorkchainFormat::Basic, kDummyVmVersion}, resolve_count)));

  auto first = registry.resolve(descriptor, config).move_as_ok();
  auto* first_config = dynamic_cast<const CountingEngineConfig*>(first.engine_config.get());
  CHECK(first_config != nullptr);
  CHECK(first_config->resolve_number == 1);
  CHECK(resolve_count == 1);

  auto second = registry.resolve(descriptor, config).move_as_ok();
  auto* second_config = dynamic_cast<const CountingEngineConfig*>(second.engine_config.get());
  CHECK(second_config != nullptr);
  CHECK(second_config->resolve_number == 2);
  CHECK(resolve_count == 2);
  CHECK(first.engine_config.get() != second.engine_config.get());
}

TEST(WorkchainExecutionRegistry, RejectsActiveExecutionDescriptorTransitionsWithoutMigration) {
  block::WorkchainSet old_workchains;
  block::WorkchainSet new_workchains;

  old_workchains.emplace(7, make_basic_workchain_info(7, kEvmVmVersion, 0x544F53));
  new_workchains.emplace(7, make_basic_workchain_info(7, kEvmVmVersion, 0x544F53));
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_ok());

  new_workchains[7] = make_basic_workchain_info(7, kUnoVmVersion, 0);
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[7] = make_basic_workchain_info(7, kEvmVmVersion, 0x544F54);
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[7] = make_basic_workchain_info(7, kEvmVmVersion, 0x544F53);
  new_workchains[7].unique_write().version = 1;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  old_workchains[7].unique_write().active = false;
  new_workchains[7] = make_basic_workchain_info(7, kUnoVmVersion, 0);
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_ok());
}

TEST(WorkchainExecutionRegistry, EvmAndUnoDescriptorEnginesValidateConfig) {
  auto config = make_empty_config();
  block::WorkchainExecutionRegistry registry;
  CHECK(block::workchain_execution_capability_flags(registry) == 0);

  evm_workchain::register_evm_workchain_engine(registry);
  CHECK((block::workchain_execution_capability_flags(registry) &
         block::kTosNodeCapabilityWorkchainEvm) != 0);
  CHECK((block::workchain_execution_capability_flags(registry) &
         block::kTosNodeCapabilityWorkchainUno) == 0);

  uno_workchain::register_uno_workchain_engine(registry);
  CHECK((block::workchain_execution_capability_flags(registry) &
         block::kTosNodeCapabilityWorkchainEvm) != 0);
  CHECK((block::workchain_execution_capability_flags(registry) &
         block::kTosNodeCapabilityWorkchainUno) != 0);

  auto legacy_evm = make_basic_descriptor(1, kEvmVmVersion, 0);
  CHECK(registry.resolve(legacy_evm, config).is_error());

  auto evm = make_basic_descriptor(1, kEvmVmVersion, 0x544F53);
  auto evm_res = registry.resolve(evm, config);
  CHECK(evm_res.is_ok());
  auto evm_execution = evm_res.move_as_ok();
  CHECK(block::resolved_workchain_execution_is_custom(evm_execution));
  CHECK(block::resolved_workchain_execution_is_evm(evm_execution));
  auto evm_policy = evm_execution.executor->account_policy(
      evm_execution.descriptor, *evm_execution.engine_config);
  CHECK(evm_policy.kind == block::AccountExecutionPolicyKind::SingletonExecutor);
  CHECK(evm_policy.singleton_address.has_value());
  CHECK(evm_policy.activation_code.not_null());

  auto uno = make_basic_descriptor(2, kUnoVmVersion, 0);
  auto uno_res = registry.resolve(uno, config);
  CHECK(uno_res.is_ok());
  auto uno_execution = uno_res.move_as_ok();
  CHECK(block::resolved_workchain_execution_is_custom(uno_execution));
  CHECK(!block::resolved_workchain_execution_is_evm(uno_execution));
  auto uno_policy = uno_execution.executor->account_policy(
      uno_execution.descriptor, *uno_execution.engine_config);
  CHECK(uno_policy.kind == block::AccountExecutionPolicyKind::SingletonExecutor);
  CHECK(uno_policy.singleton_address.has_value());
  CHECK(uno_policy.activation_code.not_null());

  auto bad_uno = make_basic_descriptor(2, kUnoVmVersion, 1);
  CHECK(registry.resolve(bad_uno, config).is_error());
}

TEST(WorkchainExecutionRegistry, EvmRevertCommitsHostStateButReportsEngineFailure) {
  auto config = make_empty_config();
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockEvmEngine>(
      [](block::ComputePhase& cp,
         td::Ref<vm::Cell> /*account_data*/,
         vm::CellSlice& /*in_msg_body*/,
         uint64_t gas_limit,
         uint64_t chain_id,
         uint64_t /*block_seqno*/,
         uint64_t /*timestamp*/,
         const uint8_t /*rand_seed*/[32],
         const uint8_t /*parent_block_hash*/[32]) {
        CHECK(chain_id == 0x544F53);
        cp.accepted = true;
        cp.success = false;
        cp.gas_used = 21;
        cp.gas_limit = gas_limit;
        cp.gas_fees = td::make_refint(7);
        cp.exit_code = 1;
        cp.new_data = make_marker_cell(0xEE);
        return true;
      }));

  auto descriptor = make_basic_descriptor(1, kEvmVmVersion, 0x544F53);
  auto resolved = registry.resolve(descriptor, config).move_as_ok();

  block::WorkchainComputeInput input;
  input.inbound_body = vm::load_cell_slice_ref(make_marker_cell(0x01));
  input.gas_limit = 100;

  block::WorkchainComputeContext context;
  context.workchain_id = 1;
  context.descriptor = resolved.descriptor;
  context.engine_config = resolved.engine_config;
  context.block_transition_config = &config;

  auto output = resolved.executor->run_compute(input, context).move_as_ok();
  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(output.committed);
  CHECK(!output.engine_success);
  CHECK(output.gas_fees.not_null());
  CHECK(td::cmp(output.gas_fees, td::make_refint(7)) == 0);
  CHECK(output.new_data.not_null());
}

TEST(WorkchainExecutionRegistry, EvmComputeUsesDescriptorChainIdNotDefaultSingleton) {
  auto config = make_empty_config();

  constexpr std::uint64_t kDescriptorChainId = 0x22222222;
  CHECK(kDescriptorChainId != evm_workchain::kEvmChainId);

  std::uint64_t observed_chain_id = 0;
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockEvmEngine>(
      [&](block::ComputePhase& cp,
          td::Ref<vm::Cell> /*account_data*/,
          vm::CellSlice& /*in_msg_body*/,
          uint64_t /*gas_limit*/,
          uint64_t chain_id,
          uint64_t /*block_seqno*/,
          uint64_t /*timestamp*/,
          const uint8_t /*rand_seed*/[32],
          const uint8_t /*parent_block_hash*/[32]) {
        observed_chain_id = chain_id;
        cp.accepted = true;
        cp.success = true;
        cp.gas_used = 1;
        cp.gas_fees = td::make_refint(1);
        cp.new_data = make_marker_cell(0xCD);
        return true;
      }));

  auto descriptor = make_basic_descriptor(1, kEvmVmVersion, kDescriptorChainId);
  auto resolved = registry.resolve(descriptor, config).move_as_ok();

  block::WorkchainComputeInput input;
  input.inbound_body = vm::load_cell_slice_ref(make_marker_cell(0x01));
  input.gas_limit = 100;

  block::WorkchainComputeContext context;
  context.workchain_id = 1;
  context.descriptor = resolved.descriptor;
  context.engine_config = resolved.engine_config;
  context.block_transition_config = &config;

  auto output = resolved.executor->run_compute(input, context).move_as_ok();
  CHECK(output.completed);
  CHECK(output.committed);
  CHECK(output.engine_success);
  CHECK(observed_chain_id == kDescriptorChainId);
}

TEST(WorkchainExecutionRegistry, EvmAndUnoAcceptNullCurrentCodeBeforeActivation) {
  auto config = make_empty_config();
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockEvmEngine>(
      [](block::ComputePhase& cp,
         td::Ref<vm::Cell> account_data,
         vm::CellSlice& /*in_msg_body*/,
         uint64_t /*gas_limit*/,
         uint64_t /*chain_id*/,
         uint64_t /*block_seqno*/,
         uint64_t /*timestamp*/,
         const uint8_t /*rand_seed*/[32],
         const uint8_t /*parent_block_hash*/[32]) {
        CHECK(account_data.is_null());
        cp.accepted = true;
        cp.success = true;
        cp.gas_used = 1;
        cp.gas_fees = td::make_refint(1);
        cp.new_data = make_marker_cell(0xE1);
        return true;
      }));
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [](block::ComputePhase& cp,
         td::Ref<vm::Cell> state_data,
         vm::CellSlice& /*in_msg_body*/,
         uint64_t /*gas_limit*/,
         uint64_t /*block_seqno*/,
         uint64_t /*timestamp*/,
         const uint8_t /*rand_seed*/[32]) {
        CHECK(state_data.is_null());
        cp.accepted = true;
        cp.success = true;
        cp.gas_used = 1;
        cp.gas_fees = td::make_refint(1);
        cp.new_data = make_marker_cell(0xA1);
        return true;
      }));

  auto run_with_null_code = [&](const block::ResolvedWorkchainExecution& resolved) {
    auto policy = resolved.executor->account_policy(resolved.descriptor, *resolved.engine_config);
    CHECK(policy.activation_code.not_null());

    block::WorkchainComputeInput input;
    CHECK(input.current_code.is_null());
    input.current_data.clear();
    input.inbound_body = vm::load_cell_slice_ref(make_marker_cell(0x01));
    input.gas_limit = 100;

    block::WorkchainComputeContext context;
    context.workchain_id = resolved.descriptor.workchain_id;
    context.descriptor = resolved.descriptor;
    context.engine_config = resolved.engine_config;
    context.block_transition_config = &config;

    auto output = resolved.executor->run_compute(input, context).move_as_ok();
    CHECK(input.current_code.is_null());
    CHECK(output.completed);
    CHECK(output.committed);
    CHECK(output.engine_success);
    CHECK(output.new_data.not_null());
    CHECK(output.new_code.is_null());
  };

  auto evm = registry.resolve(make_basic_descriptor(1, kEvmVmVersion, 0x544F53), config).move_as_ok();
  run_with_null_code(evm);

  auto uno = registry.resolve(make_basic_descriptor(2, kUnoVmVersion, 0), config).move_as_ok();
  run_with_null_code(uno);
}

TEST(WorkchainExecutionRegistry, CustomComputeGasFeesAreCopiedIntoTransactionComputePhase) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(2, make_basic_workchain_info(2, kUnoVmVersion, 0));

  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [](block::ComputePhase& cp,
         td::Ref<vm::Cell> state_data,
         vm::CellSlice& /*in_msg_body*/,
         uint64_t /*gas_limit*/,
         uint64_t /*block_seqno*/,
         uint64_t /*timestamp*/,
         const uint8_t /*rand_seed*/[32]) {
        CHECK(state_data.is_null());
        cp.accepted = true;
        cp.success = true;
        cp.gas_used = 11;
        cp.gas_fees = td::make_refint(42);
        cp.new_data = make_marker_cell(0xB1);
        return true;
      }));

  auto addr = singleton_executor_address();
  block::Account account(2, addr.bits());
  account.status = block::Account::acc_nonexist;
  account.orig_status = block::Account::acc_nonexist;
  account.balance = block::CurrencyCollection::zero();

  auto msg = build_external_message(2, addr, make_marker_cell(0x01));
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_ord, 1, 100, msg);

  block::ActionPhaseConfig action_cfg;
  action_cfg.workchains = &workchains;
  CHECK(tx.unpack_input_msg(false, &action_cfg));

  block::ComputePhaseConfig compute_cfg;
  compute_cfg.gas_limit = 100;
  compute_cfg.block_transition_config = &config;
  compute_cfg.workchain_descriptors = &workchains;
  compute_cfg.workchain_execution_registry = &registry;
  compute_cfg.global_version = 14;

  CHECK(tx.prepare_compute_phase(compute_cfg));
  CHECK(tx.compute_phase != nullptr);
  CHECK(tx.compute_phase->gas_fees.not_null());
  CHECK(td::cmp(tx.compute_phase->gas_fees, td::make_refint(42)) == 0);
}

TEST(WorkchainExecutionRegistry, RejectsNegativeCustomComputeGasFees) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(2, make_basic_workchain_info(2, kUnoVmVersion, 0));

  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [](block::ComputePhase& cp,
         td::Ref<vm::Cell> state_data,
         vm::CellSlice& /*in_msg_body*/,
         uint64_t /*gas_limit*/,
         uint64_t /*block_seqno*/,
         uint64_t /*timestamp*/,
         const uint8_t /*rand_seed*/[32]) {
        CHECK(state_data.is_null());
        cp.accepted = true;
        cp.success = true;
        cp.gas_used = 11;
        cp.gas_fees = td::make_refint(-1);
        cp.new_data = make_marker_cell(0xB2);
        return true;
      }));

  auto addr = singleton_executor_address();
  block::Account account(2, addr.bits());
  account.status = block::Account::acc_nonexist;
  account.orig_status = block::Account::acc_nonexist;
  account.balance = block::CurrencyCollection::zero();

  auto msg = build_external_message(2, addr, make_marker_cell(0x01));
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_ord, 1, 100, msg);

  block::ActionPhaseConfig action_cfg;
  action_cfg.workchains = &workchains;
  CHECK(tx.unpack_input_msg(false, &action_cfg));

  block::ComputePhaseConfig compute_cfg;
  compute_cfg.gas_limit = 100;
  compute_cfg.block_transition_config = &config;
  compute_cfg.workchain_descriptors = &workchains;
  compute_cfg.workchain_execution_registry = &registry;
  compute_cfg.global_version = 14;

  CHECK(!tx.prepare_compute_phase(compute_cfg));
  CHECK(tx.compute_phase == nullptr);
}

TEST(WorkchainExecutionRegistry, RejectsCustomComputeGasUsedAboveLimit) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(2, make_basic_workchain_info(2, kUnoVmVersion, 0));

  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [](block::ComputePhase& cp,
         td::Ref<vm::Cell> state_data,
         vm::CellSlice& /*in_msg_body*/,
         uint64_t gas_limit,
         uint64_t /*block_seqno*/,
         uint64_t /*timestamp*/,
         const uint8_t /*rand_seed*/[32]) {
        CHECK(state_data.is_null());
        cp.accepted = true;
        cp.success = true;
        cp.gas_used = gas_limit + 1;
        cp.gas_fees = td::zero_refint();
        cp.new_data = make_marker_cell(0xB3);
        return true;
      }));

  auto addr = singleton_executor_address();
  block::Account account(2, addr.bits());
  account.status = block::Account::acc_nonexist;
  account.orig_status = block::Account::acc_nonexist;
  account.balance = block::CurrencyCollection::zero();

  auto msg = build_external_message(2, addr, make_marker_cell(0x01));
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_ord, 1, 100, msg);

  block::ActionPhaseConfig action_cfg;
  action_cfg.workchains = &workchains;
  CHECK(tx.unpack_input_msg(false, &action_cfg));

  block::ComputePhaseConfig compute_cfg;
  compute_cfg.gas_limit = 100;
  compute_cfg.block_transition_config = &config;
  compute_cfg.workchain_descriptors = &workchains;
  compute_cfg.workchain_execution_registry = &registry;
  compute_cfg.global_version = 14;

  CHECK(!tx.prepare_compute_phase(compute_cfg));
  CHECK(tx.compute_phase == nullptr);
}

TEST(WorkchainExecutionRegistry, CustomPolicyCanForbidUninitializedActivation) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(2, make_basic_workchain_info(2, kUnoVmVersion, 0));

  bool compute_called = false;
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [&](block::ComputePhase& /*cp*/,
          td::Ref<vm::Cell> /*state_data*/,
          vm::CellSlice& /*in_msg_body*/,
          uint64_t /*gas_limit*/,
          uint64_t /*block_seqno*/,
          uint64_t /*timestamp*/,
          const uint8_t /*rand_seed*/[32]) {
        compute_called = true;
        return false;
      },
      false));

  auto addr = singleton_executor_address();
  block::Account account(2, addr.bits());
  account.status = block::Account::acc_nonexist;
  account.orig_status = block::Account::acc_nonexist;
  account.balance = block::CurrencyCollection::zero();

  auto msg = build_external_message(2, addr, make_marker_cell(0x01));
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_ord, 1, 100, msg);

  block::ActionPhaseConfig action_cfg;
  action_cfg.workchains = &workchains;
  CHECK(tx.unpack_input_msg(false, &action_cfg));

  block::ComputePhaseConfig compute_cfg;
  compute_cfg.gas_limit = 100;
  compute_cfg.block_transition_config = &config;
  compute_cfg.workchain_descriptors = &workchains;
  compute_cfg.workchain_execution_registry = &registry;
  compute_cfg.global_version = 14;

  CHECK(tx.prepare_compute_phase(compute_cfg));
  CHECK(tx.compute_phase != nullptr);
  CHECK(tx.compute_phase->skip_reason == block::ComputePhase::sk_no_state);
  CHECK(!compute_called);
}

TEST(WorkchainExecutionRegistry, UnsupportedCustomAccountPoliciesAbortBeforeCompute) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(2, make_basic_workchain_info(2, kUnoVmVersion, 0));

  bool compute_called = false;
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [&](block::ComputePhase& /*cp*/,
          td::Ref<vm::Cell> /*state_data*/,
          vm::CellSlice& /*in_msg_body*/,
          uint64_t /*gas_limit*/,
          uint64_t /*block_seqno*/,
          uint64_t /*timestamp*/,
          const uint8_t /*rand_seed*/[32]) {
        compute_called = true;
        return false;
      },
      true,
      block::AccountExecutionPolicyKind::EngineDefined));

  auto addr = singleton_executor_address();
  block::Account account(2, addr.bits());
  account.status = block::Account::acc_nonexist;
  account.orig_status = block::Account::acc_nonexist;
  account.balance = block::CurrencyCollection::zero();

  auto msg = build_external_message(2, addr, make_marker_cell(0x01));
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_ord, 1, 100, msg);

  block::ActionPhaseConfig action_cfg;
  action_cfg.workchains = &workchains;
  CHECK(tx.unpack_input_msg(false, &action_cfg));

  block::ComputePhaseConfig compute_cfg;
  compute_cfg.gas_limit = 100;
  compute_cfg.block_transition_config = &config;
  compute_cfg.workchain_descriptors = &workchains;
  compute_cfg.workchain_execution_registry = &registry;
  compute_cfg.global_version = 14;

  CHECK(!tx.prepare_compute_phase(compute_cfg));
  CHECK(tx.compute_phase == nullptr);
  CHECK(!compute_called);
}

TEST(WorkchainExecutionRegistry, PreflightRejectsUnsupportedCustomAccountPolicies) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(2, make_basic_workchain_info(2, kUnoVmVersion, 0));

  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [](block::ComputePhase& /*cp*/,
         td::Ref<vm::Cell> /*state_data*/,
         vm::CellSlice& /*in_msg_body*/,
         uint64_t /*gas_limit*/,
         uint64_t /*block_seqno*/,
         uint64_t /*timestamp*/,
         const uint8_t /*rand_seed*/[32]) {
        return false;
      },
      true,
      block::AccountExecutionPolicyKind::ShardLocalExecutor));

  block::LocalWorkchainRoleSet roles;
  roles.required_workchains.insert(2);
  CHECK(registry.validate_required_workchains(workchains, config, roles).is_error());
}
