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
#include "block/block-parse.h"  // block::tlb::aug_ShardAccounts
#include "block/evm-workchain-dispatch.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "uno/core/dispatch-engine.h"
#include "evm/core/dispatch-engine.h"
#include "evm/core/workchain.h"
#include "jvm/avata/include/avata/contract.h"
#include "jvm/avata/include/avata/event.h"
#include "jvm/avata/include/avata/storage.h"
#include "jvm/core/avata-execution.h"
#include "jvm/core/avata-runtime.h"
#include "jvm/core/cell-codec.h"
#include "jvm/core/class-manifest.h"
#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "jvm/core/dispatch-engine.h"
#include "jvm/core/event-host.h"
#include "jvm/core/message-abi.h"
#include "jvm/core/rpc.h"
#include "jvm/core/storage-cell-host.h"
#include "jvm/core/zerostate.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

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

td::Ref<block::WorkchainInfo> make_extended_workchain_info(
    tos::WorkchainId workchain_id, std::uint32_t workchain_type_id) {
  td::Ref<block::WorkchainInfo> info{true};
  auto& w = info.unique_write();
  w.workchain = workchain_id;
  w.enabled_since = 1;
  w.monitor_min_split = 0;
  w.min_split = 0;
  w.max_split = 0;
  w.basic = false;
  w.active = true;
  w.accept_msgs = true;
  w.flags = 0;
  w.version = 0;
  w.vm_version = 0;
  w.vm_mode = 0;
  w.workchain_type_id = workchain_type_id;
  w.min_addr_len = 64;
  w.max_addr_len = 256;
  w.addr_len_step = 8;
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

td::Ref<vm::Cell> make_empty_action_list() {
  vm::CellBuilder cb;
  return cb.finalize();
}

struct FakeJvmGasThread {
  const std::uint64_t* opcode_costs{nullptr};
  std::uint32_t opcode_count{0};
  const std::uint64_t* helper_costs{nullptr};
  std::uint32_t helper_count{0};
  bool fail_helper_install{false};
};

int fake_jvm_set_opcode_gas_costs(void* thread, const std::uint64_t* gas_costs,
                                  std::uint32_t gas_cost_count) {
  auto* fake = static_cast<FakeJvmGasThread*>(thread);
  if (fake == nullptr) {
    return 1;
  }
  fake->opcode_costs = gas_costs;
  fake->opcode_count = gas_cost_count;
  return 0;
}

int fake_jvm_set_helper_gas_costs(void* thread, const std::uint64_t* gas_costs,
                                  std::uint32_t gas_cost_count) {
  auto* fake = static_cast<FakeJvmGasThread*>(thread);
  if (fake == nullptr || fake->fail_helper_install) {
    return 1;
  }
  fake->helper_costs = gas_costs;
  fake->helper_count = gas_cost_count;
  return 0;
}

const AvataStorageHost* fake_jvm_storage_host = nullptr;
const AvataEventHost* fake_jvm_event_host = nullptr;

struct FakeJvmExecutionThread : public FakeJvmGasThread {
  std::uint64_t gas_limit{0};
  std::uint64_t memory_limit{0};
  std::uint64_t remaining_gas{0};
  std::uint64_t memory_used{0};
  int begin_status{0};
  int end_status{0};
  int invoke_status{0};
  bool began{false};
  bool ended{false};
  bool invoked{false};
  bool write_storage{true};
  bool write_event{true};
};

void fake_jvm_set_storage_host(const AvataStorageHost* host) {
  fake_jvm_storage_host = host;
}

void fake_jvm_clear_storage_host() {
  fake_jvm_storage_host = nullptr;
}

void fake_jvm_set_event_host(const AvataEventHost* host) {
  fake_jvm_event_host = host;
}

void fake_jvm_clear_event_host() {
  fake_jvm_event_host = nullptr;
}

int fake_jvm_begin_contract_transaction_with_limits(
    void* thread, std::uint64_t gas_limit, std::uint64_t memory_limit) {
  auto* fake = static_cast<FakeJvmExecutionThread*>(thread);
  if (fake == nullptr) {
    return 1;
  }
  fake->began = true;
  fake->gas_limit = gas_limit;
  fake->memory_limit = memory_limit;
  return fake->begin_status;
}

int fake_jvm_end_contract_transaction(void* thread) {
  auto* fake = static_cast<FakeJvmExecutionThread*>(thread);
  if (fake == nullptr) {
    return 1;
  }
  fake->ended = true;
  return fake->end_status;
}

int fake_jvm_contract_remaining_gas(void* thread, std::uint64_t* remaining_gas) {
  auto* fake = static_cast<FakeJvmExecutionThread*>(thread);
  if (fake == nullptr || remaining_gas == nullptr) {
    return 1;
  }
  *remaining_gas = fake->remaining_gas;
  return 0;
}

int fake_jvm_contract_memory_used(void* thread, std::uint64_t* used_bytes) {
  auto* fake = static_cast<FakeJvmExecutionThread*>(thread);
  if (fake == nullptr || used_bytes == nullptr) {
    return 1;
  }
  *used_bytes = fake->memory_used;
  return 0;
}

int fake_jvm_invoke_contract(void* thread, void* /*invocation_user*/) {
  auto* fake = static_cast<FakeJvmExecutionThread*>(thread);
  if (fake == nullptr) {
    return 1;
  }
  fake->invoked = true;
  if (fake->write_storage && fake_jvm_storage_host != nullptr) {
    unsigned char slot[AVATA_STORAGE_SLOT_SIZE] = {};
    slot[31] = 9;
    const unsigned char value[] = {1, 2, 3};
    if (fake_jvm_storage_host->store(
            fake_jvm_storage_host->user, slot, value, sizeof(value)) !=
        AVATA_STORAGE_OK) {
      return 1;
    }
  }
  if (fake->write_event && fake_jvm_event_host != nullptr) {
    unsigned char topics[AVATA_EVENT_TOPIC_SIZE * 2] = {};
    topics[AVATA_EVENT_TOPIC_SIZE - 1] = 1;
    topics[AVATA_EVENT_TOPIC_SIZE * 2 - 1] = 2;
    const unsigned char data[] = {4, 5, 6};
    if (fake_jvm_event_host->emit(
            fake_jvm_event_host->user, topics, 2, data, sizeof(data)) !=
        AVATA_EVENT_OK) {
      return 1;
    }
  }
  return fake->invoke_status;
}

jvm_workchain::JvmConfig make_test_jvm_config() {
  jvm_workchain::JvmConfig cfg;
  cfg.chain_id = 85;
  cfg.gas_price = 1;
  cfg.max_gas_per_tx = 1000000;
  cfg.max_class_bytes = 65536;
  cfg.max_total_class_bytes = 1024 * 1024;
  cfg.max_heap_bytes = 4 * 1024 * 1024;
  cfg.max_storage_cells = 100000;
  cfg.class_file_major = 52;
  cfg.gas_schedule_version = 1;
  for (std::size_t i = 0; i < cfg.stdlib_hash.size(); ++i) {
    cfg.stdlib_hash[i] = static_cast<std::uint8_t>(i);
  }
  for (std::size_t i = 0; i < cfg.opcode_gas_costs.size(); ++i) {
    cfg.opcode_gas_costs[i] = 1 + i;
  }
  for (std::size_t i = 0; i < cfg.helper_gas_costs.size(); ++i) {
    cfg.helper_gas_costs[i] = 100 + i;
  }
  return cfg;
}

std::unique_ptr<block::Config> make_config_with_jvm_param(
    const jvm_workchain::JvmConfig& cfg) {
  auto config_cell = jvm_workchain::build_jvm_config_cell(cfg);
  CHECK(config_cell.not_null());

  vm::Dictionary dict{32};
  CHECK(dict.set_ref(
      td::BitArray<32>{jvm_workchain::kJvmConfigParam},
      std::move(config_cell)));
  auto config = block::Config::unpack_config(
      dict.get_root_cell(), tos::Bits256::zero(), 0);
  CHECK(config.is_ok());
  return config.move_as_ok();
}

jvm_workchain::JvmCallDescriptor make_test_jvm_call_descriptor(
    std::uint8_t marker = 1) {
  jvm_workchain::JvmCallDescriptor descriptor;
  descriptor.contract_id[31] = marker;
  descriptor.method_id = 0x01020300u + marker;
  descriptor.args = make_empty_action_list();
  return descriptor;
}

td::Ref<vm::Cell> make_jvm_call_cell(std::uint8_t marker = 1) {
  auto cell = jvm_workchain::encode_jvm_call_descriptor(
      make_test_jvm_call_descriptor(marker));
  CHECK(cell.not_null());
  return cell;
}

td::Ref<vm::CellSlice> make_jvm_call_body(std::uint8_t marker = 1) {
  return vm::load_cell_slice_ref(make_jvm_call_cell(marker));
}

td::Ref<vm::CellSlice> make_jvm_call_body_v2(std::uint32_t method_id) {
  jvm_workchain::JvmCallDescriptorV2 descriptor;
  descriptor.method_id = method_id;
  descriptor.args = make_empty_action_list();
  auto cell = jvm_workchain::encode_jvm_call_descriptor_v2(descriptor);
  CHECK(cell.not_null());
  return vm::load_cell_slice_ref(cell);
}

jvm_workchain::JvmDeployDescriptor make_test_jvm_deploy_descriptor(
    std::uint8_t marker = 1) {
  jvm_workchain::JvmDeployDescriptor descriptor;
  descriptor.deployer[31] = marker;
  descriptor.salt[31] = static_cast<std::uint8_t>(marker + 1);
  descriptor.class_name = "ContractEntryPoint";
  descriptor.class_bytes = jvm_workchain::JvmStorageValue{
      0xca, 0xfe, 0xba, 0xbe, 0x00, marker};
  descriptor.class_hash = jvm_workchain::compute_jvm_class_hash(
      descriptor.class_bytes);
  descriptor.init_args = make_empty_action_list();
  return descriptor;
}

jvm_workchain::JvmAvataClassDefinition make_test_jvm_class_definition(
    std::uint8_t marker = 1) {
  auto descriptor = make_test_jvm_deploy_descriptor(marker);
  jvm_workchain::JvmAvataClassDefinition definition;
  definition.class_hash = descriptor.class_hash;
  definition.class_name = descriptor.class_name;
  definition.class_bytes = descriptor.class_bytes;
  return definition;
}

jvm_workchain::JvmAvataClassManifestEntry make_test_jvm_class_manifest_entry(
    std::uint8_t marker = 1,
    const char* method_name = "ok") {
  auto descriptor = make_test_jvm_call_descriptor(marker);
  jvm_workchain::JvmAvataClassManifestEntry entry;
  entry.contract_id = descriptor.contract_id;
  entry.method_id = descriptor.method_id;
  entry.class_name = "ContractEntryPoint";
  entry.method_name = method_name;
  entry.method_spec = "()V";
  return entry;
}

td::Ref<vm::Cell> make_jvm_class_manifest_cell(std::uint8_t marker = 1) {
  std::vector<jvm_workchain::JvmAvataClassManifestEntry> entries;
  entries.push_back(make_test_jvm_class_manifest_entry(marker));
  auto cell = jvm_workchain::encode_jvm_avata_class_manifest(entries);
  CHECK(cell.not_null());
  return cell;
}

td::Ref<vm::Cell> make_jvm_class_state_cell(std::uint8_t marker = 1) {
  jvm_workchain::JvmAvataClassState state;
  state.manifest_entries.push_back(make_test_jvm_class_manifest_entry(marker));
  state.classes.push_back(make_test_jvm_class_definition(marker));
  auto cell = jvm_workchain::encode_jvm_avata_class_state(state);
  CHECK(cell.not_null());
  return cell;
}

void check_jvm_class_manifest_marker(td::Ref<vm::Cell> root,
                                     std::uint8_t marker) {
  auto entry = jvm_workchain::find_jvm_avata_class_manifest_entry(
      std::move(root), make_test_jvm_call_descriptor(marker)).move_as_ok();
  CHECK(entry.class_name == "ContractEntryPoint");
  CHECK(entry.method_name == "ok");
  CHECK(entry.method_spec == "()V");
}

jvm_workchain::JvmAvataExecutionApi make_test_jvm_execution_api() {
  jvm_workchain::JvmAvataExecutionApi api;
  api.ok_status = 0;
  api.out_of_gas_status = 2;
  api.out_of_memory_status = 3;
  api.gas_api.ok_status = 0;
  api.gas_api.set_opcode_gas_costs = fake_jvm_set_opcode_gas_costs;
  api.gas_api.set_contract_helper_gas_costs = fake_jvm_set_helper_gas_costs;
  api.set_storage_host = fake_jvm_set_storage_host;
  api.clear_storage_host = fake_jvm_clear_storage_host;
  api.set_event_host = fake_jvm_set_event_host;
  api.clear_event_host = fake_jvm_clear_event_host;
  api.begin_contract_transaction_with_limits =
      fake_jvm_begin_contract_transaction_with_limits;
  api.end_contract_transaction = fake_jvm_end_contract_transaction;
  api.contract_remaining_gas = fake_jvm_contract_remaining_gas;
  api.contract_memory_used = fake_jvm_contract_memory_used;
  api.invoke_contract = fake_jvm_invoke_contract;
  return api;
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

class MockJvmRuntime final : public jvm_workchain::JvmComputeRuntime {
 public:
  td::Result<jvm_workchain::JvmAvataInvocationResult> run_contract(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& context,
      const jvm_workchain::JvmConfig& config,
      const jvm_workchain::JvmExecutorState& previous_state) const override {
    using namespace jvm_workchain;

    called = true;
    CHECK(context.workchain_id == 3);
    CHECK(input.gas_limit == 1000);
    CHECK(config.chain_id == 85);
    CHECK(previous_state.stdlib_hash == config.stdlib_hash);

    JvmStorageCellHost storage(previous_state.storage_root);
    JvmStorageSlot slot{};
    slot[31] = 0x77;
    CHECK(storage.store(slot, JvmStorageValue{8, 9, 10}).is_ok());

    JvmAvataInvocationResult result;
    result.invocation_status = 0;
    result.success = true;
    result.gas_used = 123;
    result.gas_remaining = input.gas_limit - result.gas_used;
    result.memory_used = 456;
    result.storage_root = storage.root_cell();
    result.action_list = build_jvm_event_action_list(std::vector<JvmEvent>{});
    CHECK(result.action_list.not_null());
    return result;
  }

  td::Result<jvm_workchain::JvmAvataInvocationResult> run_contract_v2(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& context,
      const jvm_workchain::JvmConfig& config,
      const jvm_workchain::JvmContractAccountState& previous_state)
      const override {
    using namespace jvm_workchain;

    called_v2 = true;
    CHECK(context.workchain_id == 3);
    CHECK(input.gas_limit == 1000);
    CHECK(config.chain_id == 85);
    CHECK(previous_state.stdlib_hash == config.stdlib_hash);
    CHECK(previous_state.class_bytes.not_null());
    CHECK(previous_state.manifest_root.not_null());

    JvmStorageCellHost storage(previous_state.storage_root);
    JvmStorageSlot slot{};
    slot[31] = 0xa1;
    CHECK(storage.store(slot, JvmStorageValue{0xde, 0xad}).is_ok());

    JvmAvataInvocationResult result;
    result.invocation_status = 0;
    result.success = true;
    result.gas_used = 123;
    result.gas_remaining = input.gas_limit - result.gas_used;
    result.memory_used = 456;
    result.storage_root = storage.root_cell();
    result.action_list = build_jvm_event_action_list(std::vector<JvmEvent>{});
    CHECK(result.action_list.not_null());
    return result;
  }

  mutable bool called{false};
  mutable bool called_v2{false};
};

struct FakeJvmAvataRuntimeResolver {
  FakeJvmExecutionThread* thread{nullptr};
  bool called{false};
};

td::Result<jvm_workchain::JvmAvataCallTarget> fake_jvm_resolve_call_target(
    const block::WorkchainComputeInput& input,
    const block::WorkchainComputeContext& context,
    const jvm_workchain::JvmConfig& config,
    const jvm_workchain::JvmExecutorState& previous_state,
    void* user) {
  auto* resolver = static_cast<FakeJvmAvataRuntimeResolver*>(user);
  if (resolver == nullptr || resolver->thread == nullptr) {
    return td::Status::Error("fake JVM resolver is missing thread");
  }

  resolver->called = true;
  CHECK(context.workchain_id == 3);
  CHECK(input.gas_limit == 1000);
  CHECK(config.chain_id == 85);
  CHECK(previous_state.stdlib_hash == config.stdlib_hash);

  jvm_workchain::JvmAvataCallTarget target;
  target.thread = resolver->thread;
  return target;
}

}  // namespace

TEST(JvmWorkchainCore, StorageCellHostRoundTripAndTransactions) {
  using namespace jvm_workchain;

  JvmStorageCellHost storage;
  JvmStorageSlot slot{};
  slot[31] = 7;

  auto missing = storage.load(slot).move_as_ok();
  CHECK(!missing.has_value());

  CHECK(storage.store(slot, JvmStorageValue{}).is_ok());
  auto empty = storage.load(slot).move_as_ok();
  CHECK(empty.has_value());
  CHECK(empty->empty());

  JvmStorageSlot large_slot{};
  large_slot[0] = 1;
  large_slot[31] = 2;
  JvmStorageValue large_value(300);
  for (std::size_t i = 0; i < large_value.size(); ++i) {
    large_value[i] = static_cast<std::uint8_t>(i * 13);
  }
  CHECK(storage.store(large_slot, large_value).is_ok());
  auto loaded_large = storage.load(large_slot).move_as_ok();
  CHECK(loaded_large.has_value());
  CHECK(*loaded_large == large_value);
  CHECK(validate_jvm_storage_root(storage.root_cell()));

  JvmStorageCellHost reloaded(storage.root_cell());
  auto reloaded_large = reloaded.load(large_slot).move_as_ok();
  CHECK(reloaded_large.has_value());
  CHECK(*reloaded_large == large_value);

  JvmStorageValue replacement{1, 2, 3, 4};
  CHECK(storage.begin_transaction().is_ok());
  CHECK(storage.store(large_slot, replacement).is_ok());
  auto changed = storage.load(large_slot).move_as_ok();
  CHECK(changed.has_value());
  CHECK(*changed == replacement);
  CHECK(storage.rollback_transaction().is_ok());
  auto rolled_back = storage.load(large_slot).move_as_ok();
  CHECK(rolled_back.has_value());
  CHECK(*rolled_back == large_value);

  CHECK(storage.begin_transaction().is_ok());
  CHECK(storage.clear(large_slot).is_ok());
  CHECK(storage.commit_transaction().is_ok());
  auto cleared = storage.load(large_slot).move_as_ok();
  CHECK(!cleared.has_value());
}

TEST(JvmWorkchainCore, StorageHostCallbackKeepsEmptyValueDistinctFromMissing) {
  using namespace jvm_workchain;

  JvmStorageCellHost storage;
  AvataStorageHost host{};
  configure_avata_storage_host(storage, host);

  unsigned char raw_slot[AVATA_STORAGE_SLOT_SIZE] = {};
  unsigned char* value = nullptr;
  std::size_t value_length = 99;

  CHECK(host.load(host.user, raw_slot, &value, &value_length) == AVATA_STORAGE_OK);
  CHECK(value == nullptr);
  CHECK(value_length == 0);

  CHECK(host.store(host.user, raw_slot, nullptr, 0) == AVATA_STORAGE_OK);
  value = nullptr;
  value_length = 99;
  CHECK(host.load(host.user, raw_slot, &value, &value_length) == AVATA_STORAGE_OK);
  CHECK(value != nullptr);
  CHECK(value_length == 0);
  host.freeValue(host.user, value);
}

TEST(JvmWorkchainCore, ExecutorStateCodecRoundTripsStorageRoot) {
  using namespace jvm_workchain;

  JvmStorageCellHost storage;
  JvmStorageSlot slot{};
  slot[0] = 42;
  CHECK(storage.store(slot, JvmStorageValue{5, 6, 7, 8}).is_ok());

  JvmExecutorState state;
  auto cfg = make_test_jvm_config();
  state.stdlib_hash = cfg.stdlib_hash;
  state.storage_root = storage.root_cell();
  state.class_state_root = make_jvm_class_state_cell(0x51);

  auto encoded = encode_jvm_executor_state(state);
  CHECK(encoded.not_null());

  JvmExecutorState decoded;
  CHECK(decode_jvm_executor_state(encoded, decoded));
  CHECK(decoded.schema_version == kJvmExecutorStateSchemaVersion);
  CHECK(decoded.stdlib_hash == state.stdlib_hash);
  CHECK(decoded.storage_root.not_null());
  CHECK(decoded.class_state_root.not_null());
  check_jvm_class_manifest_marker(decoded.class_state_root, 0x51);
  CHECK(parse_jvm_avata_class_state(decoded.class_state_root)
            .move_as_ok()
            .classes.size() == 1);

  JvmStorageCellHost decoded_storage(decoded.storage_root);
  auto loaded = decoded_storage.load(slot).move_as_ok();
  CHECK(loaded.has_value());
  CHECK(*loaded == (JvmStorageValue{5, 6, 7, 8}));

  vm::CellBuilder wrong_magic;
  wrong_magic.store_long(0, 32);
  CHECK(!decode_jvm_executor_state(wrong_magic.finalize(), decoded));
  CHECK(!decode_jvm_executor_state({}, decoded));

  state.class_state_root = make_marker_cell(0x51);
  encoded = encode_jvm_executor_state(state);
  CHECK(encoded.not_null());
  CHECK(!decode_jvm_executor_state(encoded, decoded));
}

TEST(JvmWorkchainCore, ContractAccountStateCodecRoundTripsClassBytesAndStorage) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();

  // Storage with a value at slot[0]=42
  JvmStorageCellHost storage;
  JvmStorageSlot slot{};
  slot[0] = 42;
  CHECK(storage.store(slot, JvmStorageValue{1, 2, 3, 4}).is_ok());
  auto storage_root = storage.root_cell();
  CHECK(storage_root.not_null());

  // class_bytes payload (held as a Cell ref so Cell DB physically dedups
  // identical bytecode).
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x10};
  auto class_bytes_cell = encode_jvm_storage_value(class_bytes);
  CHECK(class_bytes_cell.not_null());

  // Single-method manifest.
  JvmMethodManifestEntry entry;
  entry.method_id = 0x01020304;
  entry.class_name = "ContractEntryPoint";
  entry.method_name = "ok";
  entry.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({entry});
  CHECK(manifest_root.not_null());

  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  state.class_bytes = class_bytes_cell;
  state.storage_root = storage_root;
  state.manifest_root = manifest_root;

  auto encoded = encode_jvm_contract_account_state(state);
  CHECK(encoded.not_null());

  JvmContractAccountState decoded;
  CHECK(decode_jvm_contract_account_state(encoded, decoded));
  CHECK(decoded.schema_version == kJvmContractAccountStateSchemaVersion);
  CHECK(decoded.stdlib_hash == state.stdlib_hash);
  CHECK(decoded.class_hash == state.class_hash);
  CHECK(decoded.class_bytes.not_null());
  CHECK(decoded.class_bytes->get_hash() == class_bytes_cell->get_hash());
  CHECK(decoded.storage_root.not_null());
  CHECK(decoded.manifest_root.not_null());

  // Storage values survive the round trip.
  JvmStorageCellHost decoded_storage(decoded.storage_root);
  auto loaded = decoded_storage.load(slot).move_as_ok();
  CHECK(loaded.has_value());
  CHECK(*loaded == (JvmStorageValue{1, 2, 3, 4}));

  // Manifest can still be queried by method_id.
  auto found = find_jvm_method_manifest_entry(decoded.manifest_root,
                                              entry.method_id);
  CHECK(found.is_ok());
  CHECK(found.ok().class_name == "ContractEntryPoint");
  CHECK(found.ok().method_name == "ok");
  // Capture the round-tripped class_bytes hash before running negative tests
  // (decode resets the out-state on failure, which would clobber `decoded`).
  auto round_tripped_class_bytes_hash = decoded.class_bytes->get_hash();

  // Reject envelopes with the wrong magic / null cells.  Use a separate
  // `decoded_neg` because decode is documented to reset its out-arg on failure.
  JvmContractAccountState decoded_neg;
  vm::CellBuilder wrong_magic;
  wrong_magic.store_long(0, 32);
  CHECK(!decode_jvm_contract_account_state(wrong_magic.finalize(), decoded_neg));
  CHECK(!decode_jvm_contract_account_state({}, decoded_neg));

  // Reject zero class_hash at encode time.
  {
    JvmContractAccountState bad = state;
    bad.class_hash = JvmClassHash{};
    CHECK(encode_jvm_contract_account_state(bad).is_null());
  }

  // Cell DB physical dedup: two states sharing identical class_bytes share the
  // same class_bytes Cell hash even when storage differs.
  JvmContractAccountState other = state;
  JvmStorageCellHost other_storage;
  CHECK(other_storage.store(slot, JvmStorageValue{9, 9}).is_ok());
  other.storage_root = other_storage.root_cell();
  auto other_encoded = encode_jvm_contract_account_state(other);
  CHECK(other_encoded.not_null());
  CHECK(other_encoded->get_hash() != encoded->get_hash());
  JvmContractAccountState other_decoded;
  CHECK(decode_jvm_contract_account_state(other_encoded, other_decoded));
  CHECK(other_decoded.class_bytes.not_null());
  CHECK(other_decoded.class_bytes->get_hash() == round_tripped_class_bytes_hash);
}

TEST(JvmWorkchainCore, EncodeJvmStateInitCellPassesTlbValidation) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34};

  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});

  auto state_init = encode_jvm_state_init_cell(state);
  CHECK(state_init.not_null());

  // The cell must validate as a TLB StateInit at consensus level (this is the
  // same validator the action phase uses to gate inbound StateInit-bearing
  // messages).
  CHECK(block::gen::t_StateInit.validate_ref(state_init));

  // Decode the StateInit and verify the data ref decodes back to the same
  // contract account state.
  block::gen::StateInit::Record si;
  CHECK(block::gen::t_StateInit.cell_unpack(state_init, si));
  CHECK(si.code.not_null());
  CHECK(si.data.not_null());

  // si.data is `Maybe ^Cell`, so peel the Maybe and re-decode.
  CHECK(si.data->prefetch_ulong(1) == 1);
  auto data_cs = vm::CellSlice{*si.data};
  CHECK(data_cs.fetch_ulong(1) == 1);
  td::Ref<vm::Cell> data_ref;
  CHECK(data_cs.fetch_ref_to(data_ref));
  JvmContractAccountState decoded;
  CHECK(decode_jvm_contract_account_state(data_ref, decoded));
  CHECK(decoded.class_hash == state.class_hash);
}

TEST(JvmWorkchainCore, MessageAbiCallDescriptorV2DropsContractIdAndRoundTrips) {
  using namespace jvm_workchain;

  JvmCallDescriptorV2 descriptor;
  descriptor.method_id = 0xdeadbeef;
  descriptor.args = make_empty_action_list();

  auto encoded = encode_jvm_call_descriptor_v2(descriptor);
  CHECK(encoded.not_null());

  auto parsed = parse_jvm_call_descriptor_v2(vm::load_cell_slice_ref(encoded));
  CHECK(parsed.is_ok());
  CHECK(parsed.ok().schema_version == kJvmCallDescriptorV2SchemaVersion);
  CHECK(parsed.ok().method_id == descriptor.method_id);
  CHECK(parsed.ok().args.not_null());

  // A v1 cell must not parse as v2 (different magic).
  auto v1_cell = make_jvm_call_cell(0x42);
  CHECK(parse_jvm_call_descriptor_v2(vm::load_cell_slice_ref(v1_cell)).is_error());

  // Truncated body fails parse.
  vm::CellBuilder bad;
  bad.store_long(kJvmCallDescriptorV2Magic, 32);
  bad.store_long(kJvmCallDescriptorV2SchemaVersion, 8);
  CHECK(parse_jvm_call_descriptor_v2(
            vm::load_cell_slice_ref(bad.finalize())).is_error());
}

TEST(JvmWorkchainCore, DeriveJvmContractAddressIsDeterministicAndSensitive) {
  using namespace jvm_workchain;

  auto desc = make_test_jvm_deploy_descriptor(0x77);

  auto a = derive_jvm_contract_address(desc);
  auto b = derive_jvm_contract_address(desc);
  CHECK(a.is_ok() && b.is_ok());
  CHECK(a.ok() == b.ok());

  // The v1 contract_id and v2 contract_address must differ for the same
  // descriptor (different domain tag).
  auto v1 = derive_jvm_contract_id(desc);
  CHECK(v1.is_ok());
  CHECK(v1.ok() != a.ok());

  // Salt sensitivity: same class, different salt → different address.
  auto desc2 = desc;
  desc2.salt[0] ^= 0xff;
  auto c = derive_jvm_contract_address(desc2);
  CHECK(c.is_ok());
  CHECK(c.ok() != a.ok());

  // class_hash sensitivity (perturb class_bytes; class_hash is recomputed
  // because validate_deploy_descriptor enforces hash == sha256(bytes)).
  auto desc3 = desc;
  desc3.class_bytes.back() ^= 0xaa;
  desc3.class_hash = compute_jvm_class_hash(desc3.class_bytes);
  auto d = derive_jvm_contract_address(desc3);
  CHECK(d.is_ok());
  CHECK(d.ok() != a.ok());

  // deployer sensitivity.
  auto desc4 = desc;
  // Avoid clobbering the leading non-zero deployer byte (validate rejects zero
  // deployers); flip a low byte instead.
  desc4.deployer[30] ^= 0x01;
  auto e = derive_jvm_contract_address(desc4);
  CHECK(e.is_ok());
  CHECK(e.ok() != a.ok());

  // init_args sensitivity (cell-hash).
  auto desc5 = desc;
  desc5.init_args = make_marker_cell(0x42);
  auto f = derive_jvm_contract_address(desc5);
  CHECK(f.is_ok());
  CHECK(f.ok() != a.ok());
}

TEST(JvmWorkchainCore, MethodManifestRoundTripsAndRejectsDuplicates) {
  using namespace jvm_workchain;

  std::vector<JvmMethodManifestEntry> entries;
  for (std::uint32_t i = 0; i < 3; ++i) {
    JvmMethodManifestEntry e;
    e.method_id = 0x10000000u + i;
    e.class_name = "ContractEntryPoint";
    e.method_name = "method_" + std::to_string(i);
    e.method_spec = "()V";
    entries.push_back(e);
  }

  auto encoded = encode_jvm_method_manifest(entries);
  CHECK(encoded.not_null());

  auto parsed = parse_jvm_method_manifest(encoded);
  CHECK(parsed.is_ok());
  CHECK(parsed.ok().size() == entries.size());
  for (std::size_t i = 0; i < entries.size(); ++i) {
    CHECK(parsed.ok()[i].method_id == entries[i].method_id);
    CHECK(parsed.ok()[i].method_name == entries[i].method_name);
  }

  // Lookup by method_id finds each entry; missing id fails.
  for (const auto& e : entries) {
    auto found = find_jvm_method_manifest_entry(encoded, e.method_id);
    CHECK(found.is_ok());
    CHECK(found.ok().method_name == e.method_name);
  }
  CHECK(find_jvm_method_manifest_entry(encoded, 0xdeadbeef).is_error());

  // Empty manifest is allowed and round-trips.
  auto empty = encode_jvm_method_manifest({});
  CHECK(empty.not_null());
  CHECK(parse_jvm_method_manifest(empty).move_as_ok().empty());

  // Duplicate method_id is rejected at encode time.
  std::vector<JvmMethodManifestEntry> dup = entries;
  dup.push_back(entries[0]);
  CHECK(encode_jvm_method_manifest(dup).is_null());

  // Wrong magic / null root is rejected at parse time.
  CHECK(parse_jvm_method_manifest({}).is_error());
  vm::CellBuilder wrong_magic;
  wrong_magic.store_long(0, 32);
  CHECK(parse_jvm_method_manifest(wrong_magic.finalize()).is_error());
}

TEST(JvmWorkchainCore, MessageAbiCallDescriptorRoundTripsAndRejectsMalformed) {
  using namespace jvm_workchain;

  auto descriptor = make_test_jvm_call_descriptor(0x42);
  auto encoded = encode_jvm_call_descriptor(descriptor);
  CHECK(encoded.not_null());

  auto parsed = parse_jvm_call_descriptor(
      vm::load_cell_slice_ref(encoded)).move_as_ok();
  CHECK(parsed.schema_version == kJvmCallDescriptorSchemaVersion);
  CHECK(parsed.contract_id == descriptor.contract_id);
  CHECK(parsed.method_id == descriptor.method_id);
  CHECK(parsed.args.not_null());

  CHECK(parse_jvm_call_descriptor(td::Ref<vm::CellSlice>{}).is_error());
  CHECK(parse_jvm_call_descriptor(
      vm::load_cell_slice_ref(make_marker_cell(0x01))).is_error());

  JvmCallDescriptor zero_contract = descriptor;
  zero_contract.contract_id = {};
  CHECK(encode_jvm_call_descriptor(zero_contract).is_null());

  vm::CellBuilder missing_args;
  CHECK(missing_args.store_ulong_rchk_bool(kJvmCallDescriptorMagic, 32));
  CHECK(missing_args.store_ulong_rchk_bool(kJvmCallDescriptorSchemaVersion, 8));
  CHECK(missing_args.store_bytes_bool(descriptor.contract_id.data(),
                                      descriptor.contract_id.size()));
  CHECK(missing_args.store_ulong_rchk_bool(descriptor.method_id, 32));
  CHECK(parse_jvm_call_descriptor(
      vm::load_cell_slice_ref(missing_args.finalize())).is_error());

  vm::CellBuilder trailing_bits;
  CHECK(trailing_bits.store_ulong_rchk_bool(kJvmCallDescriptorMagic, 32));
  CHECK(trailing_bits.store_ulong_rchk_bool(kJvmCallDescriptorSchemaVersion, 8));
  CHECK(trailing_bits.store_bytes_bool(descriptor.contract_id.data(),
                                      descriptor.contract_id.size()));
  CHECK(trailing_bits.store_ulong_rchk_bool(descriptor.method_id, 32));
  CHECK(trailing_bits.store_ulong_rchk_bool(1, 1));
  CHECK(trailing_bits.store_ref_bool(descriptor.args));
  CHECK(parse_jvm_call_descriptor(
      vm::load_cell_slice_ref(trailing_bits.finalize())).is_error());

  CHECK(validate_jvm_static_void_call_args("()V", descriptor.args).is_ok());
  CHECK(validate_jvm_static_void_call_args("(I)V", descriptor.args).is_error());

  JvmCallDescriptor non_empty_args = descriptor;
  non_empty_args.args = make_marker_cell(0x7a);
  auto non_empty_encoded = encode_jvm_call_descriptor(non_empty_args);
  CHECK(non_empty_encoded.not_null());
  auto parsed_non_empty_args = parse_jvm_call_descriptor(
      vm::load_cell_slice_ref(non_empty_encoded)).move_as_ok();
  CHECK(validate_jvm_static_void_call_args(
            "()V", parsed_non_empty_args.args).is_error());

  vm::CellBuilder ref_args;
  CHECK(ref_args.store_ref_bool(descriptor.args));
  CHECK(validate_jvm_static_void_call_args(
            "()V", ref_args.finalize()).is_error());
  CHECK(validate_jvm_static_void_call_args("()V", {}).is_error());
}

TEST(JvmWorkchainCore, MessageAbiTypedArgsCodecValidatesDescriptors) {
  using namespace jvm_workchain;

  JvmArgs args;
  args.values.push_back(
      JvmTypedArg{JvmArgType::Bool, JvmStorageValue{1}});
  args.values.push_back(
      JvmTypedArg{JvmArgType::Int32, JvmStorageValue{0, 0, 0, 42}});
  args.values.push_back(
      JvmTypedArg{JvmArgType::Int64,
                  JvmStorageValue{0, 0, 0, 0, 0, 0, 0, 43}});
  args.values.push_back(
      JvmTypedArg{JvmArgType::Address, JvmStorageValue(36, 0x11)});
  args.values.push_back(
      JvmTypedArg{JvmArgType::Uint256, JvmStorageValue(32, 0x33)});
  args.values.push_back(
      JvmTypedArg{JvmArgType::Bytes32, JvmStorageValue(32, 0x22)});
  args.values.push_back(
      JvmTypedArg{JvmArgType::Bytes4, JvmStorageValue{1, 2, 3, 4}});
  args.values.push_back(
      JvmTypedArg{JvmArgType::Bytes, JvmStorageValue{7, 8, 9}});

  auto encoded = encode_jvm_args(args);
  CHECK(encoded.not_null());

  auto parsed = parse_jvm_args(encoded).move_as_ok();
  CHECK(parsed.schema_version == kJvmArgsSchemaVersion);
  CHECK(parsed.values.size() == args.values.size());
  CHECK(parsed.values[0].type == JvmArgType::Bool);
  CHECK(parsed.values[7].bytes == (JvmStorageValue{7, 8, 9}));

  auto types = parse_jvm_method_argument_types(
      "(ZIJLjava/lang/Address;Ljava/lang/Uint256;Ljava/lang/Bytes32;"
      "Ljava/lang/Bytes4;Ljava/lang/Bytes;)V")
                   .move_as_ok();
  CHECK(types.size() == args.values.size());
  CHECK(types[0] == JvmArgType::Bool);
  CHECK(types[1] == JvmArgType::Int32);
  CHECK(types[2] == JvmArgType::Int64);
  CHECK(types[3] == JvmArgType::Address);
  CHECK(types[4] == JvmArgType::Uint256);
  CHECK(types[5] == JvmArgType::Bytes32);
  CHECK(types[6] == JvmArgType::Bytes4);
  CHECK(types[7] == JvmArgType::Bytes);

  CHECK(validate_jvm_typed_call_args(
            "(ZIJLjava/lang/Address;Ljava/lang/Uint256;Ljava/lang/Bytes32;"
            "Ljava/lang/Bytes4;Ljava/lang/Bytes;)V",
            encoded)
            .is_ok());
  CHECK(validate_jvm_typed_call_args(
            "(JLjava/lang/Address;Ljava/lang/Bytes32;Ljava/lang/Bytes;)V",
            encoded)
            .is_error());
  CHECK(validate_jvm_typed_call_args("(Z)V", encoded).is_error());
  CHECK(parse_jvm_method_argument_types("(F)V").is_error());
  CHECK(parse_jvm_method_argument_types("(I)I").is_error());

  JvmArgs bad_bool;
  bad_bool.values.push_back(
      JvmTypedArg{JvmArgType::Bool, JvmStorageValue{2}});
  CHECK(encode_jvm_args(bad_bool).is_null());

  CHECK(parse_jvm_args(make_marker_cell(0x01)).is_error());
}

TEST(JvmWorkchainCore, ClassManifestRoundTripsAndRejectsMalformed) {
  using namespace jvm_workchain;

  std::vector<JvmAvataClassManifestEntry> entries;
  entries.push_back(make_test_jvm_class_manifest_entry(0x42, "ok"));
  entries.push_back(make_test_jvm_class_manifest_entry(0x43, "burn"));
  entries[1].method_spec = "(ILjava/lang/Bytes;)V";

  auto encoded = encode_jvm_avata_class_manifest(entries);
  CHECK(encoded.not_null());

  auto parsed = parse_jvm_avata_class_manifest(encoded).move_as_ok();
  CHECK(parsed.size() == 2);
  CHECK(parsed[0].contract_id == entries[0].contract_id);
  CHECK(parsed[0].method_id == entries[0].method_id);
  CHECK(parsed[0].class_name == "ContractEntryPoint");
  CHECK(parsed[0].method_name == "ok");
  CHECK(parsed[0].method_spec == "()V");

  auto found = find_jvm_avata_class_manifest_entry(
      encoded, make_test_jvm_call_descriptor(0x43)).move_as_ok();
  CHECK(found.method_name == "burn");
  CHECK(found.method_spec == "(ILjava/lang/Bytes;)V");
  CHECK(find_jvm_avata_class_manifest_entry(
            encoded, make_test_jvm_call_descriptor(0x44)).is_error());

  CHECK(parse_jvm_avata_class_manifest({}).is_error());
  CHECK(parse_jvm_avata_class_manifest(make_marker_cell(0x01)).is_error());

  auto bad_entry = entries[0];
  bad_entry.class_name.clear();
  CHECK(encode_jvm_avata_class_manifest({bad_entry}).is_null());

  bad_entry = entries[0];
  bad_entry.contract_id = {};
  CHECK(encode_jvm_avata_class_manifest({bad_entry}).is_null());

  bad_entry = entries[0];
  bad_entry.class_name = "/ContractEntryPoint";
  CHECK(encode_jvm_avata_class_manifest({bad_entry}).is_null());

  bad_entry = entries[0];
  bad_entry.class_name = "Contract.EntryPoint";
  CHECK(encode_jvm_avata_class_manifest({bad_entry}).is_null());

  bad_entry = entries[0];
  bad_entry.method_name = "<init>";
  CHECK(encode_jvm_avata_class_manifest({bad_entry}).is_null());

  bad_entry = entries[0];
  bad_entry.method_spec = "(F)V";
  CHECK(encode_jvm_avata_class_manifest({bad_entry}).is_null());

  CHECK(encode_jvm_avata_class_manifest(
            std::vector<JvmAvataClassManifestEntry>{entries[0], entries[0]})
            .is_null());
}

TEST(JvmWorkchainCore, ClassStateStoresDeployBytesAndKeepsManifestResolver) {
  using namespace jvm_workchain;

  JvmAvataClassState state;
  state.manifest_entries.push_back(make_test_jvm_class_manifest_entry(0x31));
  state.classes.push_back(make_test_jvm_class_definition(0x31));

  auto encoded = encode_jvm_avata_class_state(state);
  CHECK(encoded.not_null());

  auto manifest_entries = parse_jvm_avata_class_manifest(encoded).move_as_ok();
  CHECK(manifest_entries.size() == 1);
  CHECK(manifest_entries[0].method_name == "ok");
  check_jvm_class_manifest_marker(encoded, 0x31);

  auto parsed_state = parse_jvm_avata_class_state(encoded).move_as_ok();
  CHECK(parsed_state.manifest_entries.size() == 1);
  CHECK(parsed_state.classes.size() == 1);
  CHECK(parsed_state.classes[0].class_name == "ContractEntryPoint");
  CHECK(parsed_state.classes[0].class_hash == state.classes[0].class_hash);
  CHECK(parsed_state.classes[0].class_bytes == state.classes[0].class_bytes);

  auto definition = find_jvm_avata_class_definition(
      encoded, "ContractEntryPoint").move_as_ok();
  CHECK(definition.class_bytes == state.classes[0].class_bytes);
  CHECK(parse_jvm_avata_class_state(make_jvm_class_manifest_cell(0x32))
            .move_as_ok()
            .classes.empty());

  auto duplicate = state;
  duplicate.classes.push_back(state.classes[0]);
  CHECK(encode_jvm_avata_class_state(duplicate).is_null());

  auto bad_hash = state;
  bad_hash.classes[0].class_hash[0] ^= 0xff;
  CHECK(encode_jvm_avata_class_state(bad_hash).is_null());

  auto descriptor = make_test_jvm_deploy_descriptor(0x33);
  auto installed = install_jvm_deploy_descriptor(
      make_jvm_class_manifest_cell(0x33), descriptor).move_as_ok();
  CHECK(installed.contract_id ==
        derive_jvm_contract_id(descriptor).move_as_ok());

  auto installed_state = parse_jvm_avata_class_state(
      installed.class_state_root).move_as_ok();
  CHECK(installed_state.manifest_entries.size() == 1);
  CHECK(installed_state.classes.size() == 1);
  CHECK(installed_state.classes[0].class_bytes == descriptor.class_bytes);

  auto installed_again = install_jvm_deploy_descriptor(
      installed.class_state_root, descriptor).move_as_ok();
  CHECK(parse_jvm_avata_class_state(installed_again.class_state_root)
            .move_as_ok()
            .classes.size() == 1);

  JvmClassStoreLimits exact_limits;
  exact_limits.max_class_bytes =
      static_cast<std::uint32_t>(descriptor.class_bytes.size());
  exact_limits.max_total_class_bytes =
      static_cast<std::uint32_t>(descriptor.class_bytes.size());
  CHECK(install_jvm_deploy_descriptor(
            make_jvm_class_manifest_cell(0x33), descriptor, exact_limits)
            .is_ok());
  auto config_limits = make_test_jvm_config();
  config_limits.max_class_bytes =
      static_cast<std::uint32_t>(descriptor.class_bytes.size());
  config_limits.max_total_class_bytes =
      static_cast<std::uint32_t>(descriptor.class_bytes.size());
  CHECK(install_jvm_deploy_descriptor(
            make_jvm_class_manifest_cell(0x33), descriptor, config_limits)
            .is_ok());

  JvmClassStoreLimits too_small_class = exact_limits;
  --too_small_class.max_class_bytes;
  CHECK(install_jvm_deploy_descriptor(
            make_jvm_class_manifest_cell(0x33),
            descriptor,
            too_small_class)
            .is_error());

  auto second_descriptor = make_test_jvm_deploy_descriptor(0x34);
  second_descriptor.class_name = "SecondContractEntryPoint";
  auto first_with_limits = install_jvm_deploy_descriptor(
      make_jvm_class_manifest_cell(0x33), descriptor, exact_limits)
                               .move_as_ok();
  CHECK(install_jvm_deploy_descriptor(
            first_with_limits.class_state_root,
            second_descriptor,
            exact_limits)
            .is_error());

  auto conflicting = descriptor;
  conflicting.class_bytes.push_back(0x99);
  conflicting.class_hash = compute_jvm_class_hash(conflicting.class_bytes);
  CHECK(install_jvm_deploy_descriptor(
            installed.class_state_root, conflicting).is_error());
}

TEST(JvmWorkchainCore, DeployAbiRoundTripsAndDerivesContractId) {
  using namespace jvm_workchain;

  auto descriptor = make_test_jvm_deploy_descriptor(0x21);
  auto encoded = encode_jvm_deploy_descriptor(descriptor);
  CHECK(encoded.not_null());

  auto parsed = parse_jvm_deploy_descriptor(
      vm::load_cell_slice_ref(encoded)).move_as_ok();
  CHECK(parsed.schema_version == kJvmDeployDescriptorSchemaVersion);
  CHECK(parsed.deployer == descriptor.deployer);
  CHECK(parsed.salt == descriptor.salt);
  CHECK(parsed.class_hash == descriptor.class_hash);
  CHECK(parsed.class_name == "ContractEntryPoint");
  CHECK(parsed.class_bytes == descriptor.class_bytes);
  CHECK(parsed.init_args.not_null());
  CHECK(parsed.init_args->get_hash() == descriptor.init_args->get_hash());

  auto contract_id = derive_jvm_contract_id(parsed).move_as_ok();
  CHECK(contract_id != JvmContractId{});
  CHECK(derive_jvm_contract_id(parsed).move_as_ok() == contract_id);

  auto different_salt = parsed;
  different_salt.salt[0] ^= 0x7f;
  CHECK(derive_jvm_contract_id(different_salt).move_as_ok() != contract_id);

  auto bad = descriptor;
  bad.class_hash[0] ^= 0xff;
  CHECK(encode_jvm_deploy_descriptor(bad).is_null());

  bad = descriptor;
  bad.class_bytes.clear();
  bad.class_hash = compute_jvm_class_hash(bad.class_bytes);
  CHECK(encode_jvm_deploy_descriptor(bad).is_null());

  bad = descriptor;
  bad.class_name = "Contract.EntryPoint";
  CHECK(encode_jvm_deploy_descriptor(bad).is_null());

  bad = descriptor;
  bad.deployer = {};
  CHECK(encode_jvm_deploy_descriptor(bad).is_null());

  CHECK(parse_jvm_deploy_descriptor(
            vm::load_cell_slice_ref(make_marker_cell(0x01))).is_error());
}

TEST(JvmWorkchainCore, LinkedAvataExecutionApiUsesInterpreterAbi) {
  using namespace jvm_workchain;

  auto api = make_linked_jvm_avata_execution_api();
  CHECK(api.ok_status == AVATA_CONTRACT_OK);
  CHECK(api.out_of_gas_status == AVATA_CONTRACT_OUT_OF_GAS);
  CHECK(api.out_of_memory_status == AVATA_CONTRACT_OUT_OF_MEMORY);
  CHECK(api.gas_api.set_opcode_gas_costs != nullptr);
  CHECK(api.gas_api.set_contract_helper_gas_costs != nullptr);
  CHECK(api.set_storage_host != nullptr);
  CHECK(api.clear_storage_host != nullptr);
  CHECK(api.set_event_host != nullptr);
  CHECK(api.clear_event_host != nullptr);
  CHECK(api.begin_contract_transaction_with_limits != nullptr);
  CHECK(api.end_contract_transaction != nullptr);
  CHECK(api.contract_remaining_gas != nullptr);
  CHECK(api.contract_memory_used != nullptr);
  CHECK(api.invoke_contract != nullptr);
  CHECK(api.invoke_contract(nullptr, nullptr) == AVATA_CONTRACT_BAD_ARGUMENT);
}

TEST(JvmWorkchainCore, GasBridgeInstallsConfigParam85Tables) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  JvmAvataGasApi api;
  api.ok_status = 0;
  api.set_opcode_gas_costs = fake_jvm_set_opcode_gas_costs;
  api.set_contract_helper_gas_costs = fake_jvm_set_helper_gas_costs;

  FakeJvmGasThread thread;
  CHECK(apply_jvm_gas_config_to_avata_thread(&thread, cfg, api).is_ok());
  CHECK(thread.opcode_costs == cfg.opcode_gas_costs.data());
  CHECK(thread.opcode_count == cfg.opcode_gas_costs.size());
  CHECK(thread.helper_costs == cfg.helper_gas_costs.data());
  CHECK(thread.helper_count == cfg.helper_gas_costs.size());

  thread.fail_helper_install = true;
  CHECK(apply_jvm_gas_config_to_avata_thread(&thread, cfg, api).is_error());

  cfg.chain_id = 0;
  thread.fail_helper_install = false;
  CHECK(apply_jvm_gas_config_to_avata_thread(&thread, cfg, api).is_error());
  CHECK(apply_jvm_gas_config_to_avata_thread(nullptr, make_test_jvm_config(), api).is_error());
}

TEST(JvmWorkchainCore, ConfigParam85CodecRoundTripsGasTables) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 77;
  cfg.max_gas_per_tx = 123456;
  cfg.max_heap_bytes = 987654;
  cfg.opcode_gas_costs[0] = 11;
  cfg.opcode_gas_costs[255] = 99;
  cfg.helper_gas_costs[0] = 101;
  cfg.helper_gas_costs[kJvmContractHelperGasCostCount - 1] = 909;

  auto encoded = build_jvm_config_cell(cfg);
  CHECK(encoded.not_null());

  auto decoded = parse_jvm_config_cell(encoded).move_as_ok();
  CHECK(decoded.chain_id == cfg.chain_id);
  CHECK(decoded.schema_version == cfg.schema_version);
  CHECK(decoded.gas_price == 77);
  CHECK(decoded.max_gas_per_tx == 123456);
  CHECK(decoded.max_heap_bytes == 987654);
  CHECK(decoded.stdlib_hash == cfg.stdlib_hash);
  CHECK(decoded.opcode_gas_costs == cfg.opcode_gas_costs);
  CHECK(decoded.helper_gas_costs == cfg.helper_gas_costs);

  CHECK(parse_jvm_config_cell({}).is_error());

  cfg.opcode_gas_costs[42] = 0;
  CHECK(build_jvm_config_cell(cfg).is_null());
}

TEST(JvmWorkchainCore, WorkchainDescriptorUsesJvmV1Selector) {
  using namespace jvm_workchain;

  tos::RootHash root_hash = tos::RootHash::zero();
  tos::FileHash file_hash = tos::FileHash::zero();
  root_hash.data()[31] = 0x3a;
  file_hash.data()[31] = 0x3b;

  auto cell = build_jvm_workchain_descr(root_hash, file_hash, 123);
  CHECK(cell.not_null());
  CHECK(block::gen::t_WorkchainDescr.validate_ref(cell));

  auto cs = vm::load_cell_slice(cell);
  td::Ref<block::WorkchainInfo> info{true};
  CHECK(info.unique_write().unpack(3, cs));
  auto descriptor = block::normalize_workchain_descriptor(*info).move_as_ok();

  CHECK(descriptor.workchain_id == 3);
  CHECK(descriptor.active);
  CHECK(descriptor.accept_msgs);
  CHECK(descriptor.format == block::WorkchainFormat::Basic);
  CHECK(descriptor.vm_version == kJvmVmVersion);
  CHECK(descriptor.vm_mode == 0);
  CHECK(descriptor.enabled_since == 123);
  CHECK(descriptor.min_split == 0);
  CHECK(descriptor.max_split == 8);
  CHECK(descriptor.zerostate_root_hash == root_hash);
  CHECK(descriptor.zerostate_file_hash == file_hash);
  CHECK(block::workchain_engine_key_is_jvm(
      block::workchain_engine_key_from_descriptor(descriptor)));
}

TEST(JvmWorkchainCore, AvataTransactionCommitsSuccessfulStorageWrites) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  JvmEventHost events;
  FakeJvmExecutionThread thread;
  thread.remaining_gas = 900;
  thread.memory_used = 1234;

  auto result = execute_jvm_avata_transaction(
      &thread, cfg, 1000, storage, api, nullptr, &events).move_as_ok();
  CHECK(result.success);
  CHECK(!result.out_of_gas);
  CHECK(result.gas_used == 100);
  CHECK(result.gas_remaining == 900);
  CHECK(result.memory_used == 1234);
  CHECK(result.storage_root.not_null());
  CHECK(thread.began);
  CHECK(thread.ended);
  CHECK(thread.invoked);
  CHECK(thread.gas_limit == 1000);
  CHECK(thread.memory_limit == cfg.max_heap_bytes);
  CHECK(fake_jvm_storage_host == nullptr);
  CHECK(fake_jvm_event_host == nullptr);
  CHECK(result.events.size() == 1);
  CHECK(events.events().size() == 1);
  CHECK(result.action_list.not_null());
  CHECK(block::gen::OutList{1}.validate_ref(result.action_list));
  CHECK(result.events[0].topics.size() == 2);
  CHECK(result.events[0].topics[0][31] == 1);
  CHECK(result.events[0].topics[1][31] == 2);
  CHECK(result.events[0].data == (JvmEventData{4, 5, 6}));

  JvmStorageSlot slot{};
  slot[31] = 9;
  auto loaded = storage.load(slot).move_as_ok();
  CHECK(loaded.has_value());
  CHECK(*loaded == (JvmStorageValue{1, 2, 3}));
}

TEST(JvmWorkchainCore, AvataTransactionRollsBackFailedInvocation) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  JvmEventHost events;
  FakeJvmExecutionThread thread;
  thread.invoke_status = 7;
  thread.remaining_gas = 750;
  thread.memory_used = 64;

  auto result = execute_jvm_avata_transaction(
      &thread, cfg, 1000, storage, api, nullptr, &events).move_as_ok();
  CHECK(!result.success);
  CHECK(!result.out_of_gas);
  CHECK(result.invocation_status == 7);
  CHECK(result.gas_used == 250);
  CHECK(result.storage_root.is_null());
  CHECK(result.action_list.is_null());
  CHECK(result.events.empty());
  CHECK(events.events().empty());
  CHECK(thread.began);
  CHECK(thread.ended);
  CHECK(thread.invoked);
  CHECK(fake_jvm_storage_host == nullptr);
  CHECK(fake_jvm_event_host == nullptr);

  JvmStorageSlot slot{};
  slot[31] = 9;
  auto loaded = storage.load(slot).move_as_ok();
  CHECK(!loaded.has_value());
}

TEST(JvmWorkchainCore, EventPayloadAndActionListCodec) {
  using namespace jvm_workchain;

  JvmEvent event;
  event.topics.resize(2);
  event.topics[0][31] = 0x11;
  event.topics[1][0] = 0x22;
  event.data = JvmEventData{7, 8, 9};

  auto payload = encode_jvm_event_payload(event);
  CHECK(payload.not_null());
  auto decoded = decode_jvm_event_payload(payload).move_as_ok();
  CHECK(decoded.topics == event.topics);
  CHECK(decoded.data == event.data);

  auto msg = encode_jvm_event_message(event);
  CHECK(msg.not_null());
  CHECK(block::gen::t_MessageRelaxed_Any.validate_ref(msg));

  JvmEvent second;
  second.topics.resize(1);
  second.topics[0][31] = 0x33;
  second.data = JvmEventData{};

  auto actions = build_jvm_event_action_list(std::vector<JvmEvent>{event, second});
  CHECK(actions.not_null());
  CHECK(block::gen::OutList{2}.validate_ref(actions));

  auto empty_actions = build_jvm_event_action_list(std::vector<JvmEvent>{});
  CHECK(empty_actions.not_null());
  CHECK(block::gen::OutList{0}.validate_ref(empty_actions));
}

TEST(JvmWorkchainCore, AvataTransactionClassifiesOutOfGasAndFailsClosed) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  FakeJvmExecutionThread thread;
  thread.invoke_status = api.out_of_gas_status;
  thread.remaining_gas = 0;
  thread.memory_used = 32;

  auto result = execute_jvm_avata_transaction(
      &thread, cfg, 1000, storage, api, nullptr).move_as_ok();
  CHECK(!result.success);
  CHECK(result.out_of_gas);
  CHECK(!result.out_of_memory);
  CHECK(result.gas_used == 1000);
  CHECK(fake_jvm_storage_host == nullptr);

  JvmStorageSlot slot{};
  slot[31] = 9;
  auto loaded = storage.load(slot).move_as_ok();
  CHECK(!loaded.has_value());

  FakeJvmExecutionThread begin_failure;
  begin_failure.begin_status = 1;
  CHECK(execute_jvm_avata_transaction(
            &begin_failure, cfg, 1000, storage, api, nullptr).is_error());
  CHECK(begin_failure.began);
  CHECK(!begin_failure.invoked);
  CHECK(fake_jvm_storage_host == nullptr);

  FakeJvmExecutionThread bad_gas_report;
  bad_gas_report.remaining_gas = 1001;
  CHECK(execute_jvm_avata_transaction(
            &bad_gas_report, cfg, 1000, storage, api, nullptr).is_error());
  CHECK(bad_gas_report.ended);
  CHECK(fake_jvm_storage_host == nullptr);
}

TEST(JvmWorkchainCore, AvataInvocationBuildsSuccessfulComputeOutput) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 7;
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  JvmEventHost events;
  FakeJvmExecutionThread thread;
  thread.remaining_gas = 900;
  thread.memory_used = 1234;

  JvmExecutorState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.storage_root = storage.root_cell();
  previous_state.class_state_root = make_jvm_class_manifest_cell(0x44);

  auto invocation = execute_jvm_avata_transaction(
      &thread, cfg, 1000, storage, api, nullptr, &events).move_as_ok();
  auto output = build_jvm_workchain_output(
      cfg, previous_state, 1000, invocation).move_as_ok();

  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(output.committed);
  CHECK(output.engine_success);
  CHECK(!output.out_of_gas);
  CHECK(output.skip_reason == block::ComputePhase::sk_none);
  CHECK(output.exit_code == 0);
  CHECK(output.gas_used == 100);
  CHECK(output.gas_fees.not_null());
  CHECK(td::cmp(output.gas_fees, td::make_refint(700)) == 0);
  CHECK(output.new_data.not_null());
  CHECK(output.action_list.not_null());
  CHECK(block::gen::OutList{1}.validate_ref(output.action_list));

  JvmExecutorState decoded;
  CHECK(decode_jvm_executor_state(output.new_data, decoded));
  CHECK(decoded.stdlib_hash == cfg.stdlib_hash);
  CHECK(decoded.storage_root.not_null());
  CHECK(decoded.class_state_root.not_null());

  JvmStorageCellHost decoded_storage(decoded.storage_root);
  JvmStorageSlot slot{};
  slot[31] = 9;
  auto loaded = decoded_storage.load(slot).move_as_ok();
  CHECK(loaded.has_value());
  CHECK(*loaded == (JvmStorageValue{1, 2, 3}));

  check_jvm_class_manifest_marker(decoded.class_state_root, 0x44);

  invocation.action_list = {};
  invocation.events.clear();
  auto no_event_output = build_jvm_workchain_output(
      cfg, previous_state, 1000, invocation).move_as_ok();
  CHECK(no_event_output.action_list.not_null());
  CHECK(block::gen::OutList{0}.validate_ref(no_event_output.action_list));

  previous_state.stdlib_hash[0] ^= 0xff;
  CHECK(build_jvm_workchain_output(
            cfg, previous_state, 1000, invocation).is_error());
}

TEST(JvmWorkchainCore, AvataInvocationBuildsFailedComputeOutput) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 3;
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  JvmEventHost events;
  FakeJvmExecutionThread thread;
  thread.invoke_status = 7;
  thread.remaining_gas = 750;
  thread.memory_used = 64;

  JvmExecutorState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.storage_root = storage.root_cell();
  previous_state.class_state_root = make_jvm_class_manifest_cell(0x55);

  auto invocation = execute_jvm_avata_transaction(
      &thread, cfg, 1000, storage, api, nullptr, &events).move_as_ok();
  auto output = build_jvm_workchain_output(
      cfg, previous_state, 1000, invocation).move_as_ok();

  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(!output.committed);
  CHECK(!output.engine_success);
  CHECK(!output.out_of_gas);
  CHECK(output.skip_reason == block::ComputePhase::sk_none);
  CHECK(output.exit_code == 7);
  CHECK(output.gas_used == 250);
  CHECK(output.gas_fees.not_null());
  CHECK(td::cmp(output.gas_fees, td::make_refint(750)) == 0);
  CHECK(output.new_data.is_null());
  CHECK(output.action_list.is_null());
}

TEST(JvmWorkchainCore, AvataInvocationBuildsOutOfGasComputeOutput) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 5;
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  FakeJvmExecutionThread thread;
  thread.invoke_status = api.out_of_gas_status;
  thread.remaining_gas = 0;
  thread.memory_used = 32;

  JvmExecutorState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.storage_root = storage.root_cell();

  auto invocation = execute_jvm_avata_transaction(
      &thread, cfg, 1000, storage, api, nullptr).move_as_ok();
  auto output = build_jvm_workchain_output(
      cfg, previous_state, 1000, invocation).move_as_ok();

  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(!output.committed);
  CHECK(!output.engine_success);
  CHECK(output.out_of_gas);
  CHECK(output.skip_reason == block::ComputePhase::sk_none);
  CHECK(output.exit_code == api.out_of_gas_status);
  CHECK(output.gas_used == 1000);
  CHECK(output.gas_fees.not_null());
  CHECK(td::cmp(output.gas_fees, td::make_refint(5000)) == 0);
  CHECK(output.new_data.is_null());
  CHECK(output.action_list.is_null());
}

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

TEST(WorkchainExecutionRegistry, RejectsExecutionDescriptorTransitionsWithoutMigration) {
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

  new_workchains[7] = make_basic_workchain_info(7, kEvmVmVersion, 0x544F53);
  new_workchains[7].unique_write().zerostate_root_hash.data()[31] = 1;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[7] = make_basic_workchain_info(7, kEvmVmVersion, 0x544F53);
  new_workchains[7].unique_write().zerostate_file_hash.data()[31] = 1;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains.clear();
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[7] = make_basic_workchain_info(7, kUnoVmVersion, 0);
  new_workchains[7].unique_write().active = false;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[7] = make_basic_workchain_info(7, kEvmVmVersion, 0x544F53);
  new_workchains[7].unique_write().active = false;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_ok());

  old_workchains[7].unique_write().active = false;
  new_workchains[7] = make_basic_workchain_info(7, kEvmVmVersion, 0x544F53);
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_ok());

  new_workchains[7] = make_basic_workchain_info(7, kUnoVmVersion, 0);
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[7].unique_write().active = false;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[7] = make_basic_workchain_info(7, kEvmVmVersion, 0x544F53);
  new_workchains[7].unique_write().active = false;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_ok());

  old_workchains.clear();
  new_workchains.clear();
  old_workchains.emplace(8, make_extended_workchain_info(8, kDummyExtendedType));
  new_workchains.emplace(8, make_extended_workchain_info(8, kDummyExtendedType));
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_ok());

  new_workchains[8].unique_write().min_addr_len = 128;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[8] = make_extended_workchain_info(8, kDummyExtendedType);
  new_workchains[8].unique_write().max_addr_len = 512;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());

  new_workchains[8] = make_extended_workchain_info(8, kDummyExtendedType);
  new_workchains[8].unique_write().addr_len_step = 16;
  CHECK(block::validate_workchain_execution_descriptor_transitions(
      old_workchains, new_workchains).is_error());
}

TEST(WorkchainExecutionRegistry, EngineDefinedPolicyValidates) {
  // EngineDefined was previously a stub that always returned an error;
  // JVM v2 needs it to validate so per-account contract topology is
  // accepted by the host. The capability flag
  // `admits_engine_create_account_actions` is a free-standing extension
  // and must not affect validation either way.
  block::AccountExecutionPolicy policy;
  policy.kind = block::AccountExecutionPolicyKind::EngineDefined;
  policy.singleton_address.reset();
  policy.admits_engine_create_account_actions = false;
  CHECK(block::validate_account_execution_policy_supported(policy).is_ok());
  policy.admits_engine_create_account_actions = true;
  CHECK(block::validate_account_execution_policy_supported(policy).is_ok());

  // Other unimplemented variants must still fail closed (regression
  // guard: the EngineDefined fix should not silently accept the
  // shard-local stub).
  block::AccountExecutionPolicy shard_local;
  shard_local.kind = block::AccountExecutionPolicyKind::ShardLocalExecutor;
  CHECK(block::validate_account_execution_policy_supported(shard_local).is_error());
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
  CHECK((block::workchain_execution_capability_flags(registry) &
         block::kTosNodeCapabilityWorkchainJvm) == 0);

  jvm_workchain::register_jvm_workchain_engine(registry);
  CHECK((block::workchain_execution_capability_flags(registry) &
         block::kTosNodeCapabilityWorkchainJvm) != 0);
  CHECK(registry.has_engine(block::jvm_workchain_engine_key()));

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

  auto jvm_bad_mode = make_basic_descriptor(3, jvm_workchain::kJvmVmVersion, 1);
  CHECK(registry.resolve(jvm_bad_mode, config).is_error());

  auto jvm_missing_config = make_basic_descriptor(3, jvm_workchain::kJvmVmVersion, 0);
  CHECK(registry.resolve(jvm_missing_config, config).is_error());
}

TEST(WorkchainExecutionRegistry, JvmEngineAccountPolicyIsEngineDefined) {
  // JVM v2 declares EngineDefined + admits_engine_create_account_actions so
  // the host accepts any wc=3 address and lets the engine emit
  // `action_create_account` to materialize per-contract accounts.  Regression
  // guard: under v1 this returned SingletonExecutor with the 0x0000…0001
  // address.
  using namespace jvm_workchain;

  auto jvm_cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(jvm_cfg);

  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();
  auto policy = execution.executor->account_policy(execution.descriptor,
                                                   *execution.engine_config);
  CHECK(policy.kind == block::AccountExecutionPolicyKind::EngineDefined);
  CHECK(!policy.singleton_address.has_value());
  CHECK(policy.admits_engine_create_account_actions);
  CHECK(policy.activation_code.not_null());
  CHECK(policy.may_activate_uninitialized_account);
  CHECK(policy.accepts_external_inbound);
  CHECK(policy.accepts_internal_inbound);
}

TEST(WorkchainExecutionRegistry, JvmEngineRunsInstalledRuntimeAdapter) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 7;
  auto config = make_config_with_jvm_param(cfg);

  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  block::WorkchainExecutionRegistry missing_runtime_registry;
  register_jvm_workchain_engine(missing_runtime_registry);
  auto missing_runtime_execution =
      missing_runtime_registry.resolve(descriptor, *config).move_as_ok();

  block::WorkchainComputeInput missing_runtime_input;
  missing_runtime_input.inbound_body = make_jvm_call_body(0x01);
  missing_runtime_input.gas_limit = 1000;

  block::WorkchainComputeContext missing_runtime_context;
  missing_runtime_context.workchain_id = 3;
  missing_runtime_context.descriptor = descriptor;
  missing_runtime_context.engine_config = missing_runtime_execution.engine_config;
  auto missing_runtime_output = missing_runtime_execution.executor->run_compute(
      missing_runtime_input, missing_runtime_context).move_as_ok();
  CHECK(missing_runtime_output.completed);
  CHECK(!missing_runtime_output.accepted);
  CHECK(missing_runtime_output.skip_reason == block::ComputePhase::sk_bad_state);

  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();
  CHECK(block::resolved_workchain_execution_is_custom(execution));

  JvmStorageCellHost storage;
  JvmExecutorState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.storage_root = storage.root_cell();
  previous_state.class_state_root = make_jvm_class_manifest_cell(0x66);

  block::WorkchainComputeInput input;
  input.current_data = encode_jvm_executor_state(previous_state);
  input.inbound_body = make_jvm_call_body(0x02);
  input.gas_limit = 1000;

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(runtime->called);
  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(output.committed);
  CHECK(output.engine_success);
  CHECK(output.gas_used == 123);
  CHECK(output.gas_fees.not_null());
  CHECK(td::cmp(output.gas_fees, td::make_refint(861)) == 0);
  CHECK(output.action_list.not_null());
  CHECK(block::gen::OutList{0}.validate_ref(output.action_list));

  JvmExecutorState decoded;
  CHECK(decode_jvm_executor_state(output.new_data, decoded));
  CHECK(decoded.stdlib_hash == cfg.stdlib_hash);
  CHECK(decoded.class_state_root.not_null());

  check_jvm_class_manifest_marker(decoded.class_state_root, 0x66);

  JvmStorageCellHost decoded_storage(decoded.storage_root);
  JvmStorageSlot slot{};
  slot[31] = 0x77;
  auto loaded = decoded_storage.load(slot).move_as_ok();
  CHECK(loaded.has_value());
  CHECK(*loaded == (JvmStorageValue{8, 9, 10}));
}

TEST(WorkchainExecutionRegistry, JvmEngineDispatchesV2AccountStateToRuntime) {
  // A wc=3 inbound that carries `JvmContractAccountState` (JVAC) as
  // current_data and a v2 `JvmCallDescriptor` body must be dispatched through
  // `JvmComputeRuntime::run_contract_v2`, not the v1 path.  The output
  // re-encodes a JVAC cell with the new storage_root and preserves the
  // pinned class_hash / class_bytes / manifest_root.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  // Build a per-account state with realistic class_bytes + single-method
  // manifest.  The mock runtime writes an extra storage slot at 0xa1 to
  // exercise the storage round-trip.
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x10};
  auto class_bytes_cell = encode_jvm_storage_value(class_bytes);
  CHECK(class_bytes_cell.not_null());

  JvmMethodManifestEntry method_entry;
  method_entry.method_id = 0xdeadbeef;
  method_entry.class_name = "ContractEntryPoint";
  method_entry.method_name = "ok";
  method_entry.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({method_entry});
  CHECK(manifest_root.not_null());

  JvmStorageCellHost initial_storage;
  JvmStorageSlot seed_slot{};
  seed_slot[0] = 0xaa;
  CHECK(initial_storage.store(seed_slot, JvmStorageValue{0x01}).is_ok());

  JvmContractAccountState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.class_hash = compute_jvm_class_hash(class_bytes);
  previous_state.class_bytes = class_bytes_cell;
  previous_state.storage_root = initial_storage.root_cell();
  previous_state.manifest_root = manifest_root;

  block::WorkchainComputeInput input;
  input.current_data = encode_jvm_contract_account_state(previous_state);
  CHECK(input.current_data.not_null());
  input.inbound_body = make_jvm_call_body_v2(method_entry.method_id);
  input.gas_limit = 1000;

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(runtime->called_v2);
  CHECK(!runtime->called);  // v1 path must NOT have been entered
  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(output.committed);
  CHECK(output.engine_success);
  CHECK(output.gas_used == 123);
  CHECK(output.action_list.not_null());

  JvmContractAccountState decoded;
  CHECK(decode_jvm_contract_account_state(output.new_data, decoded));
  CHECK(decoded.class_hash == previous_state.class_hash);
  CHECK(decoded.class_bytes->get_hash() == class_bytes_cell->get_hash());
  CHECK(decoded.manifest_root.not_null());
  CHECK(decoded.manifest_root->get_hash() == manifest_root->get_hash());
  CHECK(decoded.stdlib_hash == cfg.stdlib_hash);

  // The mock writes slot[31]=0xa1 = {0xde,0xad}; the seed slot at [0]=0xaa
  // must still be present (storage merges, not replaces).
  JvmStorageCellHost decoded_storage(decoded.storage_root);
  JvmStorageSlot mock_slot{};
  mock_slot[31] = 0xa1;
  auto mock_loaded = decoded_storage.load(mock_slot).move_as_ok();
  CHECK(mock_loaded.has_value());
  CHECK(*mock_loaded == (JvmStorageValue{0xde, 0xad}));
  auto seed_loaded = decoded_storage.load(seed_slot).move_as_ok();
  CHECK(seed_loaded.has_value());
  CHECK(*seed_loaded == (JvmStorageValue{0x01}));
}

TEST(WorkchainExecutionRegistry, JvmEngineV2RejectsMalformedAccountState) {
  // If `current_data` carries the JVAC magic but the rest of the cell is
  // junk, the engine must skip with sk_bad_state — without ever calling
  // either runtime path.  Regression guard for the magic-based dispatch.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  // current_data is a cell that begins with the JVAC magic but is otherwise
  // truncated.
  vm::CellBuilder cb;
  cb.store_long(kJvmContractAccountStateMagic, 32);
  cb.store_long(0, 8);  // wrong schema_version
  block::WorkchainComputeInput input;
  input.current_data = cb.finalize();
  input.inbound_body = make_jvm_call_body_v2(0x1);
  input.gas_limit = 1000;

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(output.completed);
  CHECK(!output.accepted);
  CHECK(output.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);
  CHECK(!runtime->called_v2);
}

TEST(WorkchainExecutionRegistry, JvmV2EndToEndDeployCallSequence) {
  // End-to-end v2 sequence using the engine + a mock runtime: simulate a
  // deploy that yields the initial account state, then two calls that
  // mutate storage, with the engine round-tripping JVAC cells through
  // input.current_data / output.new_data each time.  Verifies:
  //   * `derive_jvm_contract_address` is deterministic
  //   * the engine dispatches v2 cells to run_contract_v2
  //   * class_hash / class_bytes / manifest_root are pinned across calls
  //   * storage_root advances between calls
  //   * a different salt produces a different address (isolation invariant)
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);
  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  // Build a deploy descriptor and verify the v2 address derivation.
  auto deploy_desc = make_test_jvm_deploy_descriptor(0xa5);
  auto address_a = derive_jvm_contract_address(deploy_desc).move_as_ok();
  auto address_b = derive_jvm_contract_address(deploy_desc).move_as_ok();
  CHECK(address_a == address_b);  // determinism

  // Different salt yields a different per-account address (storage is
  // therefore isolated; this is the v2 alternative to v1's contract_id key).
  auto deploy_desc_other_salt = deploy_desc;
  deploy_desc_other_salt.salt[0] ^= 0xff;
  auto address_c =
      derive_jvm_contract_address(deploy_desc_other_salt).move_as_ok();
  CHECK(address_c != address_a);

  // Build the initial account state that `action_create_account` would
  // install for this deploy descriptor (this is the v2 analog of
  // install_jvm_deploy_descriptor in v1).
  auto class_bytes_cell = encode_jvm_storage_value(deploy_desc.class_bytes);
  CHECK(class_bytes_cell.not_null());
  JvmMethodManifestEntry method_entry;
  method_entry.method_id = 0xb00b1e5;
  method_entry.class_name = deploy_desc.class_name;
  method_entry.method_name = "ok";
  method_entry.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({method_entry});
  CHECK(manifest_root.not_null());

  JvmContractAccountState state0;
  state0.stdlib_hash = cfg.stdlib_hash;
  state0.class_hash = deploy_desc.class_hash;
  state0.class_bytes = class_bytes_cell;
  state0.storage_root = JvmStorageCellHost{}.root_cell();
  state0.manifest_root = manifest_root;
  auto state0_cell = encode_jvm_contract_account_state(state0);
  CHECK(state0_cell.not_null());

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  // Call 1: feed state0, expect engine to dispatch to v2 path and produce
  // a state1 cell with a different storage_root.
  block::WorkchainComputeInput call1;
  call1.current_data = state0_cell;
  call1.inbound_body = make_jvm_call_body_v2(method_entry.method_id);
  call1.gas_limit = 1000;
  auto out1 = execution.executor->run_compute(call1, context).move_as_ok();
  CHECK(runtime->called_v2);
  CHECK(out1.committed);
  CHECK(out1.new_data.not_null());
  CHECK(out1.new_data->get_hash() != state0_cell->get_hash());

  JvmContractAccountState state1;
  CHECK(decode_jvm_contract_account_state(out1.new_data, state1));
  CHECK(state1.class_hash == state0.class_hash);
  CHECK(state1.class_bytes->get_hash() == class_bytes_cell->get_hash());
  CHECK(state1.manifest_root->get_hash() == manifest_root->get_hash());

  // Call 2: feed state1, expect another storage advance.  class_hash /
  // class_bytes / manifest must remain pinned.
  runtime->called_v2 = false;
  block::WorkchainComputeInput call2;
  call2.current_data = out1.new_data;
  call2.inbound_body = make_jvm_call_body_v2(method_entry.method_id);
  call2.gas_limit = 1000;
  auto out2 = execution.executor->run_compute(call2, context).move_as_ok();
  CHECK(runtime->called_v2);
  CHECK(out2.committed);
  JvmContractAccountState state2;
  CHECK(decode_jvm_contract_account_state(out2.new_data, state2));
  CHECK(state2.class_hash == state0.class_hash);
  CHECK(state2.class_bytes->get_hash() == class_bytes_cell->get_hash());
  CHECK(state2.manifest_root->get_hash() == manifest_root->get_hash());

  // Determinism: re-running call 1 from state0 produces the same new_data
  // (the engine is a pure function of state + input).
  runtime->called_v2 = false;
  auto out1_again = execution.executor->run_compute(call1, context).move_as_ok();
  CHECK(runtime->called_v2);
  CHECK(out1_again.new_data.not_null());
  CHECK(out1_again.new_data->get_hash() == out1.new_data->get_hash());
}

TEST(WorkchainExecutionRegistry, JvmEngineRejectsMalformedInboundAbiBeforeRuntime) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  JvmStorageCellHost storage;
  JvmExecutorState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.storage_root = storage.root_cell();

  block::WorkchainComputeInput input;
  input.current_data = encode_jvm_executor_state(previous_state);
  input.inbound_body = vm::load_cell_slice_ref(make_marker_cell(0x22));
  input.gas_limit = 1000;

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(output.completed);
  CHECK(!output.accepted);
  CHECK(output.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);
}

TEST(WorkchainExecutionRegistry, JvmEngineRunsAvataRuntimeExecutionBridge) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 11;
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  FakeJvmExecutionThread thread;
  thread.remaining_gas = 777;
  thread.memory_used = 2048;
  FakeJvmAvataRuntimeResolver resolver;
  resolver.thread = &thread;

  auto runtime = std::make_shared<JvmAvataRuntime>(
      make_test_jvm_execution_api(),
      fake_jvm_resolve_call_target,
      &resolver);
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  JvmStorageCellHost storage;
  JvmExecutorState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.storage_root = storage.root_cell();

  block::WorkchainComputeInput input;
  input.current_data = encode_jvm_executor_state(previous_state);
  input.inbound_body = make_jvm_call_body(0x03);
  input.gas_limit = 1000;

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(resolver.called);
  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(output.committed);
  CHECK(output.engine_success);
  CHECK(!output.out_of_gas);
  CHECK(output.gas_used == 223);
  CHECK(output.gas_fees.not_null());
  CHECK(td::cmp(output.gas_fees, td::make_refint(2453)) == 0);
  CHECK(output.action_list.not_null());
  CHECK(block::gen::OutList{1}.validate_ref(output.action_list));
  CHECK(fake_jvm_storage_host == nullptr);
  CHECK(fake_jvm_event_host == nullptr);

  JvmExecutorState decoded;
  CHECK(decode_jvm_executor_state(output.new_data, decoded));
  JvmStorageCellHost decoded_storage(decoded.storage_root);
  JvmStorageSlot slot{};
  slot[31] = 9;
  auto loaded = decoded_storage.load(slot).move_as_ok();
  CHECK(loaded.has_value());
  CHECK(*loaded == (JvmStorageValue{1, 2, 3}));
}

TEST(WorkchainExecutionRegistry, JvmComputeOutputIsDeterministicAcrossReplay) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 13;
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  FakeJvmAvataRuntimeResolver resolver;
  auto runtime = std::make_shared<JvmAvataRuntime>(
      make_test_jvm_execution_api(),
      fake_jvm_resolve_call_target,
      &resolver);
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  auto run_once = [&]() {
    FakeJvmExecutionThread thread;
    thread.remaining_gas = 701;
    thread.memory_used = 333;
    resolver.thread = &thread;
    resolver.called = false;

    JvmStorageCellHost storage;
    JvmExecutorState previous_state;
    previous_state.stdlib_hash = cfg.stdlib_hash;
    previous_state.storage_root = storage.root_cell();
    previous_state.class_state_root = make_jvm_class_manifest_cell(0x06);

    block::WorkchainComputeInput input;
    input.current_data = encode_jvm_executor_state(previous_state);
    input.inbound_body = make_jvm_call_body(0x06);
    input.gas_limit = 1000;

    block::WorkchainComputeContext context;
    context.workchain_id = 3;
    context.descriptor = descriptor;
    context.engine_config = execution.engine_config;

    auto output = execution.executor->run_compute(input, context).move_as_ok();
    CHECK(resolver.called);
    return output;
  };

  auto first = run_once();
  auto second = run_once();

  CHECK(first.completed == second.completed);
  CHECK(first.accepted == second.accepted);
  CHECK(first.committed == second.committed);
  CHECK(first.engine_success == second.engine_success);
  CHECK(first.out_of_gas == second.out_of_gas);
  CHECK(first.skip_reason == second.skip_reason);
  CHECK(first.exit_code == second.exit_code);
  CHECK(first.gas_used == second.gas_used);
  CHECK(td::cmp(first.gas_fees, second.gas_fees) == 0);
  CHECK(first.vm_log == second.vm_log);
  CHECK(first.new_data.not_null());
  CHECK(second.new_data.not_null());
  CHECK(first.new_data->get_hash() == second.new_data->get_hash());
  CHECK(first.action_list.not_null());
  CHECK(second.action_list.not_null());
  CHECK(first.action_list->get_hash() == second.action_list->get_hash());
}

TEST(WorkchainExecutionRegistry, JvmAvataRuntimeFailsClosedOnBadTargets) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();

  JvmStorageCellHost storage;
  JvmExecutorState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.storage_root = storage.root_cell();

  block::WorkchainComputeInput input;
  input.inbound_body = make_jvm_call_body(0x04);
  input.gas_limit = 1000;

  block::WorkchainComputeContext context;
  context.workchain_id = 3;

  JvmAvataRuntime missing_resolver(make_test_jvm_execution_api(), nullptr);
  CHECK(missing_resolver.run_contract(input, context, cfg, state).is_error());

  FakeJvmAvataRuntimeResolver resolver;
  JvmAvataRuntime missing_thread(
      make_test_jvm_execution_api(),
      fake_jvm_resolve_call_target,
      &resolver);
  CHECK(missing_thread.run_contract(input, context, cfg, state).is_error());

  FakeJvmExecutionThread thread;
  resolver.thread = &thread;
  JvmAvataRuntime runtime(
      make_test_jvm_execution_api(),
      fake_jvm_resolve_call_target,
      &resolver);

  state.storage_root = make_marker_cell(0x99);
  CHECK(runtime.run_contract(input, context, cfg, state).is_error());
  CHECK(!resolver.called);
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
        cp.actions = make_empty_action_list();
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
        cp.actions = make_empty_action_list();
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
        cp.actions = make_empty_action_list();
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
        cp.actions = make_empty_action_list();
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

TEST(WorkchainExecutionRegistry, RejectsSuccessfulCustomComputeWithoutActionList) {
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
        cp.new_data = make_marker_cell(0xB4);
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
        cp.actions = make_empty_action_list();
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
        cp.actions = make_empty_action_list();
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

TEST(WorkchainExecutionRegistry, CustomWorkchainRejectsExternalWhenAcceptMsgsDisabled) {
  auto config = make_empty_config();
  block::WorkchainSet workchains;
  workchains.emplace(2, make_basic_workchain_info(2, kUnoVmVersion, 0));
  workchains[2].unique_write().accept_msgs = false;

  bool compute_called = false;
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<MockUnoEngine>(
      [&](block::ComputePhase& cp,
          td::Ref<vm::Cell> /*state_data*/,
          vm::CellSlice& /*in_msg_body*/,
          uint64_t /*gas_limit*/,
          uint64_t /*block_seqno*/,
          uint64_t /*timestamp*/,
          const uint8_t /*rand_seed*/[32]) {
        compute_called = true;
        cp.accepted = true;
        cp.success = true;
        cp.gas_used = 1;
        cp.gas_fees = td::zero_refint();
        cp.new_data = make_marker_cell(0xB5);
        cp.actions = make_empty_action_list();
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
  CHECK(!tx.compute_phase->accepted);
  CHECK(tx.compute_phase->skip_reason == block::ComputePhase::sk_bad_state);
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
      // EngineDefined is now a supported variant (used by JVM v2). Use the
      // still-unimplemented ShardLocalExecutor to exercise the
      // abort-before-compute path.
      block::AccountExecutionPolicyKind::ShardLocalExecutor));

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

// ---------------------------------------------------------------------------
// JVM zerostate
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, ZerostateAccountsCellIsEmpty) {
  // Under v2 account-native topology the wc=3 genesis shard ships with no
  // preexisting accounts; contracts materialize later via the host
  // `action_create_account` path.  The cell must therefore decode as an
  // empty HashmapAugE(256) — leading bit is 0 (`hme_empty$0`) with no
  // child refs and the dict iterator visits zero entries.
  using namespace jvm_workchain;

  auto cell = build_jvm_zerostate_accounts_cell();
  CHECK(cell.not_null());

  // Determinism: building the cell twice must produce the same hash.
  auto cell2 = build_jvm_zerostate_accounts_cell();
  CHECK(cell2.not_null());
  CHECK(cell->get_hash() == cell2->get_hash());

  vm::CellSlice cs = vm::load_cell_slice(cell);
  CHECK(cs.prefetch_ulong(1) == 0);  // hme_empty$0
  CHECK(cs.size_refs() == 0);

  // Round-trip through AugmentedDictionary: zero entries.
  vm::AugmentedDictionary accounts_dict(vm::load_cell_slice_ref(cell), 256,
                                        block::tlb::aug_ShardAccounts);
  std::size_t entries = 0;
  accounts_dict.check_for_each([&entries](td::Ref<vm::CellSlice>,
                                          td::ConstBitPtr,
                                          int) -> bool {
    ++entries;
    return true;
  });
  CHECK(entries == 0);
}

// ---------------------------------------------------------------------------
// End-to-end deploy → call → persist integration test.
//
// Simulates three consecutive transactions against JvmNativeEngine, each
// using a custom JvmComputeRuntime implementation:
//   Tx 1 (deploy):  runtime writes v1 to slot 0xAB and commits.
//   Tx 2 (call):    runtime inherits Tx1 storage, reads v1, writes v2, commits.
//   Tx 3 (fail):    runtime reports failure — storage must not advance.
//
// Verifies:
//   - new_data is non-null after a successful transaction.
//   - The next transaction correctly inherits the prior storage root.
//   - Ordinary heap values (local variables) do not persist; only explicit
//     Storage writes survive transaction boundaries.
//   - A failed invocation produces null new_data (rollback).
// ---------------------------------------------------------------------------

namespace {

// JvmComputeRuntime that writes a fixed value to a storage slot.
class WriteSlotRuntime final : public jvm_workchain::JvmComputeRuntime {
 public:
  explicit WriteSlotRuntime(jvm_workchain::JvmStorageSlot slot,
                            jvm_workchain::JvmStorageValue value)
      : slot_(slot), value_(value) {}

  td::Result<jvm_workchain::JvmAvataInvocationResult> run_contract(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& /*ctx*/,
      const jvm_workchain::JvmConfig& /*cfg*/,
      const jvm_workchain::JvmExecutorState& state) const override {
    using namespace jvm_workchain;

    JvmStorageCellHost storage(state.storage_root);
    CHECK(storage.begin_transaction().is_ok());
    CHECK(storage.store(slot_, value_).is_ok());
    CHECK(storage.commit_transaction().is_ok());

    JvmAvataInvocationResult r;
    r.success = true;
    r.gas_used = 50;
    r.gas_remaining = input.gas_limit - r.gas_used;
    r.storage_root = storage.root_cell();
    r.action_list = jvm_workchain::build_jvm_event_action_list({});
    return r;
  }

 private:
  jvm_workchain::JvmStorageSlot slot_;
  jvm_workchain::JvmStorageValue value_;
};

// JvmComputeRuntime that verifies an expected prior value in a slot and then
// overwrites it with a new value.
class ReadThenWriteRuntime final : public jvm_workchain::JvmComputeRuntime {
 public:
  explicit ReadThenWriteRuntime(jvm_workchain::JvmStorageSlot slot,
                                jvm_workchain::JvmStorageValue expected,
                                jvm_workchain::JvmStorageValue write)
      : slot_(slot), expected_(expected), write_(write) {}

  td::Result<jvm_workchain::JvmAvataInvocationResult> run_contract(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& /*ctx*/,
      const jvm_workchain::JvmConfig& /*cfg*/,
      const jvm_workchain::JvmExecutorState& state) const override {
    using namespace jvm_workchain;

    JvmStorageCellHost storage(state.storage_root);
    auto loaded = storage.load(slot_).move_as_ok();
    CHECK(loaded.has_value());
    CHECK(*loaded == expected_);

    CHECK(storage.begin_transaction().is_ok());
    CHECK(storage.store(slot_, write_).is_ok());
    CHECK(storage.commit_transaction().is_ok());

    JvmAvataInvocationResult r;
    r.success = true;
    r.gas_used = 30;
    r.gas_remaining = input.gas_limit - r.gas_used;
    r.storage_root = storage.root_cell();
    r.action_list = jvm_workchain::build_jvm_event_action_list({});
    return r;
  }

 private:
  jvm_workchain::JvmStorageSlot slot_;
  jvm_workchain::JvmStorageValue expected_;
  jvm_workchain::JvmStorageValue write_;
};

// JvmComputeRuntime that always returns a failed (non-success) invocation.
class FailingRuntime final : public jvm_workchain::JvmComputeRuntime {
 public:
  td::Result<jvm_workchain::JvmAvataInvocationResult> run_contract(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& /*ctx*/,
      const jvm_workchain::JvmConfig& /*cfg*/,
      const jvm_workchain::JvmExecutorState& /*state*/) const override {
    jvm_workchain::JvmAvataInvocationResult r;
    r.success = false;
    r.gas_used = 10;
    r.gas_remaining = input.gas_limit - r.gas_used;
    return r;
  }
};

td::Result<block::WorkchainComputeOutput> run_jvm_tx(
    std::shared_ptr<const jvm_workchain::JvmComputeRuntime> runtime,
    td::Ref<vm::Cell> current_data,
    std::uint8_t call_marker,
    const block::WorkchainExecutionDescriptor& descriptor,
    const std::unique_ptr<block::Config>& config) {
  block::WorkchainExecutionRegistry registry;
  jvm_workchain::register_jvm_workchain_engine(registry, runtime);
  auto exec = registry.resolve(descriptor, *config).move_as_ok();

  block::WorkchainComputeInput input;
  input.current_data = current_data;
  input.inbound_body = make_jvm_call_body(call_marker);
  input.gas_limit = 1000;

  block::WorkchainComputeContext ctx;
  ctx.workchain_id = 3;
  ctx.descriptor = descriptor;
  ctx.engine_config = exec.engine_config;

  return exec.executor->run_compute(input, ctx);
}

}  // namespace

TEST(JvmWorkchainCore, EndToEndDeployCallPersistAndRollback) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  JvmStorageSlot slot{};
  slot[31] = 0xAB;
  const JvmStorageValue v1{0x01};
  const JvmStorageValue v2{0x02};

  // Tx 1: initial write — current_data is null (uninitialised account).
  auto out1 = run_jvm_tx(
      std::make_shared<WriteSlotRuntime>(slot, v1),
      td::Ref<vm::Cell>{}, 0x01, descriptor, config).move_as_ok();
  CHECK(out1.completed && out1.accepted && out1.committed);
  CHECK(out1.new_data.not_null());

  JvmExecutorState state1;
  CHECK(decode_jvm_executor_state(out1.new_data, state1));
  {
    JvmStorageCellHost check(state1.storage_root);
    auto v = check.load(slot).move_as_ok();
    CHECK(v.has_value() && *v == v1);
  }

  // Tx 2: inherits Tx1 state, reads v1, writes v2.
  auto out2 = run_jvm_tx(
      std::make_shared<ReadThenWriteRuntime>(slot, v1, v2),
      out1.new_data, 0x02, descriptor, config).move_as_ok();
  CHECK(out2.completed && out2.accepted && out2.committed);
  CHECK(out2.new_data.not_null());

  JvmExecutorState state2;
  CHECK(decode_jvm_executor_state(out2.new_data, state2));
  {
    JvmStorageCellHost check(state2.storage_root);
    auto v = check.load(slot).move_as_ok();
    CHECK(v.has_value() && *v == v2);
  }

  // Tx 3: failing invocation — new_data must be null (no state committed).
  auto out3 = run_jvm_tx(
      std::make_shared<FailingRuntime>(),
      out2.new_data, 0x03, descriptor, config).move_as_ok();
  CHECK(out3.completed);
  CHECK(out3.new_data.is_null());
}

// ---------------------------------------------------------------------------
// JVM RPC codec tests
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, RpcIsJvmMethod) {
  using namespace jvm_workchain;
  CHECK(is_jvm_rpc_method("jvm_deployContract"));
  CHECK(is_jvm_rpc_method("jvm_callContract"));
  CHECK(is_jvm_rpc_method("jvm_getContractState"));
  CHECK(is_jvm_rpc_method("jvm_getReceipts"));
  CHECK(!is_jvm_rpc_method("eth_chainId"));
  CHECK(!is_jvm_rpc_method("jvm_unknown"));
  CHECK(!is_jvm_rpc_method(""));
}

TEST(JvmWorkchainCore, RpcDeployContractParsesAndValidates) {
  using namespace jvm_workchain;

  // Valid deploy request: minimal Java magic header.
  std::string good_params = R"({
    "classBytes": "0xcafebabe00000034",
    "className": "ContractEntryPoint",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "salt":     "0x0000000000000000000000000000000000000000000000000000000000000002"
  })";
  auto req = parse_jvm_deploy_contract_request(good_params);
  CHECK(req.has_value());
  CHECK(req->class_name == "ContractEntryPoint");
  CHECK(!req->class_bytes.empty());

  // Missing className — must fail.
  std::string missing_name = R"({
    "classBytes": "0xcafe",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001"
  })";
  CHECK(!parse_jvm_deploy_contract_request(missing_name).has_value());

  // Missing classBytes — must fail.
  std::string missing_bytes = R"({
    "className": "Foo",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001"
  })";
  CHECK(!parse_jvm_deploy_contract_request(missing_bytes).has_value());

  // Deployer with wrong length — must fail.
  std::string bad_deployer = R"({
    "classBytes": "0xcafe",
    "className": "Foo",
    "deployer": "0xdeadbeef"
  })";
  CHECK(!parse_jvm_deploy_contract_request(bad_deployer).has_value());
}

TEST(JvmWorkchainCore, RpcDeployContractAdmissionChecksClassSize) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.max_class_bytes = 4;  // tiny limit for test

  JvmDeployContractRequest req;
  req.class_name = "Test";
  req.class_bytes = {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x34};  // 6 bytes > 4 limit
  req.deployer[31] = 1;

  auto result = handle_jvm_deploy_contract(req, cfg);
  CHECK(result.is_error);
  CHECK(result.json.find("max_class_bytes") != std::string::npos);

  // Exactly at limit: bytes that fit.
  req.class_bytes = {0xca, 0xfe, 0xba, 0xbe};
  cfg.max_class_bytes = 4;
  // class_name "/" prefix is invalid — check shape validation.
  req.class_name = "/BadName";
  auto shape_err = handle_jvm_deploy_contract(req, cfg);
  CHECK(shape_err.is_error);
}

TEST(JvmWorkchainCore, RpcDeployContractReturnsBothContractIdAndContractAddress) {
  // The v2 deploy result must surface BOTH the legacy v1 `contractId`
  // (manifest key under SingletonExecutor) and the new v2
  // `contractAddress` (deterministic wc=3 account address derived by
  // `derive_jvm_contract_address`).  Clients on the v1 wire format keep
  // working; v2 clients use `contractAddress` to drive
  // `action_create_account` to the right per-account address.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();

  JvmDeployContractRequest req;
  req.class_name = "ContractEntryPoint";
  req.class_bytes = {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x34};
  req.deployer[31] = 0x77;
  req.salt[31] = 0x55;
  req.init_args = make_empty_action_list();

  auto result = handle_jvm_deploy_contract(req, cfg);
  CHECK(!result.is_error);

  // Both fields appear in the response JSON.
  CHECK(result.json.find("\"contractId\":") != std::string::npos);
  CHECK(result.json.find("\"contractAddress\":") != std::string::npos);

  // Compute the expected v2 address and verify it is what the RPC reports.
  JvmDeployDescriptor descriptor;
  descriptor.deployer = req.deployer;
  descriptor.salt = req.salt;
  descriptor.class_name = req.class_name;
  descriptor.class_bytes = req.class_bytes;
  descriptor.class_hash = compute_jvm_class_hash(descriptor.class_bytes);
  descriptor.init_args = req.init_args;
  auto expected_address = derive_jvm_contract_address(descriptor).move_as_ok();
  std::string expected_addr_hex = "0x";
  for (auto b : expected_address) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(b));
    expected_addr_hex += buf;
  }
  CHECK(result.json.find(expected_addr_hex) != std::string::npos);

  // The v1 contract_id and v2 contract_address differ for the same
  // descriptor (different domain tag).
  auto expected_id = derive_jvm_contract_id(descriptor).move_as_ok();
  CHECK(expected_id != expected_address);
}

TEST(JvmWorkchainCore, RpcCallContractParsesRequest) {
  using namespace jvm_workchain;

  std::string params = R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "methodId": 305419896,
    "gasLimit": 100000
  })";
  auto req = parse_jvm_call_contract_request(params);
  CHECK(req.has_value());
  CHECK(req->method_id == 305419896u);
  CHECK(req->gas_limit == 100000u);
  CHECK(req->contract_id[31] == 1);
  // args must be initialised to a canonical empty cell, not null.
  CHECK(req->args.not_null());

  // Missing contractId — must fail.
  CHECK(!parse_jvm_call_contract_request(R"({"methodId":1})").has_value());

  // Handler must return a real BOC-encoded call descriptor, not a placeholder.
  auto result = handle_jvm_call_contract(*req, "99");
  CHECK(!result.is_error);
  // id must be threaded through correctly.
  CHECK(result.json.find("\"id\":99") != std::string::npos);
  // Response must contain callDescriptorBoc field with a 0x-prefixed hex value.
  auto boc_pos = result.json.find("\"callDescriptorBoc\":\"0x");
  CHECK(boc_pos != std::string::npos);
  // BOC must be non-trivially long (at minimum a few bytes for the descriptor).
  auto hex_start = result.json.find("0x", boc_pos) + 2;
  unsigned hex_len = 0;
  while (hex_start + hex_len < result.json.size()
         && std::isxdigit(static_cast<unsigned char>(
                result.json[hex_start + hex_len]))) {
    ++hex_len;
  }
  CHECK(hex_len >= 8);

  // executorStateBoc is optional: when present it must decode into current_state.
  constexpr uint8_t kMarker = 0x03;
  JvmExecutorState exec_state;
  exec_state.stdlib_hash = make_test_jvm_config().stdlib_hash;
  exec_state.class_state_root = make_jvm_class_state_cell(kMarker);
  auto state_cell = encode_jvm_executor_state(exec_state);
  auto boc_r = vm::std_boc_serialize(state_cell, 0);
  CHECK(!boc_r.is_error());
  static constexpr char kHex[] = "0123456789abcdef";
  std::string boc_hex = "0x";
  for (size_t i = 0; i < boc_r.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(boc_r.ok().data()[i]);
    boc_hex += kHex[(b >> 4) & 0xF];
    boc_hex += kHex[b & 0xF];
  }
  std::string params_with_state = R"({"contractId":"0x0000000000000000000000000000000000000000000000000000000000000001","methodId":1,"gasLimit":0,"executorStateBoc":")" + boc_hex + "\"}";
  auto req_with_state = parse_jvm_call_contract_request(params_with_state);
  CHECK(req_with_state.has_value());
  CHECK(req_with_state->current_state.not_null());
  CHECK(req_with_state->current_state->get_hash() == state_cell->get_hash());

  // Malformed executorStateBoc must cause parse to fail.
  std::string params_bad_state = R"({"contractId":"0x0000000000000000000000000000000000000000000000000000000000000001","methodId":1,"executorStateBoc":"0xdeadbeef"})";
  CHECK(!parse_jvm_call_contract_request(params_bad_state).has_value());
}

TEST(JvmWorkchainCore, RpcGetContractStateParsesRequest) {
  using namespace jvm_workchain;

  std::string params = R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000001"
  })";
  auto req = parse_jvm_get_contract_state_request(params);
  CHECK(req.has_value());
  CHECK(req->contract_id[31] == 1);

  CHECK(!parse_jvm_get_contract_state_request(R"({})").has_value());

  // When executor_state contains a class state rooted at the queried
  // contract_id, the handler must populate className and classHash.
  constexpr uint8_t kMarker = 0x01;
  req->contract_id = make_test_jvm_call_descriptor(kMarker).contract_id;

  JvmExecutorState exec_state;
  exec_state.stdlib_hash = make_test_jvm_config().stdlib_hash;
  exec_state.storage_root = {};
  exec_state.class_state_root = make_jvm_class_state_cell(kMarker);
  req->executor_state = encode_jvm_executor_state(exec_state);

  auto result = handle_jvm_get_contract_state(*req, "5");
  CHECK(!result.is_error);
  CHECK(result.json.find("\"id\":5") != std::string::npos);
  // className must be the class registered for this contract_id.
  CHECK(result.json.find("\"className\":\"ContractEntryPoint\"") != std::string::npos);
  // classHash must be a 0x-prefixed 64-hex-char value (non-null).
  CHECK(result.json.find("\"classHash\":\"0x") != std::string::npos);
  // storageRootHash must be null (no storage set).
  CHECK(result.json.find("\"storageRootHash\":null") != std::string::npos);

  // Without executor_state the handler must return an error.
  req->executor_state = {};
  CHECK(handle_jvm_get_contract_state(*req, "6").is_error);
}

// Verify that executorStateBoc in the JSON params round-trips correctly through
// parse_jvm_get_contract_state_request: the hex BOC is decoded back to a cell
// with the same hash as the original, and the handler can then resolve the
// class name and hash from it without any out-of-band state injection.
TEST(JvmWorkchainCore, RpcGetContractStateDecodesExecutorStateBocFromJson) {
  using namespace jvm_workchain;

  constexpr uint8_t kMarker = 0x02;

  // Build an executor state cell and encode it to a hex BOC string.
  JvmExecutorState exec_state;
  exec_state.stdlib_hash = make_test_jvm_config().stdlib_hash;
  exec_state.storage_root = {};
  exec_state.class_state_root = make_jvm_class_state_cell(kMarker);
  auto state_cell = encode_jvm_executor_state(exec_state);
  CHECK(state_cell.not_null());

  auto boc = vm::std_boc_serialize(state_cell, 0);
  CHECK(!boc.is_error());
  static constexpr char kHex[] = "0123456789abcdef";
  std::string boc_hex = "0x";
  for (size_t i = 0; i < boc.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(boc.ok().data()[i]);
    boc_hex += kHex[(b >> 4) & 0xF];
    boc_hex += kHex[b & 0xF];
  }

  auto contract_id = make_test_jvm_call_descriptor(kMarker).contract_id;
  // Encode contract_id to 0x-prefixed hex.
  std::string cid_hex = "0x";
  for (auto b : contract_id) {
    cid_hex += kHex[(b >> 4) & 0xF];
    cid_hex += kHex[b & 0xF];
  }

  std::string params = "{\"contractId\":\"" + cid_hex
                     + "\",\"executorStateBoc\":\"" + boc_hex + "\"}";
  auto req = parse_jvm_get_contract_state_request(params);
  CHECK(req.has_value());
  // executor_state must be populated from the BOC — same cell hash.
  CHECK(req->executor_state.not_null());
  CHECK(req->executor_state->get_hash() == state_cell->get_hash());

  // The handler must resolve className/classHash without any extra injection.
  auto result = handle_jvm_get_contract_state(*req, "8");
  CHECK(!result.is_error);
  CHECK(result.json.find("\"className\":\"ContractEntryPoint\"") != std::string::npos);
  CHECK(result.json.find("\"classHash\":\"0x") != std::string::npos);

  // Malformed BOC must cause parse to return nullopt.
  std::string bad_params = "{\"contractId\":\"" + cid_hex
                          + "\",\"executorStateBoc\":\"0xdeadbeef\"}";
  CHECK(!parse_jvm_get_contract_state_request(bad_params).has_value());
}

TEST(JvmWorkchainCore, RpcGetReceiptsParsesRequest) {
  using namespace jvm_workchain;

  std::string params = R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "fromBlock": 100,
    "toBlock": 200
  })";
  auto req = parse_jvm_get_receipts_request(params);
  CHECK(req.has_value());
  CHECK(req->from_block == 100);
  CHECK(req->to_block == 200);

  CHECK(!parse_jvm_get_receipts_request(R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "fromBlock": -1
  })").has_value());
  CHECK(!parse_jvm_get_receipts_request(R"({})").has_value());
}

TEST(JvmWorkchainCore, RpcDispatcherRoutesJvmMethods) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();

  // Unknown jvm_* method returns nullopt (not this facade's business).
  CHECK(!handle_jvm_rpc("jvm_unknown", "{}", "1", cfg).has_value());

  // Non-JVM method returns nullopt.
  CHECK(!handle_jvm_rpc("eth_chainId", "{}", "1", cfg).has_value());

  // Valid method with missing params returns error result, not nullopt.
  auto deploy_err = handle_jvm_rpc("jvm_deployContract", "{}", "1", cfg);
  CHECK(deploy_err.has_value());
  CHECK(deploy_err->is_error);

  // getReceipts with minimal params succeeds.
  std::string receipts_params = R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000001"
  })";
  auto receipts = handle_jvm_rpc("jvm_getReceipts", receipts_params, "2", cfg);
  CHECK(receipts.has_value());
  CHECK(!receipts->is_error);
  CHECK(receipts->json.find("\"id\":2") != std::string::npos);
}

// Verify that the dispatcher forwards the real sub-handler result (not a
// placeholder) and threads the caller-supplied request id through correctly.
TEST(JvmWorkchainCore, RpcDispatcherPropagatesRealResults) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();

  // jvm_deployContract: contractId field must be a real 0x-prefixed hex hash,
  // not the placeholder "see_result".
  std::string deploy_params = R"({
    "classBytes": "0xcafebabe00000034",
    "className": "ContractEntryPoint",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "salt":     "0x0000000000000000000000000000000000000000000000000000000000000002"
  })";
  auto deploy = handle_jvm_rpc("jvm_deployContract", deploy_params, "42", cfg);
  CHECK(deploy.has_value() && !deploy->is_error);
  // id must be the caller-supplied value, not "null".
  CHECK(deploy->json.find("\"id\":42") != std::string::npos);
  // contractId must be a real hex value (66 chars: 0x + 64 hex digits).
  auto cid_pos = deploy->json.find("\"contractId\":\"0x");
  CHECK(cid_pos != std::string::npos);
  // The hex string immediately follows "contractId":"0x — check it's 64 hex chars.
  auto hex_start = deploy->json.find("0x", cid_pos) + 2;
  unsigned hex_count = 0;
  while (hex_start + hex_count < deploy->json.size()
         && std::isxdigit(static_cast<unsigned char>(
                deploy->json[hex_start + hex_count]))) {
    ++hex_count;
  }
  CHECK(hex_count == 64);

  // jvm_getReceipts: receipts field must be present and contractId correct.
  std::string receipts_params = R"({
    "contractId": "0xabcdef0000000000000000000000000000000000000000000000000000000001"
  })";
  auto receipts = handle_jvm_rpc("jvm_getReceipts", receipts_params, "7", cfg);
  CHECK(receipts.has_value() && !receipts->is_error);
  CHECK(receipts->json.find("\"id\":7") != std::string::npos);
  CHECK(receipts->json.find("\"receipts\":[]") != std::string::npos);
  CHECK(receipts->json.find("0xabcdef") != std::string::npos);
}

// jvm_deployContract returns deployDescriptorBoc alongside contractId.
// The BOC must deserialize to a valid JvmDeployDescriptor cell.
TEST(JvmWorkchainCore, RpcDeployContractReturnsDescriptorBoc) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  std::string params = R"({
    "classBytes": "0xcafebabe00000034",
    "className": "ContractEntryPoint",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "salt":     "0x0000000000000000000000000000000000000000000000000000000000000002"
  })";
  auto result = handle_jvm_rpc("jvm_deployContract", params, "1", cfg);
  CHECK(result.has_value() && !result->is_error);

  // Both contractId and deployDescriptorBoc must be present.
  CHECK(result->json.find("\"contractId\":\"0x") != std::string::npos);
  auto boc_pos = result->json.find("\"deployDescriptorBoc\":\"0x");
  CHECK(boc_pos != std::string::npos);

  // Extract the deployDescriptorBoc hex and round-trip it through the decoder.
  auto hex_start = result->json.find("0x", boc_pos);
  auto hex_end = result->json.find('"', hex_start + 2);
  CHECK(hex_start != std::string::npos && hex_end != std::string::npos);
  std::string boc_hex = result->json.substr(hex_start, hex_end - hex_start);
  // Must be a valid hex string with 0x prefix.
  CHECK(boc_hex.size() > 2);
  CHECK(boc_hex[0] == '0' && boc_hex[1] == 'x');
  // Decode to bytes.
  std::vector<uint8_t> boc_bytes;
  for (size_t i = 2; i + 1 < boc_hex.size(); i += 2) {
    auto nibble = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
      if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
      return static_cast<uint8_t>(c - 'A' + 10);
    };
    boc_bytes.push_back(static_cast<uint8_t>((nibble(boc_hex[i]) << 4) | nibble(boc_hex[i+1])));
  }
  auto cell = vm::std_boc_deserialize(
      td::Slice(reinterpret_cast<const char*>(boc_bytes.data()), boc_bytes.size()));
  CHECK(!cell.is_error() && cell.ok().not_null());
  // Must decode as a valid JvmDeployDescriptor.
  auto desc = parse_jvm_deploy_descriptor(vm::load_cell_slice(cell.ok()));
  CHECK(!desc.is_error());
  CHECK(desc.ok().class_name == "ContractEntryPoint");
}

// jvm_callContract with argsBoc passes the args cell through to the local
// simulation.  Verify that argsBoc round-trips: encode a JVMA args cell,
// supply it as argsBoc, and confirm the local execution receives it correctly.
TEST(JvmWorkchainCore, RpcCallContractArgsBocRoundTrips) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;

  // Build executor state.
  JvmExecutorState state;
  state.schema_version = kJvmExecutorStateSchemaVersion;
  state.stdlib_hash = cfg.stdlib_hash;
  auto state_cell = encode_jvm_executor_state(state);
  CHECK(state_cell.not_null());
  auto state_boc_r = vm::std_boc_serialize(state_cell, 0);
  CHECK(!state_boc_r.is_error());
  static constexpr char kHex[] = "0123456789abcdef";
  std::string state_hex = "0x";
  for (size_t i = 0; i < state_boc_r.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(state_boc_r.ok().data()[i]);
    state_hex += kHex[(b >> 4) & 0xF];
    state_hex += kHex[b & 0xF];
  }

  // Encode a non-empty JVMA typed args cell (one int arg = 42).
  JvmArgs typed_args;
  JvmTypedArg int_arg;
  int_arg.type = JvmArgType::Int32;
  int_arg.bytes = {0, 0, 0, 42};
  typed_args.values.push_back(int_arg);
  auto args_cell = encode_jvm_args(typed_args);
  CHECK(args_cell.not_null());
  auto args_boc_r = vm::std_boc_serialize(args_cell, 0);
  CHECK(!args_boc_r.is_error());
  std::string args_hex = "0x";
  for (size_t i = 0; i < args_boc_r.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(args_boc_r.ok().data()[i]);
    args_hex += kHex[(b >> 4) & 0xF];
    args_hex += kHex[b & 0xF];
  }

  // Parse call request — argsBoc must populate req.args.
  std::string params = R"({"contractId": "0x0000000000000000000000000000000000000000000000000000000000000001", "methodId": 1, "argsBoc": ")" + args_hex + R"("})";
  auto req = parse_jvm_call_contract_request(params);
  CHECK(req.has_value());
  CHECK(req->args.not_null());
  CHECK(req->args->get_hash() == args_cell->get_hash());

  // Malformed argsBoc must cause parse to return nullopt.
  std::string bad_params = R"({"contractId": "0x0000000000000000000000000000000000000000000000000000000000000001", "methodId": 1, "argsBoc": "0xdeadbeef"})";
  CHECK(!parse_jvm_call_contract_request(bad_params).has_value());

  // Absent argsBoc falls back to canonical empty args cell.
  std::string no_args_params = R"({"contractId": "0x0000000000000000000000000000000000000000000000000000000000000001", "methodId": 1})";
  auto no_args_req = parse_jvm_call_contract_request(no_args_params);
  CHECK(no_args_req.has_value());
  CHECK(no_args_req->args.not_null());
  // Empty args cell: CellBuilder().finalize() has a specific hash.
  auto empty_args = vm::CellBuilder().finalize();
  CHECK(no_args_req->args->get_hash() == empty_args->get_hash());
}

// ---------------------------------------------------------------------------
// Multi-instance storage isolation
// ---------------------------------------------------------------------------

// Prove that two contract instances (different slot keys representing different
// namespace prefixes) coexist in the shared executor storage without clobbering
// each other.  The canonical v1 isolation mechanism is Mapping.namespace() in
// Java; this C++ test exercises the underlying storage cell-host layer.
TEST(JvmWorkchainCore, MultiInstanceIndependentStorageSlots) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  JvmStorageSlot slot_a{};
  slot_a[31] = 0xAA;
  JvmStorageSlot slot_b{};
  slot_b[31] = 0xBB;

  const JvmStorageValue v1{0x11};
  const JvmStorageValue v2{0x22};
  const JvmStorageValue v3{0x33};

  // Tx 1: instance A writes to slot_a.
  auto out1 = run_jvm_tx(
      std::make_shared<WriteSlotRuntime>(slot_a, v1),
      td::Ref<vm::Cell>{}, 0x01, descriptor, config).move_as_ok();
  CHECK(out1.committed && out1.new_data.not_null());

  // Tx 2: instance B writes to slot_b, inheriting instance A's state.
  auto out2 = run_jvm_tx(
      std::make_shared<WriteSlotRuntime>(slot_b, v2),
      out1.new_data, 0x02, descriptor, config).move_as_ok();
  CHECK(out2.committed && out2.new_data.not_null());

  // After both writes: both slots must coexist with correct values.
  {
    JvmExecutorState state;
    CHECK(decode_jvm_executor_state(out2.new_data, state));
    JvmStorageCellHost check(state.storage_root);
    auto va = check.load(slot_a).move_as_ok();
    auto vb = check.load(slot_b).move_as_ok();
    CHECK(va.has_value() && *va == v1);
    CHECK(vb.has_value() && *vb == v2);
  }

  // Tx 3: instance A overwrites slot_a — instance B's slot_b must be unchanged.
  auto out3 = run_jvm_tx(
      std::make_shared<WriteSlotRuntime>(slot_a, v3),
      out2.new_data, 0x03, descriptor, config).move_as_ok();
  CHECK(out3.committed && out3.new_data.not_null());

  {
    JvmExecutorState state;
    CHECK(decode_jvm_executor_state(out3.new_data, state));
    JvmStorageCellHost check(state.storage_root);
    auto va = check.load(slot_a).move_as_ok();
    auto vb = check.load(slot_b).move_as_ok();
    CHECK(va.has_value() && *va == v3);
    CHECK(vb.has_value() && *vb == v2);
  }
}

// Verify that JvmConfig::default_activation() produces a config that
// build_jvm_config_cell() encodes and parse_jvm_config_cell() round-trips
// without loss.
TEST(JvmWorkchainCore, JvmActivationConfigBuildsAndRoundTrips) {
  using namespace jvm_workchain;

  auto cfg = JvmConfig::default_activation();

  // Sanity-check a few fields before encoding.
  CHECK(cfg.chain_id == 3);
  CHECK(cfg.gas_schedule_version == 1);
  CHECK(cfg.class_file_major == 52);
  CHECK(cfg.max_gas_per_tx == 1000000);
  CHECK(cfg.max_heap_bytes == 4194304);
  // Every opcode slot must be non-zero (zero is reserved as "invalid").
  for (unsigned i = 0; i < kJvmOpcodeGasCostCount; ++i) {
    CHECK(cfg.opcode_gas_costs[i] != 0);
  }
  for (unsigned i = 0; i < kJvmContractHelperGasCostCount; ++i) {
    CHECK(cfg.helper_gas_costs[i] != 0);
  }

  // Build must succeed.
  auto cell = build_jvm_config_cell(cfg);
  CHECK(cell.not_null());

  // Round-trip: parse must succeed and reproduce the original config.  The
  // v2 wire schema does NOT carry `max_total_class_bytes`, so the parsed
  // struct field is intentionally zero regardless of the input.
  auto parsed = parse_jvm_config_cell(cell).move_as_ok();
  CHECK(parsed.chain_id == cfg.chain_id);
  CHECK(parsed.gas_price == cfg.gas_price);
  CHECK(parsed.max_gas_per_tx == cfg.max_gas_per_tx);
  CHECK(parsed.max_class_bytes == cfg.max_class_bytes);
  CHECK(parsed.max_total_class_bytes == 0);  // dropped from v2 wire schema
  CHECK(parsed.max_heap_bytes == cfg.max_heap_bytes);
  CHECK(parsed.max_storage_cells == cfg.max_storage_cells);
  CHECK(parsed.class_file_major == cfg.class_file_major);
  CHECK(parsed.gas_schedule_version == cfg.gas_schedule_version);
  CHECK(parsed.opcode_gas_costs == cfg.opcode_gas_costs);
  CHECK(parsed.helper_gas_costs == cfg.helper_gas_costs);
}

// Verify that an out-of-memory invocation produces a correct compute output:
// not committed, not out_of_gas, vm_log identifies OOM, new_data is null.
TEST(JvmWorkchainCore, AvataInvocationBuildsOutOfMemoryComputeOutput) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 3;
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  FakeJvmExecutionThread thread;
  thread.invoke_status = api.out_of_memory_status;
  thread.remaining_gas = 800;
  thread.memory_used = cfg.max_heap_bytes;  // at limit — not exceeding

  JvmExecutorState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.storage_root = storage.root_cell();

  auto invocation = execute_jvm_avata_transaction(
      &thread, cfg, 1000, storage, api, nullptr).move_as_ok();
  CHECK(!invocation.success);
  CHECK(!invocation.out_of_gas);
  CHECK(invocation.out_of_memory);

  auto output = build_jvm_workchain_output(
      cfg, previous_state, 1000, invocation).move_as_ok();

  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(!output.committed);
  CHECK(!output.engine_success);
  CHECK(!output.out_of_gas);
  CHECK(output.skip_reason == block::ComputePhase::sk_none);
  CHECK(output.exit_code == api.out_of_memory_status);
  CHECK(output.gas_used == 200);  // 1000 - 800
  CHECK(output.vm_log == "JVM execution exhausted memory");
  CHECK(output.new_data.is_null());
  CHECK(output.action_list.is_null());
}

// Verify that memory_used exceeding max_heap_bytes causes
// execute_jvm_avata_transaction to return an error rather than a result.
// This is the post-invocation config guard that prevents a misbehaving Avata
// thread from reporting usage above the arena limit.
TEST(JvmWorkchainCore, MaxHeapBytesExceededReturnsError) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto api = make_test_jvm_execution_api();
  JvmStorageCellHost storage;
  FakeJvmExecutionThread thread;
  // Avata reports "success" but claims it used more memory than the limit.
  thread.invoke_status = api.ok_status;
  thread.remaining_gas = 900;
  thread.memory_used = cfg.max_heap_bytes + 1;

  CHECK(execute_jvm_avata_transaction(
            &thread, cfg, 1000, storage, api, nullptr).is_error());
}

// Verify that the executor-state cell serializes to bytes (BOC) and back
// without loss, and that re-running compute against the deserialized cell
// produces an identical result.  This is the "serialize to disk / reimport"
// replay test from Phase 8.
TEST(JvmWorkchainCore, JvmStateCellBocRoundTripPreservesComputeOutput) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  JvmStorageSlot slot{};
  slot[31] = 0xCC;
  const JvmStorageValue value{0x55};

  // Tx 1: write a known value into storage.
  auto out1 = run_jvm_tx(
      std::make_shared<WriteSlotRuntime>(slot, value),
      td::Ref<vm::Cell>{}, 0x11, descriptor, config).move_as_ok();
  CHECK(out1.committed && out1.new_data.not_null());

  // BOC round-trip: serialize new_data to bytes, deserialize back.
  auto boc = vm::std_boc_serialize(out1.new_data).move_as_ok();
  auto restored = vm::std_boc_deserialize(boc.as_slice()).move_as_ok();
  CHECK(restored.not_null());

  // Cell identity: deserialized cell must have the same hash as the original.
  CHECK(restored->get_hash() == out1.new_data->get_hash());

  // Functional identity: running compute from the deserialized cell must
  // produce the same storage content as running it from the original cell.
  auto out_orig = run_jvm_tx(
      std::make_shared<WriteSlotRuntime>(slot, JvmStorageValue{0xDD}),
      out1.new_data, 0x12, descriptor, config).move_as_ok();
  auto out_restored = run_jvm_tx(
      std::make_shared<WriteSlotRuntime>(slot, JvmStorageValue{0xDD}),
      restored, 0x12, descriptor, config).move_as_ok();

  CHECK(out_orig.committed && out_restored.committed);
  CHECK(out_orig.new_data.not_null() && out_restored.new_data.not_null());
  CHECK(out_orig.new_data->get_hash() == out_restored.new_data->get_hash());
}

// ---------------------------------------------------------------------------
// RPC local execution and storage enumeration
// ---------------------------------------------------------------------------

// jvm_callContract with a runtime and executorStateBoc performs a local
// simulation and returns localResult alongside the call descriptor BOC.
TEST(JvmWorkchainCore, RpcCallContractLocalExecution) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;

  // Build a minimal executor state cell.
  JvmExecutorState state;
  state.schema_version = kJvmExecutorStateSchemaVersion;
  state.stdlib_hash = cfg.stdlib_hash;
  auto state_cell = encode_jvm_executor_state(state);
  CHECK(state_cell.not_null());
  auto state_boc_r = vm::std_boc_serialize(state_cell, 0);
  CHECK(!state_boc_r.is_error());
  static constexpr char kH1[] = "0123456789abcdef";
  std::string state_hex = "0x";
  for (size_t i = 0; i < state_boc_r.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(state_boc_r.ok().data()[i]);
    state_hex += kH1[(b >> 4) & 0xF];
    state_hex += kH1[b & 0xF];
  }

  // WriteSlotRuntime writes one slot and reports 50 gas used.
  JvmStorageSlot slot{};
  slot[31] = 0x42;
  const JvmStorageValue val{0xBE, 0xEF};
  auto runtime = std::make_shared<WriteSlotRuntime>(slot, val);

  std::string params = R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "methodId": 12345,
    "gasLimit": 1000,
    "executorStateBoc": ")" + state_hex + R"("
  })";

  auto result = handle_jvm_rpc("jvm_callContract", params, "1", cfg,
                               runtime.get());
  CHECK(result.has_value() && !result->is_error);

  // callDescriptorBoc must still be present.
  CHECK(result->json.find("\"callDescriptorBoc\":\"0x") != std::string::npos);

  // localResult must show success.
  CHECK(result->json.find("\"success\":true") != std::string::npos);
  CHECK(result->json.find("\"gasUsed\":50") != std::string::npos);

  // newStateBoc must be a non-null hex string (the committed new state).
  CHECK(result->json.find("\"newStateBoc\":\"0x") != std::string::npos);
}

// jvm_callContract with a failing runtime returns localResult.success=false
// and no newStateBoc.
TEST(JvmWorkchainCore, RpcCallContractLocalExecutionFailure) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;

  JvmExecutorState state;
  state.schema_version = kJvmExecutorStateSchemaVersion;
  state.stdlib_hash = cfg.stdlib_hash;
  auto state_cell = encode_jvm_executor_state(state);
  CHECK(state_cell.not_null());

  auto state_boc_r2 = vm::std_boc_serialize(state_cell, 0);
  CHECK(!state_boc_r2.is_error());
  static constexpr char kH2[] = "0123456789abcdef";
  std::string state_hex2 = "0x";
  for (size_t i = 0; i < state_boc_r2.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(state_boc_r2.ok().data()[i]);
    state_hex2 += kH2[(b >> 4) & 0xF];
    state_hex2 += kH2[b & 0xF];
  }

  auto runtime = std::make_shared<FailingRuntime>();
  std::string params = R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000002",
    "methodId": 99,
    "gasLimit": 500,
    "executorStateBoc": ")" + state_hex2 + R"("
  })";

  auto result = handle_jvm_rpc("jvm_callContract", params, "2", cfg,
                               runtime.get());
  CHECK(result.has_value() && !result->is_error);
  CHECK(result->json.find("\"success\":false") != std::string::npos);
  // No new state committed on failure.
  CHECK(result->json.find("\"newStateBoc\":null") != std::string::npos);
}

// jvm_getContractState with executorStateBoc enumerates storage slots
// and includes them in storageSlots.
TEST(JvmWorkchainCore, RpcGetContractStateEnumeratesStorageSlots) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;

  // Build executor state with two storage entries.
  JvmStorageSlot slot_a{};
  slot_a[31] = 0x01;
  JvmStorageSlot slot_b{};
  slot_b[31] = 0x02;
  const JvmStorageValue val_a{0xAA};
  const JvmStorageValue val_b{0xBB, 0xCC};

  JvmStorageCellHost storage;
  CHECK(storage.begin_transaction().is_ok());
  CHECK(storage.store(slot_a, val_a).is_ok());
  CHECK(storage.store(slot_b, val_b).is_ok());
  CHECK(storage.commit_transaction().is_ok());

  JvmExecutorState state;
  state.schema_version = kJvmExecutorStateSchemaVersion;
  state.stdlib_hash = cfg.stdlib_hash;
  state.storage_root = storage.root_cell();
  auto state_cell = encode_jvm_executor_state(state);
  CHECK(state_cell.not_null());
  auto state_boc_r3 = vm::std_boc_serialize(state_cell, 0);
  CHECK(!state_boc_r3.is_error());
  static constexpr char kH3[] = "0123456789abcdef";
  std::string state_hex3 = "0x";
  for (size_t i = 0; i < state_boc_r3.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(state_boc_r3.ok().data()[i]);
    state_hex3 += kH3[(b >> 4) & 0xF];
    state_hex3 += kH3[b & 0xF];
  }

  std::string params = R"({
    "contractId": "0x0000000000000000000000000000000000000000000000000000000000000003",
    "executorStateBoc": ")" + state_hex3 + R"("
  })";

  auto result = handle_jvm_rpc("jvm_getContractState", params, "3", cfg);
  CHECK(result.has_value() && !result->is_error);

  // storageSlots must be a JSON array with two entries.
  CHECK(result->json.find("\"storageSlots\":[") != std::string::npos);
  CHECK(result->json.find("\"storageTruncated\":false") != std::string::npos);
  // Both slot values must appear in hex.
  CHECK(result->json.find("\"0xaa\"") != std::string::npos
     || result->json.find("\"0xAA\"") != std::string::npos
     || result->json.find("0xaa") != std::string::npos);
  CHECK(result->json.find("\"0xbbcc\"") != std::string::npos
     || result->json.find("\"0xBBCC\"") != std::string::npos
     || result->json.find("0xbbcc") != std::string::npos);
}

// jvm_deployContract with executorStateBoc installs the class into the
// executor state and returns newStateBoc alongside contractId and
// deployDescriptorBoc.  The returned newStateBoc must decode back to an
// executor state whose class_state_root contains the deployed class.
TEST(JvmWorkchainCore, RpcDeployContractWithExecutorStateBocInstallsClass) {
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();

  // Build a minimal (empty) executor state.
  JvmExecutorState initial_state;
  initial_state.schema_version = kJvmExecutorStateSchemaVersion;
  initial_state.stdlib_hash = cfg.stdlib_hash;
  auto state_cell = encode_jvm_executor_state(initial_state);
  CHECK(state_cell.not_null());
  auto state_boc_r = vm::std_boc_serialize(state_cell, 0);
  CHECK(!state_boc_r.is_error());
  static constexpr char kHex[] = "0123456789abcdef";
  std::string state_hex = "0x";
  for (size_t i = 0; i < state_boc_r.ok().size(); ++i) {
    auto b = static_cast<uint8_t>(state_boc_r.ok().data()[i]);
    state_hex += kHex[(b >> 4) & 0xF];
    state_hex += kHex[b & 0xF];
  }

  std::string params = R"({
    "classBytes": "0xcafebabe00000034",
    "className": "ContractEntryPoint",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "salt":     "0x0000000000000000000000000000000000000000000000000000000000000002",
    "executorStateBoc": ")" + state_hex + R"("
  })";

  auto result = handle_jvm_rpc("jvm_deployContract", params, "1", cfg);
  CHECK(result.has_value() && !result->is_error);

  // All three fields must be present.
  CHECK(result->json.find("\"contractId\":\"0x") != std::string::npos);
  CHECK(result->json.find("\"deployDescriptorBoc\":\"0x") != std::string::npos);
  auto ns_pos = result->json.find("\"newStateBoc\":\"0x");
  CHECK(ns_pos != std::string::npos);

  // Extract and round-trip newStateBoc.
  auto hex_start = result->json.find("0x", ns_pos);
  auto hex_end = result->json.find('"', hex_start + 2);
  CHECK(hex_start != std::string::npos && hex_end != std::string::npos);
  std::string new_boc_hex = result->json.substr(hex_start, hex_end - hex_start);
  std::vector<uint8_t> new_boc_bytes;
  for (size_t i = 2; i + 1 < new_boc_hex.size(); i += 2) {
    auto nibble = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
      if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
      return static_cast<uint8_t>(c - 'A' + 10);
    };
    new_boc_bytes.push_back(
        static_cast<uint8_t>((nibble(new_boc_hex[i]) << 4)
                             | nibble(new_boc_hex[i + 1])));
  }
  auto new_cell = vm::std_boc_deserialize(
      td::Slice(reinterpret_cast<const char*>(new_boc_bytes.data()),
                new_boc_bytes.size()));
  CHECK(!new_cell.is_error() && new_cell.ok().not_null());

  // The new state must decode and contain the installed class.
  JvmExecutorState new_state;
  CHECK(decode_jvm_executor_state(new_cell.ok(), new_state));
  CHECK(new_state.class_state_root.not_null());

  // Class definition must be findable by name.
  auto def = find_jvm_avata_class_definition(
      new_state.class_state_root, "ContractEntryPoint");
  CHECK(!def.is_error());
  CHECK(def.ok().class_name == "ContractEntryPoint");
}
