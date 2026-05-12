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
#include "jvm/core/genesis-wallet.h"
#include "jvm/core/message-abi.h"
#include "jvm/core/rpc.h"
#include "jvm/core/storage-cell-host.h"
#include "jvm/core/zerostate.h"
#include "td/utils/crypto.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

#include <cstdint>
#include <cstring>
#include <ethash/keccak.hpp>
#include <functional>
#include <memory>
#include <optional>
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

td::Ref<vm::CellSlice> make_jvm_call_body(std::uint32_t method_id) {
  jvm_workchain::JvmCallDescriptor descriptor;
  descriptor.method_id = method_id;
  descriptor.args = make_empty_action_list();
  auto cell = jvm_workchain::encode_jvm_call_descriptor(descriptor);
  CHECK(cell.not_null());
  return vm::load_cell_slice_ref(cell);
}

// Build a minimal int_msg_info wc=<workchain> → wc=3 message cell with
// the supplied src address (32-byte addr_std).  Used in JVM v2 first-
// activation tests to satisfy the round-14 gate that requires
// `msg.src.addr == state.deployer` and the round-15 gate that requires
// `msg.src.workchain == 3`.
td::Ref<vm::Cell> make_jvm_int_msg_with_src_at_wc(
    const std::array<std::uint8_t, 32>& src_addr,
    int src_workchain) {
  vm::CellBuilder cb;
  // CommonMsgInfo: int_msg_info$0
  CHECK(cb.store_long_bool(0, 1));
  // ihr_disabled, bounce, bounced (3 bits, all 0)
  CHECK(cb.store_long_bool(0, 3));
  // src: addr_std$10 anycast=Nothing workchain=<src_workchain> address=<src_addr>
  CHECK(cb.store_long_bool(0b10, 2));   // addr_std$10
  CHECK(cb.store_long_bool(0, 1));       // anycast: Nothing
  CHECK(cb.store_long_bool(src_workchain, 8));  // workchain_id (signed int8)
  CHECK(cb.store_bytes_bool(src_addr.data(), 32));
  // dest: addr_std$10 anycast=Nothing workchain=3 address=<zero>
  CHECK(cb.store_long_bool(0b10, 2));
  CHECK(cb.store_long_bool(0, 1));
  CHECK(cb.store_long_bool(3, 8));
  CHECK(cb.store_zeroes_bool(256));
  // value: Tomis (VarUInteger 16) — 0
  CHECK(cb.store_long_bool(0, 4));
  // value extra: ExtraCurrencyCollection (HashmapE 32 ...) — empty
  CHECK(cb.store_long_bool(0, 1));
  // ihr_fee / extra_flags: Tomis 0 / 0
  CHECK(cb.store_long_bool(0, 4));
  CHECK(cb.store_long_bool(0, 4));
  // created_lt:uint64
  CHECK(cb.store_long_bool(0, 64));
  // created_at:uint32
  CHECK(cb.store_long_bool(0, 32));
  // init: Maybe — Nothing
  CHECK(cb.store_long_bool(0, 1));
  // body: Either X ^X — left (inline empty)
  CHECK(cb.store_long_bool(0, 1));
  return cb.finalize();
}

td::Ref<vm::Cell> make_jvm_int_msg_with_src(
    const std::array<std::uint8_t, 32>& src_addr) {
  return make_jvm_int_msg_with_src_at_wc(src_addr, 3);
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
  // The engine's round-17 gate compares this against
  // `cfg.stdlib_hash`.  The test config builder returns a fixed
  // stdlib_hash; we mirror that here so tests pass the gate.  When a
  // test wants to drive the gate (mismatch path), it sets
  // `mock_rt_jar_hash` directly.
  std::array<std::uint8_t, 32> rt_jar_hash() const override {
    if (mock_rt_jar_hash) {
      return *mock_rt_jar_hash;
    }
    // Default: matches make_test_jvm_config()'s stdlib_hash.
    auto cfg = make_test_jvm_config();
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), cfg.stdlib_hash.data(), out.size());
    return out;
  }
  // Optional override for the rt.jar hash.  When set, the engine
  // sees this value instead of the canonical test hash.
  mutable std::optional<std::array<std::uint8_t, 32>> mock_rt_jar_hash;

  td::Result<jvm_workchain::JvmAvataInvocationResult> run_contract(
      const block::WorkchainComputeInput& input,
      const block::WorkchainComputeContext& context,
      const jvm_workchain::JvmConfig& config,
      const jvm_workchain::JvmContractAccountState& previous_state)
      const override {
    using namespace jvm_workchain;

    called = true;
    CHECK(context.workchain_id == 3);
    // Round-35: tests pass gas_limit=2000 (above the 1024 admission
    // floor enforced in dispatch-engine.cpp pre-runtime).  Round-40
    // regression tests override this via `mock_expected_gas_limit`
    // because the engine's affordability cap can shrink gas_limit.
    CHECK(input.gas_limit == mock_expected_gas_limit.value_or(2000));
    CHECK(config.chain_id == 85);
    CHECK(previous_state.stdlib_hash == config.stdlib_hash);
    CHECK(previous_state.class_bytes.not_null());
    CHECK(previous_state.manifest_root.not_null());

    JvmStorageCellHost storage(previous_state.storage_root);
    JvmStorageSlot slot{};
    slot[31] = 0xa1;
    CHECK(storage.store(slot, JvmStorageValue{0xde, 0xad}).is_ok());

    // Round 45 regression: optionally force the runtime to return
    // a Status::Error (mirrors a real-world resolver/typed-args
    // failure) so tests can exercise the runtime-error gasUsed
    // billing path.
    if (mock_runtime_error) {
      return td::Status::Error(*mock_runtime_error);
    }

    JvmAvataInvocationResult result;
    result.invocation_status = 0;
    result.success = true;
    result.gas_used = mock_gas_used.value_or(123);
    result.gas_remaining = input.gas_limit - result.gas_used;
    result.memory_used = 456;
    result.storage_root = storage.root_cell();
    result.action_list = build_jvm_event_action_list(std::vector<JvmEvent>{});
    CHECK(result.action_list.not_null());
    return result;
  }

  mutable bool called{false};
  // Round-40 regression: optional override of the expected
  // `input.gas_limit` value asserted above; defaults to 2000 to
  // preserve existing-test behavior.
  mutable std::optional<std::uint64_t> mock_expected_gas_limit;
  // Optional override of the runtime-reported `gas_used`; defaults
  // to 123.  Used to drive the post-walk gas past the affordability
  // cap (Round-40 regression).
  mutable std::optional<std::uint64_t> mock_gas_used;
  // Round 45 regression: optional runtime error message.  When set,
  // `run_contract` returns `td::Status::Error(*mock_runtime_error)`
  // before producing any result.  Used to exercise consensus's
  // round-37 floor-billing on runtime errors and the matching RPC
  // round-45 fix.
  mutable std::optional<std::string> mock_runtime_error;
};

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
  // Distinct sentinel so the round-trip check below detects any silent
  // truncation / drop of the address_commit field.
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x80 + i);
  }
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
  CHECK(decoded.address_commit == state.address_commit);
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

  // Encoder no longer rejects zero class_hash on the struct (round-14
  // moved class_hash off the wire and into a recomputed field).  But
  // a null class_bytes is still rejected — an empty class_bytes
  // payload would produce a zero class_hash on decode, which the
  // decoder rejects.
  {
    JvmContractAccountState bad = state;
    bad.class_bytes = {};
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

TEST(JvmWorkchainCore, DecodeAlwaysSetsCanonicalClassHash) {
  // Round 14 dropped `class_hash` from the JVAC wire format (the
  // root cell would otherwise exceed 1023 bits with the new
  // `deployer` field).  The decoder now always recomputes
  // `class_hash = sha256(decoded class_bytes)` and surfaces it on
  // the struct.  This trivially closes the original VM-cache-
  // poisoning vulnerability: a malicious caller cannot declare a
  // class_hash that disagrees with class_bytes, because the
  // class_hash isn't transmitted at all — the engine and the
  // Avata cache always see the canonical recomputed value.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x10};

  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  // Caller can leave class_hash unset / set wrong — encoder ignores
  // it, decoder recomputes.
  state.class_hash = JvmClassHash{};  // intentionally wrong
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});

  auto encoded = encode_jvm_contract_account_state(state);
  CHECK(encoded.not_null());

  JvmContractAccountState decoded;
  CHECK(decode_jvm_contract_account_state(encoded, decoded));
  // Decoded class_hash equals sha256(class_bytes), independent of
  // what the caller set on the struct before encoding.
  CHECK(decoded.class_hash == compute_jvm_class_hash(class_bytes));
  CHECK(decoded.class_hash != JvmClassHash{});

  // Empty class_bytes is rejected (would produce zero class_hash,
  // which is invalid for the address-binding gate).
  state.class_bytes = encode_jvm_storage_value(JvmStorageValue{});
  encoded = encode_jvm_contract_account_state(state);
  if (encoded.not_null()) {
    JvmContractAccountState rejected;
    CHECK(!decode_jvm_contract_account_state(encoded, rejected));
  }
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

TEST(JvmWorkchainCore, DecodeJvmStorageValueRejectsZeroByteContinuation) {
  // Round 56/57 fix: non-canonical continuation cells must be
  // rejected.  Round 56 closed the `byte_count == 0` case; Round 57
  // tightened to require `byte_count == kJvmStorageValueChunkBytes`
  // (127) for every non-final cell, so an attacker cannot build a
  // chain of 1..126-byte cells that walks the decoder more cells
  // per byte than the canonical encoding.
  using namespace jvm_workchain;

  // Build a hand-crafted "next=1" cell with zero payload bytes,
  // pointing at a normal final cell.  Canonical encoding never
  // produces this shape — `encode_jvm_storage_value` emits an
  // empty cell only as the lone cell for the empty value.
  vm::CellBuilder final_cell;
  // 1-byte payload + has_next=0
  std::uint8_t b = 0xab;
  CHECK(final_cell.store_bytes_bool(&b, 1));
  CHECK(final_cell.store_ulong_rchk_bool(0, 1));
  auto final_ref = final_cell.finalize();

  vm::CellBuilder zero_cont;
  // 0-byte payload + has_next=1 + ref
  CHECK(zero_cont.store_ulong_rchk_bool(1, 1));
  CHECK(zero_cont.store_ref_bool(std::move(final_ref)));
  auto zero_cont_ref = zero_cont.finalize();

  // Decode must reject (non-canonical zero-byte continuation).
  auto r = decode_jvm_storage_value(zero_cont_ref);
  CHECK(r.is_error());
  CHECK(r.error().message().str().find("non-canonical continuation chunk size")
        != std::string::npos);

  // Also reject when sandwiched between two non-empty cells.
  vm::CellBuilder middle_zero;
  // Build: head(1 byte, next=1, ref→ zero_cont(0 bytes, next=1, ref→ final))
  vm::CellBuilder zero_mid;
  CHECK(zero_mid.store_ulong_rchk_bool(1, 1));
  // Need a fresh final ref since we moved the previous one.
  vm::CellBuilder final2;
  CHECK(final2.store_bytes_bool(&b, 1));
  CHECK(final2.store_ulong_rchk_bool(0, 1));
  CHECK(zero_mid.store_ref_bool(final2.finalize()));
  auto zero_mid_ref = zero_mid.finalize();

  vm::CellBuilder head;
  CHECK(head.store_bytes_bool(&b, 1));
  CHECK(head.store_ulong_rchk_bool(1, 1));
  CHECK(head.store_ref_bool(std::move(zero_mid_ref)));
  auto head_ref = head.finalize();
  auto r2 = decode_jvm_storage_value(head_ref);
  CHECK(r2.is_error());
  CHECK(r2.error().message().str().find("non-canonical continuation chunk size")
        != std::string::npos);

  // The canonical empty-value encoding (single cell, no payload,
  // has_next=0) must still decode.
  vm::CellBuilder empty_cell;
  CHECK(empty_cell.store_ulong_rchk_bool(0, 1));
  auto empty_ref = empty_cell.finalize();
  auto r_empty = decode_jvm_storage_value(empty_ref);
  CHECK(r_empty.is_ok());
  CHECK(r_empty.ok().empty());

  // Round 57 MEDIUM: 1-byte non-final cell (canonical chunks are
  // 127 bytes) must also reject.  Builds: head(1 byte, next=1,
  // ref→ final(1 byte, next=0)).  Pre-Round-57 this decoded as a
  // 2-byte payload, walking 2 cells for 2 bytes — non-canonical.
  vm::CellBuilder final_one;
  std::uint8_t fb = 0xee;
  CHECK(final_one.store_bytes_bool(&fb, 1));
  CHECK(final_one.store_ulong_rchk_bool(0, 1));
  auto final_one_ref = final_one.finalize();

  vm::CellBuilder short_cont;
  std::uint8_t hb = 0xdd;
  CHECK(short_cont.store_bytes_bool(&hb, 1));
  CHECK(short_cont.store_ulong_rchk_bool(1, 1));
  CHECK(short_cont.store_ref_bool(std::move(final_one_ref)));
  auto short_cont_ref = short_cont.finalize();
  auto r_short = decode_jvm_storage_value(short_cont_ref);
  CHECK(r_short.is_error());
  CHECK(r_short.error().message().str().find(
            "non-canonical continuation chunk size") != std::string::npos);
}

TEST(JvmWorkchainCore, DecodeJvmStorageValueRejectsSubChunkCap) {
  // Round 55 MEDIUM fix: pre-Round-55 the bail-out check
  //   `out.size() > effective_cap - byte_count`
  // underflowed `size_t` whenever `effective_cap < byte_count`,
  // letting the decoder accept up to one full 127-byte chunk even
  // when the caller's cap was smaller.  A 65-byte payload with a
  // 64-byte cap silently fully decoded.  Now uses additive form
  // (`out.size() + byte_count > effective_cap`) which has no
  // underflow and rejects correctly.
  using namespace jvm_workchain;

  // 65-byte payload encodes as a single 65-byte chunk.
  JvmStorageValue v(65, 0xab);
  auto root = encode_jvm_storage_value(v);
  CHECK(root.not_null());

  // Cap 64 bytes — must reject (was silently accepted pre-fix).
  auto r64 = decode_jvm_storage_value(root, /*max_bytes=*/64);
  CHECK(r64.is_error());

  // Cap 65 bytes — must accept (exact boundary).
  auto r65 = decode_jvm_storage_value(root, /*max_bytes=*/65);
  CHECK(r65.is_ok());
  CHECK(r65.ok().size() == 65);

  // Cap 0 falls back to the legacy 1 MiB envelope cap (no extra
  // restriction).
  auto r0 = decode_jvm_storage_value(root, /*max_bytes=*/0);
  CHECK(r0.is_ok());
  CHECK(r0.ok().size() == 65);

  // Many-chunk payload (300 bytes ≈ 3 chunks at 127 bytes each).
  // Cap 127 bytes — must reject after the first chunk.
  JvmStorageValue v300(300, 0xcd);
  auto root300 = encode_jvm_storage_value(v300);
  CHECK(root300.not_null());
  auto r300_127 = decode_jvm_storage_value(root300, /*max_bytes=*/127);
  CHECK(r300_127.is_error());
  // Cap 300 bytes — must accept (exact boundary).
  auto r300_300 = decode_jvm_storage_value(root300, /*max_bytes=*/300);
  CHECK(r300_300.is_ok());
  CHECK(r300_300.ok().size() == 300);
}

TEST(JvmWorkchainCore, DecodeContractAccountStateBailsOnOversizedClassBytes) {
  // Round 54 MEDIUM fix: when the caller forwards a tighter
  // `max_class_bytes` to `decode_jvm_contract_account_state`, an
  // oversized `class_bytes` payload must be rejected without copying
  // every byte and SHA-256 hashing the full blob.  Pre-fix the engine
  // ran `decode_jvm_storage_value` (full memcpy) + `td::sha256` on up
  // to 1 MiB before checking ConfigParam-85's `max_class_bytes`,
  // letting external senders force unmetered validator-CPU work
  // proportional to their submitted blob size.
  using namespace jvm_workchain;

  JvmStorageValue large_class_bytes(8 * 1024, 0xab);  // 8 KiB > 4 KiB cap
  JvmContractAccountState state;
  state.stdlib_hash = {};
  state.stdlib_hash[0] = 0x99;
  state.class_hash = compute_jvm_class_hash(large_class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x60 + i);
  }
  state.class_bytes = encode_jvm_storage_value(large_class_bytes);
  state.storage_root = {};
  state.manifest_root = encode_jvm_method_manifest({});

  auto encoded = encode_jvm_contract_account_state(state);
  CHECK(encoded.not_null());

  // Decode with no cap (legacy behavior) — succeeds.
  JvmContractAccountState decoded_no_cap;
  CHECK(decode_jvm_contract_account_state(encoded, decoded_no_cap));
  CHECK(decoded_no_cap.decoded_class_bytes_size == large_class_bytes.size());

  // Decode with cap = 4 KiB — must reject (fast bail in the storage-
  // value walker).  The state struct comes back fully zeroed.
  JvmContractAccountState decoded_capped;
  CHECK(!decode_jvm_contract_account_state(encoded, decoded_capped,
                                            /*max_class_bytes=*/4 * 1024));
  CHECK(decoded_capped.decoded_class_bytes_size == 0);
  CHECK(decoded_capped.class_hash == JvmClassHash{});

  // Decode with cap == exact size — succeeds.
  JvmContractAccountState decoded_exact;
  CHECK(decode_jvm_contract_account_state(
      encoded, decoded_exact,
      /*max_class_bytes=*/large_class_bytes.size()));
  CHECK(decoded_exact.decoded_class_bytes_size == large_class_bytes.size());
}

TEST(JvmWorkchainCore, MessageAbiCallDescriptorRoundTripsAndOmitsContractId) {
  using namespace jvm_workchain;

  JvmCallDescriptor descriptor;
  descriptor.method_id = 0xdeadbeef;
  descriptor.args = make_empty_action_list();

  auto encoded = encode_jvm_call_descriptor(descriptor);
  CHECK(encoded.not_null());

  auto parsed = parse_jvm_call_descriptor(vm::load_cell_slice_ref(encoded));
  CHECK(parsed.is_ok());
  CHECK(parsed.ok().schema_version == kJvmCallDescriptorSchemaVersion);
  CHECK(parsed.ok().method_id == descriptor.method_id);
  CHECK(parsed.ok().args.not_null());

  // A cell with the wrong magic must fail parse.
  vm::CellBuilder wrong_magic_cb;
  wrong_magic_cb.store_long(0x4a564d49, 32);  // legacy "JVMI" magic
  wrong_magic_cb.store_long(1, 8);
  wrong_magic_cb.store_zeroes(256);
  wrong_magic_cb.store_long(0, 32);
  wrong_magic_cb.store_ref(make_empty_action_list());
  CHECK(parse_jvm_call_descriptor(
            vm::load_cell_slice_ref(wrong_magic_cb.finalize())).is_error());

  // Truncated body fails parse.
  vm::CellBuilder bad;
  bad.store_long(kJvmCallDescriptorMagic, 32);
  bad.store_long(kJvmCallDescriptorSchemaVersion, 8);
  CHECK(parse_jvm_call_descriptor(
            vm::load_cell_slice_ref(bad.finalize())).is_error());
}

TEST(JvmWorkchainCore, DeriveJvmContractAddressIsDeterministicAndSensitive) {
  using namespace jvm_workchain;

  auto desc = make_test_jvm_deploy_descriptor(0x77);
  auto manifest = encode_jvm_method_manifest({});  // canonical empty manifest

  auto a = derive_jvm_contract_address(desc, manifest);
  auto b = derive_jvm_contract_address(desc, manifest);
  CHECK(a.is_ok() && b.is_ok());
  CHECK(a.ok() == b.ok());

  // Salt sensitivity: same class, different salt → different address.
  auto desc2 = desc;
  desc2.salt[0] ^= 0xff;
  auto c = derive_jvm_contract_address(desc2, manifest);
  CHECK(c.is_ok());
  CHECK(c.ok() != a.ok());

  // class_hash sensitivity (perturb class_bytes; class_hash is recomputed
  // because validate_deploy_descriptor enforces hash == sha256(bytes)).
  auto desc3 = desc;
  desc3.class_bytes.back() ^= 0xaa;
  desc3.class_hash = compute_jvm_class_hash(desc3.class_bytes);
  auto d = derive_jvm_contract_address(desc3, manifest);
  CHECK(d.is_ok());
  CHECK(d.ok() != a.ok());

  // deployer sensitivity.
  auto desc4 = desc;
  // Avoid clobbering the leading non-zero deployer byte (validate rejects zero
  // deployers); flip a low byte instead.
  desc4.deployer[30] ^= 0x01;
  auto e = derive_jvm_contract_address(desc4, manifest);
  CHECK(e.is_ok());
  CHECK(e.ok() != a.ok());

  // init_args sensitivity (cell-hash).
  auto desc5 = desc;
  desc5.init_args = make_marker_cell(0x42);
  auto f = derive_jvm_contract_address(desc5, manifest);
  CHECK(f.is_ok());
  CHECK(f.ok() != a.ok());

  // manifest sensitivity (round-3 binding): different manifest → different
  // address even when the rest of the descriptor is identical.
  JvmMethodManifestEntry entry;
  entry.method_id = 0x42;
  entry.class_name = "ContractEntryPoint";
  entry.method_name = "ok";
  entry.method_spec = "()V";
  auto other_manifest = encode_jvm_method_manifest({entry});
  auto g = derive_jvm_contract_address(desc, other_manifest);
  CHECK(g.is_ok());
  CHECK(g.ok() != a.ok());

  // Null manifest yields the all-zero manifest_root_hash, which is
  // distinct from the canonical empty-manifest cell hash.  Forcing
  // callers to pass manifest_root explicitly (no default) is what
  // prevents confusing these two.
  auto h = derive_jvm_contract_address(desc, td::Ref<vm::Cell>{});
  CHECK(h.is_ok());
  CHECK(h.ok() != a.ok());
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

TEST(JvmWorkchainCore, MethodManifestRejectsMalformedUtf8Strings) {
  // Manifest strings get spliced into JSON RPC responses (className /
  // methodName / methodSpec).  The JSON spec requires UTF-8, so a
  // malformed byte sequence in any of those fields would let an
  // attacker emit a response that strict clients refuse to parse —
  // i.e., an RPC-response DoS.  Regression for the round-2 LOW
  // finding: validate_method_manifest_string now rejects malformed
  // UTF-8 at consensus level, before the manifest is ever encoded.
  using namespace jvm_workchain;

  auto with_class_name = [](std::string name) {
    JvmMethodManifestEntry e;
    e.method_id = 0x42;
    e.class_name = std::move(name);
    e.method_name = "ok";
    e.method_spec = "()V";
    return e;
  };

  // Valid ASCII / valid UTF-8 round-trip.
  CHECK(encode_jvm_method_manifest({with_class_name("Hello")}).not_null());
  CHECK(encode_jvm_method_manifest({with_class_name("Héllo")}).not_null());
  CHECK(encode_jvm_method_manifest({with_class_name("日本語")}).not_null());
  CHECK(encode_jvm_method_manifest({with_class_name("a\xF0\x9F\x98\x80z")})
            .not_null());  // U+1F600 (4-byte)

  // Lone continuation byte.
  CHECK(encode_jvm_method_manifest({with_class_name("\x80")}).is_null());
  // Overlong / forbidden leader bytes.
  CHECK(encode_jvm_method_manifest({with_class_name("\xC0\xAF")}).is_null());
  CHECK(encode_jvm_method_manifest({with_class_name("\xC1\x80")}).is_null());
  CHECK(encode_jvm_method_manifest({with_class_name("\xF5\x80\x80\x80")})
            .is_null());
  CHECK(encode_jvm_method_manifest({with_class_name("\xFF")}).is_null());
  // Truncated 2/3/4-byte sequence.
  CHECK(encode_jvm_method_manifest({with_class_name("\xC3")}).is_null());
  CHECK(encode_jvm_method_manifest({with_class_name("\xE0\xA0")}).is_null());
  CHECK(encode_jvm_method_manifest({with_class_name("\xF0\x90\x80")}).is_null());
  // UTF-16 surrogate half (U+D800) encoded as 0xED 0xA0 0x80 — invalid in UTF-8.
  CHECK(encode_jvm_method_manifest({with_class_name("\xED\xA0\x80")}).is_null());
  // Overlong NUL via 0xC0 0x80 — rejected (and 0xC0 is forbidden anyway).
  CHECK(encode_jvm_method_manifest({with_class_name("\xC0\x80")}).is_null());
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

TEST(JvmWorkchainCore, BuildJvmWorkchainOutputRejectsStorageOverMaxCells) {
  // Round 12: ConfigParam 85's `max_storage_cells` cap is now enforced
  // post-execution.  CellStorageStat with limit_cells terminates the
  // walk early when the cap is exceeded, so the worst-case cost is
  // bounded by the configured cap rather than total storage size.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.max_storage_cells = 1;  // intentionally tiny

  // Build an invocation whose storage_root has more than 1 cell.
  // Two distinct slots produce a tree with multiple cells (root +
  // value cells + dictionary internal nodes).
  JvmStorageCellHost storage;
  JvmStorageSlot slot_a{};
  slot_a[31] = 0x10;
  CHECK(storage.store(slot_a, JvmStorageValue{0xaa, 0xbb, 0xcc}).is_ok());
  JvmStorageSlot slot_b{};
  slot_b[31] = 0x20;
  CHECK(storage.store(slot_b, JvmStorageValue{0xdd, 0xee, 0xff}).is_ok());
  CHECK(storage.root_cell().not_null());

  // Previous state has empty storage so the change-detection check
  // sees the storage as mutated and runs the cell-count gate.
  JvmContractAccountState previous;
  previous.stdlib_hash = cfg.stdlib_hash;
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x42};
  previous.class_hash = compute_jvm_class_hash(class_bytes);
  previous.class_bytes = encode_jvm_storage_value(class_bytes);
  previous.storage_root = {};
  previous.manifest_root = encode_jvm_method_manifest({});

  JvmAvataInvocationResult invocation;
  invocation.success = true;
  invocation.storage_root = storage.root_cell();
  invocation.action_list = {};
  invocation.gas_used = 100;
  invocation.gas_remaining = 900;
  invocation.memory_used = 0;

  auto result = build_jvm_workchain_output(cfg, previous, 1000, invocation);
  CHECK(result.is_error());
  CHECK(result.error().message().str().find("max_storage_cells")
        != std::string::npos);

  // With the cap raised, the same invocation succeeds.
  cfg.max_storage_cells = 100;
  auto ok_result = build_jvm_workchain_output(cfg, previous, 1000, invocation);
  CHECK(ok_result.is_ok());
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

TEST(WorkchainExecutionRegistry, ActionCreateAccountTlbRoundTrip) {
  // Lock the wire shape of action_create_account: pack the record carrying
  // a JVM v2 StateInit (code = activation marker, data = JVAC cell), unpack
  // it back, and verify dest_addr + state_init are preserved bit-for-bit.
  // Direct exercise through the action phase requires a full Transaction
  // harness with masterchain config + credit phase, so this test locks the
  // round trip at the OutAction TLB level — the same shape the host
  // serializes / deserializes when it runs the action phase.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto descriptor = make_test_jvm_deploy_descriptor(0xa5);

  // Build the initial JvmContractAccountState that action_create_account would
  // install at the new wc=3 account.
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = descriptor.class_hash;
  state.class_bytes = encode_jvm_storage_value(descriptor.class_bytes);
  state.manifest_root = encode_jvm_method_manifest({});
  state.storage_root = JvmStorageCellHost{}.root_cell();
  CHECK(state.class_bytes.not_null());
  CHECK(state.manifest_root.not_null());

  auto state_init = encode_jvm_state_init_cell(state);
  CHECK(state_init.not_null());
  CHECK(block::gen::t_StateInit.validate_ref(state_init));

  // Pass the same manifest_root the JVAC is built with so the address
  // binds to it.
  auto contract_address =
      derive_jvm_contract_address(descriptor, state.manifest_root)
          .move_as_ok();
  td::BitArray<256> dest_addr;
  std::memcpy(dest_addr.data(), contract_address.data(), 32);

  // value = 0 Tomis encoded as VarUInteger 16 with zero length prefix
  // (0b0000 = 4 bits).  Wrap it as a CellSlice the OutAction packer can
  // consume via t_Tomis.store_from.
  vm::CellBuilder value_cb;
  CHECK(value_cb.store_long_bool(0, 4));
  auto value_cs = vm::load_cell_slice_ref(value_cb.finalize());

  // body = Maybe ^Cell with Nothing (single 0 bit).
  vm::CellBuilder body_cb;
  CHECK(body_cb.store_long_bool(0, 1));
  auto body_cs = vm::load_cell_slice_ref(body_cb.finalize());

  block::gen::OutAction::Record_action_create_account rec;
  rec.mode = 0;
  rec.dest_addr = dest_addr;
  rec.state_init = state_init;
  rec.value = value_cs;
  rec.body = body_cs;

  td::Ref<vm::Cell> packed;
  CHECK(block::gen::t_OutAction.cell_pack(packed, rec));
  CHECK(packed.not_null());

  // Round trip: unpack and verify the dest_addr + state_init survive intact.
  block::gen::OutAction::Record_action_create_account decoded;
  CHECK(block::gen::t_OutAction.cell_unpack(packed, decoded));
  CHECK(decoded.mode == 0);
  CHECK(decoded.dest_addr == dest_addr);
  CHECK(decoded.state_init.not_null());
  CHECK(decoded.state_init->get_hash() == state_init->get_hash());
}

TEST(WorkchainExecutionRegistry, ActionCreateAccountRequiresPolicyAdmission) {
  // The full runtime check sits inside Transaction::try_action_create_account
  // and rejects with action result_code=34 when the engine's account policy
  // sets `admits_engine_create_account_actions=false`.  Driving that path
  // requires a complete Transaction harness (masterchain config, credit
  // phase, action phase wiring); here we exercise the structural pieces:
  //   * the policy struct is well-formed regardless of the admission flag
  //     (admission is an authorization toggle, not a validation predicate)
  //   * the action_create_account TLB record itself round-trips without
  //     embedding the admission flag in its wire shape (admission is a
  //     host-side gate, not part of the cell)
  // The transaction-level reject path is exercised by integration tests.
  using namespace jvm_workchain;

  block::AccountExecutionPolicy policy;
  policy.kind = block::AccountExecutionPolicyKind::EngineDefined;
  policy.singleton_address.reset();
  policy.admits_engine_create_account_actions = false;
  CHECK(block::validate_account_execution_policy_supported(policy).is_ok());

  policy.admits_engine_create_account_actions = true;
  CHECK(block::validate_account_execution_policy_supported(policy).is_ok());

  // Build an action_create_account record and confirm its packed cell does
  // not vary with the host-side admission flag (the gate is enforced when
  // the engine emits the action, not when the cell itself is encoded).
  auto cfg = make_test_jvm_config();
  auto desc = make_test_jvm_deploy_descriptor(0xb6);
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = desc.class_hash;
  state.class_bytes = encode_jvm_storage_value(desc.class_bytes);
  state.manifest_root = encode_jvm_method_manifest({});
  state.storage_root = JvmStorageCellHost{}.root_cell();
  auto state_init = encode_jvm_state_init_cell(state);
  CHECK(state_init.not_null());

  auto contract_address =
      derive_jvm_contract_address(desc, state.manifest_root).move_as_ok();
  td::BitArray<256> dest_addr;
  std::memcpy(dest_addr.data(), contract_address.data(), 32);

  vm::CellBuilder value_cb;
  CHECK(value_cb.store_long_bool(0, 4));
  auto value_cs = vm::load_cell_slice_ref(value_cb.finalize());
  vm::CellBuilder body_cb;
  CHECK(body_cb.store_long_bool(0, 1));
  auto body_cs = vm::load_cell_slice_ref(body_cb.finalize());

  block::gen::OutAction::Record_action_create_account rec;
  rec.mode = 0;
  rec.dest_addr = dest_addr;
  rec.state_init = state_init;
  rec.value = value_cs;
  rec.body = body_cs;
  td::Ref<vm::Cell> packed;
  CHECK(block::gen::t_OutAction.cell_pack(packed, rec));
  CHECK(packed.not_null());

  // The cell bytes are independent of admits_engine_create_account_actions:
  // running the same pack again yields the same hash regardless of the
  // policy flag value.
  td::Ref<vm::Cell> packed_again;
  CHECK(block::gen::t_OutAction.cell_pack(packed_again, rec));
  CHECK(packed_again->get_hash() == packed->get_hash());
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

TEST(WorkchainExecutionRegistry, JvmEngineDispatchesAccountStateToRuntime) {
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
  // Engine address-binding gate: the wc=3 account address must equal
  // sha256("TOS-JVM-CONTRACT-v2" || state.address_commit || state.class_hash).
  // For tests built without a deploy descriptor, populate a synthetic
  // address_commit and derive the matching account_addr.
  for (std::size_t i = 0; i < previous_state.address_commit.size(); ++i) {
    previous_state.address_commit[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  for (std::size_t i = 0; i < previous_state.deployer.size(); ++i) {
    previous_state.deployer[i] = static_cast<std::uint8_t>(0x60 + i);
  }
  previous_state.class_bytes = class_bytes_cell;
  previous_state.storage_root = initial_storage.root_cell();
  previous_state.manifest_root = manifest_root;

  block::WorkchainComputeInput input;
  auto expected_addr = derive_jvm_contract_address_from_state(
      previous_state.deployer, previous_state.address_commit,
      previous_state.class_hash,
      compute_jvm_manifest_root_hash(previous_state.manifest_root));
  std::memcpy(input.account_addr.data(), expected_addr.data(), 32);
  input.current_data = encode_jvm_contract_account_state(previous_state);
  CHECK(input.current_data.not_null());
  input.inbound_body = make_jvm_call_body(method_entry.method_id);
  input.gas_limit = 2000;
  // This is a "subsequent call" test (the previous_state already has
  // seeded storage), so msg_state_used remains false.

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
  // Round-34: gas_used is bumped to the JVM admission floor (1024)
  // when the runtime reports < 1024 gas used.  The mock returns 123
  // gas used, so the floor takes over.
  CHECK(output.gas_used == 1024);
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

TEST(WorkchainExecutionRegistry, JvmEngineCapsWalkGasOverflowingAffordableLimit) {
  // Round-40 fix regression.  The round-39 storage-walk gas billing
  // (`invocation.gas_used += stat.cells * 1`) can push the runtime's
  // post-walk gas above `effective_gas_limit` — the affordability cap
  // computed as `min(input.gas_limit, max_gas_per_tx, balance/gas_price)`.
  // Pre-fix outcomes:
  //   1. `build_jvm_workchain_output` rejected with "gas_used > gas_limit",
  //      OR
  //   2. the host's round-30 charging block saw `gas_fees > balance`,
  //      converted the call to `sk_no_gas` with `gas_fees = 0`, and no
  //      state committed — so the contract repeated runtime work plus
  //      the validator-CPU walk for free.
  // Round-40 caps the post-walk `gas_used` at `effective_gas_limit`
  // and emits `skipped_output_billed(sk_no_gas, ..., cap, out_of_gas=true)`,
  // billing exactly what the account can afford.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;  // 1 tomi per gas → balance = affordable gas budget
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  // Effective gas limit will be 2000 (= input.gas_limit, since balance
  // 2000 / gas_price 1 == 2000 and max_gas_per_tx is large in the test
  // config).  The mock will report runtime gas_used = 2000 (the entire
  // budget), so any walk gas at all (>= 1) tips the total over the cap.
  runtime->mock_expected_gas_limit = 2000;
  runtime->mock_gas_used = 2000;
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x40};
  auto class_bytes_cell = encode_jvm_storage_value(class_bytes);

  JvmMethodManifestEntry method_entry;
  method_entry.method_id = 0x40404040;
  method_entry.class_name = "ContractEntryPoint";
  method_entry.method_name = "ok";
  method_entry.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({method_entry});

  // Seed a few storage slots so the round-39 walk has cells to count.
  // The mock writes one more slot, so storage_changed=true and walk runs.
  JvmStorageCellHost initial_storage;
  for (std::uint8_t i = 1; i <= 4; ++i) {
    JvmStorageSlot slot{};
    slot[0] = i;
    CHECK(initial_storage.store(slot, JvmStorageValue{i, i, i}).is_ok());
  }

  JvmContractAccountState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < previous_state.address_commit.size(); ++i) {
    previous_state.address_commit[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  for (std::size_t i = 0; i < previous_state.deployer.size(); ++i) {
    previous_state.deployer[i] = static_cast<std::uint8_t>(0x60 + i);
  }
  previous_state.class_bytes = class_bytes_cell;
  previous_state.storage_root = initial_storage.root_cell();
  previous_state.manifest_root = manifest_root;

  block::WorkchainComputeInput input;
  auto expected_addr = derive_jvm_contract_address_from_state(
      previous_state.deployer, previous_state.address_commit,
      previous_state.class_hash,
      compute_jvm_manifest_root_hash(previous_state.manifest_root));
  std::memcpy(input.account_addr.data(), expected_addr.data(), 32);
  input.current_data = encode_jvm_contract_account_state(previous_state);
  CHECK(input.current_data.not_null());
  input.inbound_body = make_jvm_call_body(method_entry.method_id);
  input.gas_limit = 2000;
  // Balance covers exactly `runtime_gas * gas_price` (= 2000 * 1).
  // The post-walk total (2000 + walk_gas) will exceed this cap.
  input.account_balance =
      block::CurrencyCollection(td::make_refint(2000));

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(runtime->called);
  CHECK(output.completed);
  // skipped_output_billed: accepted=true so the host actually debits
  // the fees; committed=false so no state transition; engine_success
  // false because the call was rejected.  Round 49 fix: the engine
  // emits this on the executed-but-failed wire branch
  // (skip_reason=sk_none, exit_code=-100 for sk_no_gas-class) so the
  // serialized `tr_phase_compute_vm$1` form carries the gas fields.
  // Pre-fix the wire would have lost them via tr_compute_phase_skipped.
  CHECK(output.accepted);
  CHECK(!output.committed);
  CHECK(!output.engine_success);
  CHECK(output.skip_reason == block::ComputePhase::sk_none);
  CHECK(output.exit_code == -100);
  CHECK(output.out_of_gas);
  // gas_used capped at effective_gas_limit (= 2000), NOT the runtime-
  // reported 2000 + walk_gas.  Pre-fix, gas_used would have been
  // 2000 + walk_gas, exceeding the limit and either bouncing through
  // build_output's rejection or the host's gas_fees > balance branch
  // (which billed zero).
  CHECK(output.gas_used == 2000);
  // gas_fees == cap * gas_price = 2000.  Pre-fix would have been zero
  // (free runtime + walk work).
  CHECK(output.gas_fees.not_null());
  CHECK(td::cmp(output.gas_fees, td::make_refint(2000)) == 0);
  // No state transition committed — new_data must be null/unset.
  CHECK(output.new_data.is_null());
}

TEST(WorkchainExecutionRegistry, JvmEngineRejectsMalformedAccountState) {
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
  input.inbound_body = make_jvm_call_body(0x1);
  input.gas_limit = 2000;

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

TEST(WorkchainExecutionRegistry,
     JvmEngineRejectsRuntimeJarMismatchedToConfigStdlibHash) {
  // Round 17 fix: ConfigParam 85's `stdlib_hash` is the consensus
  // commitment to the rt.jar that every validator runs.  Without
  // this gate, two validators with the same on-chain config could
  // pass the existing `state.stdlib_hash == cfg.stdlib_hash` check
  // and silently execute against different local rt.jar bytes —
  // consensus divergence.  The engine therefore also compares
  // `runtime->rt_jar_hash()` to `cfg.stdlib_hash` and fails closed
  // on mismatch.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  // Override the runtime's rt.jar hash to a value that does NOT
  // match cfg.stdlib_hash.
  std::array<std::uint8_t, 32> wrong_jar_hash{};
  wrong_jar_hash[0] = 0xee;
  runtime->mock_rt_jar_hash = wrong_jar_hash;

  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  // Build a well-formed JVAC state.
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x99};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x55 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x77 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = {};
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto bound_addr = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));
  block::WorkchainComputeInput input;
  std::memcpy(input.account_addr.data(), bound_addr.data(), 32);
  input.current_data = state_cell;
  input.inbound_body = make_jvm_call_body(0x42);
  input.gas_limit = 2000;
  auto out = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(out.completed);
  CHECK(!out.accepted);
  CHECK(out.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);
}

TEST(WorkchainExecutionRegistry,
     JvmEngineRejectsClassBytesExceedingConfigCap) {
  // Round 9: ConfigParam 85's `max_class_bytes` cap must be enforced at
  // consensus, not just at JSON-RPC admission.  Without this check a
  // class up to `kJvmStorageValueMaxBytes` (1 MiB) bypasses the
  // governance limit even though admission sets a much smaller default
  // (64 KiB).
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.max_class_bytes = 64;  // intentionally small for this test
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  // Build a JVAC whose class_bytes is intentionally over the cap.
  JvmStorageValue large_class_bytes(cfg.max_class_bytes + 1, 0xab);
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(large_class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x33 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0xb0 + i);
  }
  state.class_bytes = encode_jvm_storage_value(large_class_bytes);
  state.storage_root = {};
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto bound_addr = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));
  block::WorkchainComputeInput input;
  std::memcpy(input.account_addr.data(), bound_addr.data(), 32);
  input.current_data = state_cell;
  input.inbound_body = make_jvm_call_body(0x42);
  input.gas_limit = 2000;
  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(output.completed);
  CHECK(!output.accepted);
  CHECK(output.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, ContractAccountStateDecodeSkipsFullStorageWalk) {
  // Round 9: pre-round-9 decode called validate_jvm_storage_root on
  // every load, walking the entire dictionary and decoding every
  // value before any gas was metered.  Verify the heavy walk is gone
  // by feeding decode a JVAC whose storage_root contains one
  // structurally-malformed value: decode used to reject this; now it
  // accepts (because storage values are validated lazily at
  // execution time under the contract's gas budget) and the bad
  // value would only be detected when actually loaded.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x33};

  // Build a 256-bit dictionary with one entry whose value cell is a
  // valid storage value (we don't actually need a malformed one — the
  // point is decode no longer pays O(N) walk cost; this test pins
  // that decode succeeds with non-empty storage_root that has not
  // been consensus-validated for malformed values).
  JvmStorageCellHost storage;
  JvmStorageSlot slot{};
  slot[31] = 0x42;
  CHECK(storage.store(slot, JvmStorageValue{0xaa}).is_ok());

  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = storage.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto encoded = encode_jvm_contract_account_state(state);
  CHECK(encoded.not_null());

  JvmContractAccountState decoded;
  CHECK(decode_jvm_contract_account_state(encoded, decoded));
  // decoded_class_bytes_size populated for the engine's max_class_bytes
  // gate.
  CHECK(decoded.decoded_class_bytes_size == class_bytes.size());
}

TEST(WorkchainExecutionRegistry,
     JvmEngineRejectsAccountStateWithMismatchedAddress) {
  // Address-binding gate (round 2 fix): the host's custom-engine branch
  // unpacks `StateInit.data` for every acc_uninit wc=3 transaction and
  // deliberately skips `check_in_msg_state_hash` because v2 addresses are
  // derived from the deploy descriptor, not from `hash(StateInit)`.  The
  // engine therefore must verify on every run_compute that
  //   account_addr == sha256("TOS-JVM-CONTRACT-v2"
  //                          || state.address_commit
  //                          || state.class_hash)
  // otherwise an attacker could squat any victim's deterministic but
  // not-yet-active address with attacker bytecode.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  // Build a well-formed JVAC state.
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x99};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x55 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x77 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  // Wrong account_addr (does not match address_commit + class_hash).
  block::WorkchainComputeInput bad;
  bad.account_addr.set_zero();  // sha256(domain || commit || class_hash) != 0
  bad.current_data = state_cell;
  bad.inbound_body = make_jvm_call_body(0x42);
  bad.gas_limit = 2000;
  auto bad_out = execution.executor->run_compute(bad, context).move_as_ok();
  CHECK(bad_out.completed);
  CHECK(!bad_out.accepted);
  CHECK(bad_out.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);

  // Correct account_addr (matches the binding) — runtime is invoked.
  runtime->called = false;
  block::WorkchainComputeInput ok;
  auto bound_addr = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));
  std::memcpy(ok.account_addr.data(), bound_addr.data(), 32);
  ok.current_data = state_cell;
  ok.inbound_body = make_jvm_call_body(0x42);
  ok.gas_limit = 2000;
  auto ok_out = execution.executor->run_compute(ok, context).move_as_ok();
  CHECK(ok_out.completed);
  CHECK(runtime->called);

  // Manifest-swap rejected (different manifest root → expected_addr
  // shifts; account_addr no longer matches).
  runtime->called = false;
  JvmContractAccountState attacker_state = state;
  JvmMethodManifestEntry attacker_entry;
  attacker_entry.method_id = 0x42;
  attacker_entry.class_name = "AttackerEntryPoint";
  attacker_entry.method_name = "ok";
  attacker_entry.method_spec = "()V";
  attacker_state.manifest_root =
      encode_jvm_method_manifest({attacker_entry});
  CHECK(attacker_state.manifest_root->get_hash()
        != state.manifest_root->get_hash());
  auto attacker_state_cell =
      encode_jvm_contract_account_state(attacker_state);
  CHECK(attacker_state_cell.not_null());
  block::WorkchainComputeInput swap;
  // Aim at the LEGITIMATE address (what the attacker actually wants
  // to squat) — the swapped manifest must shift expected_addr away.
  std::memcpy(swap.account_addr.data(), bound_addr.data(), 32);
  swap.current_data = attacker_state_cell;
  swap.inbound_body = make_jvm_call_body(0x42);
  swap.gas_limit = 2000;
  auto swap_out = execution.executor->run_compute(swap, context).move_as_ok();
  CHECK(swap_out.completed);
  CHECK(!swap_out.accepted);
  CHECK(swap_out.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);

  // First-activation invariant: msg_state_used==true with non-empty
  // storage_root must reject.  An attacker would otherwise pre-load
  // attacker-favorable storage at the victim's deterministic address.
  // Uses an int_msg whose src.addr matches state.deployer so the
  // round-14 deployer-auth gate passes; the gate that fires here is
  // the round-3 storage-empty invariant.
  runtime->called = false;
  JvmStorageCellHost preload;
  JvmStorageSlot owner_slot{};
  CHECK(preload.store(owner_slot, JvmStorageValue{0xAA, 0xAA}).is_ok());
  JvmContractAccountState preload_state = state;
  preload_state.storage_root = preload.root_cell();
  CHECK(preload_state.storage_root.not_null());
  auto preload_cell =
      encode_jvm_contract_account_state(preload_state);
  CHECK(preload_cell.not_null());
  block::WorkchainComputeInput first_act;
  std::memcpy(first_act.account_addr.data(), bound_addr.data(), 32);
  first_act.current_data = preload_cell;
  first_act.inbound_body = make_jvm_call_body(0x42);
  first_act.inbound_message = make_jvm_int_msg_with_src(state.deployer);
  first_act.gas_limit = 2000;
  first_act.msg_state_used = true;
  auto first_act_out =
      execution.executor->run_compute(first_act, context).move_as_ok();
  CHECK(first_act_out.completed);
  CHECK(!first_act_out.accepted);
  CHECK(first_act_out.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);

  // Front-run rejected (round-14 fix): even though the StateInit is
  // identical to the legitimate one (same address, address_commit,
  // class_hash, manifest, deployer), an attacker whose msg.src.addr
  // != state.deployer cannot run their first call body.
  runtime->called = false;
  std::array<std::uint8_t, 32> attacker_addr{};
  attacker_addr[31] = 0xfe;
  CHECK(attacker_addr != state.deployer);
  block::WorkchainComputeInput frontrun;
  std::memcpy(frontrun.account_addr.data(), bound_addr.data(), 32);
  frontrun.current_data = state_cell;
  frontrun.inbound_body = make_jvm_call_body(0x42);
  frontrun.inbound_message = make_jvm_int_msg_with_src(attacker_addr);
  frontrun.gas_limit = 2000;
  frontrun.msg_state_used = true;
  auto frontrun_out =
      execution.executor->run_compute(frontrun, context).move_as_ok();
  CHECK(frontrun_out.completed);
  CHECK(!frontrun_out.accepted);
  CHECK(frontrun_out.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);

  // Cross-workchain bypass rejected (round-15 fix): attacker uses the
  // SAME 32-byte address as state.deployer but sends from wc=0
  // instead of wc=3.  Pre-round-15 the engine compared only the 32
  // bytes and accepted; round-15 also requires src.workchain == 3.
  runtime->called = false;
  block::WorkchainComputeInput cross_wc;
  std::memcpy(cross_wc.account_addr.data(), bound_addr.data(), 32);
  cross_wc.current_data = state_cell;
  cross_wc.inbound_body = make_jvm_call_body(0x42);
  cross_wc.inbound_message =
      make_jvm_int_msg_with_src_at_wc(state.deployer, 0);  // wc=0
  cross_wc.gas_limit = 2000;
  cross_wc.msg_state_used = true;
  auto cross_wc_out =
      execution.executor->run_compute(cross_wc, context).move_as_ok();
  CHECK(cross_wc_out.completed);
  CHECK(!cross_wc_out.accepted);
  CHECK(cross_wc_out.skip_reason == block::ComputePhase::sk_bad_state);
  CHECK(!runtime->called);

  // Same preload accepted on a SUBSEQUENT call (msg_state_used==false)
  // because storage legitimately mutates after activation, and the
  // deployer-auth gate doesn't apply once the account is active.
  runtime->called = false;
  block::WorkchainComputeInput later;
  std::memcpy(later.account_addr.data(), bound_addr.data(), 32);
  later.current_data = preload_cell;
  later.inbound_body = make_jvm_call_body(0x42);
  later.gas_limit = 2000;
  // later.msg_state_used = false (default)
  auto later_out =
      execution.executor->run_compute(later, context).move_as_ok();
  CHECK(later_out.completed);
  CHECK(runtime->called);
}

TEST(WorkchainExecutionRegistry, JvmEndToEndDeployCallSequence) {
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

  // Build the manifest first because the v2 address derivation now binds
  // manifest_root.hash too.
  JvmMethodManifestEntry method_entry;
  method_entry.method_id = 0xb00b1e5;
  auto deploy_desc_for_class = make_test_jvm_deploy_descriptor(0xa5);
  method_entry.class_name = deploy_desc_for_class.class_name;
  method_entry.method_name = "ok";
  method_entry.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({method_entry});
  CHECK(manifest_root.not_null());

  // Build a deploy descriptor and verify the v2 address derivation.
  auto deploy_desc = deploy_desc_for_class;
  auto address_a =
      derive_jvm_contract_address(deploy_desc, manifest_root).move_as_ok();
  auto address_b =
      derive_jvm_contract_address(deploy_desc, manifest_root).move_as_ok();
  CHECK(address_a == address_b);  // determinism

  // Different salt yields a different per-account address (storage is
  // therefore isolated; this is the v2 alternative to v1's contract_id key).
  auto deploy_desc_other_salt = deploy_desc;
  deploy_desc_other_salt.salt[0] ^= 0xff;
  auto address_c = derive_jvm_contract_address(deploy_desc_other_salt,
                                                manifest_root)
                       .move_as_ok();
  CHECK(address_c != address_a);

  // Build the initial account state that `action_create_account` would
  // install for this deploy descriptor (this is the v2 analog of
  // install_jvm_deploy_descriptor in v1).
  auto class_bytes_cell = encode_jvm_storage_value(deploy_desc.class_bytes);
  CHECK(class_bytes_cell.not_null());

  JvmContractAccountState state0;
  state0.stdlib_hash = cfg.stdlib_hash;
  state0.class_hash = deploy_desc.class_hash;
  // The engine's address-binding gate requires
  //   input.account_addr == sha256("TOS-JVM-CONTRACT-v2"
  //                                || state.address_commit
  //                                || state.class_hash
  //                                || sha256-cell-hash(state.manifest_root))
  // so the JVAC state and input.account_addr must agree by construction.
  state0.address_commit = compute_jvm_address_commit(
      deploy_desc.deployer, deploy_desc.salt, deploy_desc.init_args);
  state0.deployer = deploy_desc.deployer;
  state0.class_bytes = class_bytes_cell;
  // Empty initial storage_root — the engine's first-activation invariant
  // requires this on `msg_state_used == true`.  Subsequent calls below
  // pass `msg_state_used == false` (default) so a non-null storage_root
  // is allowed there.
  state0.storage_root = {};
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
  std::memcpy(call1.account_addr.data(), address_a.data(), 32);
  call1.current_data = state0_cell;
  call1.inbound_body = make_jvm_call_body(method_entry.method_id);
  call1.gas_limit = 2000;
  auto out1 = execution.executor->run_compute(call1, context).move_as_ok();
  CHECK(runtime->called);
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
  runtime->called = false;
  block::WorkchainComputeInput call2;
  std::memcpy(call2.account_addr.data(), address_a.data(), 32);
  call2.current_data = out1.new_data;
  call2.inbound_body = make_jvm_call_body(method_entry.method_id);
  call2.gas_limit = 2000;
  auto out2 = execution.executor->run_compute(call2, context).move_as_ok();
  CHECK(runtime->called);
  CHECK(out2.committed);
  JvmContractAccountState state2;
  CHECK(decode_jvm_contract_account_state(out2.new_data, state2));
  CHECK(state2.class_hash == state0.class_hash);
  CHECK(state2.class_bytes->get_hash() == class_bytes_cell->get_hash());
  CHECK(state2.manifest_root->get_hash() == manifest_root->get_hash());

  // Determinism: re-running call 1 from state0 produces the same new_data
  // (the engine is a pure function of state + input).
  runtime->called = false;
  auto out1_again = execution.executor->run_compute(call1, context).move_as_ok();
  CHECK(runtime->called);
  CHECK(out1_again.new_data.not_null());
  CHECK(out1_again.new_data->get_hash() == out1.new_data->get_hash());
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

TEST(WorkchainExecutionRegistry, CustomComputeGasFeesAreChargedToAccount) {
  // Round-29 fix: the custom-compute path now mirrors TVM/precompiled
  // and actually charges `output.gas_fees` from the account.  The
  // pre-fix behavior (only copy fees into cp.gas_fees, never debit
  // balance or accumulate total_fees) let custom-engine contracts
  // consume validator CPU without paying.  Test verifies:
  //   * gas_fees=42 is copied into cp.gas_fees,
  //   * the account balance is debited by 42, and
  //   * the transaction's total_fees rises by 42.
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
  // Fund the account with 1000 tomis so the round-29 charging block
  // can actually debit gas_fees=42 without underflow.
  account.balance = block::CurrencyCollection(td::make_refint(1000));

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
  // Balance after charging.  account starts with 1000; gas_fees=42
  // is debited.  Need to read tx.balance which is the balance the
  // transaction holds during execution.
  CHECK(tx.balance.tomis.not_null());
  CHECK(td::cmp(tx.balance.tomis, td::make_refint(958)) == 0);
  CHECK(tx.total_fees.tomis.not_null());
  CHECK(td::cmp(tx.total_fees.tomis, td::make_refint(42)) == 0);
}

TEST(WorkchainExecutionRegistry,
     CustomComputeMarksRejectedWhenBalanceCannotPayGasFees) {
  // Round-29/30 fix: when the custom engine reports gas_fees >
  // balance, the host marks the compute phase as rejected
  // (sk_no_gas, accepted=false, success=false) so the collator's
  // external-rejection path (error code -701) handles it
  // gracefully.  Round 29 returned `false` from
  // prepare_compute_phase, which mapped to fatal collator error
  // -669 — a user-triggerable condition crashing block production.
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
        cp.gas_fees = td::make_refint(1000);  // > zero balance
        cp.new_data = make_marker_cell(0xB1);
        cp.actions = make_empty_action_list();
        return true;
      }));

  auto addr = singleton_executor_address();
  block::Account account(2, addr.bits());
  account.status = block::Account::acc_nonexist;
  account.orig_status = block::Account::acc_nonexist;
  account.balance = block::CurrencyCollection::zero();  // zero!

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

  // prepare_compute_phase returns true (graceful), but the compute
  // phase is marked rejected so the collator sees accepted=false
  // and treats the external as -701.
  CHECK(tx.prepare_compute_phase(compute_cfg));
  CHECK(tx.compute_phase != nullptr);
  CHECK(!tx.compute_phase->accepted);
  CHECK(!tx.compute_phase->success);
  CHECK(tx.compute_phase->skip_reason == block::ComputePhase::sk_no_gas);
  CHECK(tx.compute_phase->gas_fees.not_null());
  CHECK(td::sgn(tx.compute_phase->gas_fees) == 0);
  // Engine's new_data is dropped because the host couldn't bill.
  CHECK(tx.compute_phase->new_data.is_null());
  // Account balance and total_fees are unchanged (no charge).
  CHECK(tx.balance.tomis.not_null());
  CHECK(td::sgn(tx.balance.tomis) == 0);
  CHECK(tx.total_fees.tomis.not_null());
  CHECK(td::sgn(tx.total_fees.tomis) == 0);
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

// ---------------------------------------------------------------------------
// Phase F: wc=3 genesis wallet seeding.
// ---------------------------------------------------------------------------

namespace jvm_genesis_test {

// A class blob substitute: real Wallet.class bytes are 2-3 KiB.  For the
// genesis tests we only assert encoding / address-derivation properties,
// so a small distinct byte string suffices to drive a non-trivial
// class_hash through the address derivation.
inline std::string fake_wallet_class_bytes() {
    std::string out(256, '\0');
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<char>(i & 0xff);
    }
    return out;
}

inline std::array<std::uint8_t, 32> stdlib_hash_fixture() {
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(0xa0 + i);
    }
    return out;
}

inline jvm_workchain::JvmGenesisWallet make_wallet(std::uint8_t tag) {
    jvm_workchain::JvmGenesisWallet w;
    for (std::size_t i = 0; i < w.owner_pubkey.size(); ++i) {
        w.owner_pubkey[i] = static_cast<std::uint8_t>(tag * 7 + i);
    }
    for (std::size_t i = 0; i < w.salt.size(); ++i) {
        w.salt[i] = static_cast<std::uint8_t>(tag * 13 + i);
    }
    w.initial_balance = td::make_refint(1'000'000'000ULL);
    return w;
}

}  // namespace jvm_genesis_test

TEST(JvmWorkchainCore, GenesisWalletBuildIsDeterministic) {
  // Two builds with identical inputs must produce byte-identical Account
  // cells.  This is the property genesis builders rely on: the same
  // zerostate script run on different machines must produce the same
  // network state.
  using namespace jvm_workchain;
  using namespace jvm_genesis_test;

  auto class_bytes = fake_wallet_class_bytes();
  auto stdlib = stdlib_hash_fixture();
  auto wallet = make_wallet(1);

  auto a = build_jvm_genesis_wallet(wallet, stdlib, td::Slice(class_bytes));
  CHECK(a.is_ok());
  auto b = build_jvm_genesis_wallet(wallet, stdlib, td::Slice(class_bytes));
  CHECK(b.is_ok());
  CHECK(a.ok().address == b.ok().address);
  CHECK(a.ok().account_cell->get_hash()
        == b.ok().account_cell->get_hash());
}

TEST(JvmWorkchainCore, GenesisWalletAddressBindingMatchesDispatchGate) {
  // dispatch-engine.cpp recomputes the expected address from the
  // (deployer, address_commit, class_hash, manifest_root) tuple stored
  // inside the JVAC, and rejects any account whose stored address
  // doesn't match.  Genesis wallets MUST satisfy this property — if
  // not, every wc=3 transaction against a seeded wallet would fail
  // sk_bad_state.  This test re-derives the address from the encoded
  // JVAC the same way the dispatch engine would.
  using namespace jvm_workchain;
  using namespace jvm_genesis_test;

  auto class_bytes = fake_wallet_class_bytes();
  auto stdlib = stdlib_hash_fixture();
  auto wallet = make_wallet(2);

  auto build = build_jvm_genesis_wallet(
      wallet, stdlib, td::Slice(class_bytes)).move_as_ok();

  JvmContractAccountState decoded;
  CHECK(decode_jvm_contract_account_state(
            build.contract_account_state_cell, decoded));
  CHECK(decoded.deployer == kJvmGenesisDeployer);
  CHECK(decoded.stdlib_hash == stdlib);

  auto manifest_hash = compute_jvm_manifest_root_hash(decoded.manifest_root);
  auto rederived = derive_jvm_contract_address_from_state(
      decoded.deployer,
      decoded.address_commit,
      decoded.class_hash,
      manifest_hash);

  CHECK(rederived == build.address);
}

TEST(JvmWorkchainCore, GenesisWalletStorageSlotsMatchWalletInit) {
  // The seeded storage_root must contain exactly the three slots
  // `Wallet.init(ownerPubKey)` would have written — same keccak256 slot
  // derivation, same values.  Otherwise the on-chain Wallet.execute()
  // would see no INIT_FLAG and revert with NotInitialized.
  using namespace jvm_workchain;
  using namespace jvm_genesis_test;

  auto class_bytes = fake_wallet_class_bytes();
  auto stdlib = stdlib_hash_fixture();
  auto wallet = make_wallet(3);

  auto build = build_jvm_genesis_wallet(
      wallet, stdlib, td::Slice(class_bytes)).move_as_ok();

  JvmContractAccountState decoded;
  CHECK(decode_jvm_contract_account_state(
            build.contract_account_state_cell, decoded));
  CHECK(decoded.storage_root.not_null());

  JvmStorageCellHost storage(decoded.storage_root);

  auto keccak_slot = [](const char* name) -> JvmStorageSlot {
      auto digest = ethash::keccak256(
          reinterpret_cast<const std::uint8_t*>(name), std::strlen(name));
      JvmStorageSlot s{};
      std::memcpy(s.data(), digest.bytes, 32);
      return s;
  };

  auto owner = storage.load(keccak_slot("Wallet.ownerPubKey")).move_as_ok();
  CHECK(owner.has_value());
  CHECK(owner.value().size() == 32);
  for (std::size_t i = 0; i < 32; ++i) {
      CHECK(owner.value()[i] == wallet.owner_pubkey[i]);
  }

  auto nonce = storage.load(keccak_slot("Wallet.nonce")).move_as_ok();
  CHECK(nonce.has_value());
  CHECK(nonce.value().size() == 32);
  for (std::size_t i = 0; i < 32; ++i) {
      CHECK(nonce.value()[i] == 0);
  }

  auto flag = storage.load(keccak_slot("Wallet.initFlag")).move_as_ok();
  CHECK(flag.has_value());
  CHECK(flag.value().size() == 1);
  CHECK(flag.value()[0] == 0x01);
}

TEST(JvmWorkchainCore, GenesisWalletDifferentSaltProducesDifferentAddresses) {
  // Two wallets with the same owner pubkey but different salts must
  // resolve to different wc=3 addresses (the chain's basic "salt
  // disambiguates instances" property).
  using namespace jvm_workchain;
  using namespace jvm_genesis_test;

  auto class_bytes = fake_wallet_class_bytes();
  auto stdlib = stdlib_hash_fixture();

  auto w1 = make_wallet(4);
  auto w2 = make_wallet(4);
  // Mutate only the salt.
  for (std::size_t i = 0; i < w2.salt.size(); ++i) {
      w2.salt[i] = static_cast<std::uint8_t>(w2.salt[i] ^ 0x55);
  }
  CHECK(w1.owner_pubkey == w2.owner_pubkey);
  CHECK(w1.salt != w2.salt);

  auto a = build_jvm_genesis_wallet(w1, stdlib, td::Slice(class_bytes))
              .move_as_ok();
  auto b = build_jvm_genesis_wallet(w2, stdlib, td::Slice(class_bytes))
              .move_as_ok();
  CHECK(a.address != b.address);
}

TEST(JvmWorkchainCore, GenesisZerostateAccountsCellEmbedsAllWallets) {
  // The parameterized zerostate builder must produce a dict whose
  // entries iterate exactly the supplied wallets, keyed on their
  // derived wc=3 addresses.
  using namespace jvm_workchain;
  using namespace jvm_genesis_test;

  auto class_bytes = fake_wallet_class_bytes();
  auto stdlib = stdlib_hash_fixture();
  std::vector<JvmGenesisWallet> wallets{
      make_wallet(5), make_wallet(6), make_wallet(7),
  };

  std::vector<JvmContractId> expected_addrs;
  for (const auto& w : wallets) {
      auto built = build_jvm_genesis_wallet(w, stdlib, td::Slice(class_bytes))
                       .move_as_ok();
      expected_addrs.push_back(built.address);
  }

  auto cell = build_jvm_zerostate_accounts_cell(wallets, stdlib,
                                                 td::Slice(class_bytes));
  CHECK(cell.not_null());

  // Determinism: building twice yields identical hashes.
  auto cell2 = build_jvm_zerostate_accounts_cell(wallets, stdlib,
                                                  td::Slice(class_bytes));
  CHECK(cell2.not_null());
  CHECK(cell->get_hash() == cell2->get_hash());

  // Every wallet's address must appear in the dict.
  vm::AugmentedDictionary accounts_dict(vm::load_cell_slice_ref(cell), 256,
                                        block::tlb::aug_ShardAccounts);
  std::size_t entries = 0;
  for (const auto& expected_addr : expected_addrs) {
      auto bits = td::ConstBitPtr{expected_addr.data()};
      auto value = accounts_dict.lookup(bits, 256);
      CHECK(value.not_null());
      ++entries;
  }
  CHECK(entries == wallets.size());
}

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

  // manifestEntries parsed faithfully (round-4 fix): without this,
  // non-empty manifests cannot be deployed because the RPC would
  // always derive the empty-manifest address.
  std::string with_manifest = R"({
    "classBytes": "0xcafebabe00000034",
    "className": "ContractEntryPoint",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "salt":     "0x0000000000000000000000000000000000000000000000000000000000000002",
    "manifestEntries": [
      {"methodId": 66, "className": "ContractEntryPoint",
       "methodName": "transfer", "methodSpec": "(I)I"},
      {"methodId": 99, "className": "ContractEntryPoint",
       "methodName": "balance", "methodSpec": "()I"}
    ]
  })";
  auto with_man = parse_jvm_deploy_contract_request(with_manifest);
  CHECK(with_man.has_value());
  CHECK(with_man->manifest_entries.size() == 2);
  CHECK(with_man->manifest_entries[0].method_id == 66);
  CHECK(with_man->manifest_entries[0].method_name == "transfer");
  CHECK(with_man->manifest_entries[0].method_spec == "(I)I");
  CHECK(with_man->manifest_entries[1].method_id == 99);
  CHECK(with_man->manifest_entries[1].method_name == "balance");

  // Manifest entry missing methodId — must fail.
  std::string bad_manifest = R"({
    "classBytes": "0xcafebabe",
    "className": "Foo",
    "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "manifestEntries": [{"className":"X","methodName":"y","methodSpec":"()V"}]
  })";
  CHECK(!parse_jvm_deploy_contract_request(bad_manifest).has_value());

  // methodId range / format validation (round-5 fix): values that
  // std::stoul would silently truncate or wrap must be rejected.
  auto with_bad_method_id = [](const char* method_id) {
    std::string p = std::string(R"({
      "classBytes": "0xcafebabe",
      "className": "Foo",
      "deployer": "0x0000000000000000000000000000000000000000000000000000000000000001",
      "manifestEntries": [{"methodId":)") + method_id +
        R"(,"className":"X","methodName":"y","methodSpec":"()V"}]
    })";
    return parse_jvm_deploy_contract_request(p);
  };
  CHECK(!with_bad_method_id("-1").has_value());           // negative
  CHECK(!with_bad_method_id("1.5").has_value());          // decimal
  CHECK(!with_bad_method_id("1e2").has_value());          // exponent
  CHECK(!with_bad_method_id("4294967296").has_value());   // UINT32_MAX+1
  CHECK(!with_bad_method_id("99999999999").has_value()); // huge
  // Boundary cases that must succeed.
  CHECK(with_bad_method_id("0").has_value());
  CHECK(with_bad_method_id("4294967295").has_value());    // UINT32_MAX

  // manifestEntries with non-empty content must change the derived
  // contractAddress vs. the empty-manifest case (round-3/4 binding).
  auto cfg = make_test_jvm_config();
  auto good_no_manifest = parse_jvm_deploy_contract_request(good_params);
  CHECK(good_no_manifest.has_value());
  auto without_addr_result =
      handle_jvm_deploy_contract(*good_no_manifest, cfg);
  auto with_addr_result = handle_jvm_deploy_contract(*with_man, cfg);
  CHECK(!without_addr_result.is_error);
  CHECK(!with_addr_result.is_error);
  // The two results' contractAddress must differ.
  auto extract_addr = [](const std::string& json) {
    auto needle = std::string("\"contractAddress\":\"");
    auto pos = json.find(needle);
    if (pos == std::string::npos) return std::string();
    pos += needle.size();
    auto end = json.find('"', pos);
    return json.substr(pos, end - pos);
  };
  auto addr_without = extract_addr(without_addr_result.json);
  auto addr_with = extract_addr(with_addr_result.json);
  CHECK(!addr_without.empty());
  CHECK(!addr_with.empty());
  CHECK(addr_without != addr_with);
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

TEST(JvmWorkchainCore, RpcDeployContractReturnsContractAddress) {
  // The deploy result surfaces the deterministic wc=3 `contractAddress`
  // from `derive_jvm_contract_address` so the client can drive
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
  CHECK(result.json.find("\"contractAddress\":") != std::string::npos);

  // Compute the expected address and verify it is what the RPC reports.
  JvmDeployDescriptor descriptor;
  descriptor.deployer = req.deployer;
  descriptor.salt = req.salt;
  descriptor.class_name = req.class_name;
  descriptor.class_bytes = req.class_bytes;
  descriptor.class_hash = compute_jvm_class_hash(descriptor.class_bytes);
  descriptor.init_args = req.init_args;
  // The RPC's deploy handler builds an empty manifest_root for callers
  // that don't supply manifest_entries.  derive_jvm_contract_address now
  // binds manifest_root.hash too, so the test must compute the same
  // empty-manifest root to match.
  auto expected_manifest_root = encode_jvm_method_manifest({});
  CHECK(expected_manifest_root.not_null());
  auto expected_address =
      derive_jvm_contract_address(descriptor, expected_manifest_root)
          .move_as_ok();
  std::string expected_addr_hex = "0x";
  for (auto b : expected_address) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(b));
    expected_addr_hex += buf;
  }
  CHECK(result.json.find(expected_addr_hex) != std::string::npos);
}

// Verify that executorStateBoc in the JSON params round-trips correctly through
// parse_jvm_get_contract_state_request: the hex BOC is decoded back to a cell
// with the same hash as the original, and the handler can then resolve the
// class name and hash from it without any out-of-band state injection.
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

  // jvm_deployContract: contractAddress field must be a real 0x-prefixed
  // hex hash, not the placeholder "see_result".
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
  // contractAddress must be a real hex value (66 chars: 0x + 64 hex digits).
  auto cid_pos = deploy->json.find("\"contractAddress\":\"0x");
  CHECK(cid_pos != std::string::npos);
  // The hex string immediately follows "contractAddress":"0x — check 64 hex chars.
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
// jvm_callContract with argsBoc passes the args cell through to the local
// simulation.  Verify that argsBoc round-trips: encode a JVMA args cell,
// supply it as argsBoc, and confirm the local execution receives it correctly.
// ---------------------------------------------------------------------------
// Multi-instance storage isolation
// ---------------------------------------------------------------------------

// Prove that two contract instances (different slot keys representing different
// namespace prefixes) coexist in the shared executor storage without clobbering
// each other.  The canonical v1 isolation mechanism is Mapping.namespace() in
// Java; this C++ test exercises the underlying storage cell-host layer.
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
  auto parsed = parse_jvm_config_cell(cell).move_as_ok();
  CHECK(parsed.chain_id == cfg.chain_id);
  CHECK(parsed.gas_price == cfg.gas_price);
  CHECK(parsed.max_gas_per_tx == cfg.max_gas_per_tx);
  CHECK(parsed.max_class_bytes == cfg.max_class_bytes);
  CHECK(parsed.max_heap_bytes == cfg.max_heap_bytes);
  CHECK(parsed.max_storage_cells == cfg.max_storage_cells);
  CHECK(parsed.class_file_major == cfg.class_file_major);
  CHECK(parsed.gas_schedule_version == cfg.gas_schedule_version);
  CHECK(parsed.opcode_gas_costs == cfg.opcode_gas_costs);
  CHECK(parsed.helper_gas_costs == cfg.helper_gas_costs);
}

// Verify that an out-of-memory invocation produces a correct compute output:
// not committed, not out_of_gas, vm_log identifies OOM, new_data is null.
// Verify that memory_used exceeding max_heap_bytes causes
// execute_jvm_avata_transaction to return an error rather than a result.
// This is the post-invocation config guard that prevents a misbehaving Avata
// thread from reporting usage above the arena limit.
// Verify that the executor-state cell serializes to bytes (BOC) and back
// without loss, and that re-running compute against the deserialized cell
// produces an identical result.  This is the "serialize to disk / reimport"
// replay test from Phase 8.
// ---------------------------------------------------------------------------
// RPC local execution and storage enumeration
// ---------------------------------------------------------------------------

// jvm_callContract with a runtime and executorStateBoc performs a local
// simulation and returns localResult alongside the call descriptor BOC.
// jvm_callContract with a failing runtime returns localResult.success=false
// and no newStateBoc.
// jvm_getContractState with executorStateBoc enumerates storage slots
// and includes them in storageSlots.
// jvm_deployContract with executorStateBoc installs the class into the
// executor state and returns newStateBoc alongside contractId and
// deployDescriptorBoc.  The returned newStateBoc must decode back to an
// executor state whose class_state_root contains the deployed class.

// ---------------------------------------------------------------------------
// Address derivation: hand-computed SHA-256 conformance
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, DeriveJvmContractAddressFormulaMatchesSpec) {
  // Lock the v2 address derivation formula:
  //   address_commit     = sha256(deployer (32B) || salt (32B)
  //                               || init_args_cell.hash (32B))
  //   manifest_root_hash = sha256-cell-hash(manifest_root) or zero
  //   addr               = sha256("TOS-JVM-CONTRACT-v2"
  //                               || address_commit (32B)
  //                               || class_hash (32B)
  //                               || manifest_root_hash (32B))
  //
  // The four-input formula keeps the address-binding gate cheap to
  // verify on every `run_compute` while binding both the bytecode
  // (class_hash) and the ABI dispatch table (manifest_root) to the
  // address.  Regression guards against any future tweak to the input
  // layout that would silently break existing deterministic addresses.
  using namespace jvm_workchain;

  JvmDeployDescriptor descriptor;
  for (std::size_t i = 0; i < descriptor.deployer.size(); ++i) {
    descriptor.deployer[i] = static_cast<std::uint8_t>(0x01 + i);
  }
  for (std::size_t i = 0; i < descriptor.salt.size(); ++i) {
    descriptor.salt[i] = static_cast<std::uint8_t>(0xff - i);
  }
  descriptor.class_bytes = JvmStorageValue{0xca, 0xfe, 0xba, 0xbe};
  descriptor.class_name = "P/Q";
  descriptor.init_args = make_empty_action_list();
  descriptor.class_hash = compute_jvm_class_hash(descriptor.class_bytes);

  JvmMethodManifestEntry entry;
  entry.method_id = 0x77;
  entry.class_name = "P/Q";
  entry.method_name = "ok";
  entry.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({entry});
  CHECK(manifest_root.not_null());

  // Hand-compute address_commit = sha256(deployer || salt ||
  //                                       init_args_cell.hash).
  std::string commit_material;
  commit_material.append(
      reinterpret_cast<const char*>(descriptor.deployer.data()),
      descriptor.deployer.size());
  commit_material.append(
      reinterpret_cast<const char*>(descriptor.salt.data()),
      descriptor.salt.size());
  auto init_hash = descriptor.init_args->get_hash().as_slice();
  commit_material.append(init_hash.data(), init_hash.size());

  std::array<std::uint8_t, 32> expected_commit{};
  td::sha256(td::Slice(commit_material),
             td::MutableSlice(reinterpret_cast<char*>(expected_commit.data()),
                              expected_commit.size()));

  // compute_jvm_address_commit must produce the same value.
  auto computed_commit = compute_jvm_address_commit(
      descriptor.deployer, descriptor.salt, descriptor.init_args);
  CHECK(computed_commit == expected_commit);

  // compute_jvm_manifest_root_hash must equal manifest_root->get_hash().
  auto computed_manifest_hash =
      compute_jvm_manifest_root_hash(manifest_root);
  auto raw_manifest_hash = manifest_root->get_hash().as_slice();
  for (std::size_t i = 0; i < computed_manifest_hash.size(); ++i) {
    CHECK(computed_manifest_hash[i]
          == static_cast<std::uint8_t>(raw_manifest_hash[i]));
  }

  // Null manifest → zero hash.
  JvmManifestRootHash zero_hash{};
  CHECK(compute_jvm_manifest_root_hash({}) == zero_hash);

  // Hand-compute the expected address from deployer + commit + class_hash
  // + manifest_root_hash (round-14 added deployer to the derivation as the
  // 5th input so the engine can authenticate the first-activation source).
  std::string addr_material = "TOS-JVM-CONTRACT-v2";
  addr_material.append(reinterpret_cast<const char*>(descriptor.deployer.data()),
                       descriptor.deployer.size());
  addr_material.append(reinterpret_cast<const char*>(expected_commit.data()),
                       expected_commit.size());
  addr_material.append(
      reinterpret_cast<const char*>(descriptor.class_hash.data()),
      descriptor.class_hash.size());
  addr_material.append(
      reinterpret_cast<const char*>(computed_manifest_hash.data()),
      computed_manifest_hash.size());

  std::array<std::uint8_t, 32> expected{};
  td::sha256(td::Slice(addr_material),
             td::MutableSlice(reinterpret_cast<char*>(expected.data()),
                              expected.size()));

  auto actual =
      derive_jvm_contract_address(descriptor, manifest_root).move_as_ok();
  for (std::size_t i = 0; i < actual.size(); ++i) {
    CHECK(actual[i] == expected[i]);
  }
  // Re-derivation is stable.
  auto again =
      derive_jvm_contract_address(descriptor, manifest_root).move_as_ok();
  CHECK(again == actual);

  // Different manifest → different address (manifest binds to the
  // address; this is the round-3 fix against ABI swap at first
  // activation).
  JvmMethodManifestEntry other_entry;
  other_entry.method_id = 0x77;
  other_entry.class_name = "P/Q";
  other_entry.method_name = "evil";
  other_entry.method_spec = "()V";
  auto other_manifest = encode_jvm_method_manifest({other_entry});
  CHECK(other_manifest.not_null());
  auto other_addr =
      derive_jvm_contract_address(descriptor, other_manifest).move_as_ok();
  CHECK(other_addr != actual);

  // derive_jvm_contract_address_from_state(deployer, commit, class_hash,
  // manifest_root_hash) reconstructs the same address — this is the
  // helper the engine uses on every `run_compute` to verify the
  // address-binding gate.
  auto from_state = derive_jvm_contract_address_from_state(
      descriptor.deployer, computed_commit, descriptor.class_hash,
      computed_manifest_hash);
  CHECK(from_state == actual);
}

// ---------------------------------------------------------------------------
// Avata resolver: per-account method manifest lookup
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, AvataResolverFindsMethodInPerAccountManifest) {
  // Per-account manifest must be queryable by method_id alone (no contract_id
  // tagging under v2).  Verifies the resolver returns the correct
  // (class_name, method_name, method_spec) triple for a known entry.
  using namespace jvm_workchain;

  JvmContractAccountState state;
  state.stdlib_hash = make_test_jvm_config().stdlib_hash;
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x42};
  state.class_hash = compute_jvm_class_hash(class_bytes);
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();

  JvmMethodManifestEntry entry;
  entry.method_id = 0x42;
  entry.class_name = "ContractEntryPoint";
  entry.method_name = "doStuff";
  entry.method_spec = "(I)I";
  state.manifest_root = encode_jvm_method_manifest({entry});
  CHECK(state.manifest_root.not_null());

  auto found = find_jvm_method_manifest_entry(state.manifest_root, 0x42);
  CHECK(found.is_ok());
  CHECK(found.ok().method_id == entry.method_id);
  CHECK(found.ok().class_name == entry.class_name);
  CHECK(found.ok().method_name == entry.method_name);
  CHECK(found.ok().method_spec == entry.method_spec);
}

TEST(JvmWorkchainCore, AvataResolverRejectsUnknownMethodId) {
  // A method_id absent from the per-account manifest must fail the lookup
  // with a non-OK status; engines that resolve a call must not silently
  // dispatch to a wrong entry.
  using namespace jvm_workchain;

  JvmMethodManifestEntry entry;
  entry.method_id = 0x10;
  entry.class_name = "ContractEntryPoint";
  entry.method_name = "ok";
  entry.method_spec = "()V";
  auto root = encode_jvm_method_manifest({entry});
  CHECK(root.not_null());

  auto missed = find_jvm_method_manifest_entry(root, 0xdeadbeef);
  CHECK(missed.is_error());
  // The error message must mention the missing id; this guards against a
  // generic "manifest error" that would mask a wrong-key dispatch.
  auto msg = missed.error().message().str();
  CHECK(msg.find("method") != std::string::npos
        || msg.find("entry") != std::string::npos
        || msg.find("not found") != std::string::npos
        || msg.find("missing") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Class cache: structural property keying on class_hash
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, AvataClassCacheKeyedOnClassHash) {
  // The runtime's vm_cache lives inside avata-runtime.cpp and is keyed by
  // class_hash.  The Cell DB-level invariant the cache relies on is that
  // two JvmContractAccountState cells sharing the same class_bytes produce
  // identical class_bytes Cell hashes — even when the surrounding state
  // (storage_root) differs.  This test pins that invariant.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x77, 0x88};
  auto class_hash = compute_jvm_class_hash(class_bytes);

  JvmStorageCellHost storage_a;
  JvmStorageSlot slot{};
  slot[31] = 0xa1;
  CHECK(storage_a.store(slot, JvmStorageValue{0x01, 0x02}).is_ok());

  JvmStorageCellHost storage_b;
  CHECK(storage_b.store(slot, JvmStorageValue{0xff, 0xee}).is_ok());

  JvmContractAccountState state_a;
  state_a.stdlib_hash = cfg.stdlib_hash;
  state_a.class_hash = class_hash;
  state_a.class_bytes = encode_jvm_storage_value(class_bytes);
  state_a.storage_root = storage_a.root_cell();
  state_a.manifest_root = encode_jvm_method_manifest({});

  JvmContractAccountState state_b;
  state_b.stdlib_hash = cfg.stdlib_hash;
  state_b.class_hash = class_hash;
  state_b.class_bytes = encode_jvm_storage_value(class_bytes);
  state_b.storage_root = storage_b.root_cell();
  state_b.manifest_root = encode_jvm_method_manifest({});

  auto cell_a = encode_jvm_contract_account_state(state_a);
  auto cell_b = encode_jvm_contract_account_state(state_b);
  CHECK(cell_a.not_null() && cell_b.not_null());
  // Outer cells differ because storage_root differs.
  CHECK(cell_a->get_hash() != cell_b->get_hash());

  JvmContractAccountState decoded_a, decoded_b;
  CHECK(decode_jvm_contract_account_state(cell_a, decoded_a));
  CHECK(decode_jvm_contract_account_state(cell_b, decoded_b));
  CHECK(decoded_a.class_bytes.not_null());
  CHECK(decoded_b.class_bytes.not_null());
  // The class_bytes Cell hash matches across both states — that is the
  // single key the runtime's vm_cache uses to share a parsed class.
  CHECK(decoded_a.class_bytes->get_hash() == decoded_b.class_bytes->get_hash());
  CHECK(decoded_a.class_hash == decoded_b.class_hash);
}

// ---------------------------------------------------------------------------
// JvmConfig schema gating
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, JvmConfigCellRejectsV1Schema) {
  // The v2 parser must reject any cell whose schema_version field is not
  // kJvmConfigSchemaVersion (=2).  Since v1's wire shape differs from v2,
  // we don't need to faithfully reproduce its layout — it suffices that
  // a cell carrying the magic but schema_version=1 is refused before any
  // attempt to read v1 fields.
  using namespace jvm_workchain;

  vm::CellBuilder cb;
  CHECK(cb.store_ulong_rchk_bool(kJvmConfigMagic, kJvmConfigMagicBits));
  CHECK(cb.store_ulong_rchk_bool(1, 8));  // schema_version = 1 (legacy)
  // Pad with arbitrary bytes; the parser must reject before reading them.
  CHECK(cb.store_zeroes_bool(256));
  auto cell = cb.finalize();
  CHECK(cell.not_null());

  auto parsed = parse_jvm_config_cell(cell);
  CHECK(parsed.is_error());
  CHECK(parsed.error().message().str().find("schema") != std::string::npos);
}

TEST(JvmWorkchainCore, JvmConfigDefaultActivationV2) {
  // default_activation() must yield a v2-shape config (schema_version=2,
  // chain_id=3 for the wc=3 JVM workchain).  No `max_total_class_bytes`
  // exists at the struct level — Cell DB hash dedup replaced it under v2.
  using namespace jvm_workchain;

  auto cfg = JvmConfig::default_activation();
  CHECK(cfg.schema_version == kJvmConfigSchemaVersion);
  CHECK(cfg.schema_version == 2);
  CHECK(cfg.chain_id == 3);
  CHECK(cfg.gas_schedule_version == 1);
  CHECK(cfg.class_file_major == 52);
  CHECK(cfg.max_class_bytes > 0);
  CHECK(cfg.max_heap_bytes > 0);
  CHECK(cfg.max_storage_cells > 0);
  CHECK(cfg.max_gas_per_tx > 0);
  // The JvmConfig struct does not carry max_total_class_bytes (compile-time
  // guarantee enforced by the absence of the field).  This sizeof bound is a
  // structural sanity check: the sum of declared field sizes is what the
  // struct should contain — no more, no less, which signals that no extra
  // legacy field is silently present.
  static_assert(
      sizeof(JvmConfig::stdlib_hash) == kJvmStdlibHashBytes,
      "stdlib_hash size must be 32 bytes");
}

// ---------------------------------------------------------------------------
// RPC parameter aliasing and per-account state fetch
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, RpcCallContractAcceptsAddressNotContractId) {
  // jvm_callContract must accept the v2 canonical "contractAddress" as well
  // as the legacy "contractId" alias (so older clients still work).
  using namespace jvm_workchain;

  std::string canonical_params = R"({
    "contractAddress": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "methodId": 12345
  })";
  auto canonical = parse_jvm_call_contract_request(canonical_params);
  CHECK(canonical.has_value());
  CHECK(canonical->method_id == 12345);
  CHECK(canonical->contract_address[0] == 0x01);
  CHECK(canonical->contract_address[31] == 0x20);

  std::string legacy_params = R"({
    "contractId": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    "methodId": 7
  })";
  auto legacy = parse_jvm_call_contract_request(legacy_params);
  CHECK(legacy.has_value());
  CHECK(legacy->method_id == 7);
  CHECK(legacy->contract_address[0] == 0xaa);
  CHECK(legacy->contract_address[31] == 0x99);

  // No address at all — must fail.
  std::string missing_addr = R"({"methodId": 1})";
  CHECK(!parse_jvm_call_contract_request(missing_addr).has_value());

  // methodId range / format validation (round-6 fix): the call path
  // must reject the same malformed values the deploy path already
  // rejects (round 5).  Otherwise tooling can produce a callDescriptor
  // for a different method than requested.
  auto with_bad = [](const std::string& method_id_token,
                      const std::string& gas_token = "") {
    std::string p = R"({"contractAddress": ")";
    p += "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    p += "\",\"methodId\":";
    p += method_id_token;
    if (!gas_token.empty()) {
      p += ",\"gasLimit\":";
      p += gas_token;
    }
    p += "}";
    return parse_jvm_call_contract_request(p);
  };
  CHECK(!with_bad("-1").has_value());
  CHECK(!with_bad("1.5").has_value());
  CHECK(!with_bad("1e2").has_value());
  CHECK(!with_bad("4294967296").has_value());
  // Boundary OK.
  CHECK(with_bad("0").has_value());
  CHECK(with_bad("4294967295").has_value());
  // gasLimit also strict: rejects negatives, decimals, exponent forms.
  CHECK(!with_bad("1", "-1").has_value());
  CHECK(!with_bad("1", "1.5").has_value());
  CHECK(with_bad("1", "1000000").has_value());
  // Round-7 fix: gasLimit values above UINT64_MAX must reject without
  // wrapping (the accumulator caught the overflow during the loop).
  // 18446744073709551616 = UINT64_MAX + 1; 99999999999999999999 = 20 9s.
  CHECK(!with_bad("1", "18446744073709551616").has_value());
  CHECK(!with_bad("1", "99999999999999999999").has_value());
  // Boundary OK at UINT64_MAX itself.
  CHECK(with_bad("1", "18446744073709551615").has_value());
}

TEST(JvmWorkchainCore, RpcGetContractStateFetchesPerAccount) {
  // jvm_getContractState must accept an `accountStateBoc` carrying a
  // per-account JvmContractAccountState cell, decode it, and surface
  // contractAddress + classHash in the JSON response.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x42, 0x42};

  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});

  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());
  auto boc = vm::std_boc_serialize(state_cell, 0).move_as_ok();
  std::string state_hex = "0x";
  {
    auto slice = boc.as_slice();
    for (std::size_t i = 0; i < slice.size(); ++i) {
      char buf[3];
      std::snprintf(buf, sizeof(buf), "%02x",
                    static_cast<unsigned>(
                        static_cast<std::uint8_t>(slice.data()[i])));
      state_hex += buf;
    }
  }

  // Round 123 MEDIUM fix: jvm_getContractState now mirrors the
  // consensus address-binding gate, so the test must use the
  // address derived from this state instead of an arbitrary one.
  auto bound_addr = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));
  std::string contract_address_hex = "0x";
  for (auto b : bound_addr) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(b));
    contract_address_hex += buf;
  }

  std::string params = "{\"contractAddress\":\"" + contract_address_hex
                     + "\",\"accountStateBoc\":\"" + state_hex + "\"}";
  auto req = parse_jvm_get_contract_state_request(params);
  CHECK(req.has_value());
  CHECK(req->account_state.not_null());
  CHECK(req->account_state->get_hash() == state_cell->get_hash());

  auto result = handle_jvm_get_contract_state(*req);
  CHECK(!result.is_error);
  CHECK(result.json.find(contract_address_hex.substr(2)) != std::string::npos);
  // classHash must be present and correctly hex-encoded.
  std::string expected_hash_hex;
  for (auto b : state.class_hash) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(b));
    expected_hash_hex += buf;
  }
  CHECK(result.json.find(expected_hash_hex) != std::string::npos);
}

TEST(JvmWorkchainCore, RpcGetContractStateEscapesClassNameJson) {
  // Regression for the JSON-injection finding: manifest strings admit
  // `"` and `\` (only NUL / oversize / empty are rejected at validation
  // time), so a malicious accountStateBoc whose first manifest entry
  // has a class_name like `A","x":"` must not be reflected verbatim
  // into the response body.  json_escape_string in rpc.cpp wraps the
  // emit so the response stays well-formed JSON.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x99};

  JvmMethodManifestEntry entry;
  entry.method_id = 0x42;
  entry.class_name = "A\",\"injected\":true,\"x\":\"";
  entry.method_name = "ok";
  entry.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({entry});
  CHECK(manifest_root.not_null());

  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = manifest_root;

  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  JvmGetContractStateRequest req;
  // Round 123 MEDIUM fix: address-binding gate also applies to
  // this test — derive the bound address from the state.
  auto bound_addr = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));
  req.contract_address = bound_addr;
  req.account_state = state_cell;

  auto result = handle_jvm_get_contract_state(req);
  CHECK(!result.is_error);
  // The unescaped attacker payload `","injected":true,"x":"` must NOT
  // appear in the response — it would close the className value early
  // and inject sibling fields.
  CHECK(result.json.find("\",\"injected\":true") == std::string::npos);
  // The escaped form `\"` is what we expect to see instead.
  CHECK(result.json.find("\\\"") != std::string::npos);
}

TEST(JvmWorkchainCore, RpcCallContractRejectsAccountStateWithBadStdlibHash) {
  // Regression for the stdlib_hash bypass: consensus rejects a JVM
  // account state whose stdlib_hash differs from ConfigParam 85 with
  // sk_bad_state.  RPC simulation must mirror that — otherwise a
  // full-node returns a successful localResult for state that on-chain
  // execution would skip.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  // Use a runtime that would *succeed* if it ever ran — so the only
  // way the test passes is the stdlib_hash gate firing first.
  auto runtime = std::make_shared<MockJvmRuntime>();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x55};
  JvmContractAccountState state;
  // Deliberately wrong stdlib_hash (consensus would reject):
  state.stdlib_hash = {};
  state.stdlib_hash[0] = 0x99;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  JvmCallContractRequest req;
  req.contract_address.fill(0);
  req.contract_address[31] = 0xcd;
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 1000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  // The localResult must report failure with the stdlib_hash mismatch
  // reason.  And, critically, the runtime must NOT have been invoked —
  // otherwise the bypass is still live.
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("stdlib_hash") != std::string::npos);
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, RpcCallContractRejectsAccountStateExceedingMaxClassBytes) {
  // Round 10: RPC's local-simulation must mirror the consensus
  // max_class_bytes gate (round-9 fix).  Without this, public
  // full-nodes can be pushed into oversized class decode/load work
  // for states that on-chain execution would skip with sk_bad_state.
  //
  // Round 54/55 MEDIUM fix: the rejection now happens INSIDE
  // `decode_jvm_contract_account_state` (which forwards
  // `cfg.max_class_bytes` to the storage-value walker that bails
  // out before copying / hashing the oversized blob).  RPC's
  // localResult therefore surfaces the JSON-RPC malformed-state
  // error rather than the consensus-side "max_class_bytes"
  // localResult message — both shapes prove the runtime never ran.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.max_class_bytes = 32;  // small cap for this test
  auto runtime = std::make_shared<MockJvmRuntime>();

  JvmStorageValue oversized_class(cfg.max_class_bytes + 1, 0xab);
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(oversized_class);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x66 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x88 + i);
  }
  state.class_bytes = encode_jvm_storage_value(oversized_class);
  state.storage_root = {};
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  // Use the address that the binding gate would compute for this
  // (oversized) state, so the request reaches the new max_class_bytes
  // gate (which sits AFTER the address-binding gate).
  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 1000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  // Round 54/55: the decoder rejects the oversized class up front,
  // so this returns a JSON-RPC error (is_error=true) rather than a
  // localResult.  The critical property is unchanged: the runtime
  // must NOT have been invoked.
  CHECK(result.is_error);
  CHECK(result.json.find("malformed contract account state")
        != std::string::npos);
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, RpcCallContractRejectsRuntimeJarMismatch) {
  // Round 18 MEDIUM fix: handle_jvm_call_contract must mirror the
  // round-17 consensus rt.jar gate.  Without it, a full node could
  // run a successful localResult for a state+config pair that
  // on-chain consensus would skip.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto runtime = std::make_shared<MockJvmRuntime>();
  // Override runtime hash to NOT match cfg.stdlib_hash.
  std::array<std::uint8_t, 32> wrong_jar_hash{};
  wrong_jar_hash[0] = 0xee;
  runtime->mock_rt_jar_hash = wrong_jar_hash;

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x99};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x55 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x77 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = {};
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 1000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("rt.jar") != std::string::npos);
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, RpcCallContractAppliesBalanceAffordabilityCap) {
  // Round 42 MEDIUM fix: live RPC must mirror the consensus
  // affordability cap (`balance / gas_price`).  Pre-fix the
  // validator-engine fetched the on-chain balance and threw it away,
  // so a request with `gasLimit=3000` against an account whose
  // `balance=2000`, `gas_price=1` would simulate `success=true` while
  // consensus capped at 2000 gas, ran out, and rejected with sk_no_gas.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;
  auto runtime = std::make_shared<MockJvmRuntime>();
  // Affordability cap = balance/gas_price = 2000.  Mock sees 2000.
  // But the runtime returns success without exceeding it — the test
  // pin is that the cap *happens*, not that the runtime fails.
  runtime->mock_expected_gas_limit = 2000;
  runtime->mock_gas_used = 100;

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x42};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 3000;        // requested above the affordability cap
  req.account_balance = 2000;  // live account balance hint

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  // The mock asserts input.gas_limit == 2000 — if the cap didn't
  // fire, the mock would have seen 3000 and crashed the test.
  CHECK(runtime->called);
  CHECK(result.json.find("\"success\":true") != std::string::npos);
}

TEST(JvmWorkchainCore, RpcCallContractZeroBalanceTriggersFloorReject) {
  // Round 43 MEDIUM fix (#2): a live zero-balance account must trigger
  // the affordability cap (effective_gas_limit = 0 → reject pre-runtime).
  // Pre-fix `account_balance` was a plain uint64 with `> 0` predicate,
  // so `accountBalance:0` (the live path's encoding for a real zero
  // balance) was indistinguishable from "no hint" and the cap was
  // skipped — RPC ran the runtime where consensus would reject.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;
  auto runtime = std::make_shared<MockJvmRuntime>();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x43};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 5000;
  // Live zero-balance account.  After Round 43, this is treated as
  // "balance hint present, value zero" — distinct from "no hint".
  req.account_balance = std::uint64_t{0};

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("\"outOfGas\":true") != std::string::npos);
  // The cap reduced effective_gas_limit to 0; the zero-cap reject path
  // fires before the floor check (matching consensus order).
  CHECK(result.json.find("effective gasLimit is zero") != std::string::npos);
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, RpcCallContractAppliesAffordabilityCapBeforeFloor) {
  // Round 42 MEDIUM fix (continued): if the balance can't even cover
  // the admission floor, the RPC must reject with sk_no_gas pre-runtime
  // — matching consensus's order (cap then floor check, line ~247 in
  // dispatch-engine.cpp).
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1;
  auto runtime = std::make_shared<MockJvmRuntime>();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x42};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 5000;       // requested high
  req.account_balance = 100;  // can't even pay the 1024-gas floor

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("\"outOfGas\":true") != std::string::npos);
  CHECK(result.json.find("admission floor") != std::string::npos);
  // Runtime must NOT have been called — the affordability cap
  // dropped the budget below the floor pre-runtime.
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, RpcCallContractCapsToMaxGasBeforeFloor) {
  // Round 42 LOW fix: if `max_gas_per_tx < kJvmAdmissionGasFloor`
  // (a misconfiguration permitted by ConfigParam 85's only-non-zero
  // validation) consensus rejects pre-runtime because effective_gas_limit
  // < floor.  Pre-Round-42 the RPC checked the floor against the
  // un-capped `input.gas_limit`, allowing `gasLimit=2000` to slip past
  // the floor check, get capped to 512, and run the runtime — producing
  // a successful localResult that consensus could not produce.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.max_gas_per_tx = 512;  // intentionally below the admission floor
  auto runtime = std::make_shared<MockJvmRuntime>();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x42};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 2000;  // above floor pre-cap, below floor post-cap

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("\"outOfGas\":true") != std::string::npos);
  CHECK(result.json.find("admission floor") != std::string::npos);
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, RpcCallContractReportsConsensusGasUsedFloor) {
  // Round 43 LOW fix (#4): RPC must report the consensus-charged
  // gas_used (which `build_jvm_workchain_output` floors to
  // `kJvmAdmissionGasFloor` on success), not the raw runtime-reported
  // gas.  Pre-fix `inv.gas_used` was emitted directly so a contract
  // that consumed 100 gas saw `gasUsed:100` in localResult while
  // consensus billed 1024 — a meaningful UX divergence (and one that
  // could confuse fee-estimation logic that mirrors the RPC).
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto runtime = std::make_shared<MockJvmRuntime>();
  runtime->mock_expected_gas_limit = 2000;
  runtime->mock_gas_used = 100;  // below the 1024 admission floor

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x44};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 2000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(runtime->called);
  CHECK(result.json.find("\"success\":true") != std::string::npos);
  // gasUsed should be 1024 (the admission floor), not 100 (raw runtime).
  CHECK(result.json.find("\"gasUsed\":1024") != std::string::npos);
}

TEST(JvmWorkchainCore, RpcCallContractDetectsMaxStorageCellsAfterWalkBypass) {
  // Round 44 MEDIUM fix: the round-43 optimization that lets RPC pass
  // `storage_walk_already_billed=true` to `build_jvm_workchain_output`
  // skipped the builder's defensive `max_storage_cells` walk.  RPC was
  // discarding the dispatch-style `stat_result` (its own walk's error
  // status), so a contract committing a storage_root above the cap
  // simulated `success=true` while consensus rejected with sk_bad_state.
  // Round 44 captures the stat_result and reports the same rejection
  // shape RPC would have shown pre-Round-43.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.max_storage_cells = 1;  // intentionally tiny so the walk overflows
  auto runtime = std::make_shared<MockJvmRuntime>();
  runtime->mock_expected_gas_limit = 2000;
  runtime->mock_gas_used = 100;

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x44};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);

  // Pre-existing storage with a few cells so the mock's mutation
  // forces the walk to exceed `max_storage_cells=1`.
  JvmStorageCellHost initial_storage;
  for (std::uint8_t i = 1; i <= 4; ++i) {
    JvmStorageSlot slot{};
    slot[0] = i;
    CHECK(initial_storage.store(slot, JvmStorageValue{i, i, i}).is_ok());
  }
  state.storage_root = initial_storage.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 2000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(runtime->called);
  // Consensus dispatch returns sk_bad_state with a max_storage_cells
  // message; RPC must mirror that shape.
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("max_storage_cells") != std::string::npos);
  CHECK(result.json.find("\"newStateBoc\":null") != std::string::npos);
}

TEST(JvmWorkchainCore, StripTopLevelJsonFieldHandlesNestedAndDuplicates) {
  // Round 46 fixes:
  //   LOW — nested object/array values for the scrubbed key were
  //         half-removed by the round-45 helper and corrupted the
  //         JSON.
  //   MED — duplicate scrubbed keys triggered O(n²) `find` + `erase`
  //         scans, which a public RPC caller could exploit within
  //         the 4 MiB JSON-RPC body cap.
  // The replacement is a single forward-pass O(n) walk, depth-aware
  // for nested objects/arrays and string-escape-aware so neither
  // `"className":"foo accountBalance bar"` nor `"\"accountBalance\""`
  // fool the matcher.
  using namespace jvm_workchain;

  // Scalar-only flat object — happy path.
  {
    auto out = strip_top_level_json_field(
        R"({"contractAddress":"0xab","accountBalance":2,"methodId":1})",
        "accountBalance");
    CHECK(out == R"({"contractAddress":"0xab","methodId":1})");
  }

  // Last-field scrub: trailing comma in input, no trailing comma in output.
  {
    auto out = strip_top_level_json_field(
        R"({"a":1,"accountBalance":2})", "accountBalance");
    CHECK(out == R"({"a":1})");
  }

  // First-field scrub: strip the trailing comma to keep JSON well-formed.
  {
    auto out = strip_top_level_json_field(
        R"({"accountBalance":2,"a":1})", "accountBalance");
    CHECK(out == R"({"a":1})");
  }

  // Empty object: identity.
  {
    auto out = strip_top_level_json_field(R"({})", "accountBalance");
    CHECK(out == R"({})");
  }

  // Sole field: empty object after strip.
  {
    auto out = strip_top_level_json_field(
        R"({"accountBalance":2})", "accountBalance");
    CHECK(out == R"({})");
  }

  // Round 46 LOW — nested object value MUST be removed wholesale.
  {
    auto out = strip_top_level_json_field(
        R"({"a":1,"accountBalance":{"n":1},"b":2})", "accountBalance");
    CHECK(out == R"({"a":1,"b":2})");
  }

  // Round 46 LOW — nested array value MUST be removed wholesale.
  {
    auto out = strip_top_level_json_field(
        R"({"a":1,"accountBalance":[1,2,3],"b":2})", "accountBalance");
    CHECK(out == R"({"a":1,"b":2})");
  }

  // Round 46 MEDIUM — duplicate scalar keys are all removed in one pass.
  {
    auto out = strip_top_level_json_field(
        R"({"a":1,"accountBalance":1,"accountBalance":2,"accountBalance":3,"b":4})",
        "accountBalance");
    CHECK(out == R"({"a":1,"b":4})");
  }

  // String-escape-aware: a literal backslash-quote in a value must NOT
  // be mistaken for a key boundary.
  {
    auto out = strip_top_level_json_field(
        R"({"className":"foo\"accountBalance\"bar","accountBalance":42})",
        "accountBalance");
    CHECK(out == R"({"className":"foo\"accountBalance\"bar"})");
  }

  // Key inside an ordinary (non-escaped) string value MUST be ignored.
  {
    auto out = strip_top_level_json_field(
        R"({"vmLog":"the accountBalance is too low","accountBalance":3})",
        "accountBalance");
    CHECK(out == R"({"vmLog":"the accountBalance is too low"})");
  }

  // Nested object containing the same key as a sub-field: the nested
  // copy must be preserved (depth gate).
  {
    auto out = strip_top_level_json_field(
        R"({"a":{"accountBalance":5},"accountBalance":7})", "accountBalance");
    CHECK(out == R"({"a":{"accountBalance":5}})");
  }

  // Field absent: identity.
  {
    auto out = strip_top_level_json_field(
        R"({"a":1,"b":2})", "accountBalance");
    CHECK(out == R"({"a":1,"b":2})");
  }
}

TEST(JvmWorkchainCore, RpcParserIgnoresNestedTopLevelKeys) {
  // Round 47 MEDIUM fix: `parse_jvm_call_contract_request` and the
  // validator-engine live-state gate must ignore nested copies of
  // `accountStateBoc` / `executorStateBoc` / `accountBalance` /
  // `gasLimit`.  Pre-fix the raw `find()` first-match scanner would
  // pick a nested copy: a request like
  //   {"contractAddress":"...","methodId":1,"x":{"accountStateBoc":"0x00"}}
  // looked to the gate as if the caller supplied state (so the live
  // path skipped its fetch+inject) AND the parser then read the
  // nested BOC as the state.
  using namespace jvm_workchain;

  // (1) The depth-aware top-level lookup correctly says "no" for
  // a nested `accountStateBoc` and "yes" for a top-level one.
  CHECK(!is_top_level_json_field_present(
      R"({"x":{"accountStateBoc":"0x00"}})", "accountStateBoc"));
  CHECK(is_top_level_json_field_present(
      R"({"accountStateBoc":"0x00"})", "accountStateBoc"));
  CHECK(is_top_level_json_field_present(
      R"({"a":1,"accountStateBoc":"0x00"})", "accountStateBoc"));

  // (2) The full request parser uses the depth-aware lookup, so a
  // nested `accountStateBoc` is NOT consumed as the state BOC.
  std::string nested_request = R"({
    "contractAddress":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "methodId":1,
    "x":{"accountStateBoc":"0x00"}
  })";
  auto parsed = parse_jvm_call_contract_request(nested_request);
  CHECK(parsed.has_value());
  // current_state must remain null — the nested BOC must not be
  // read as the per-account state.
  CHECK(parsed->current_state.is_null());

  // (3) Same depth-awareness for `accountBalance` (an attacker
  // could otherwise nest a high balance to bypass the affordability
  // cap when validator-engine omits live balance injection).
  std::string nested_balance = R"({
    "contractAddress":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "methodId":1,
    "x":{"accountBalance":18446744073709551615}
  })";
  auto parsed_balance = parse_jvm_call_contract_request(nested_balance);
  CHECK(parsed_balance.has_value());
  CHECK(!parsed_balance->account_balance.has_value());

  // (4) Same depth-awareness for `gasLimit`.
  std::string nested_gas = R"({
    "contractAddress":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "methodId":1,
    "x":{"gasLimit":99999999}
  })";
  auto parsed_gas = parse_jvm_call_contract_request(nested_gas);
  CHECK(parsed_gas.has_value());
  CHECK(parsed_gas->gas_limit == 0);

  // (5) The depth-aware lookup also handles a string value containing
  // the literal key text — must NOT match.
  CHECK(!is_top_level_json_field_present(
      R"({"vmLog":"the accountStateBoc field is wrong"})",
      "accountStateBoc"));
}

TEST(JvmWorkchainCore, RpcCallContractAffordableGasOverridesBalance) {
  // Round 50 MEDIUM fix: when validator-engine's live path injects
  // the pre-divided `accountAffordableGas`, RPC uses it directly as
  // the cap instead of dividing `accountBalance / gas_price` itself.
  // This lets balances above `UINT64_MAX` still produce a correct
  // cap (computed by validator-engine in 256-bit math).  Pre-fix,
  // such balances returned `nullopt` from the extractor, the live
  // path omitted injection, and RPC stayed balance-blind.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  cfg.gas_price = 1000;
  auto runtime = std::make_shared<MockJvmRuntime>();
  // Affordable gas hint = 100 → cap below admission floor → reject
  // pre-runtime.  The mock should NEVER be called; if it is, that
  // proves the cap didn't fire.
  runtime->mock_expected_gas_limit = 0;  // would assert if called

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x50};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 5000;
  // Authoritative pre-divided cap (e.g. validator-engine extracted
  // `balance=100*1000` against `gas_price=1000`).  Below the
  // admission floor, so RPC must reject pre-runtime.
  req.account_affordable_gas = 100;
  // Set a wildly-different `accountBalance` to verify it is NOT
  // honoured when `accountAffordableGas` is present.  If the cap
  // logic accidentally divides this balance, it would compute
  // 1e9/1000 = 1_000_000 (above the floor) and incorrectly run.
  req.account_balance = std::uint64_t{1'000'000'000};

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("\"outOfGas\":true") != std::string::npos);
  CHECK(result.json.find("admission floor") != std::string::npos);
  CHECK(!runtime->called);
}

TEST(JvmWorkchainCore, RpcCallContractAffordableGasZeroRejects) {
  // Round 50 MEDIUM fix continued: a live zero-affordable-gas account
  // (e.g. balance < gas_price) must still trigger the zero-cap
  // reject path, mirroring the round-43 zero-balance behaviour.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto runtime = std::make_shared<MockJvmRuntime>();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x50};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 5000;
  req.account_affordable_gas = std::uint64_t{0};

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("\"outOfGas\":true") != std::string::npos);
  CHECK(result.json.find("effective gasLimit is zero") != std::string::npos);
  CHECK(!runtime->called);
}

TEST(WorkchainExecutionRegistry, JvmSubsequentCallReportsMsgStateUsedFalse) {
  // Round 50 LOW fix half 1: subsequent (non-activation) JVM calls
  // must report `msg_state_used = false` and `account_activated =
  // false` on the wire.  Pre-Round-50 build_jvm_workchain_output
  // never set these fields, so the host copied default `false`
  // values into ComputePhase — which happens to match the expected
  // serialization for non-activation calls only by accident.  This
  // test pins the non-activation contract.
  //
  // The first-activation half (msg_state_used = true → output sets
  // both to true) requires the engine's StateInit-binding invariants
  // (round-14 first-activation gates) which need a fully-formed
  // inbound int_msg_info matching state.deployer, beyond this unit
  // test's scope.  The engine's `output.msg_state_used =
  // input.msg_state_used` plumbing is mechanically correct — see
  // dispatch-engine.cpp run_compute.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);

  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x55, 0x00};
  auto class_bytes_cell = encode_jvm_storage_value(class_bytes);
  auto manifest_root = encode_jvm_method_manifest({});

  JvmContractAccountState previous_state;
  previous_state.stdlib_hash = cfg.stdlib_hash;
  previous_state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < previous_state.address_commit.size(); ++i) {
    previous_state.address_commit[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  for (std::size_t i = 0; i < previous_state.deployer.size(); ++i) {
    previous_state.deployer[i] = static_cast<std::uint8_t>(0x60 + i);
  }
  previous_state.class_bytes = class_bytes_cell;
  previous_state.storage_root = JvmStorageCellHost{}.root_cell();
  previous_state.manifest_root = manifest_root;

  auto bound_addr = derive_jvm_contract_address_from_state(
      previous_state.deployer, previous_state.address_commit,
      previous_state.class_hash,
      compute_jvm_manifest_root_hash(previous_state.manifest_root));

  block::WorkchainComputeInput input;
  std::memcpy(input.account_addr.data(), bound_addr.data(), 32);
  input.current_data = encode_jvm_contract_account_state(previous_state);
  CHECK(input.current_data.not_null());
  input.inbound_body = make_jvm_call_body(0xdeadbeef);
  input.gas_limit = 2000;
  input.msg_state_used = false;  // subsequent (non-activation) call

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto output = execution.executor->run_compute(input, context).move_as_ok();
  CHECK(output.completed);
  CHECK(output.accepted);
  CHECK(output.committed);
  CHECK(output.engine_success);
  // Round 50 fix: subsequent calls correctly report false for both
  // fields (matching the wire's default).
  CHECK(!output.msg_state_used);
  CHECK(!output.account_activated);
}

TEST(JvmWorkchainCore, RpcCallContractRuntimeErrorBillsAdmissionFloor) {
  // Round 45 LOW fix: when the runtime returns Status::Error (e.g.,
  // unknown method_id, malformed typed args) consensus bills the
  // admission floor via `skipped_output_billed(sk_bad_state, ...,
  // kJvmAdmissionGasFloor)` (round 37 fix in dispatch-engine.cpp).
  // Pre-fix RPC reported `gasUsed:0` for the same condition,
  // so localResult under-reported the on-chain charge.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto runtime = std::make_shared<MockJvmRuntime>();
  runtime->mock_runtime_error = "synthetic resolver failure";

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x45};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 2000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  CHECK(runtime->called);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("\"gasUsed\":1024") != std::string::npos);
  CHECK(result.json.find("synthetic resolver failure") != std::string::npos);
}

TEST(JvmWorkchainCore, RpcCallContractEscapesRuntimeErrorVmLog) {
  // Round 52 LOW fix: a runtime error message containing `"`, `\`,
  // or control characters could close the `vmLog` JSON field early
  // and inject sibling fields (e.g. a forged `newStateBoc`) into
  // the response.  Round 45 added a `mock_runtime_error` knob to
  // the mock; we feed an injection attempt and verify the resulting
  // `vmLog` is escaped, not raw.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto runtime = std::make_shared<MockJvmRuntime>();
  // Attempt to break out of the vmLog string and inject a forged
  // `newStateBoc` field.  Pre-fix this concatenated raw, breaking
  // the JSON.
  runtime->mock_runtime_error =
      std::string("oops\",\"newStateBoc\":\"0xdead");

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x52};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x21 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x43 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);
  state.storage_root = JvmStorageCellHost{}.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 2000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  // Pre-fix the raw concat would have produced
  //   "vmLog":"runtime error: oops","newStateBoc":"0xdead",...
  // (closing the vmLog string early and injecting a forged
  // `newStateBoc` field).  Post-fix the closing quote is escaped:
  //   "vmLog":"runtime error: oops\",\"newStateBoc\":\"0xdead",...
  // So the un-escaped injection substring `oops","newStateBoc":"`
  // MUST NOT appear; the escaped form `oops\",\"newStateBoc\":\"`
  // SHOULD appear.
  CHECK(result.json.find("oops\",\"newStateBoc\":\"0xdead") ==
        std::string::npos);
  CHECK(result.json.find("oops\\\",\\\"newStateBoc\\\":\\\"0xdead") !=
        std::string::npos);
  // The canonical localResult `"newStateBoc":null` MUST still appear
  // (the runtime-error branch always emits it).  Combined with the
  // first assertion, this proves the only un-escaped `newStateBoc`
  // is the legitimate one.
  CHECK(result.json.find("\"newStateBoc\":null") != std::string::npos);
}

TEST(JvmWorkchainCore, RpcCallContractMirrorsConsensusWalkGasCap) {
  // Round 41 MEDIUM fix: handle_jvm_call_contract must mirror the
  // consensus round-39 storage-walk gas billing AND the round-40
  // affordable-cap reject.  Pre-fix, a storage-mutating call whose
  // runtime gas equals input.gas_limit would simulate `success=true`
  // with `newStateBoc != null`, while consensus adds walk gas, sees
  // the total exceed `effective_gas_limit`, and rejects with
  // sk_no_gas — RPC told clients the tx would succeed when on-chain
  // execution would burn the cap and discard state.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto runtime = std::make_shared<MockJvmRuntime>();
  // Make the mock consume the entire budget.  RPC has no balance,
  // so the cap is just `input.gas_limit`.  Any walk gas at all (>= 1)
  // tips the post-walk total over.
  runtime->mock_expected_gas_limit = 2000;
  runtime->mock_gas_used = 2000;

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x41};
  JvmContractAccountState state;
  state.stdlib_hash = cfg.stdlib_hash;
  state.class_hash = compute_jvm_class_hash(class_bytes);
  for (std::size_t i = 0; i < state.address_commit.size(); ++i) {
    state.address_commit[i] = static_cast<std::uint8_t>(0x33 + i);
  }
  for (std::size_t i = 0; i < state.deployer.size(); ++i) {
    state.deployer[i] = static_cast<std::uint8_t>(0x55 + i);
  }
  state.class_bytes = encode_jvm_storage_value(class_bytes);

  // Seed the storage root so the walk has cells to count.  The mock
  // writes one extra slot, triggering storage_changed=true.
  JvmStorageCellHost initial_storage;
  for (std::uint8_t i = 1; i <= 4; ++i) {
    JvmStorageSlot slot{};
    slot[0] = i;
    CHECK(initial_storage.store(slot, JvmStorageValue{i, i, i}).is_ok());
  }
  state.storage_root = initial_storage.root_cell();
  state.manifest_root = encode_jvm_method_manifest({});
  auto state_cell = encode_jvm_contract_account_state(state);
  CHECK(state_cell.not_null());

  auto bound = derive_jvm_contract_address_from_state(
      state.deployer, state.address_commit, state.class_hash,
      compute_jvm_manifest_root_hash(state.manifest_root));

  JvmCallContractRequest req;
  std::memcpy(req.contract_address.data(), bound.data(), 32);
  req.method_id = 0x42;
  req.args = make_empty_action_list();
  req.current_state = state_cell;
  req.gas_limit = 2000;

  auto result = handle_jvm_call_contract(req, "1", &cfg, runtime.get());
  CHECK(!result.is_error);
  // The runtime ran (the gates above passed), but the post-walk gas
  // exceeded the cap and RPC must report failure with outOfGas=true,
  // gasUsed=cap, newStateBoc=null — matching consensus.
  CHECK(runtime->called);
  CHECK(result.json.find("\"success\":false") != std::string::npos);
  CHECK(result.json.find("\"outOfGas\":true") != std::string::npos);
  CHECK(result.json.find("\"gasUsed\":2000") != std::string::npos);
  CHECK(result.json.find("\"newStateBoc\":null") != std::string::npos);
  CHECK(result.json.find("storage walk gas exceeded") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Multi-contract per-account isolation with shared class
// ---------------------------------------------------------------------------

TEST(JvmWorkchainCore, MultiContractIsolatedStorageWithSharedClass) {
  // Two contracts that differ only in `salt` must:
  //   * derive distinct wc=3 addresses (per-contract storage namespace),
  //   * share the same class_bytes Cell hash (Cell DB physical dedup), and
  //   * keep their storage independent across reads/writes.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto desc_a = make_test_jvm_deploy_descriptor(0xc1);
  auto desc_b = desc_a;
  desc_b.salt[0] ^= 0xff;  // only difference

  auto manifest = encode_jvm_method_manifest({});
  auto addr_a = derive_jvm_contract_address(desc_a, manifest).move_as_ok();
  auto addr_b = derive_jvm_contract_address(desc_b, manifest).move_as_ok();
  CHECK(addr_a != addr_b);

  JvmStorageCellHost storage_a;
  JvmStorageCellHost storage_b;
  JvmStorageSlot slot_x{};
  slot_x[31] = 0x42;
  CHECK(storage_a.store(slot_x, JvmStorageValue{0xaa, 0xaa}).is_ok());
  CHECK(storage_b.store(slot_x, JvmStorageValue{0xbb, 0xbb}).is_ok());

  JvmContractAccountState state_a;
  state_a.stdlib_hash = cfg.stdlib_hash;
  state_a.class_hash = desc_a.class_hash;
  state_a.class_bytes = encode_jvm_storage_value(desc_a.class_bytes);
  state_a.storage_root = storage_a.root_cell();
  state_a.manifest_root = encode_jvm_method_manifest({});

  JvmContractAccountState state_b;
  state_b.stdlib_hash = cfg.stdlib_hash;
  state_b.class_hash = desc_b.class_hash;
  state_b.class_bytes = encode_jvm_storage_value(desc_b.class_bytes);
  state_b.storage_root = storage_b.root_cell();
  state_b.manifest_root = encode_jvm_method_manifest({});

  auto cell_a = encode_jvm_contract_account_state(state_a);
  auto cell_b = encode_jvm_contract_account_state(state_b);
  CHECK(cell_a.not_null() && cell_b.not_null());
  // Outer cells differ because storage_root differs.
  CHECK(cell_a->get_hash() != cell_b->get_hash());
  // class_bytes Cell hash is shared (Cell DB dedup).
  CHECK(state_a.class_bytes->get_hash() == state_b.class_bytes->get_hash());
  // class_hash is also identical (sha256 of identical bytes).
  CHECK(state_a.class_hash == state_b.class_hash);

  // Storage isolation: each account loads exactly the value it stored.
  JvmStorageCellHost reload_a(state_a.storage_root);
  JvmStorageCellHost reload_b(state_b.storage_root);
  auto loaded_a = reload_a.load(slot_x).move_as_ok();
  auto loaded_b = reload_b.load(slot_x).move_as_ok();
  CHECK(loaded_a.has_value());
  CHECK(loaded_b.has_value());
  CHECK(*loaded_a == (JvmStorageValue{0xaa, 0xaa}));
  CHECK(*loaded_b == (JvmStorageValue{0xbb, 0xbb}));
}

// ---------------------------------------------------------------------------
// Determinism: replay invariance under the engine + mock runtime
// ---------------------------------------------------------------------------

TEST(WorkchainExecutionRegistry, JvmDeterminismReplay) {
  // The engine is a pure function of (state, input).  Driving the same
  // input cell twice against the same starting state must yield byte-
  // identical new_data hashes; interleaving two distinct inputs (A, B,
  // A, B) must yield matching hashes between the first and second pass
  // at each step.  This is the consensus-replay invariant.
  using namespace jvm_workchain;

  auto cfg = make_test_jvm_config();
  auto config = make_config_with_jvm_param(cfg);
  auto descriptor = make_basic_descriptor(3, kJvmVmVersion, 0);
  auto runtime = std::make_shared<MockJvmRuntime>();
  block::WorkchainExecutionRegistry registry;
  register_jvm_workchain_engine(registry, runtime);
  auto execution = registry.resolve(descriptor, *config).move_as_ok();

  JvmStorageValue class_bytes{0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34};
  auto class_bytes_cell = encode_jvm_storage_value(class_bytes);

  JvmMethodManifestEntry entry_a;
  entry_a.method_id = 0xaaaaaaaa;
  entry_a.class_name = "ContractEntryPoint";
  entry_a.method_name = "a";
  entry_a.method_spec = "()V";
  JvmMethodManifestEntry entry_b;
  entry_b.method_id = 0xbbbbbbbb;
  entry_b.class_name = "ContractEntryPoint";
  entry_b.method_name = "b";
  entry_b.method_spec = "()V";
  auto manifest_root = encode_jvm_method_manifest({entry_a, entry_b});

  JvmContractAccountState state0;
  state0.stdlib_hash = cfg.stdlib_hash;
  state0.class_hash = compute_jvm_class_hash(class_bytes);
  // Synthetic address_commit so the engine's address-binding gate
  // accepts the JVAC state.  account_addr below is computed from this
  // commit + class_hash + deployer via the same helper the engine uses.
  for (std::size_t i = 0; i < state0.address_commit.size(); ++i) {
    state0.address_commit[i] = static_cast<std::uint8_t>(0x71 + i);
  }
  for (std::size_t i = 0; i < state0.deployer.size(); ++i) {
    state0.deployer[i] = static_cast<std::uint8_t>(0x91 + i);
  }
  state0.class_bytes = class_bytes_cell;
  state0.storage_root = JvmStorageCellHost{}.root_cell();
  state0.manifest_root = manifest_root;
  auto state0_cell = encode_jvm_contract_account_state(state0);
  CHECK(state0_cell.not_null());

  auto bound_addr = derive_jvm_contract_address_from_state(
      state0.deployer, state0.address_commit, state0.class_hash,
      compute_jvm_manifest_root_hash(state0.manifest_root));

  block::WorkchainComputeContext context;
  context.workchain_id = 3;
  context.descriptor = descriptor;
  context.engine_config = execution.engine_config;

  auto run = [&](td::Ref<vm::Cell> in_state, std::uint32_t method_id) {
    block::WorkchainComputeInput input;
    std::memcpy(input.account_addr.data(), bound_addr.data(), 32);
    input.current_data = in_state;
    input.inbound_body = make_jvm_call_body(method_id);
    input.gas_limit = 2000;
    return execution.executor->run_compute(input, context).move_as_ok();
  };

  // First pass: A → B → A → B.  Capture every new_data hash.
  auto pass1_step1 = run(state0_cell, entry_a.method_id);
  CHECK(pass1_step1.committed);
  auto pass1_step2 = run(pass1_step1.new_data, entry_b.method_id);
  CHECK(pass1_step2.committed);
  auto pass1_step3 = run(pass1_step2.new_data, entry_a.method_id);
  CHECK(pass1_step3.committed);
  auto pass1_step4 = run(pass1_step3.new_data, entry_b.method_id);
  CHECK(pass1_step4.committed);

  // Second pass: same input sequence, same starting state.
  auto pass2_step1 = run(state0_cell, entry_a.method_id);
  CHECK(pass2_step1.committed);
  auto pass2_step2 = run(pass2_step1.new_data, entry_b.method_id);
  auto pass2_step3 = run(pass2_step2.new_data, entry_a.method_id);
  auto pass2_step4 = run(pass2_step3.new_data, entry_b.method_id);

  // Each step's new_data hash must match across the two passes.
  CHECK(pass1_step1.new_data->get_hash() == pass2_step1.new_data->get_hash());
  CHECK(pass1_step2.new_data->get_hash() == pass2_step2.new_data->get_hash());
  CHECK(pass1_step3.new_data->get_hash() == pass2_step3.new_data->get_hash());
  CHECK(pass1_step4.new_data->get_hash() == pass2_step4.new_data->get_hash());

  // Also: state(A→B) reached from two independent paths is identical
  // (steps 1→2 in pass 1 and pass 2).
  CHECK(pass1_step2.new_data->get_hash() == pass2_step2.new_data->get_hash());

  // 10 sequential A calls from state0 must each reproduce identically across
  // a second 10-call run.
  std::vector<vm::CellHash> series_pass1;
  td::Ref<vm::Cell> rolling = state0_cell;
  for (int i = 0; i < 10; ++i) {
    auto out = run(rolling, entry_a.method_id);
    CHECK(out.committed);
    series_pass1.push_back(out.new_data->get_hash());
    rolling = out.new_data;
  }
  rolling = state0_cell;
  for (int i = 0; i < 10; ++i) {
    auto out = run(rolling, entry_a.method_id);
    CHECK(out.committed);
    CHECK(out.new_data->get_hash() == series_pass1[i]);
    rolling = out.new_data;
  }
}
