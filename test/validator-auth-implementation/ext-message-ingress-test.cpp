// Whether the path that admits an external message to the pool can execute one
// that needs the registry authority.
//
// Mempool admission is not a formality here: it runs the destination contract.
// The configuration contract applies a registry update and only then accepts
// the message, so a run offered no authority throws the privileged
// instruction's refusal inside the gas credit and the message is rejected at
// the door. Every valid registry update would be dropped before any collator
// saw one, and the chain would look exactly like a chain on which nobody
// submits updates -- which is why no admission, collation or validation case
// could notice it.
//
// This exercises the seam that carries an authority through that path. The
// contract stands in for the configuration contract: one privileged instruction
// and an accept, so the only question the run asks is whether an authority
// arrived.
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "validator/impl/ext-message-admission.h"
#include "validator/impl/external-message.hpp"
#include "vm/authops.h"
#include "vm/vm.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include "native-history-fixture.h"

namespace {
unsigned passed = 0, failed = 0;

void expect(bool condition, const std::string& name) {
  if (condition) {
    ++passed;
    std::cout << "CASE_PASS " << name << '\n';
  } else {
    ++failed;
    std::cout << "CASE_FAIL " << name << '\n';
  }
}

// Counts what reached it, so a run that succeeded for some other reason is
// distinguishable from one that actually used the authority.
struct Host final : vm::ValidatorAuthHost {
  unsigned checkpoints = 0;
  td::Ref<vm::Cell> checkpoint(const Charge& charge) override {
    ++checkpoints;
    charge.gas(1);
    return vm::CellBuilder().finalize();
  }
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) override {
    return {};
  }
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) override {
    return {};
  }
};

constexpr unsigned accept_message_opcode = 0xf800;

// A contract that only accepts, to show the fixture can execute a message at
// all. Without it, a failure in the privileged case is ambiguous between the
// seam and the scaffolding around it.
td::Ref<vm::Cell> accepting_code() {
  return vm::CellBuilder().store_long(accept_message_opcode, 16).finalize();
}

td::Ref<vm::Cell> privileged_code() {
  vm::CellBuilder code;
  code.store_long(vm::validator_auth_state_opcode, 16).store_long(accept_message_opcode, 16);
  return code.finalize();
}

// An active masterchain account holding that code, in the shape the account
// unpacker expects.
td::Ref<vm::CellSlice> account_entry(const td::Bits256& address, td::Ref<vm::Cell> code) {
  vm::CellBuilder account;
  account.store_long(1, 1)
      .store_long(0x9f, 8)
      .store_long(7, 3)
      .store_bytes(td::Slice(address.data(), 32))
      .store_zeroes(3 + 3 + 3 + 32 + 1)
      .store_long(1, 64)
      .store_long(4, 4)
      .store_long(1000000000, 32)
      .store_long(0, 1)
      .store_long(1, 1)
      .store_long(0, 1)
      .store_long(1, 1)
      .store_long(0, 1)
      .store_long(1, 1)
      .store_long(1, 1)
      .store_ref(std::move(code))
      .store_long(1, 1)
      .store_ref(vm::CellBuilder().finalize())
      .store_long(0, 1);
  return vm::load_cell_slice_ref(
      vm::CellBuilder().store_ref(account.finalize()).store_zeroes(256 + 64).finalize());
}

td::Ref<vm::Cell> external_message(const td::Bits256& address) {
  vm::CellBuilder message;
  message.store_long(2, 2).store_long(0, 2).store_long(2, 2).store_long(0, 1).store_long(tos::masterchainId, 8);
  message.store_bytes(td::Slice(address.data(), 32));
  message.store_long(0, 4).store_long(0, 1).store_long(0, 1);
  return message.finalize();
}

// A masterchain configuration complete enough to execute a transaction.
//
// Built from the shared fixture and then given the parameters an execution
// configuration is assembled from, rather than assembled field by field here.
// A hand-filled ComputePhaseConfig leaves the pointers that fetching fills --
// the workchain list, the transition config -- null, and the virtual machine
// dies before reaching any instruction. That failure looks nothing like the
// question this file asks.
constexpr std::uint32_t state_coordinate = 1;

td::Ref<vm::Cell> activated_state() {
  // The coordinate the block id below names. A configuration refuses a block id
  // whose sequence number is not the one the state itself carries.
  auto root = auth_fixture::masterchain(auth_fixture::state(1), state_coordinate);
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::gen::ConfigParams::Record params;
  if (!tlb::unpack_cell(root, state) || !tlb::unpack_cell(state.custom->prefetch_ref(), extra) ||
      !tlb::csr_unpack(extra.config, params)) {
    throw std::runtime_error("fixture-state");
  }
  vm::Dictionary config(params.config, 32);
  auto put = [&](int index, td::Ref<vm::Cell> value) {
    if (!config.set_ref(td::BitArray<32>{index}, std::move(value))) {
      throw std::runtime_error("fixture-config-entry");
    }
  };

  // Storage prices, keyed by the time they take effect.
  vm::CellBuilder prices;
  prices.store_long(0xcc, 8).store_long(0, 32).store_long(1, 64).store_long(1, 64).store_long(1, 64).store_long(1, 64);
  // Stored inline: a storage-prices entry is the value itself, not a reference
  // to it, and a dictionary of references parses as an invalid one.
  vm::Dictionary storage(32);
  if (!storage.set_builder(td::BitArray<32>{0LL}, prices)) {
    throw std::runtime_error("fixture-storage-prices");
  }
  put(18, storage.get_root_cell());

  // Gas prices. Generous limits, because what is measured here is reachability,
  // not cost.
  auto gas = [] {
    vm::CellBuilder b;
    b.store_long(0xde, 8)
        .store_long(1000, 64)
        .store_long(1000000, 64)
        .store_long(1000000, 64)
        // The credit a transaction is serialized with is a narrow field: a
        // larger value here fails serialization rather than execution, which
        // reads as the contract being at fault.
        .store_long(10000, 64)
        .store_long(10000000, 64)
        .store_long(0, 64)
        .store_long(0, 64);
    return b.finalize();
  };
  put(20, gas());
  put(21, gas());

  auto forward = [] {
    vm::CellBuilder b;
    b.store_long(0xea, 8)
        .store_long(0, 64)
        .store_long(0, 64)
        .store_long(0, 64)
        .store_long(0, 32)
        .store_long(0, 16)
        .store_long(0, 16);
    return b.finalize();
  };
  put(24, forward());
  put(25, forward());

  params.config = config.get_root_cell();
  vm::CellBuilder packed;
  if (!tlb::pack(packed, params)) {
    throw std::runtime_error("fixture-config-pack");
  }
  extra.config = vm::load_cell_slice_ref(packed.finalize());
  td::Ref<vm::Cell> custom;
  if (!tlb::pack_cell(custom, extra)) {
    throw std::runtime_error("fixture-extra-pack");
  }
  state.custom = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(custom).finalize());
  td::Ref<vm::Cell> configured;
  if (!tlb::pack_cell(configured, state)) {
    throw std::runtime_error("fixture-state-pack");
  }

  // A masterchain state is refused unless its own history index names the zero
  // state. Composed from the fixture that builds that index rather than
  // assembled here, so this file holds no second encoder for it.
  auto zero = history_state(configured, 0, {});
  Entry genesis{0, 0, hash(zero), file_hash(boc(zero))};
  auto indexed = history_state(configured, state_coordinate, {genesis});

  // And a key state, so the configuration can answer which the last key block
  // was. Assembling an execution configuration reads that; nothing here depends
  // on which block it names.
  block::gen::ShardStateUnsplit::Record shard;
  block::gen::McStateExtra::Record key;
  if (!tlb::unpack_cell(indexed, shard) || !tlb::unpack_cell(shard.custom->prefetch_ref(), key)) {
    throw std::runtime_error("fixture-key-state");
  }
  key.r1.after_key_block = true;
  td::Ref<vm::Cell> keyed;
  if (!tlb::pack_cell(keyed, key)) {
    throw std::runtime_error("fixture-key-state-pack");
  }
  shard.custom = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(keyed).finalize());
  td::Ref<vm::Cell> out;
  if (!tlb::pack_cell(out, shard)) {
    throw std::runtime_error("fixture-key-state-repack");
  }
  return out;
}

std::unique_ptr<tos::validator::ExtMessageQ::ExecutionConfig> activated(const block::ConfigInfo& config) {
  auto built = tos::validator::ExtMessageQ::ExecutionConfig::create(config, tos::masterchainId, 1000, false);
  if (built.is_error()) {
    throw std::runtime_error("fixture-execution-config: " + built.error().message().str());
  }
  return built.move_as_ok();
}
}  // namespace

int main() {
  try {
    // Registers the opcode table. A node does this at start-up; without it the
    // virtual machine has no codepage and dies before any instruction, which
    // looks like a failure of whatever was being tested.
    vm::init_vm().ensure();

    td::Bits256 address;
    address.set_zero();
    address.bits().store_uint(46, 32);

    auto root = activated_state();
    const tos::BlockIdExt block_id{{tos::masterchainId, tos::shardIdAll, state_coordinate},
                                   td::Bits256::zero(), td::Bits256::zero()};
    // Only what assembling an execution configuration reads. The wider mode the
    // pool uses would also require an elected validator set, which decides
    // nothing here and would be a second fixture to keep correct.
    auto config = block::ConfigInfo::extract_config(
        root, block_id,
        block::ConfigInfo::needCapabilities | block::ConfigInfo::needWorkchainInfo |
            block::ConfigInfo::needSpecialSmc | block::ConfigInfo::needLibraries |
            block::ConfigInfo::needPrevBlocks);
    if (config.is_error()) {
      throw std::runtime_error("fixture-config-info: " + config.move_as_error().message().str());
    }
    auto info = config.move_as_ok();

    auto run = [&](std::shared_ptr<vm::ValidatorAuthHost> host, td::Ref<vm::Cell> code) {
      auto execution = activated(*info);
      block::Account account;
      if (!account.unpack(account_entry(address, std::move(code)), 1000, true)) {
        throw std::runtime_error("account-unpack");
      }
      account.block_lt = 1;
      return tos::validator::ExtMessageQ::run_message_on_account(tos::masterchainId, &account, 1000, 2,
                                                                 external_message(address), *execution,
                                                                 std::move(host));
    };

    // With an authority the message is admitted, and the authority is what made
    // it so: the instruction it reaches is the one that counts.
    auto ordinary = run(nullptr, accepting_code());
    if (ordinary.is_error()) {
      std::cerr << "DETAIL ordinary=" << ordinary.error().message().str() << '\n';
    }
    expect(ordinary.is_ok(), "the-fixture-executes-an-ordinary-message");

    auto host = std::make_shared<Host>();
    auto admitted = run(host, privileged_code());
    if (admitted.is_error()) {
      std::cerr << "DETAIL admitted=" << admitted.error().message().str() << '\n';
    }
    expect(admitted.is_ok() && host->checkpoints == 1, "the-ingress-authority-reaches-the-instruction");

    // Without one the run must fail, and specifically at that instruction: any
    // other refusal would mean the message never reached it, and this case
    // would be measuring the fixture instead of the seam.
    auto refused = run(nullptr, privileged_code());
    const auto reason = refused.is_error() ? refused.error().message().str() : std::string();
    const auto expected = "exitcode=" + std::to_string(static_cast<int>(vm::Excno::inv_opcode));
    if (reason.find(expected) == std::string::npos) {
      std::cerr << "DETAIL refused=" << (refused.is_ok() ? std::string("admitted") : reason) << '\n';
    }
    expect(refused.is_error() && reason.find(expected) != std::string::npos,
          "a-message-needing-the-authority-is-rejected-without-one");

    // The queue in front of the expensive check is sized from a delay, so what
    // it allows has to be that delay's own statement at every rate. It used to
    // carry a floor of 512 entries, which is a count under a cap derived from a
    // delay: the two agreed only above about a hundred completions a second and
    // diverged further the slower the node got, which is the condition the
    // bound exists for.
    {
      using tos::validator::admission_cap;
      using tos::validator::max_admission_queue_delay;
      using tos::validator::max_admission_waiters_ceiling;
      bool honoured = true;
      for (double rate : {0.5, 1.0, 10.0, 50.0, 102.4, 500.0, 2000.0}) {
        // What a full queue at this rate implies in seconds, which is the
        // quantity the bound is about.
        const double implied = static_cast<double>(admission_cap(rate)) / rate;
        if (implied > max_admission_queue_delay) {
          std::cerr << "DETAIL rate=" << rate << " queue=" << admission_cap(rate) << " implies " << implied << "s\n";
          honoured = false;
        }
      }
      expect(honoured, "a-full-queue-never-implies-more-than-the-delay-allows");

      // The ceiling still holds, so the rule is a bound and not merely a
      // multiplication, and a pool completing nothing admits nothing rather
      // than a ceiling-sized queue.
      expect(admission_cap(1e12) == max_admission_waiters_ceiling, "a-fast-pool-stops-at-the-ceiling");
      expect(admission_cap(0.0) == 0 && admission_cap(-1.0) == 0,
             "a-pool-completing-nothing-admits-no-queue");
      // A rate that is not a number answers the same way. Reached through the
      // same comparison, so the refusal covers it rather than leaving it to
      // multiply into the ceiling.
      expect(admission_cap(std::numeric_limits<double>::quiet_NaN()) == 0,
             "an-unmeasurable-rate-admits-no-queue");
    }

    // With no floor the estimate is the only thing standing between a burst and
    // a refusal, so what it measures has to be throughput and not traffic. A
    // pool nobody is sending to completes nothing because there is no work; if
    // that reads as a throughput of zero, an idle pool sheds the next burst it
    // would previously have queued, and the removed floor would have been
    // covering that case by accident rather than serving nothing.
    {
      using tos::validator::admission_cap;
      using tos::validator::updated_completion_rate;
      // An idle pool completes nothing because there is no work: that window
      // has measured nothing, and the estimate stands.
      expect(updated_completion_rate(2000.0, 0, 1.0, false) == 2000.0,
             "an-idle-window-measures-nothing");
      // A saturated pool completing nothing has measured its throughput, and
      // the throughput is zero. This is the case production is in, because the
      // cap is consulted only while every check slot is occupied -- so keeping
      // the older estimate here promises five seconds of a throughput nobody is
      // observing, to a queue standing in front of checks that are not
      // finishing.
      expect(updated_completion_rate(2000.0, 0, 1.0, true) == 0.0,
             "a-saturated-window-with-no-completions-measures-zero");
      expect(admission_cap(updated_completion_rate(2000.0, 0, 1.0, true)) == 0,
             "a-stalled-pool-admits-no-queue");
      // One window with work in it brings it straight back, so a stall costs a
      // second of queue rather than the pool's ability to recover.
      expect(updated_completion_rate(0.0, 4000, 1.0, true) == 2000.0,
             "one-window-with-work-in-it-restores-the-estimate");
      // A window with work in it moves the estimate either way, so the cases
      // above are about emptiness rather than about the estimate being frozen.
      expect(updated_completion_rate(2000.0, 10, 1.0, true) < 2000.0 &&
                 updated_completion_rate(2000.0, 10, 1.0, false) < 2000.0,
             "a-window-with-work-in-it-moves-the-estimate");
      // And the window itself has to be a measurement: too short to have
      // measured anything, or so long the pool was idle for most of it.
      expect(updated_completion_rate(2000.0, 10, 0.5, true) == 2000.0 &&
                 updated_completion_rate(2000.0, 10, 60.0, true) == 2000.0 &&
                 updated_completion_rate(2000.0, 0, 0.5, true) == 2000.0,
             "a-window-that-is-not-a-measurement-is-not-read-as-one");
    }

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
