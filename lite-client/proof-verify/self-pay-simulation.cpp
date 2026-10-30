/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "common/global-version.h"
#include "crypto/smc-envelope/QuantumSelfPayCode.h"
#include "emulator/transaction-emulator.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/dict.h"

#include "self-pay-simulation.h"
#include "simulation-config.h"
#include "wallet-transaction.h"

namespace tos::proofverify::detail {
namespace {
td::Status invalid() {
  return self_pay_simulation_error(SelfPaySimulationError::Input);
}

bool supported_code(const td::Ref<vm::Cell>& code) {
  return code.not_null() && td::hex_encode(code->get_hash().as_slice()) == tos::kQuantumSelfPayV1CodeHash;
}

td::Result<td::Ref<vm::Cell>> message_init(td::Ref<vm::CellSlice> field) {
  auto slice = *field;
  if (!slice.fetch_ulong(1)) {
    return td::Ref<vm::Cell>{};
  }
  if (slice.fetch_ulong(1)) {
    if (slice.size() != 0 || slice.size_refs() != 1) {
      return invalid();
    }
    return slice.fetch_ref();
  }
  vm::CellBuilder builder;
  if (!builder.append_cellslice_bool(slice)) {
    return invalid();
  }
  return builder.finalize();
}
}  // namespace

td::Result<BoundSimulationMessage> bind_simulation_message(const block::StdAddress& expected, td::Slice bytes) {
  try {
    auto preflight = preflight_wallet_boc(bytes);
    if (preflight.is_error()) {
      return self_pay_simulation_error(preflight.code() == static_cast<int>(WalletBocError::Resource)
                                           ? SelfPaySimulationError::Resource
                                           : SelfPaySimulationError::Input);
    }
    auto parsed = vm::std_boc_deserialize(bytes);
    if (parsed.is_error())
      return invalid();
    auto message = parsed.move_as_ok();
    auto complete = check_complete_simulation_config(message);
    if (complete.is_error()) {
      return self_pay_simulation_error(complete.error().code() == static_cast<int>(SimulationConfigError::Resource)
                                           ? SelfPaySimulationError::Resource
                                           : SelfPaySimulationError::Input);
    }
    block::gen::Message::Record record;
    block::gen::CommonMsgInfo::Record_ext_in_msg_info external;
    block::StdAddress destination;
    if (!block::gen::t_Message_Any.validate_ref(65536, message) ||
        !block::gen::t_Message_Any.cell_unpack(message, record) || !tlb::csr_unpack(record.info, external) ||
        !block::tlb::t_MsgAddressInt.extract_std_address(external.dest, destination) ||
        destination.workchain != expected.workchain || destination.addr != expected.addr)
      return invalid();
    td::Bits256 bytes_hash;
    td::sha256(bytes, bytes_hash.as_slice());
    return BoundSimulationMessage{message, bytes_hash, td::Bits256{message->get_hash().bits()}};
  } catch (vm::VmError&) {
    return invalid();
  } catch (vm::VmVirtError&) {
    return invalid();
  }
}

td::Result<SelfPaySimulation> execute_prepared_self_pay(const tos::BlockIdExt& target,
                                                        std::shared_ptr<block::Config> config,
                                                        td::Ref<vm::Tuple> previous_blocks,
                                                        PreparedSimulationAccount prepared, td::Slice message_boc) {
  try {
    SelfPaySimulation result;
    result.context = prepared.context;
    if (!config || !prepared.account.balance.is_valid()) {
      return invalid();
    }
    result.authenticated_balance = prepared.account.balance.tomis->to_dec_string();
    TRY_RESULT(bound, bind_simulation_message(block::StdAddress{prepared.account.workchain, prepared.account.addr},
                                              message_boc));
    auto message = std::move(bound.root);
    block::gen::Message::Record record;
    if (!block::gen::t_Message_Any.cell_unpack(message, record)) {
      return self_pay_simulation_error(SelfPaySimulationError::Internal);
    }
    result.message_bytes_hash = bound.bytes_hash;
    result.message_root_hash = bound.root_hash;
    result.config_root_hash = td::Bits256{config->get_root_cell()->get_hash().bits()};
    if (config->get_global_version() < 16 || config->get_global_version() > tos::SUPPORTED_VERSION ||
        prepared.account.workchain != 0 || prepared.account.library.not_null()) {
      result.context.reset();
      return result;
    }
    if (previous_blocks.is_null() || prepared.context.estimated_time == 0 ||
        prepared.context.estimated_transaction_lt == 0 || prepared.context.estimated_block_start_lt == 0 ||
        prepared.context.estimated_transaction_lt - 1 != prepared.context.estimated_block_start_lt ||
        prepared.context.estimated_block_start_lt % block::Config::get_lt_align() != 0) {
      return self_pay_simulation_error(SelfPaySimulationError::Context);
    }
    TRY_RESULT(init, message_init(record.init));
    if (init.not_null()) {
      block::gen::StateInit::Record state;
      if (!tlb::unpack_cell(init, state) || state.fixed_prefix_length->prefetch_ulong(1) != 0 ||
          state.special->prefetch_ulong(1) != 0 || state.library->prefetch_ulong(1) != 0 ||
          state.code->prefetch_ulong(1) != 1 || state.data->prefetch_ulong(1) != 1 ||
          !supported_code(state.code->prefetch_ref())) {
        return result;
      }
      const auto expected_hash =
          prepared.account.status == block::Account::acc_frozen ? prepared.account.state_hash : prepared.account.addr;
      if (td::Bits256{init->get_hash().bits()} != expected_hash) {
        return result;
      }
    }
    if (prepared.account.status == block::Account::acc_active) {
      if (!supported_code(prepared.account.code)) {
        return result;
      }
    } else if (init.is_null()) {
      return result;
    }
    // Fixed-width, domain-separated seed input binds the exact authorization and
    // authenticated target/address. A zero result refuses rather than selecting
    // the emulator's random default.
    std::string seed_input = "tos-self-pay-simulation-seed/1";
    seed_input.append(target.root_hash.as_slice().str());
    seed_input.append(target.file_hash.as_slice().str());
    seed_input.append(prepared.account.addr.as_slice().str());
    seed_input.append(result.message_bytes_hash.as_slice().str());
    td::Bits256 seed;
    td::sha256(seed_input, seed.as_slice());
    if (seed.is_zero()) {
      return self_pay_simulation_error(SelfPaySimulationError::Context);
    }
    result.simulation_seed = seed;
    emulator::TransactionEmulator emulator{std::move(config), 0};
    emulator.set_unixtime(prepared.context.estimated_time);
    emulator.set_lt(prepared.context.estimated_transaction_lt);
    emulator.set_rand_seed(seed);
    emulator.set_prev_blocks_info(std::move(previous_blocks));
    // The fixed code has no external library dependency. Preparation scans its account graph; the
    // local library policy is checked above; missing libraries cannot fall back
    // to endpoint-supplied code.
    emulator.set_libs(vm::Dictionary{256});
    auto executed = emulator.emulate_transaction(std::move(prepared.account), message, prepared.context.estimated_time,
                                                 prepared.context.estimated_transaction_lt,
                                                 block::transaction::Transaction::tr_ord);
    if (executed.is_error()) {
      if (executed.error().code() == -701) {
        result.outcome = SimulationOutcome::ImportRejected;
        return result;
      }
      return self_pay_simulation_error(SelfPaySimulationError::Internal);
    }
    auto execution = executed.move_as_ok();
    if (auto* rejected = dynamic_cast<emulator::TransactionEmulator::EmulationExternalNotAccepted*>(execution.get())) {
      result.outcome = SimulationOutcome::NotAccepted;
      result.vm_exit_code = rejected->vm_exit_code;
      // Never return the VM tail or construct transaction/fee fields here.
      return result;
    }
    auto* success = dynamic_cast<emulator::TransactionEmulator::EmulationSuccess*>(execution.get());
    if (success == nullptr) {
      return self_pay_simulation_error(SelfPaySimulationError::Internal);
    }
    auto serialized = vm::std_boc_serialize(success->transaction, 2);
    if (serialized.is_error()) {
      return self_pay_simulation_error(SelfPaySimulationError::Internal);
    }
    auto decoded =
        verify_wallet_transaction(success->account.addr.as_slice(), prepared.context.estimated_transaction_lt,
                                  success->transaction->get_hash().as_slice(), serialized.ok().as_slice());
    if (decoded.is_error()) {
      return self_pay_simulation_error(decoded.error().code() == static_cast<int>(WalletBocError::Resource)
                                           ? SelfPaySimulationError::Resource
                                           : SelfPaySimulationError::Internal);
    }
    result.transaction = SimulatedTransaction{decoded.move_as_ok(), success->account.balance.tomis->to_dec_string(),
                                              td::Bits256{success->account.total_state->get_hash().bits()}};
    result.outcome = SimulationOutcome::Executed;
    return result;
  } catch (vm::VmError&) {
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  } catch (vm::VmVirtError&) {
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  } catch (vm::CellBuilder::CellWriteError&) {
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  } catch (vm::CellBuilder::CellCreateError&) {
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  }
}

}  // namespace tos::proofverify::detail
