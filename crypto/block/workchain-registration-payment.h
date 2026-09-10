#pragma once

#include "block/workchain-execution-dispatch.h"
#include "block/workchain-native-inbox.h"
#include "block/workchain-registration.h"
#include "block/workchain-value-flow.h"

namespace block {

struct WorkchainRegistrationPaymentResult {
  WorkchainRegistrationTransition registration;
  WorkchainAccountValueFlow coordinator_flow;
  td::Bits256 imported_message;
  // Locally constructed snapshot binding, not a candidate-declared hash.
  td::Bits256 old_coordinator_data_hash;
};

// Post-admission consumption of ONE final-import message. The enclosing batch
// authenticates the inbox against queue/state evidence and consumes this message
// exactly once alongside these account changes. A transport-valid envelope by
// itself is not evidence of payment. Errors acquiring that evidence are local;
// a successfully acquired inbox without the claimed message is candidate-invalid.
//
// The message body is the existing complete confidential registration record;
// it commits the Native payer to the account and historical refund destination.
// The possession proof is separate authorization, never an alternative source
// for the message value. This introduces no second account-record encoding.
inline td::Result<WorkchainRegistrationPaymentResult> execute_workchain_registration_payment(
    const WorkchainRegistrationPolicy& policy, const WorkchainNativeIngressPolicy& ingress,
    const WorkchainExecutionDescriptor& descriptor, const td::Result<WorkchainNativeInboxPlan>& admitted_inbox,
    const td::Bits256& message_hash, const WorkchainCoordinatorState& old_coordinator,
    const CurrencyCollection& old_coordinator_balance, const td::Ref<vm::Cell>& existing_account,
    const std::array<unsigned char, 64>& proof) {
  auto invalid = [](td::Slice text) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid), text);
  };
  auto local = [](td::Slice text) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable), text);
  };
  try {
    if (admitted_inbox.is_error())
      return local("registration payment inbox unavailable");
    if (ingress.workchain_id != 2 || validate_workchain_native_ingress_binding(ingress, descriptor).is_error()) {
      return local("registration ingress configuration binding unavailable");
    }
    auto parameters = decode_workchain_engine_parameters(ingress.engine_configuration);
    if (parameters.is_error() || parameters.ok().registration_deposit != policy.deposit ||
        parameters.ok().instance_id != policy.instance) {
      return local("registration deposit differs from authenticated ingress configuration");
    }
    const auto& envelopes = admitted_inbox.ok().envelopes;
    std::vector<td::Bits256> roles{ingress.executor_address};
    if (ingress.custody_address) roles.push_back(*ingress.custody_address);
    std::sort(roles.begin(), roles.end());
    auto planned =
        plan_workchain_native_envelopes(envelopes, 2, roles, admitted_inbox.ok().after_lt,
                                        parameters.ok().resources.input.max_inbound);
    if (planned.is_error())
      return invalid("registration inbox violates authenticated ingress limits or destination");
    td::Ref<vm::Cell> message;
    for (const auto& cell : envelopes) {
      tlb::MsgEnvelope::Record_std envelope;
      if (!tlb::unpack_cell(cell, envelope))
        return invalid("malformed admitted registration envelope");
      if (td::Bits256(envelope.msg->get_hash().bits()) == message_hash) {
        if (message.not_null())
          return invalid("registration payment occurs twice in inbox");
        message = envelope.msg;
      }
    }
    if (message.is_null())
      return invalid("registration payment absent from authenticated inbox");
    gen::Message::Record msg;
    gen::CommonMsgInfo::Record_int_msg_info info;
    gen::MsgAddressInt::Record_addr_std payer, receiver;
    if (!tlb::type_unpack_cell(message, gen::t_Message_Any, msg) || !gen::csr_unpack(msg.info, info) || info.bounced ||
        !gen::csr_unpack(info.src, payer) || payer.anycast->size() != 1 ||
        !gen::csr_unpack(info.dest, receiver) || receiver.address != ingress.executor_address || msg.init->size() != 1 ||
        msg.init->prefetch_ulong(1) != 0) {
      return invalid("registration requires an unbounced Native payment without StateInit");
    }
    CurrencyCollection received;
    if (!received.unpack(info.value) || received.extra.not_null())
      return invalid("registration payment must contain only TOS");
    // Build the unsigned amount without narrowing a uint64 tariff through int64.
    auto amount_cell = vm::CellBuilder().store_long(policy.deposit, 64).finalize();
    CurrencyCollection deposit(vm::load_cell_slice(amount_cell).fetch_int256(64, false));
    if (received != deposit)
      return invalid("registration payment differs from authenticated deposit");
    auto body = *msg.body;
    td::Ref<vm::Cell> registration_data;
    auto selector = body.fetch_ulong(1);
    if (selector == 1 && body.size() == 0 && body.size_refs() == 1) {
      registration_data = body.fetch_ref();
    } else if (selector == 0) {
      registration_data = vm::CellBuilder().append_cellslice(body).finalize();
    } else {
      return invalid("malformed registration message body");
    }
    auto account = decode_workchain_confidential_account(registration_data);
    if (account.is_error())
      return invalid("Native payment body is not a confidential registration");
    if (account.ok().address.account == ingress.executor_address) {
      return invalid("confidential registration cannot replace coordinator");
    }
    // This balance is the consumable message value, NOT the sender's old Native
    // balance: source-chain execution already debited that balance. Never debit
    // it again during final import. Exact payment above leaves no unowned excess.
    WorkchainRegistrationSnapshot old{old_coordinator, existing_account, payer.workchain_id, payer.address,
                                      policy.deposit};
    TRY_RESULT(registration,
               execute_workchain_registration(policy, old, account.ok().address.account, registration_data, proof));
    CurrencyCollection new_balance;
    if (!old_coordinator_balance.is_valid() || !old_coordinator_balance.tomis->is_valid() ||
        !old_coordinator_balance.tomis->unsigned_fits_bits(256) ||
        !CurrencyCollection::add(old_coordinator_balance, received, new_balance) ||
        !new_balance.tomis->unsigned_fits_bits(256)) {
      return local("registration coordinator Native balance unavailable or overflowing");
    }
    WorkchainAccountValueFlow flow{ingress.executor_address, old_coordinator_balance, received, new_balance,
                                   CurrencyCollection(0),    CurrencyCollection(0)};
    // Extra currencies are absent in the imported payment; the historical
    // balance closure must already have been admitted with this same bound.
    const auto cells = parameters.ok().resources.state.max_cells;
    if (cells > INT_MAX || !cells)
      return local("unsupported registration value-flow bound");
    if (verify_workchain_value_flow({flow}, {}, 1, 0, static_cast<int>(cells)).is_error()) {
      return local("registration value-flow reconstruction failed");
    }
    // No Native StoragePhase runs for engine-owned accounts (§3.1). Deposit is
    // locked in refundable_deposits, not principal or a fee. Actual coordinator
    // operating fees must be separate explicit effects, never an implicit rent.
    TRY_RESULT(old_data, encode_workchain_coordinator_state(old_coordinator));
    return WorkchainRegistrationPaymentResult{std::move(registration), std::move(flow), message_hash,
                                              td::Bits256(old_data->get_hash().bits())};
  } catch (const vm::VmVirtError&) {
    return local("registration payment view incomplete");
  } catch (const vm::VmError&) {
    return local("registration payment view unavailable");
  } catch (const vm::CellBuilder::CellCreateError&) {
    return local("registration payment allocation failure");
  } catch (const vm::CellBuilder::CellWriteError&) {
    return local("registration payment construction failure");
  } catch (const std::bad_alloc&) {
    return local("registration payment allocation failure");
  }
}

}  // namespace block
