#pragma once

#include "block/workchain-execution-dispatch.h"
#include "block/workchain-native-inbox.h"
#include "block/workchain-native-disposal.h"
#include "block/workchain-unexpected-bucket.h"

namespace block {

struct WorkchainRejectedDeposit {
  td::Bits256 inbound_message;
  WorkchainNativeDisposal native;
  WorkchainUnexpectedBucket unexpected;
  bool sender_attribution_lost, extra_attribution_lost;
};

// A rejected Deposit is a NORMAL protocol result. This planner is used only
// after admission has independently selected rejection; it cannot make that
// decision for a caller. Errors here are NOT fallback permission. The enclosing
// acquisition boundary classifies unavailable local state versus a candidate
// that claims a branch/message inconsistent with these authenticated inputs.
// No transaction phase is run, no message is consumed and nothing is published.
// The host must install the bucket, Native row, outbound and queue removal in
// one atomic settlement. Validator rebuilds from its own authenticated inbox.
inline td::Result<WorkchainRejectedDeposit> plan_workchain_rejected_deposit(
    const WorkchainNativeIngressPolicy& ingress, const WorkchainExecutionDescriptor& descriptor,
    const WorkchainNativeInboxPlan& inbox, const td::Bits256& message_id,
    const CurrencyCollection& coordinator_balance, const WorkchainUnexpectedBucket& unexpected,
    WorkchainUnexpectedLimits limits, std::uint64_t outgoing_lt, std::uint32_t now,
    ActionPhaseConfig messages, const WorkchainSet& workchains, int extra_validation_cells) {
  TRY_STATUS(validate_workchain_native_ingress_binding(ingress, descriptor));
  if (ingress.workchain_id != 2) return td::Status::Error("Deposit rejection requires wc=2 ingress");
  TRY_RESULT(parameters, decode_workchain_engine_parameters(ingress.engine_configuration));
  std::vector<td::Bits256> roles{ingress.executor_address};
  if (ingress.custody_address) roles.push_back(*ingress.custody_address);
  std::sort(roles.begin(), roles.end());
  TRY_RESULT(checked, plan_workchain_native_envelopes(inbox.envelopes, ingress.workchain_id, roles,
                                                    inbox.after_lt, parameters.resources.input.max_inbound));
  if (outgoing_lt <= checked.after_lt) return td::Status::Error("Deposit rejection LT precedes authenticated inbox");
  td::Ref<vm::Cell> message;
  for (const auto& encoded : checked.envelopes) {
    tlb::MsgEnvelope::Record_std envelope;
    if (!tlb::unpack_cell(encoded, envelope)) return td::Status::Error("malformed rejection inbox envelope");
    if (td::Bits256(envelope.msg->get_hash().bits()) == message_id) {
      if (message.not_null()) return td::Status::Error("rejected Deposit occurs twice in inbox");
      message = envelope.msg;
    }
  }
  if (message.is_null()) return td::Status::Error("rejected Deposit absent from authenticated inbox");
  gen::CommonMsgInfo::Record_int_msg_info info;
  WorkchainUnexpectedSender sender;
  tos::WorkchainId destination_wc;
  td::Bits256 destination;
  if (!tlb::unpack_cell_inexact(message, info) ||
      !tlb::t_MsgAddressInt.extract_std_address(info.src, sender.workchain, sender.account) ||
      !tlb::t_MsgAddressInt.extract_std_address(info.dest, destination_wc, destination) ||
      destination_wc != ingress.workchain_id)
    return td::Status::Error("rejected Deposit lacks standard authenticated addresses");
  TRY_RESULT(bucket_balance, workchain_unexpected_balance(unexpected));
  CurrencyCollection unlocked;
  // Checked subtraction establishes that existing bucket coins actually exist;
  // none of them may finance a bounce of this incoming message.
  if (!CurrencyCollection::sub(coordinator_balance, bucket_balance, unlocked))
    return td::Status::Error("unexpected bucket exceeds authenticated processing balance");
  // Use the existing skipped-compute diagnostics as an implementation choice,
  // not a new Native failure code or a claim that a compute phase ran.
  NativeDisposalProfile profile{NativeDisposalSource::OriginalDestination,
                               {0, -ComputePhase::sk_no_state, {}}, false};
  TRY_RESULT(native, plan_workchain_native_disposal(message, ingress.workchain_id, destination,
      ingress.executor_address, coordinator_balance, outgoing_lt, now, messages, workchains,
      extra_validation_cells, profile));
  if (native.branch == NativeDisposalBranch::Bounce) {
    // The shared planner prices from incoming value only and preserves the
    // ORIGINAL destination as source. InMsg/OutMsg exceptions must bind this
    // exact one-to-one message relation, not permit arbitrary source rewriting.
    if (info.bounced || native.bounce.is_null()) return td::Status::Error("invalid rebounce plan");
    return WorkchainRejectedDeposit{message_id, std::move(native), unexpected, false, false};
  }
  // The shared planner selects this branch for bounced/non-bounceable messages
  // or protocol-unaffordable/unroutable bounce, NEVER on a local error.
  TRY_RESULT(credited, credit_workchain_unexpected(unexpected, limits, sender,
                                                 native.row.imported, extra_validation_cells));
  return WorkchainRejectedDeposit{message_id, std::move(native), std::move(credited.bucket),
                                  credited.sender_attribution_lost, credited.extra_attribution_lost};
}

}  // namespace block
