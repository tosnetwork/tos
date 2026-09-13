#include "admin-service.h"
namespace tos::auth {
Result<PermitExpectation> AdminContext::permission(const Update& update, std::uint8_t method) const {
  auto id = object_id("update", update);
  if (!id.ok())
    return id.error();
  auto result = permission_;
  if (update.identity_ != identity_.identity_ || result.body.identity_ != identity_.identity_ ||
      result.body.network_ != chain_.network || result.body.genesis_root_ != chain_.genesis_root ||
      result.body.genesis_file_ != chain_.genesis_file || result.body.anchor_.seqno_ != result.current_coordinate)
    return Error{"admin-context"};
  result.body.method_ = method;
  result.body.subject_ = id.value();
  return result;
}
Result<PermitExpectation> AdminContext::authorize(const StageRequest& request) const {
  auto valid = validate_stage_update(identity_, history_, request.update_, request.authorizations_,
                                     permission_.current_coordinate, authority_);
  if (!valid.ok())
    return valid.error();
  if (!valid.value())
    return Error{"unauthorized"};
  return permission(request.update_, 4);
}
Result<PermitExpectation> AdminContext::authorize(const RetireRequest& request) const {
  auto valid = apply_identity_update(identity_, history_, request.update_, request.authorizations_,
                                     permission_.current_coordinate, authority_);
  if (!valid.ok())
    return valid.error();
  Hash target = request.update_.old_key_;
  if (request.update_.operation_ == 7) {
    target = {};
    for (const auto& pending : identity_.pending_) {
      auto id = object_id("transition", pending);
      if (!id.ok())
        return id.error();
      if (Bytes(id.value().begin(), id.value().end()) == request.update_.operation_data_)
        target = pending.new_key_ == Hash{} ? pending.old_key_ : pending.new_key_;
    }
  }
  if (target == Hash{} || target != request.key_id_)
    return Error{"retire-target"};
  return permission(request.update_, 7);
}
Result<Receipt> AdminSignerService::receipt(const OperationPlan& plan, const Bytes& result_body) {
  auto sequence = ledger_.next_sequence();
  if (!sequence.ok())
    return sequence.error();
  Bytes raw{plan.method};
  raw.insert(raw.end(), result_body.begin(), result_body.end());
  auto hash = digest("api-result", raw);
  if (!hash.ok())
    return hash.error();
  auto body = receipts_.base();
  body.request_id_ = plan.request_id;
  body.method_ = plan.method;
  body.subject_ = plan.subject;
  body.result_hash_ = hash.value();
  body.journal_sequence_ = sequence.value();
  body.fence_ = plan.fence;
  body.state_ = 2;
  body.context_id_ = plan.context;
  auto signed_receipt = receipts_.issue(body);
  if (!signed_receipt.ok())
    return signed_receipt.error();
  if (signed_receipt.value().body_ != body)
    return Error{"receipt-issuer-binding"};
  return signed_receipt;
}
Result<PrepareResult> AdminSignerService::prepare(const PrepareRequest& request) {
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  auto plan = plan_operation(3, raw.value(), context_.chain());
  if (!plan.ok())
    return plan.error();
  auto prior = ledger_.operation(plan.value().request_id);
  if (!prior.ok())
    return prior.error();
  if (prior.value() && !prior.value()->result.empty())
    return decode<PrepareResult>(prior.value()->result);
  if (!prior.value()) {
    auto reserved = ledger_.reserve_operation(plan.value());
    if (!reserved.ok())
      return reserved.error();
    if (!reserved.value())
      return Error{"storage-unavailable"};
  }
  // The provider first reconciles its durable preparation ID. A missing result
  // after a consumed witness claim cannot generate replacement key material.
  auto key = provider_.prepare(request);
  if (!key.ok())
    return key.error();
  PrepareResult result{key.value(), {}};
  auto body = encode(PrepareResultBody{result.prepared_});
  if (!body.ok())
    return body.error();
  auto signed_receipt = receipt(plan.value(), body.value());
  if (!signed_receipt.ok())
    return signed_receipt.error();
  result.receipt_ = signed_receipt.value();
  auto encoded = encode(result);
  if (!encoded.ok())
    return encoded.error();
  auto complete = ledger_.complete_operation(plan.value().request_id, encoded.value());
  if (!complete.ok())
    return complete.error();
  if (!complete.value())
    return Error{"storage-unavailable"};
  return result;
}
Result<StageResult> AdminSignerService::stage(const StageRequest& request) {
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  auto plan = plan_operation(4, raw.value(), context_.chain());
  if (!plan.ok())
    return plan.error();
  auto prior = ledger_.operation(plan.value().request_id);
  if (!prior.ok())
    return prior.error();
  if (prior.value()) {
    if (prior.value()->result.empty())
      return Error{"result-uncertain"};
    return decode<StageResult>(prior.value()->result);
  }
  auto permission = context_.authorize(request);
  if (!permission.ok())
    return permission.error();
  auto valid = verify_permit(request.permit_, permission.value().body, permits_, permission.value().current_coordinate,
                             permission.value().fence, permission.value().live_permission);
  if (!valid.ok())
    return valid.error();
  if (!valid.value())
    return Error{"unauthorized"};
  auto key = provider_.descriptor(request.handle_);
  if (!key.ok())
    return key.error();
  if (key.value() != request.key_)
    return Error{"stage-provider-key"};
  auto reserved = ledger_.reserve_operation(plan.value());
  if (!reserved.ok())
    return reserved.error();
  if (!reserved.value())
    return Error{"storage-unavailable"};
  auto proof = provider_.prove_possession(context_.chain(), request);
  if (!proof.ok())
    return Error{"result-uncertain"};
  auto verified = verify_possession(context_.chain(), request.update_, request.key_, proof.value());
  if (!verified.ok())
    return verified.error();
  if (!verified.value())
    return Error{"provider-possession-signature"};
  StageResult result{request.key_, proof.value(), {}};
  auto body = encode(StageResultBody{result.key_, result.possession_});
  if (!body.ok())
    return body.error();
  auto signed_receipt = receipt(plan.value(), body.value());
  if (!signed_receipt.ok())
    return signed_receipt.error();
  result.receipt_ = signed_receipt.value();
  auto encoded = encode(result);
  if (!encoded.ok())
    return encoded.error();
  auto complete = ledger_.complete_operation(plan.value().request_id, encoded.value());
  if (!complete.ok())
    return complete.error();
  if (!complete.value())
    return Error{"storage-unavailable"};
  return result;
}
Result<RetireResult> AdminSignerService::retire(const RetireRequest& request) {
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  auto plan = plan_operation(7, raw.value(), context_.chain());
  if (!plan.ok())
    return plan.error();
  auto prior = ledger_.operation(plan.value().request_id);
  if (!prior.ok())
    return prior.error();
  if (prior.value()) {
    if (prior.value()->result.empty())
      return Error{"result-uncertain"};
    return decode<RetireResult>(prior.value()->result);
  }
  auto permission = context_.authorize(request);
  if (!permission.ok())
    return permission.error();
  auto valid = verify_permit(request.permit_, permission.value().body, permits_, permission.value().current_coordinate,
                             permission.value().fence, permission.value().live_permission);
  if (!valid.ok())
    return valid.error();
  if (!valid.value())
    return Error{"unauthorized"};
  auto reserved = ledger_.reserve_operation(plan.value());
  if (!reserved.ok())
    return reserved.error();
  if (!reserved.value())
    return Error{"storage-unavailable"};
  auto uid = object_id("update", request.update_);
  if (!uid.ok())
    return uid.error();
  RetireResult result{request.key_id_, uid.value(), {}};
  auto body = encode(RetireResultBody{result.key_id_, result.update_id_});
  if (!body.ok())
    return body.error();
  auto signed_receipt = receipt(plan.value(), body.value());
  if (!signed_receipt.ok())
    return signed_receipt.error();
  result.receipt_ = signed_receipt.value();
  auto encoded = encode(result);
  if (!encoded.ok())
    return encoded.error();
  auto complete = ledger_.complete_operation(plan.value().request_id, encoded.value());
  if (!complete.ok())
    return complete.error();
  if (!complete.value())
    return Error{"storage-unavailable"};
  return result;
}
}  // namespace tos::auth
