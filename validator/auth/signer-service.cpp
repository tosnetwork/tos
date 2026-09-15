#include "signer-service.h"
namespace tos::auth {
Result<Receipt> SignerService::receipt(const SignRequest& request, const SignPlan& plan, std::uint8_t state,
                                       Hash result) {
  auto sequence = ledger_.next_sequence();
  if (!sequence.ok())
    return sequence.error();
  auto body = receipts_.base();
  body.request_id_ = request.request_id_;
  body.method_ = 5;
  body.subject_ = plan.statement_id;
  body.result_hash_ = result;
  body.journal_sequence_ = sequence.value();
  body.fence_ = request.fence_;
  body.state_ = state;
  body.context_id_ = plan.context_id;
  auto receipt = receipts_.issue(body);
  if (!receipt.ok())
    return receipt.error();
  if (receipt.value().body_ != body)
    return Error{"receipt-issuer-binding"};
  return receipt.value();
}
Result<SignResult> SignerService::sign(const SignRequest& request) {
  auto plan = plan_sign(request);
  if (!plan.ok())
    return plan.error();
  auto prior = ledger_.get(request.request_id_);
  if (!prior.ok())
    return prior.error();
  if (prior.value().state_ != 0) {
    auto original = ledger_.original(request.request_id_);
    if (!original.ok())
      return original.error();
    if (original.value().request.envelope_template_ != request.envelope_template_ ||
        original.value().request.key_handles_ != request.key_handles_)
      return Error{"cached-request-conflict"};
    if (prior.value().state_ != 2)
      return Error{"result-uncertain"};
    // Exact durable bytes, including the original fence and receipt. Renewing a
    // context or replacing a process never causes another primitive invocation.
    return prior.value().result_[0];
  }
  auto expected = context_.authorize(plan.value());
  if (!expected.ok())
    return expected.error();
  auto permit = verify_permit(request.permit_, expected.value().body, permits_, expected.value().current_coordinate,
                              expected.value().fence, expected.value().live_permission);
  if (!permit.ok())
    return permit.error();
  if (!permit.value())
    return Error{"unauthorized"};
  const auto& p = expected.value().body;
  const auto& e = plan.value().envelope;
  if (p.network_ != e.duty_.network_ || p.genesis_root_ != e.duty_.genesis_root_ ||
      p.genesis_file_ != e.duty_.genesis_file_ || p.policy_ != e.duty_.policy_ || p.committee_ != e.duty_.committee_ ||
      p.session_ != e.duty_.session_ || p.identity_ != e.record_.identity_ || p.method_ != 5 ||
      p.subject_ != plan.value().statement_id || p.anchor_.seqno_ < e.duty_.anchor_mc_ || p.fence_ != request.fence_)
    return Error{"sign-permit-association"};
  auto key = provider_.descriptor(request.key_handles_[0]);
  if (!key.ok())
    return key.error();
  auto ref = key_reference(key.value());
  if (!ref.ok())
    return ref.error();
  const auto& c = e.record_.components_[0];
  if (ref.value() != Keyref{c.suite_, c.parameters_, c.epoch_, c.key_id_} ||
      key.value().identity_ != e.record_.identity_ || key.value().role_ != e.duty_.role_ ||
      key.value().valid_from_ > e.duty_.anchor_mc_ || key.value().valid_until_ <= e.duty_.anchor_mc_)
    return Error{"sign-key-context"};
  auto reserved = receipt(request, plan.value(), 1, {});
  if (!reserved.ok())
    return reserved.error();
  auto committed = ledger_.reserve(request, reserved.value());
  if (!committed.ok())
    return committed.error();
  if (!committed.value())
    return Error{"storage-unavailable"};
  auto record = provider_.sign(request);
  if (!record.ok())
    return Error{"result-uncertain"};
  auto actual = signing_statement(e.duty_, record.value());
  if (!actual.ok())
    return actual.error();
  if (actual.value() != plan.value().statement || record.value().components_.size() != 1)
    return Error{"provider-result-binding"};
  auto admitted = AdmittedKey::admit(key.value().suite_, key.value().parameters_, key.value().public_key_);
  if (!admitted.ok())
    return admitted.error();
  auto signature = admitted.value().verify(plan.value().statement, record.value().components_[0].signature_);
  if (!signature.ok())
    return signature.error();
  if (!signature.value())
    return Error{"provider-result-signature"};
  SignResult result{request.request_id_, plan.value().statement_id, record.value(), request.fence_, {}};
  auto body = encode(SignResultBody{result.request_id_, result.statement_id_, result.record_, result.fence_});
  if (!body.ok())
    return body.error();
  body.value().insert(body.value().begin(), 5);
  auto hash = digest("api-result", body.value());
  if (!hash.ok())
    return hash.error();
  auto complete = receipt(request, plan.value(), 2, hash.value());
  if (!complete.ok())
    return complete.error();
  result.receipt_ = complete.value();
  auto finished = ledger_.complete(request.request_id_, result);
  if (!finished.ok())
    return finished.error();
  if (!finished.value())
    return Error{"storage-unavailable"};
  return result;
}
Result<RequestState> SignerService::get_result(const Hash& request) const {
  return ledger_.get(request);
}
}  // namespace tos::auth
