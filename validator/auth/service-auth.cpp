#include "service-auth.h"
namespace tos::auth {
Result<bool> ServiceTrust::install_trusted(const ServicePolicy& policy, const ServiceKey& key) {
  if (policy.issuer_ == Hash{} || key.id == Hash{} || policy.suites_ != std::vector<Suite>{{1, 1}})
    return Error{"service-policy"};
  auto hash = object_id("service_policy", policy);
  if (!hash.ok())
    return hash.error();
  auto existing = history_.find(hash.value());
  if (existing != history_.end()) {
    if (existing->second.key.id != key.id || existing->second.key.public_key != key.public_key)
      return Error{"service-key-replacement"};
    return true;
  }
  auto previous = current_.find(policy.issuer_);
  if (previous == current_.end()) {
    if (policy.revision_ != 1 || policy.previous_ != Hash{})
      return Error{"service-policy-history"};
  } else {
    auto old = history_.find(previous->second);
    if (old == history_.end() || old->second.policy.revision_ == std::numeric_limits<std::uint64_t>::max() ||
        policy.revision_ != old->second.policy.revision_ + 1 || policy.previous_ != previous->second)
      return Error{"service-policy-history"};
  }
  auto admitted = AdmittedKey::admit(key.public_key);
  if (!admitted.ok())
    return admitted.error();
  history_.emplace(hash.value(), Installed{policy, hash.value(), key, admitted.value()});
  current_[policy.issuer_] = hash.value();
  return true;
}
Result<bool> ServiceTrust::verify_body(const Hash& issuer, const Hash& policy, std::span<const std::uint8_t> body,
                                       const std::vector<ServiceComponent>& components) const {
  auto found = history_.find(policy);
  if (found == history_.end() || found->second.policy.issuer_ != issuer)
    return Error{"service-issuer"};
  if (components.size() != 1)
    return Error{"service-components"};
  const auto& c = components[0];
  if (c.suite_ != 1 || c.parameters_ != 1 || c.key_id_ != found->second.key.id)
    return Error{"service-components"};
  auto signature = found->second.admitted.verify(body, c.signature_);
  if (!signature.ok())
    return signature.error();
  if (!signature.value())
    return Error{"service-signature"};
  return true;
}
Result<bool> ServiceTrust::verify(const Permit& permit) const {
  auto current = current_.find(permit.body_.issuer_);
  if (current == current_.end() || current->second != permit.body_.service_policy_)
    return Error{"stale-permit-policy"};
  auto raw = encode(permit.body_);
  if (!raw.ok())
    return raw.error();
  return verify_body(permit.body_.issuer_, permit.body_.service_policy_, raw.value(), permit.components_);
}
Result<bool> ServiceTrust::verify(const Receipt& receipt) const {
  auto raw = encode(receipt.body_);
  if (!raw.ok())
    return raw.error();
  return verify_body(receipt.body_.issuer_, receipt.body_.service_policy_, raw.value(), receipt.components_);
}
Result<bool> verify_permit(const Permit& permit, const PermitBody& expected, const ServiceTrust& trust,
                           std::uint32_t current, std::uint64_t fence, bool live) {
  if (permit.body_ != expected)
    return Error{"permit-context"};
  auto valid = validate_permit_context(permit.body_, current, fence, live);
  if (!valid.ok())
    return valid.error();
  return trust.verify(permit);
}
Result<bool> validate_permit_context(const PermitBody& body, std::uint32_t current, std::uint64_t fence, bool live) {
  if (body.issuer_ == Hash{} || body.service_policy_ == Hash{} || body.audience_ == Hash{} ||
      body.genesis_root_ == Hash{} || body.genesis_file_ == Hash{} || body.registry_root_ == Hash{} ||
      body.policy_ == Hash{} || body.committee_ == Hash{} || body.session_ == Hash{} || body.identity_ == Hash{} ||
      body.subject_ == Hash{} || (body.method_ != 4 && body.method_ != 5 && body.method_ != 7))
    return Error{"permit-shape"};
  if (body.anchor_.seqno_ == std::numeric_limits<std::uint32_t>::max() || body.anchor_.root_ == Hash{} ||
      body.anchor_.file_ == Hash{} || body.anchor_.state_ == Hash{} ||
      body.expires_mc_ == std::numeric_limits<std::uint32_t>::max() || body.expires_mc_ < body.anchor_.seqno_ ||
      body.expires_mc_ - body.anchor_.seqno_ > 128)
    return Error{"permit-expiry"};
  if (current < body.anchor_.seqno_ || current > body.expires_mc_)
    return Error{"permit-current-coordinate"};
  if (fence == 0 || body.fence_ != fence)
    return Error{"fenced"};
  if (!live)
    return Error{"duty-not-permitted"};
  return true;
}
Result<bool> verify_receipt(const Receipt& receipt, const ReceiptBody& expected, const ServiceTrust& trust,
                            const ReceiptWitness& witness) {
  const auto& body = receipt.body_;
  if (body != expected)
    return Error{"receipt-binding"};
  if (body.journal_sequence_ == 0 || body.fence_ == 0 || body.state_ < 1 || body.state_ > 3)
    return Error{"receipt-state"};
  auto checked = trust.verify(receipt);
  if (!checked.ok())
    return checked.error();
  auto id = object_id("receipt_body", body);
  if (!id.ok())
    return id.error();
  auto retained = witness.contains(body.journal_sequence_, id.value());
  if (!retained.ok())
    return retained.error();
  if (!retained.value())
    return Error{"receipt-frontier"};
  return true;
}
Result<bool> validate_request_state(const RequestState& state, const Hash& id) {
  auto raw = encode(state);
  if (!raw.ok())
    return raw.error();
  if (state.request_id_ != id)
    return Error{"state-correlation"};
  if (state.state_ > 3)
    return Error{"state-code"};
  if (state.state_ == 0) {
    if (state.statement_id_ != Hash{} || state.fence_ != 0 || !state.result_.empty() || !state.receipt_.empty())
      return Error{"absent-shape"};
    return true;
  }
  if (state.statement_id_ == Hash{} || state.fence_ == 0)
    return Error{"known-state"};
  if (state.state_ == 2) {
    if (state.result_.size() != 1 || !state.receipt_.empty())
      return Error{"complete-shape"};
    const auto& result = state.result_[0];
    if (result.request_id_ != id || result.statement_id_ != state.statement_id_ || result.fence_ != state.fence_)
      return Error{"state-result"};
  } else {
    if (!state.result_.empty() || state.receipt_.size() != 1)
      return Error{"pending-shape"};
    const auto& body = state.receipt_[0].body_;
    if (body.state_ != state.state_ || body.request_id_ != id || body.method_ != 5 ||
        body.subject_ != state.statement_id_ || body.fence_ != state.fence_ || body.result_hash_ != Hash{})
      return Error{"state-receipt-binding"};
  }
  return true;
}
Result<bool> observe_request_state(const RequestState* previous, const RequestState& next, const Hash& id) {
  auto valid = validate_request_state(next, id);
  if (!valid.ok())
    return valid.error();
  if (!previous)
    return true;
  valid = validate_request_state(*previous, id);
  if (!valid.ok())
    return valid.error();
  if ((previous->state_ == 2 || previous->state_ == 3) && *previous != next)
    return Error{"terminal-state-regression"};
  if (previous->state_ == 1) {
    if (next.state_ == 0)
      return Error{"reserved-state-regression"};
    if (next.statement_id_ != previous->statement_id_ || next.fence_ != previous->fence_)
      return Error{"reserved-state-binding"};
  }
  return true;
}
}  // namespace tos::auth
