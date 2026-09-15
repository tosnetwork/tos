#include "safety-ledger.h"
namespace tos::auth {
namespace {
Result<bool> receipt_binding(const StoredSign& stored, const Receipt& receipt, std::uint64_t sequence,
                             std::uint8_t state, const Hash& result) {
  const auto& b = receipt.body_;
  if (b.request_id_ != stored.plan.request_id || b.method_ != 5 || b.subject_ != stored.plan.statement_id ||
      b.fence_ != stored.request.fence_ || b.state_ != state || b.context_id_ != stored.plan.context_id ||
      b.journal_sequence_ != sequence || b.result_hash_ != result || b.issuer_ == Hash{} ||
      b.service_policy_ == Hash{} || b.audience_ == Hash{} || receipt.components_.size() != 1 ||
      receipt.components_[0].suite_ != 1 || receipt.components_[0].parameters_ != 1 ||
      receipt.components_[0].signature_.size() != 64 || receipt.components_[0].key_id_ == Hash{})
    return Error{"journal-receipt-binding"};
  return true;
}
Result<Bytes> event(std::uint8_t state, const SignRequest& request, const Bytes& response) {
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  Writer w;
  w.header("SIG1");
  w.integer(state);
  w.blob(raw.value(), 2000000);
  w.blob(response, 2000000);
  if (!w.ok())
    return Error{w.error};
  return w.data;
}
Result<Hash> result_hash(const SignResult& result) {
  auto body = encode(SignResultBody{result.request_id_, result.statement_id_, result.record_, result.fence_});
  if (!body.ok())
    return body.error();
  body.value().insert(body.value().begin(), 5);
  return digest("api-result", body.value());
}
Result<bool> complete_binding(const StoredSign& stored, const SignResult& result, std::uint64_t sequence) {
  if (result.request_id_ != stored.plan.request_id || result.statement_id_ != stored.plan.statement_id ||
      result.fence_ != stored.request.fence_)
    return Error{"journal-result-binding"};
  auto statement = signing_statement(stored.plan.envelope.duty_, result.record_);
  if (!statement.ok())
    return statement.error();
  if (statement.value() != stored.plan.statement || result.record_.components_.size() != 1 ||
      result.record_.components_[0].signature_.size() != 64)
    return Error{"journal-statement-binding"};
  auto hash = result_hash(result);
  if (!hash.ok())
    return hash.error();
  return receipt_binding(stored, result.receipt_, sequence, 2, hash.value());
}
}  // namespace
Result<SignPlan> plan_sign(const SignRequest& request) {
  if (request.fence_ == 0 || request.key_handles_.size() != 1 || request.key_handles_[0] == Hash{})
    return Error{"sign-handles-fence"};
  auto envelope = decode<Envelope>(request.envelope_template_);
  if (!envelope.ok())
    return envelope.error();
  const auto& e = envelope.value();
  auto payload = validate_payload(e.duty_, e.payload_);
  if (!payload.ok())
    return payload.error();
  if (e.record_.identity_ == Hash{} || e.record_.components_.size() != 1 || e.duty_.genesis_root_ == Hash{} ||
      e.duty_.genesis_file_ == Hash{} || e.duty_.session_ == Hash{} || e.duty_.policy_ == Hash{} ||
      e.duty_.committee_ == Hash{})
    return Error{"sign-context"};
  const auto& component = e.record_.components_[0];
  if (component.suite_ != 1 || component.parameters_ != 1 || component.epoch_ == 0 ||
      component.epoch_ == std::numeric_limits<std::uint64_t>::max() || component.key_id_ == Hash{} ||
      !component.signature_.empty())
    return Error{"sign-template"};
  auto statement = signing_statement(e.duty_, e.record_);
  if (!statement.ok())
    return statement.error();
  auto rid = digest("sign-request", statement.value()), sid = digest("statement", statement.value());
  if (!rid.ok())
    return rid.error();
  if (!sid.ok())
    return sid.error();
  if (rid.value() != request.request_id_)
    return Error{"sign-request-id"};
  auto context = object_id("permit", request.permit_);
  if (!context.ok())
    return context.error();
  Writer w;
  w.integer(e.duty_.network_);
  w.bytes(e.duty_.genesis_root_);
  w.bytes(e.duty_.genesis_file_);
  w.bytes(e.record_.identity_);
  w.bytes(e.duty_.session_);
  w.integer(e.duty_.workchain_);
  w.integer(e.duty_.shard_);
  w.integer(e.duty_.position_);
  if (!w.ok())
    return Error{w.error};
  auto duty = digest("local-safety-duty", w.data);
  if (!duty.ok())
    return duty.error();
  return SignPlan{std::move(envelope.value()),
                  std::move(statement.value()),
                  sid.value(),
                  rid.value(),
                  duty.value(),
                  context.value()};
}
Result<std::unique_ptr<SafetyLedger>> SafetyLedger::open(const std::string& path, bool create,
                                                         MonotonicWitness& witness, std::uint64_t fence,
                                                         std::uint64_t limit) {
  auto ledger = std::unique_ptr<SafetyLedger>(new SafetyLedger(witness, fence));
  auto log = DurableLog::open(
      path, create,
      [&](const LogFrontier& frontier, std::span<const std::uint8_t> raw) { return ledger->replay(frontier, raw); },
      limit);
  if (!log.ok())
    return log.error();
  ledger->log_ = std::move(log.value());
  auto check = witness.check(fence, ledger->log_->frontier());
  if (!check.ok())
    return check.error();
  if (!check.value())
    return Error{"journal-witness-mismatch"};
  return ledger;
}
Result<bool> SafetyLedger::conflict(const SignPlan& plan) const {
  auto slot = duties_.find(plan.duty_id);
  if (slot == duties_.end())
    return true;
  const auto role = plan.envelope.duty_.role_;
  for (const auto& [old_role, request] : slot->second) {
    const auto& old = requests_.at(request).plan;
    if (old_role == role)
      return Error{"duty-conflict"};
    if ((old_role == 3 && role == 4) || (old_role == 4 && role == 3))
      return Error{"finalize-skip-conflict"};
    if ((old_role == 2 && role == 3) || (old_role == 3 && role == 2)) {
      // Both payloads were canonically parsed. Their first four bytes differ
      // by vote type; the complete remaining candidate ID must be identical.
      if (!std::equal(old.envelope.payload_.begin() + 4, old.envelope.payload_.end(),
                      plan.envelope.payload_.begin() + 4))
        return Error{"candidate-conflict"};
    }
  }
  return true;
}
Result<bool> SafetyLedger::replay(const LogFrontier& frontier, std::span<const std::uint8_t> raw) {
  if (raw.size() >= 4 && std::equal(raw.begin(), raw.begin() + 4, "OPR1"))
    return replay_operation(frontier, raw);
  Reader r(raw);
  std::uint8_t state = 0;
  Bytes request_raw, response;
  r.header("SIG1");
  r.integer(state);
  r.blob(request_raw, 2000000);
  r.blob(response, 2000000);
  if (!r.ok() || r.remaining() || state < 1 || state > 3)
    return Error{"journal-record"};
  auto request = decode<SignRequest>(request_raw);
  if (!request.ok())
    return request.error();
  auto plan = plan_sign(request.value());
  if (!plan.ok())
    return plan.error();
  auto found = requests_.find(plan.value().request_id);
  if (state == 1) {
    if (found != requests_.end())
      return Error{"journal-reservation-replacement"};
    auto allowed = conflict(plan.value());
    if (!allowed.ok())
      return allowed.error();
    auto receipt = decode<Receipt>(response);
    if (!receipt.ok())
      return receipt.error();
    StoredSign stored{request.value(), plan.value(), 1, receipt.value(), {}};
    auto binding = receipt_binding(stored, receipt.value(), frontier.sequence, 1, {});
    if (!binding.ok())
      return binding.error();
    duties_[plan.value().duty_id][plan.value().envelope.duty_.role_] = plan.value().request_id;
    requests_.emplace(plan.value().request_id, std::move(stored));
    return true;
  }
  if (found == requests_.end() || found->second.state != 1 || found->second.request != request.value())
    return Error{"journal-terminal-transition"};
  if (state == 2) {
    auto result = decode<SignResult>(response);
    if (!result.ok())
      return result.error();
    auto binding = complete_binding(found->second, result.value(), frontier.sequence);
    if (!binding.ok())
      return binding.error();
    found->second.result = result.value();
  } else {
    auto receipt = decode<Receipt>(response);
    if (!receipt.ok())
      return receipt.error();
    auto binding = receipt_binding(found->second, receipt.value(), frontier.sequence, 3, {});
    if (!binding.ok())
      return binding.error();
    found->second.receipt = receipt.value();
  }
  found->second.state = state;
  return true;
}
Result<bool> SafetyLedger::commit(const Bytes& raw, const Hash& request, std::uint8_t state, const Receipt* receipt) {
  if (stopped_)
    return Error{"storage-unavailable"};
  auto checked = witness_.check(fence_, log_->frontier());
  if (!checked.ok())
    return checked.error();
  if (!checked.value())
    return Error{"journal-witness-mismatch"};
  const auto before = log_->frontier();
  auto receipt_id = receipt ? object_id("receipt_body", receipt->body_) : Result<Hash>(Hash{});
  if (!receipt_id.ok())
    return receipt_id.error();
  stopped_ = true;
  auto appended = log_->append(raw);
  if (!appended.ok())
    return appended.error();
  auto witnessed = witness_.advance(fence_, before, {appended.value(), receipt_id.value(), request, state});
  if (!witnessed.ok())
    return witnessed.error();
  if (!witnessed.value())
    return Error{"witness-unavailable"};
  auto applied = replay(appended.value(), raw);
  if (!applied.ok())
    return applied.error();
  stopped_ = false;
  return true;
}
Result<std::uint64_t> SafetyLedger::next_sequence() const {
  if (stopped_)
    return Error{"storage-unavailable"};
  if (log_->frontier().sequence == std::numeric_limits<std::uint64_t>::max())
    return Error{"journal-exhausted"};
  return log_->frontier().sequence + 1;
}
Result<bool> SafetyLedger::reserve(const SignRequest& request, const Receipt& receipt) {
  if (request.fence_ != fence_)
    return Error{"fenced"};
  auto plan = plan_sign(request);
  if (!plan.ok())
    return plan.error();
  if (requests_.contains(plan.value().request_id))
    return Error{"request-already-known"};
  auto allowed = conflict(plan.value());
  if (!allowed.ok())
    return allowed.error();
  auto seq = next_sequence();
  if (!seq.ok())
    return seq.error();
  auto binding = receipt_binding({request, plan.value(), 1, receipt, {}}, receipt, seq.value(), 1, {});
  if (!binding.ok())
    return binding.error();
  auto encoded = encode(receipt);
  if (!encoded.ok())
    return encoded.error();
  auto raw = event(1, request, encoded.value());
  if (!raw.ok())
    return raw.error();
  return commit(raw.value(), plan.value().request_id, 1, &receipt);
}
Result<bool> SafetyLedger::complete(const Hash& id, const SignResult& result) {
  auto found = requests_.find(id);
  if (found == requests_.end() || found->second.state != 1)
    return Error{"journal-terminal-transition"};
  auto seq = next_sequence();
  if (!seq.ok())
    return seq.error();
  auto binding = complete_binding(found->second, result, seq.value());
  if (!binding.ok())
    return binding.error();
  auto encoded = encode(result);
  if (!encoded.ok())
    return encoded.error();
  auto raw = event(2, found->second.request, encoded.value());
  if (!raw.ok())
    return raw.error();
  return commit(raw.value(), id, 2, &result.receipt_);
}
Result<bool> SafetyLedger::burn(const Hash& id, const Receipt& receipt) {
  auto found = requests_.find(id);
  if (found == requests_.end() || found->second.state != 1)
    return Error{"journal-terminal-transition"};
  auto seq = next_sequence();
  if (!seq.ok())
    return seq.error();
  auto binding = receipt_binding(found->second, receipt, seq.value(), 3, {});
  if (!binding.ok())
    return binding.error();
  auto encoded = encode(receipt);
  if (!encoded.ok())
    return encoded.error();
  auto raw = event(3, found->second.request, encoded.value());
  if (!raw.ok())
    return raw.error();
  return commit(raw.value(), id, 3, &receipt);
}
Result<RequestState> SafetyLedger::get(const Hash& id) const {
  if (stopped_)
    return Error{"storage-unavailable"};
  auto checked = witness_.check(fence_, log_->frontier());
  if (!checked.ok())
    return checked.error();
  if (!checked.value())
    return Error{"journal-witness-mismatch"};
  auto found = requests_.find(id);
  if (found == requests_.end())
    return RequestState{id, 0, {}, 0, {}, {}};
  const auto& s = found->second;
  RequestState state{id, s.state, s.plan.statement_id, s.request.fence_, {}, {}};
  if (s.state == 2)
    state.result_.push_back(s.result);
  else
    state.receipt_.push_back(s.receipt);
  return state;
}
Result<StoredSign> SafetyLedger::original(const Hash& id) const {
  auto state = get(id);
  if (!state.ok())
    return state.error();
  auto found = requests_.find(id);
  if (found == requests_.end())
    return Error{"request-absent"};
  return found->second;
}
}  // namespace tos::auth
