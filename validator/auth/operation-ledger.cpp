#include "api-semantics.h"
#include "safety-ledger.h"
namespace tos::auth {
namespace {
Result<Receipt> operation_receipt(std::uint8_t method, const Bytes& raw) {
  if (method == 3) {
    auto r = decode<PrepareResult>(raw);
    if (!r.ok())
      return r.error();
    return r.value().receipt_;
  }
  if (method == 4) {
    auto r = decode<StageResult>(raw);
    if (!r.ok())
      return r.error();
    return r.value().receipt_;
  }
  if (method == 7) {
    auto r = decode<RetireResult>(raw);
    if (!r.ok())
      return r.error();
    return r.value().receipt_;
  }
  return Error{"operation-method"};
}
Result<Bytes> event(const OperationPlan& plan, const Bytes& result) {
  Writer w;
  w.header("OPR1");
  w.integer(plan.method);
  w.integer(plan.chain.network);
  w.bytes(plan.chain.genesis_root);
  w.bytes(plan.chain.genesis_file);
  w.bytes(plan.chain.chain_domain);
  w.blob(plan.request, 2000000);
  w.blob(result, 2000000);
  if (!w.ok())
    return Error{w.error};
  return w.data;
}
Result<bool> result_binding(const OperationPlan& plan, const Bytes& raw, std::uint64_t sequence) {
  ObjectReader reader({});
  auto valid = validate_api_response(plan.method, plan.request, raw, reader);
  if (!valid.ok())
    return valid.error();
  if (!valid.value())
    return Error{"operation-result-binding"};
  auto receipt = operation_receipt(plan.method, raw);
  if (!receipt.ok())
    return receipt.error();
  if (receipt.value().body_.journal_sequence_ != sequence)
    return Error{"operation-receipt-sequence"};
  return true;
}
PrepareRequest parameters(PrepareRequest request) {
  request.fence_ = 0;
  return request;
}
}  // namespace
Result<OperationPlan> plan_operation(std::uint8_t method, const Bytes& raw, const ChainContext& chain) {
  if (method != 3 && method != 4 && method != 7)
    return Error{"operation-method"};
  ObjectReader reader({});
  auto valid = validate_api_request(method, raw, reader);
  if (!valid.ok())
    return valid.error();
  if (!valid.value())
    return Error{"operation-request"};
  auto id = api_request_id(method, raw), subject = digest("api-subject", raw);
  if (!id.ok())
    return id.error();
  if (!subject.ok())
    return subject.error();
  OperationPlan plan{method, raw, chain, id.value(), id.value(), subject.value(), {}, 0};
  if (method == 3) {
    auto q = decode<PrepareRequest>(raw);
    if (!q.ok())
      return q.error();
    if (q.value().suite_ != 1 || q.value().parameters_ != 1)
      return Error{"disabled-suite"};
    plan.fence = q.value().fence_;
  } else {
    Permit permit;
    if (method == 4) {
      auto q = decode<StageRequest>(raw);
      if (!q.ok())
        return q.error();
      permit = q.value().permit_;
      plan.fence = q.value().fence_;
      auto preimage = possession_preimage(chain, q.value().update_, q.value().key_);
      if (!preimage.ok())
        return preimage.error();
      auto reservation = digest("possession-request", preimage.value());
      if (!reservation.ok())
        return reservation.error();
      plan.reservation = reservation.value();
    } else {
      auto q = decode<RetireRequest>(raw);
      if (!q.ok())
        return q.error();
      permit = q.value().permit_;
      plan.fence = q.value().fence_;
    }
    if (chain.network != permit.body_.network_ || chain.genesis_root != permit.body_.genesis_root_ ||
        chain.genesis_file != permit.body_.genesis_file_ || chain.chain_domain == Hash{})
      return Error{"operation-chain"};
    auto context = object_id("permit", permit);
    if (!context.ok())
      return context.error();
    plan.context = context.value();
  }
  return plan;
}
Result<bool> SafetyLedger::replay_operation(const LogFrontier& frontier, std::span<const std::uint8_t> raw) {
  Reader r(raw);
  std::uint8_t method = 0;
  ChainContext chain;
  Bytes request, result;
  r.header("OPR1");
  r.integer(method);
  r.integer(chain.network);
  r.hash(chain.genesis_root);
  r.hash(chain.genesis_file);
  r.hash(chain.chain_domain);
  r.blob(request, 2000000);
  r.blob(result, 2000000);
  if (!r.ok() || r.remaining())
    return Error{"operation-record"};
  auto plan = plan_operation(method, request, chain);
  if (!plan.ok())
    return plan.error();
  auto found = operations_.find(plan.value().request_id);
  if (result.empty()) {
    if (found != operations_.end() || operation_reservations_.contains(plan.value().reservation))
      return Error{"operation-reservation-conflict"};
    if (method == 3) {
      auto q = decode<PrepareRequest>(request);
      if (!q.ok())
        return q.error();
      auto old = preparations_.find(q.value().preparation_id_);
      if (old != preparations_.end() && old->second != parameters(q.value()))
        return Error{"preparation-conflict"};
      preparations_[q.value().preparation_id_] = parameters(q.value());
    }
    operation_reservations_.emplace(plan.value().reservation, plan.value().request_id);
    operations_.emplace(plan.value().request_id, StoredOperation{plan.value(), {}});
  } else {
    if (found == operations_.end() || !found->second.result.empty() || found->second.plan.request != request ||
        found->second.plan.reservation != plan.value().reservation)
      return Error{"operation-terminal-transition"};
    auto valid = result_binding(found->second.plan, result, frontier.sequence);
    if (!valid.ok())
      return valid.error();
    found->second.result = std::move(result);
  }
  return true;
}
Result<std::optional<StoredOperation>> SafetyLedger::operation(const Hash& id) const {
  if (stopped_)
    return Error{"storage-unavailable"};
  auto valid = witness_.check(fence_, log_->frontier());
  if (!valid.ok())
    return valid.error();
  if (!valid.value())
    return Error{"journal-witness-mismatch"};
  auto found = operations_.find(id);
  if (found == operations_.end())
    return std::optional<StoredOperation>{};
  return std::optional<StoredOperation>{found->second};
}
Result<bool> SafetyLedger::reserve_operation(const OperationPlan& plan) {
  auto rebuilt = plan_operation(plan.method, plan.request, plan.chain);
  if (!rebuilt.ok())
    return rebuilt.error();
  const auto& p = rebuilt.value();
  if (p.request_id != plan.request_id || p.reservation != plan.reservation || p.fence != fence_)
    return Error{"operation-plan"};
  if (operations_.contains(p.request_id) || operation_reservations_.contains(p.reservation))
    return Error{"operation-reservation-conflict"};
  if (p.method == 3) {
    auto q = decode<PrepareRequest>(p.request);
    if (!q.ok())
      return q.error();
    auto old = preparations_.find(q.value().preparation_id_);
    if (old != preparations_.end() && old->second != parameters(q.value()))
      return Error{"preparation-conflict"};
  }
  auto raw = event(p, {});
  if (!raw.ok())
    return raw.error();
  return commit(raw.value(), p.reservation, 1, nullptr);
}
Result<bool> SafetyLedger::complete_operation(const Hash& id, const Bytes& result) {
  auto found = operations_.find(id);
  if (found == operations_.end() || !found->second.result.empty())
    return Error{"operation-terminal-transition"};
  auto sequence = next_sequence();
  if (!sequence.ok())
    return sequence.error();
  auto valid = result_binding(found->second.plan, result, sequence.value());
  if (!valid.ok())
    return valid.error();
  auto receipt = operation_receipt(found->second.plan.method, result);
  if (!receipt.ok())
    return receipt.error();
  auto raw = event(found->second.plan, result);
  if (!raw.ok())
    return raw.error();
  return commit(raw.value(), found->second.plan.reservation, 2, &receipt.value());
}
}  // namespace tos::auth
