#pragma once
#include <optional>

#include "context.h"
#include "witness.h"
namespace tos::auth {
struct SignPlan {
  Envelope envelope;
  Bytes statement;
  Hash statement_id{}, request_id{}, duty_id{}, context_id{};
};
Result<SignPlan> plan_sign(const SignRequest&);
struct StoredSign {
  SignRequest request;
  SignPlan plan;
  std::uint8_t state = 1;
  Receipt receipt;
  SignResult result;
};
struct OperationPlan {
  std::uint8_t method = 0;
  Bytes request;
  ChainContext chain;
  Hash request_id{}, reservation{}, subject{}, context{};
  std::uint64_t fence = 0;
};
Result<OperationPlan> plan_operation(std::uint8_t method, const Bytes&, const ChainContext&);
struct StoredOperation {
  OperationPlan plan;
  Bytes result;
};
// A serialized, durable anti-equivocation ledger. Authority, provider handle
// resolution and signature verification are performed by the signer before
// committing; the ledger independently enforces immutable statement/result links.
class SafetyLedger {
  std::unique_ptr<DurableLog> log_;
  MonotonicWitness& witness_;
  std::uint64_t fence_;
  std::map<Hash, StoredSign> requests_;
  std::map<Hash, std::map<std::uint8_t, Hash>> duties_;
  std::map<Hash, StoredOperation> operations_;
  std::map<Hash, Hash> operation_reservations_;
  std::map<Hash, PrepareRequest> preparations_;
  bool stopped_ = false;
  SafetyLedger(MonotonicWitness& w, std::uint64_t fence) : witness_(w), fence_(fence) {
  }
  Result<bool> replay(const LogFrontier&, std::span<const std::uint8_t>);
  Result<bool> commit(const Bytes&, const Hash& request, std::uint8_t state, const Receipt*);
  Result<bool> replay_operation(const LogFrontier&, std::span<const std::uint8_t>);
  Result<bool> conflict(const SignPlan&) const;

 public:
  static Result<std::unique_ptr<SafetyLedger>> open(const std::string&, bool create, MonotonicWitness&,
                                                    std::uint64_t fence, std::uint64_t storage_limit = 1073741824);
  Result<std::optional<StoredOperation>> operation(const Hash&) const;
  Result<bool> reserve_operation(const OperationPlan&);
  Result<bool> complete_operation(const Hash&, const Bytes&);
  Result<bool> reserve(const SignRequest&, const Receipt& reserved);
  Result<bool> complete(const Hash& request, const SignResult&);
  Result<bool> burn(const Hash& request, const Receipt& burned);
  Result<RequestState> get(const Hash& request) const;
  Result<StoredSign> original(const Hash& request) const;
  Result<std::uint64_t> next_sequence() const;
  const LogFrontier& frontier() const {
    return log_->frontier();
  }
};
}  // namespace tos::auth
