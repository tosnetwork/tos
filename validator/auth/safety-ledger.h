#pragma once
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
// A serialized, durable anti-equivocation ledger. Authority, provider handle
// resolution and signature verification are performed by the signer before
// committing; the ledger independently enforces immutable statement/result links.
class SafetyLedger {
  std::unique_ptr<DurableLog> log_;
  MonotonicWitness& witness_;
  std::uint64_t fence_;
  std::map<Hash, StoredSign> requests_;
  std::map<Hash, std::map<std::uint8_t, Hash>> duties_;
  bool stopped_ = false;
  SafetyLedger(MonotonicWitness& w, std::uint64_t fence) : witness_(w), fence_(fence) {
  }
  Result<bool> replay(const LogFrontier&, std::span<const std::uint8_t>);
  Result<bool> commit(const Bytes&, const Hash& request, std::uint8_t state, const Receipt&);
  Result<bool> conflict(const SignPlan&) const;

 public:
  static Result<std::unique_ptr<SafetyLedger>> open(const std::string&, bool create, MonotonicWitness&,
                                                    std::uint64_t fence, std::uint64_t storage_limit = 1073741824);
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
