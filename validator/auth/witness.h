#pragma once
#include <set>

#include "durable-log.h"
#include "service-auth.h"
namespace tos::auth {
struct WitnessMark {
  LogFrontier journal;
  Hash receipt_body{}, request{};
  std::uint8_t state = 0;
  bool operator==(const WitnessMark&) const = default;
};
class MonotonicWitness : public ReceiptWitness {
 public:
  virtual Result<std::uint64_t> acquire() = 0;
  virtual Result<bool> check(std::uint64_t fence, const LogFrontier&) const = 0;
  virtual Result<bool> advance(std::uint64_t fence, const LogFrontier& expected, const WitnessMark&) = 0;
  virtual Result<bool> check_fence(std::uint64_t fence) const = 0;
  virtual Result<bool> claim_primitive(std::uint64_t fence, const Hash& request) = 0;
  virtual Result<bool> primitive_allowed(std::uint64_t fence, const Hash& reservation_request) const = 0;
};
// A process-owned witness for explicitly provisioned C0 local deployments and
// rehearsal. Its file must be retained independently from signer backups. It
// does not claim hardware resistance to rolling back the whole host or VM.
class FileWitness final : public MonotonicWitness {
  Hash ledger_id_;
  std::unique_ptr<DurableLog> log_;
  std::uint64_t fence_ = 0;
  LogFrontier journal_;
  std::map<std::uint64_t, Hash> receipts_;
  std::map<Hash, std::uint8_t> requests_;
  std::map<Hash, std::uint64_t> request_fences_;
  std::set<Hash> claimed_;
  bool stopped_ = false;
  explicit FileWitness(Hash id) : ledger_id_(id) {
  }
  Result<bool> replay(std::span<const std::uint8_t>);

 public:
  static Result<std::unique_ptr<FileWitness>> open(const std::string&, Hash ledger_id, bool create);
  Result<std::uint64_t> acquire() override;
  Result<bool> check(std::uint64_t, const LogFrontier&) const override;
  Result<bool> advance(std::uint64_t, const LogFrontier&, const WitnessMark&) override;
  Result<bool> check_fence(std::uint64_t) const override;
  Result<bool> claim_primitive(std::uint64_t, const Hash&) override;
  Result<bool> primitive_allowed(std::uint64_t, const Hash&) const override;
  Result<bool> contains(std::uint64_t, const Hash&) const override;
};
}  // namespace tos::auth
