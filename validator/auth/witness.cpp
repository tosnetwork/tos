#include "witness.h"
namespace tos::auth {
namespace {
Bytes event(Hash ledger, std::uint8_t kind, std::uint64_t fence, const WitnessMark& mark) {
  Writer w;
  w.header("WIT1");
  w.bytes(ledger);
  w.integer(kind);
  w.integer(fence);
  w.integer(mark.journal.sequence);
  w.bytes(mark.journal.hash);
  w.bytes(mark.receipt_body);
  w.bytes(mark.request);
  w.integer(mark.state);
  return w.data;
}
}  // namespace
Result<std::unique_ptr<FileWitness>> FileWitness::open(const std::string& path, Hash id, bool create) {
  if (id == Hash{})
    return Error{"witness-identity"};
  auto witness = std::unique_ptr<FileWitness>(new FileWitness(id));
  auto log = DurableLog::open(
      path, create, [&](const LogFrontier&, std::span<const std::uint8_t> raw) { return witness->replay(raw); });
  if (!log.ok())
    return log.error();
  witness->log_ = std::move(log.value());
  // An empty existing file cannot prove that a previously used witness is new.
  if (!create && witness->fence_ == 0)
    return Error{"witness-history-unavailable"};
  return witness;
}
Result<bool> FileWitness::replay(std::span<const std::uint8_t> raw) {
  Reader r(raw);
  Hash ledger{};
  std::uint8_t kind = 0;
  std::uint64_t fence = 0;
  WitnessMark mark;
  r.header("WIT1");
  r.hash(ledger);
  r.integer(kind);
  r.integer(fence);
  r.integer(mark.journal.sequence);
  r.hash(mark.journal.hash);
  r.hash(mark.receipt_body);
  r.hash(mark.request);
  r.integer(mark.state);
  if (!r.ok() || r.remaining() || ledger != ledger_id_)
    return Error{"witness-record"};
  if (kind == 1) {
    if (fence_ == std::numeric_limits<std::uint64_t>::max() || fence != fence_ + 1 || mark != WitnessMark{})
      return Error{"witness-fence-history"};
    fence_ = fence;
    return true;
  }
  if (kind == 3) {
    auto allowed = primitive_allowed(fence, mark.request);
    if (!allowed.ok())
      return allowed.error();
    if (mark.journal != LogFrontier{} || mark.receipt_body != Hash{} || mark.state != 0)
      return Error{"witness-claim-record"};
    claimed_.insert(mark.request);
    return true;
  }
  if (kind != 2 || fence == 0 || fence != fence_ || journal_.sequence == std::numeric_limits<std::uint64_t>::max() ||
      mark.journal.sequence != journal_.sequence + 1 || mark.journal.hash == Hash{} || mark.request == Hash{} ||
      mark.state < 1 || mark.state > 3)
    return Error{"witness-journal-history"};
  auto previous = requests_.find(mark.request);
  if ((previous == requests_.end() && mark.state != 1) ||
      (previous != requests_.end() && (previous->second != 1 || mark.state == 1)))
    return Error{"witness-request-transition"};
  journal_ = mark.journal;
  requests_[mark.request] = mark.state;
  if (mark.state == 1)
    request_fences_.emplace(mark.request, fence);
  if (mark.receipt_body != Hash{})
    receipts_.emplace(mark.journal.sequence, mark.receipt_body);
  return true;
}
Result<std::uint64_t> FileWitness::acquire() {
  if (stopped_)
    return Error{"witness-unavailable"};
  if (fence_ == std::numeric_limits<std::uint64_t>::max())
    return Error{"fence-exhausted"};
  auto raw = event(ledger_id_, 1, fence_ + 1, {});
  stopped_ = true;
  auto committed = log_->append(raw);
  if (!committed.ok())
    return committed.error();
  auto applied = replay(raw);
  if (!applied.ok())
    return applied.error();
  stopped_ = false;
  return fence_;
}
Result<bool> FileWitness::check(std::uint64_t fence, const LogFrontier& expected) const {
  if (stopped_)
    return Error{"witness-unavailable"};
  if (fence == 0 || fence != fence_)
    return Error{"fenced"};
  if (expected != journal_)
    return Error{"journal-witness-mismatch"};
  return true;
}
Result<bool> FileWitness::advance(std::uint64_t fence, const LogFrontier& previous, const WitnessMark& mark) {
  auto valid = check(fence, previous);
  if (!valid.ok())
    return valid.error();
  if (previous.sequence == std::numeric_limits<std::uint64_t>::max() ||
      mark.journal.sequence != previous.sequence + 1 || mark.journal.hash == Hash{} || mark.request == Hash{} ||
      mark.state < 1 || mark.state > 3)
    return Error{"witness-mark"};
  auto found = requests_.find(mark.request);
  if ((found == requests_.end() && mark.state != 1) ||
      (found != requests_.end() && (found->second != 1 || mark.state == 1)))
    return Error{"witness-request-transition"};
  auto raw = event(ledger_id_, 2, fence, mark);
  stopped_ = true;
  auto committed = log_->append(raw);
  if (!committed.ok())
    return committed.error();
  auto applied = replay(raw);
  if (!applied.ok())
    return applied.error();
  stopped_ = false;
  return true;
}
Result<bool> FileWitness::check_fence(std::uint64_t fence) const {
  if (stopped_)
    return Error{"witness-unavailable"};
  if (fence == 0 || fence != fence_)
    return Error{"fenced"};
  return true;
}
Result<bool> FileWitness::claim_primitive(std::uint64_t fence, const Hash& request) {
  auto allowed = primitive_allowed(fence, request);
  if (!allowed.ok())
    return allowed.error();
  WitnessMark mark;
  mark.request = request;
  auto raw = event(ledger_id_, 3, fence, mark);
  stopped_ = true;
  auto committed = log_->append(raw);
  if (!committed.ok())
    return committed.error();
  // All shape/state checks above precede the append; a committed claim burns
  // the invocation even if the provider dies before entering the primitive.
  claimed_.insert(request);
  stopped_ = false;
  return true;
}
Result<bool> FileWitness::primitive_allowed(std::uint64_t fence, const Hash& request) const {
  if (stopped_)
    return Error{"witness-unavailable"};
  if (fence == 0 || fence != fence_)
    return Error{"fenced"};
  auto found = requests_.find(request);
  if (found == requests_.end() || found->second != 1)
    return Error{"primitive-not-reserved"};
  if (request_fences_.at(request) != fence)
    return Error{"primitive-reservation-fence"};
  if (claimed_.contains(request))
    return Error{"primitive-already-claimed"};
  return true;
}
Result<bool> FileWitness::contains(std::uint64_t sequence, const Hash& receipt) const {
  if (stopped_)
    return Error{"witness-unavailable"};
  auto found = receipts_.find(sequence);
  return found != receipts_.end() && found->second == receipt;
}
}  // namespace tos::auth
