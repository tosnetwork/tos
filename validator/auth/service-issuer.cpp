#include <sodium.h>

#include "service-issuer.h"
namespace tos::auth {
namespace {
struct SecretBuffer {
  std::array<unsigned char, 64> bytes{};
  ~SecretBuffer() {
    sodium_memzero(bytes.data(), bytes.size());
  }
};
Result<Bytes> public_key(const Hash& seed) {
  Bytes key(32);
  SecretBuffer secret;
  if (crypto_sign_seed_keypair(key.data(), secret.bytes.data(), seed.data()) != 0)
    return Error{"backend-error"};
  return key;
}
}  // namespace
ServiceIssuer::~ServiceIssuer() {
  sodium_memzero(seed_.data(), seed_.size());
}
Result<bool> ServiceIssuer::replay(std::span<const std::uint8_t> raw) {
  Reader r(raw);
  std::uint8_t purpose = 0;
  Hash issuer{}, audience{}, seed{}, key_id{};
  ServicePolicy policy;
  Bytes key;
  r.header("SIS1");
  r.integer(purpose);
  r.hash(issuer);
  r.hash(audience);
  read(r, policy);
  r.hash(key_id);
  r.blob(key, 32);
  r.hash(seed);
  // Keep all transient private bytes under a wiping owner, including failures.
  SecretBuffer private_copy;
  std::copy(seed.begin(), seed.end(), private_copy.bytes.begin());
  sodium_memzero(seed.data(), seed.size());
  if (!r.ok() || r.remaining() || purpose != static_cast<std::uint8_t>(purpose_) || issuer != issuer_ ||
      audience != audience_ || policy.issuer_ != issuer_ || policy.suites_ != std::vector<Suite>{{1, 1}} ||
      key_id == Hash{} || key.size() != 32)
    return Error{"issuer-store-binding"};
  if (history_.size() >= 4096 || policy.previous_ != policy_id_ || policy.revision_ != history_.size() + 1)
    return Error{"issuer-policy-history"};
  Hash current_seed{};
  std::copy_n(private_copy.bytes.begin(), 32, current_seed.begin());
  auto derived = public_key(current_seed);
  sodium_memzero(current_seed.data(), current_seed.size());
  if (!derived.ok())
    return derived.error();
  if (derived.value() != key)
    return Error{"issuer-key-binding"};
  for (const auto& previous : history_)
    if (previous.key.id == key_id || previous.key.public_key == key)
      return Error{"issuer-key-reuse"};
  auto id = object_id("service_policy", policy);
  if (!id.ok())
    return id.error();
  history_.push_back({policy, {key_id, std::move(key)}});
  policy_id_ = id.value();
  sodium_memzero(seed_.data(), seed_.size());
  std::copy_n(private_copy.bytes.begin(), 32, seed_.begin());
  return true;
}
Result<std::unique_ptr<ServiceIssuer>> ServiceIssuer::open(const std::string& path, bool create, ServicePurpose purpose,
                                                           Hash issuer, Hash audience) {
  if (sodium_init() < 0)
    return Error{"backend-error"};
  if ((purpose != ServicePurpose::permit && purpose != ServicePurpose::receipt) || issuer == Hash{} ||
      audience == Hash{})
    return Error{"issuer-configuration"};
  auto value = std::unique_ptr<ServiceIssuer>(new ServiceIssuer(purpose, issuer, audience));
  auto log = DurableLog::open(
      path, create, [&](const LogFrontier&, std::span<const std::uint8_t> raw) { return value->replay(raw); }, 4194304);
  if (!log.ok())
    return log.error();
  value->log_ = std::move(log.value());
  if (create) {
    auto first = value->rotate();
    if (!first.ok())
      return first.error();
  }
  if (value->history_.empty())
    return Error{"issuer-history-unavailable"};
  return value;
}
Result<ServiceIdentity> ServiceIssuer::rotate() {
  if (stopped_)
    return Error{"issuer-unavailable"};
  if (history_.size() >= 4096)
    return Error{"issuer-policy-capacity"};
  Hash seed{}, key_id{};
  randombytes_buf(seed.data(), seed.size());
  randombytes_buf(key_id.data(), key_id.size());
  auto key = public_key(seed);
  if (!key.ok()) {
    sodium_memzero(seed.data(), seed.size());
    return key.error();
  }
  ServicePolicy policy{issuer_, history_.size() + 1, policy_id_, {{1, 1}}};
  Writer w;
  w.header("SIS1");
  w.integer(static_cast<std::uint8_t>(purpose_));
  w.bytes(issuer_);
  w.bytes(audience_);
  write(w, policy);
  w.bytes(key_id);
  w.blob(key.value(), 32);
  w.bytes(seed);
  sodium_memzero(seed.data(), seed.size());
  if (!w.ok()) {
    sodium_memzero(w.data.data(), w.data.size());
    return Error{w.error};
  }
  stopped_ = true;
  auto saved = log_->append(w.data);
  if (!saved.ok()) {
    sodium_memzero(w.data.data(), w.data.size());
    return saved.error();
  }
  auto applied = replay(w.data);
  sodium_memzero(w.data.data(), w.data.size());
  if (!applied.ok())
    return applied.error();
  stopped_ = false;
  return history_.back();
}
Result<ServiceComponent> ServiceIssuer::signature(std::span<const std::uint8_t> raw) const {
  if (stopped_ || history_.empty())
    return Error{"issuer-unavailable"};
  SecretBuffer secret;
  Hash pk{};
  if (crypto_sign_seed_keypair(pk.data(), secret.bytes.data(), seed_.data()) != 0)
    return Error{"backend-error"};
  Bytes bytes(64);
  if (crypto_sign_detached(bytes.data(), nullptr, raw.data(), raw.size(), secret.bytes.data()) != 0)
    return Error{"backend-error"};
  return ServiceComponent{1, 1, history_.back().key.id, std::move(bytes)};
}
ReceiptBody ServiceIssuer::base() const {
  ReceiptBody body;
  body.issuer_ = issuer_;
  body.audience_ = audience_;
  body.service_policy_ = policy_id_;
  return body;
}
Result<Receipt> ServiceIssuer::issue(const ReceiptBody& body) {
  if (purpose_ != ServicePurpose::receipt)
    return Error{"issuer-purpose"};
  if (body.issuer_ != issuer_ || body.audience_ != audience_ || body.service_policy_ != policy_id_)
    return Error{"issuer-body-binding"};
  if (body.request_id_ == Hash{} || body.subject_ == Hash{} || body.journal_sequence_ == 0 || body.fence_ == 0 ||
      (body.method_ != 3 && body.method_ != 4 && body.method_ != 5 && body.method_ != 7) || body.state_ < 1 ||
      body.state_ > 3 || (body.state_ != 2 && body.method_ != 5) ||
      (body.state_ == 2 ? body.result_hash_ == Hash{} : body.result_hash_ != Hash{}) ||
      (body.method_ == 3 ? body.context_id_ != Hash{} : body.context_id_ == Hash{}))
    return Error{"issuer-receipt-shape"};
  auto raw = encode(body);
  if (!raw.ok())
    return raw.error();
  auto component = signature(raw.value());
  if (!component.ok())
    return component.error();
  return Receipt{body, {component.value()}};
}
Result<Permit> ServiceIssuer::issue_permit(const PermitExpectation& expectation) {
  if (purpose_ != ServicePurpose::permit)
    return Error{"issuer-purpose"};
  const auto& body = expectation.body;
  if (body.issuer_ != issuer_ || body.audience_ != audience_ || body.service_policy_ != policy_id_)
    return Error{"issuer-body-binding"};
  auto valid =
      validate_permit_context(body, expectation.current_coordinate, expectation.fence, expectation.live_permission);
  if (!valid.ok())
    return valid.error();
  auto raw = encode(body);
  if (!raw.ok())
    return raw.error();
  auto component = signature(raw.value());
  if (!component.ok())
    return component.error();
  return Permit{body, {component.value()}};
}
}  // namespace tos::auth
