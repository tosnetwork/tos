#include <sodium.h>

#include "c0-provider.h"
namespace tos::auth {
namespace {
Result<Hash> public_key(const Hash& seed) {
  Hash pk{};
  std::array<unsigned char, 64> sk{};
  auto status = crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
  sodium_memzero(sk.data(), sk.size());
  if (status != 0)
    return Error{"backend-error"};
  return pk;
}
Result<Bytes> sign_bytes(const Hash& seed, std::span<const std::uint8_t> raw) {
  Hash pk{};
  std::array<unsigned char, 64> sk{};
  Bytes signature(64);
  if (crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data()) != 0) {
    sodium_memzero(sk.data(), sk.size());
    return Error{"backend-error"};
  }
  auto status = crypto_sign_detached(signature.data(), nullptr, raw.data(), raw.size(), sk.data());
  sodium_memzero(sk.data(), sk.size());
  if (status != 0)
    return Error{"backend-error"};
  return signature;
}
Result<Bytes> invocation(std::uint8_t state, const Hash& id, std::uint64_t fence, const Hash& handle,
                         const Bytes& statement, const Bytes& signature) {
  Writer w;
  w.header("PRI1");
  w.integer(state);
  w.bytes(id);
  w.integer(fence);
  w.bytes(handle);
  w.blob(statement, 32768);
  w.blob(signature, 64);
  if (!w.ok())
    return Error{w.error};
  return w.data;
}
}  // namespace
C0Provider::Secret::~Secret() {
  sodium_memzero(seed.data(), seed.size());
}
Result<bool> C0Provider::replay(std::span<const std::uint8_t> raw) {
  if (raw.size() >= 4 && std::equal(raw.begin(), raw.begin() + 4, "PRK1")) {
    Reader r(raw);
    Secret key;
    r.header("PRK1");
    read(r, key.key);
    r.hash(key.handle);
    r.hash(key.seed);
    if (!r.ok() || r.remaining() || key.handle == Hash{} || keys_.contains(key.handle))
      return Error{"provider-key-record"};
    auto pk = public_key(key.seed);
    if (!pk.ok())
      return pk.error();
    if (key.key.public_key_ != Bytes(pk.value().begin(), pk.value().end()) || key.key.identity_ == Hash{} ||
        key.key.role_ < 1 || key.key.role_ > 5 || key.key.suite_ != 1 || key.key.parameters_ != 1 ||
        key.key.epoch_ == 0 || key.key.epoch_ == std::numeric_limits<std::uint64_t>::max() ||
        key.key.valid_from_ >= key.key.valid_until_ || key.key.capacity_domain_ != Hash{} ||
        key.key.capacity_limit_ != 0)
      return Error{"provider-key-binding"};
    keys_.emplace(key.handle, std::move(key));
    return true;
  }
  Reader r(raw);
  std::uint8_t state = 0;
  Hash id{}, handle{};
  std::uint64_t fence = 0;
  Bytes statement, signature;
  r.header("PRI1");
  r.integer(state);
  r.hash(id);
  r.integer(fence);
  r.hash(handle);
  r.blob(statement, 32768);
  r.blob(signature, 64);
  if (!r.ok() || r.remaining() || fence == 0 || !keys_.contains(handle) || state < 1 || state > 2)
    return Error{"provider-invocation-record"};
  auto hash = digest("sign-request", statement);
  if (!hash.ok())
    return hash.error();
  if (hash.value() != id)
    return Error{"provider-request-binding"};
  auto found = invocations_.find(id);
  if (state == 1) {
    if (found != invocations_.end() || !signature.empty())
      return Error{"provider-reservation-replacement"};
    invocations_.emplace(id, Invocation{fence, handle, statement, {}});
  } else {
    if (found == invocations_.end() || !found->second.signature.empty() || found->second.fence != fence ||
        found->second.handle != handle || found->second.statement != statement || signature.size() != 64)
      return Error{"provider-terminal-transition"};
    auto key = AdmittedKey::admit(keys_.at(handle).key.public_key_);
    if (!key.ok())
      return key.error();
    auto valid = key.value().verify(statement, signature);
    if (!valid.ok())
      return valid.error();
    if (!valid.value())
      return Error{"provider-result-signature"};
    found->second.signature = std::move(signature);
  }
  return true;
}
Result<std::unique_ptr<C0Provider>> C0Provider::provision(const std::string& path, MonotonicWitness& witness,
                                                          const std::vector<LocalKeyTemplate>& templates) {
  if (sodium_init() < 0)
    return Error{"backend-error"};
  if (templates.empty() || templates.size() > 10)
    return Error{"provider-provision-bound"};
  for (const auto& t : templates)
    if (t.identity == Hash{} || t.role < 1 || t.role > 5 || t.epoch == 0 ||
        t.epoch == std::numeric_limits<std::uint64_t>::max() || t.valid_from >= t.valid_until)
      return Error{"provider-template"};
  auto provider = std::unique_ptr<C0Provider>(new C0Provider(witness));
  auto log = DurableLog::open(path, true,
                              [](const LogFrontier&, std::span<const std::uint8_t>) { return Result<bool>(false); });
  if (!log.ok())
    return log.error();
  provider->log_ = std::move(log.value());
  for (const auto& t : templates) {
    Secret secret;
    randombytes_buf(secret.seed.data(), secret.seed.size());
    randombytes_buf(secret.handle.data(), secret.handle.size());
    auto pk = public_key(secret.seed);
    if (!pk.ok())
      return pk.error();
    secret.key = {
        t.identity, t.role, 1, 1, t.epoch, t.valid_from, t.valid_until, Bytes(pk.value().begin(), pk.value().end()),
        {},         0};
    Writer w;
    w.header("PRK1");
    write(w, secret.key);
    w.bytes(secret.handle);
    w.bytes(secret.seed);
    if (!w.ok())
      return Error{w.error};
    auto stored = provider->log_->append(w.data);
    if (!stored.ok()) {
      sodium_memzero(w.data.data(), w.data.size());
      return stored.error();
    }
    auto applied = provider->replay(w.data);
    sodium_memzero(w.data.data(), w.data.size());
    if (!applied.ok())
      return applied.error();
  }
  return provider;
}
Result<std::unique_ptr<C0Provider>> C0Provider::open(const std::string& path, MonotonicWitness& witness) {
  if (sodium_init() < 0)
    return Error{"backend-error"};
  auto provider = std::unique_ptr<C0Provider>(new C0Provider(witness));
  auto log = DurableLog::open(
      path, false, [&](const LogFrontier&, std::span<const std::uint8_t> raw) { return provider->replay(raw); });
  if (!log.ok())
    return log.error();
  provider->log_ = std::move(log.value());
  if (provider->keys_.empty())
    return Error{"provider-history-unavailable"};
  return provider;
}
std::vector<OpaqueKey> C0Provider::public_keys() const {
  std::vector<OpaqueKey> keys;
  for (const auto& [handle, key] : keys_)
    keys.push_back({key.key, handle});
  return keys;
}
Result<Key> C0Provider::descriptor(const Hash& handle) const {
  auto key = keys_.find(handle);
  if (key == keys_.end())
    return Error{"unknown-key"};
  return key->second.key;
}
Result<Record> C0Provider::sign(const SignRequest& request) {
  if (stopped_)
    return Error{"provider-unavailable"};
  auto current = witness_.check_fence(request.fence_);
  if (!current.ok())
    return current.error();
  if (!current.value())
    return Error{"fenced"};
  auto plan = plan_sign(request);
  if (!plan.ok())
    return plan.error();
  auto found = keys_.find(request.key_handles_[0]);
  if (found == keys_.end())
    return Error{"unknown-key"};
  const auto& key = found->second.key;
  const auto& e = plan.value().envelope;
  auto ref = key_reference(key);
  if (!ref.ok())
    return ref.error();
  const auto& c = e.record_.components_[0];
  if (ref.value() != Keyref{c.suite_, c.parameters_, c.epoch_, c.key_id_} || key.identity_ != e.record_.identity_ ||
      key.role_ != e.duty_.role_ || key.valid_from_ > e.duty_.anchor_mc_ || key.valid_until_ <= e.duty_.anchor_mc_)
    return Error{"provider-key-context"};
  auto previous = invocations_.find(request.request_id_);
  if (previous != invocations_.end()) {
    if (previous->second.fence != request.fence_ || previous->second.handle != found->first ||
        previous->second.statement != plan.value().statement)
      return Error{"provider-invocation-conflict"};
    if (previous->second.signature.empty())
      return Error{"result-uncertain"};
    Record result = e.record_;
    result.components_[0].signature_ = previous->second.signature;
    return result;
  }
  auto allowed = witness_.primitive_allowed(request.fence_, request.request_id_);
  if (!allowed.ok())
    return allowed.error();
  if (!allowed.value())
    return Error{"primitive-not-reserved"};
  auto reservation = invocation(1, request.request_id_, request.fence_, found->first, plan.value().statement, {});
  if (!reservation.ok())
    return reservation.error();
  stopped_ = true;
  auto written = log_->append(reservation.value());
  if (!written.ok())
    return written.error();
  auto applied = replay(reservation.value());
  if (!applied.ok())
    return applied.error();
  auto claim = witness_.claim_primitive(request.fence_, request.request_id_);
  if (!claim.ok())
    return claim.error();
  if (!claim.value())
    return Error{"primitive-not-reserved"};
  auto signature = sign_bytes(found->second.seed, plan.value().statement);
  if (!signature.ok())
    return signature.error();
  auto still_current = witness_.check_fence(request.fence_);
  if (!still_current.ok())
    return still_current.error();
  if (!still_current.value())
    return Error{"fenced"};
  auto complete =
      invocation(2, request.request_id_, request.fence_, found->first, plan.value().statement, signature.value());
  if (!complete.ok())
    return complete.error();
  written = log_->append(complete.value());
  if (!written.ok())
    return written.error();
  applied = replay(complete.value());
  if (!applied.ok())
    return applied.error();
  stopped_ = false;
  Record result = e.record_;
  result.components_[0].signature_ = std::move(signature.value());
  return result;
}
}  // namespace tos::auth
