#include <sodium.h>

#include "api-semantics.h"
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
                         const Bytes& statement, const Bytes& signature, bool possession = false) {
  Writer w;
  w.header(possession ? "PRP1" : "PRI1");
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
  if (raw.size() >= 4 && std::equal(raw.begin(), raw.begin() + 4, "PRA1"))
    return replay_preparation(raw);
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
  bool possession = raw.size() >= 4 && std::equal(raw.begin(), raw.begin() + 4, "PRP1");
  r.header(possession ? "PRP1" : "PRI1");
  r.integer(state);
  r.hash(id);
  r.integer(fence);
  r.hash(handle);
  r.blob(statement, 32768);
  r.blob(signature, 64);
  if (!r.ok() || r.remaining() || fence == 0 || !keys_.contains(handle) || state < 1 || state > 2)
    return Error{"provider-invocation-record"};
  auto hash = digest(possession ? "possession-request" : "sign-request", statement);
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

namespace {
bool preparation_matches(const PrepareRequest& q, const Key& k) {
  return q.identity_ == k.identity_ && q.role_ == k.role_ && q.suite_ == k.suite_ && q.parameters_ == k.parameters_ &&
         q.epoch_ == k.epoch_ && q.valid_from_ == k.valid_from_ && q.valid_until_ == k.valid_until_;
}
PrepareRequest preparation_parameters(PrepareRequest q) {
  q.fence_ = 0;
  return q;
}
}  // namespace
Result<bool> C0Provider::replay_preparation(std::span<const std::uint8_t> raw) {
  Reader r(raw);
  PrepareRequest request;
  Secret secret;
  r.header("PRA1");
  read(r, request);
  read(r, secret.key);
  r.hash(secret.handle);
  r.hash(secret.seed);
  if (!r.ok() || r.remaining() || secret.handle == Hash{} || preparations_.contains(request.preparation_id_))
    return Error{"provider-preparation-record"};
  auto encoded = encode(request);
  if (!encoded.ok())
    return encoded.error();
  ObjectReader reader({});
  auto valid = validate_api_request(3, encoded.value(), reader);
  if (!valid.ok())
    return valid.error();
  if (!valid.value() || !preparation_matches(request, secret.key) || request.suite_ != 1 || request.parameters_ != 1 ||
      secret.key.capacity_domain_ != Hash{} || secret.key.capacity_limit_ != 0)
    return Error{"provider-preparation-binding"};
  if (request.mode_ == 0) {
    if (keys_.size() >= 4096 || keys_.contains(secret.handle))
      return Error{"provider-key-capacity"};
    auto pk = public_key(secret.seed);
    if (!pk.ok())
      return pk.error();
    if (secret.key.public_key_ != Bytes(pk.value().begin(), pk.value().end()))
      return Error{"provider-preparation-secret"};
    keys_.emplace(secret.handle, secret);
  } else {
    auto old = keys_.find(request.provider_handle_);
    if (old == keys_.end() || old->first != secret.handle || old->second.key != secret.key || secret.seed != Hash{})
      return Error{"provider-preparation-handle"};
  }
  preparations_.emplace(request.preparation_id_, std::make_pair(preparation_parameters(request), secret.handle));
  return true;
}
Result<KeyHandle> C0Provider::prepare(const PrepareRequest& request) {
  if (stopped_)
    return Error{"provider-unavailable"};
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  ObjectReader reader({});
  auto valid = validate_api_request(3, raw.value(), reader);
  if (!valid.ok())
    return valid.error();
  if (!valid.value() || request.suite_ != 1 || request.parameters_ != 1)
    return Error{"disabled-suite"};
  auto old = preparations_.find(request.preparation_id_);
  if (old != preparations_.end()) {
    if (old->second.first != preparation_parameters(request))
      return Error{"preparation-conflict"};
    return KeyHandle{keys_.at(old->second.second).key, old->second.second};
  }
  auto id = api_request_id(3, raw.value());
  if (!id.ok())
    return id.error();
  auto allowed = witness_.primitive_allowed(request.fence_, id.value());
  if (!allowed.ok())
    return allowed.error();
  if (!allowed.value())
    return Error{"primitive-not-reserved"};
  Secret secret;
  if (request.mode_ == 1) {
    auto key = keys_.find(request.provider_handle_);
    if (key == keys_.end())
      return Error{"unknown-key"};
    if (!preparation_matches(request, key->second.key))
      return Error{"preparation-key-context"};
    secret.key = key->second.key;
    secret.handle = key->first;
  } else if (keys_.size() >= 4096)
    return Error{"provider-key-capacity"};
  stopped_ = true;
  auto claim = witness_.claim_primitive(request.fence_, id.value());
  if (!claim.ok())
    return claim.error();
  if (!claim.value())
    return Error{"primitive-not-reserved"};
  if (request.mode_ == 0) {
    randombytes_buf(secret.seed.data(), secret.seed.size());
    do {
      randombytes_buf(secret.handle.data(), secret.handle.size());
    } while (secret.handle == Hash{} || keys_.contains(secret.handle));
    auto pk = public_key(secret.seed);
    if (!pk.ok())
      return pk.error();
    secret.key = {request.identity_,
                  request.role_,
                  1,
                  1,
                  request.epoch_,
                  request.valid_from_,
                  request.valid_until_,
                  Bytes(pk.value().begin(), pk.value().end()),
                  {},
                  0};
  }
  Writer w;
  w.header("PRA1");
  write(w, request);
  write(w, secret.key);
  w.bytes(secret.handle);
  w.bytes(secret.seed);
  if (!w.ok()) {
    sodium_memzero(w.data.data(), w.data.size());
    return Error{w.error};
  }
  auto appended = log_->append(w.data);
  if (!appended.ok()) {
    sodium_memzero(w.data.data(), w.data.size());
    return appended.error();
  }
  auto applied = replay_preparation(w.data);
  sodium_memzero(w.data.data(), w.data.size());
  if (!applied.ok())
    return applied.error();
  auto current = witness_.check_fence(request.fence_);
  if (!current.ok())
    return current.error();
  if (!current.value())
    return Error{"fenced"};
  stopped_ = false;
  return KeyHandle{secret.key, secret.handle};
}
Result<PossessionAuth> C0Provider::prove_possession(const ChainContext& chain, const StageRequest& request) {
  if (stopped_)
    return Error{"provider-unavailable"};
  auto current = witness_.check_fence(request.fence_);
  if (!current.ok())
    return current.error();
  if (!current.value())
    return Error{"fenced"};
  auto raw = encode(request);
  if (!raw.ok())
    return raw.error();
  auto plan = plan_operation(4, raw.value(), chain);
  if (!plan.ok())
    return plan.error();
  auto key = keys_.find(request.handle_);
  if (key == keys_.end())
    return Error{"unknown-key"};
  if (key->second.key != request.key_)
    return Error{"provider-possession-key"};
  auto statement = possession_preimage(chain, request.update_, request.key_);
  if (!statement.ok())
    return statement.error();
  auto uid = object_id("update", request.update_);
  if (!uid.ok())
    return uid.error();
  auto ref = key_reference(request.key_);
  if (!ref.ok())
    return ref.error();
  const auto& id = plan.value().reservation;
  auto previous = invocations_.find(id);
  if (previous != invocations_.end()) {
    if (previous->second.handle != request.handle_ || previous->second.statement != statement.value() ||
        previous->second.fence != request.fence_)
      return Error{"provider-possession-conflict"};
    if (previous->second.signature.empty())
      return Error{"result-uncertain"};
    return PossessionAuth{uid.value(), ref.value(), previous->second.signature};
  }
  auto allowed = witness_.primitive_allowed(request.fence_, id);
  if (!allowed.ok())
    return allowed.error();
  if (!allowed.value())
    return Error{"primitive-not-reserved"};
  auto reserved = invocation(1, id, request.fence_, request.handle_, statement.value(), {}, true);
  if (!reserved.ok())
    return reserved.error();
  stopped_ = true;
  auto stored = log_->append(reserved.value());
  if (!stored.ok())
    return stored.error();
  auto applied = replay(reserved.value());
  if (!applied.ok())
    return applied.error();
  auto claimed = witness_.claim_primitive(request.fence_, id);
  if (!claimed.ok())
    return claimed.error();
  if (!claimed.value())
    return Error{"primitive-not-reserved"};
  auto signature = sign_bytes(key->second.seed, statement.value());
  if (!signature.ok())
    return signature.error();
  current = witness_.check_fence(request.fence_);
  if (!current.ok())
    return current.error();
  if (!current.value())
    return Error{"fenced"};
  auto complete = invocation(2, id, request.fence_, request.handle_, statement.value(), signature.value(), true);
  if (!complete.ok())
    return complete.error();
  stored = log_->append(complete.value());
  if (!stored.ok())
    return stored.error();
  applied = replay(complete.value());
  if (!applied.ok())
    return applied.error();
  stopped_ = false;
  return PossessionAuth{uid.value(), ref.value(), signature.value()};
}
}  // namespace tos::auth
