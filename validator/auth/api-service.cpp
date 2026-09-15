#include "api-routes.h"
#include "api-semantics.h"
#include "api-service.h"
#include "client-api-common.h"
namespace tos::auth {
namespace {
std::uint16_t code(const Error& error) {
  return api_error_code(error);
}
Result<HttpResponse> failure(std::uint8_t method, const Hash& id, std::uint16_t error_code,
                             std::uint8_t state) {
  return api_failure_response(method, id, error_code, state);
}
Result<bool> allowed_identity(const ApiAccess& access, const Hash& identity) {
  if (!access.identities.contains(identity))
    return Error{"api-unauthorized"};
  return true;
}
Result<Anchor> request_anchor(std::uint8_t method, const Bytes& raw) {
  return client_request_anchor(method, raw);
}
bool same_chain(const ChainContext& chain, const PermitBody& body) {
  return chain.network == body.network_ && chain.genesis_root == body.genesis_root_ &&
         chain.genesis_file == body.genesis_file_;
}
template <class T>
Result<Bytes> encoded(Result<T> value) {
  if (!value.ok())
    return value.error();
  return encode(value.value());
}
}  // namespace
SignerApi::SignerApi(ChainContext chain, std::vector<ApiAccess> access, SafetyLedger& ledger, SignerService& signer,
                     AdminSignerService& admin, C0SigningProvider& provider,
                     std::function<Result<std::vector<OpaqueKey>>()> keys, ScopedObjectStore& objects, ClientRpc& rpc)
    : chain_(chain)
    , ledger_(ledger)
    , signer_(signer)
    , admin_(admin)
    , provider_(provider)
    , public_keys_(std::move(keys))
    , objects_(objects)
    , rpc_(rpc) {
  if (chain.chain_domain == Hash{} || chain.genesis_root == Hash{} || chain.genesis_file == Hash{} || access.empty() ||
      access.size() > 1024 || !public_keys_)
    return;
  for (auto& rule : access) {
    if (rule.principal == Hash{} || rule.chain_domain != chain.chain_domain || rule.methods == 0 ||
        (rule.methods & 0x8000) || rule.identities.size() > 4096 || rule.identities.contains(Hash{}) ||
        access_.contains(rule.principal))
      return;
    access_.emplace(rule.principal, std::move(rule));
  }
  configured_ = true;
}
Result<Bytes> SignerApi::invoke(const TransportFrame& frame, const ApiAccess& access, std::uint64_t now) {
  const auto method = frame.method;
  if (method >= 8 && method <= 13) {
    auto anchor = request_anchor(method, frame.payload);
    if (!anchor.ok())
      return anchor.error();
    ObjectReader reader([&](const ObjectRef& ref, std::uint8_t index) {
      return objects_.get(access.principal, anchor.value(), ref, index, now);
    });
    // Native RPC owns proof resolution/verification once. Re-running its proof
    // decoder here would charge the same attachment against the budget twice.
    return rpc_.call(method, frame.payload, access.principal, now, reader);
  }
  ObjectReader reader({});
  auto valid = validate_api_request(method, frame.payload, reader);
  if (!valid.ok() || !valid.value())
    return Error{"api-bad-request"};
  switch (method) {
    case 1:
      return encode(Capabilities{interface_fingerprint, {{1, 1}}, {{1, 1}}, 2000000, 2000000, 1, 1, 0});
    case 2: {
      auto q = decode<PublicRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto keys = public_keys_();
      if (!keys.ok())
        return keys.error();
      if (keys.value().size() > 4096)
        return Error{"provider-key-capacity"};
      for (const auto& key : keys.value()) {
        auto id = object_id("key", key.descriptor);
        if (!id.ok())
          return id.error();
        if (id.value() != q.value().key_id_)
          continue;
        auto allowed = allowed_identity(access, key.descriptor.identity_);
        if (!allowed.ok())
          return allowed.error();
        auto actual = provider_.descriptor(key.handle);
        if (!actual.ok())
          return actual.error();
        if (actual.value() != key.descriptor)
          return Error{"provider-descriptor-binding"};
        return encode(actual.value());
      }
      return Error{"unknown-key"};
    }
    case 3: {
      auto q = decode<PrepareRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto allowed = allowed_identity(access, q.value().identity_);
      if (!allowed.ok())
        return allowed.error();
      return encoded(admin_.prepare(q.value()));
    }
    case 4: {
      auto q = decode<StageRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto allowed = allowed_identity(access, q.value().update_.identity_);
      if (!allowed.ok())
        return allowed.error();
      if (!same_chain(chain_, q.value().permit_.body_))
        return Error{"operation-chain"};
      return encoded(admin_.stage(q.value()));
    }
    case 5: {
      auto q = decode<SignRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto plan = plan_sign(q.value());
      if (!plan.ok())
        return plan.error();
      const auto& duty = plan.value().envelope.duty_;
      if (duty.network_ != chain_.network || duty.genesis_root_ != chain_.genesis_root ||
          duty.genesis_file_ != chain_.genesis_file)
        return Error{"operation-chain"};
      auto allowed = allowed_identity(access, plan.value().envelope.record_.identity_);
      if (!allowed.ok())
        return allowed.error();
      return encoded(signer_.sign(q.value()));
    }
    case 6: {
      auto q = decode<ResultRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto state = ledger_.get(q.value().request_id_);
      if (!state.ok())
        return state.error();
      if (state.value().state_ != 0) {
        auto original = ledger_.original(q.value().request_id_);
        if (!original.ok())
          return original.error();
        const auto& duty = original.value().plan.envelope.duty_;
        if (duty.network_ != chain_.network || duty.genesis_root_ != chain_.genesis_root ||
            duty.genesis_file_ != chain_.genesis_file)
          return Error{"operation-chain"};
        auto allowed = allowed_identity(access, original.value().plan.envelope.record_.identity_);
        if (!allowed.ok())
          return allowed.error();
      }
      return encode(state.value());
    }
    case 7: {
      auto q = decode<RetireRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto allowed = allowed_identity(access, q.value().update_.identity_);
      if (!allowed.ok())
        return allowed.error();
      if (!same_chain(chain_, q.value().permit_.body_))
        return Error{"operation-chain"};
      return encoded(admin_.retire(q.value()));
    }
    case 14: {
      auto q = decode<ChunkRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto data = objects_.get(access.principal, q.value().anchor_, q.value().manifest_, q.value().index_, now);
      if (!data.ok())
        return data.error();
      auto id = object_id("object_ref", q.value().manifest_);
      if (!id.ok())
        return id.error();
      return encode(ChunkResult{q.value().anchor_, id.value(), q.value().index_, data.value()});
    }
    case 15: {
      auto q = decode<PutChunkRequest>(frame.payload);
      if (!q.ok())
        return q.error();
      auto stored = objects_.put(access.principal, q.value().anchor_, q.value().manifest_, q.value().index_,
                                 q.value().data_, now);
      if (!stored.ok())
        return stored.error();
      return encode(PutChunkResult{q.value().anchor_, stored.value(), q.value().index_});
    }
    default:
      return Error{"unsupported-profile"};
  }
}
Result<HttpResponse> SignerApi::dispatch(const Hash& principal, const HttpRequest& request, std::uint64_t now) {
  if (!configured_)
    return Error{"api-configuration"};
  const ApiRoute* route = nullptr;
  for (const auto& entry : api_routes)
    if (entry.path == request.path)
      route = &entry;
  if (!route)
    return HttpResponse{404, "", ""};
  if (request.verb != route->verb || request.body.size() > 4194304 ||
      (route->method != 1 && request.content_type != api_media_type) || (route->method == 1 && !request.body.empty()))
    return failure(route->method, {}, 1, 0);
  Result<TransportFrame> parsed(Error{"request"});
  if (route->method == 1) {
    auto raw = encode(CapabilitiesRequest{});
    if (!raw.ok())
      return raw.error();
    parsed = TransportFrame{1, {}, raw.value(), false, false};
  } else
    parsed = decode_transport_frame(request.body, route->method);
  if (!parsed.ok())
    return failure(route->method, {}, 1, 0);
  const auto& frame = parsed.value();
  auto rule = access_.find(principal);
  if (rule == access_.end() || rule->second.chain_domain != chain_.chain_domain ||
      !(rule->second.methods & (std::uint16_t{1} << (route->method - 1))))
    return failure(route->method, frame.request_id, 2, 4);
  auto result = invoke(frame, rule->second, now);
  if (!result.ok()) {
    if (result.error().code == "api-unauthorized")
      return failure(frame.method, frame.request_id, 2, 4);
    if (result.error().code == "api-bad-request")
      return failure(frame.method, frame.request_id, 1, 4);
    std::uint8_t state = 0;
    if (frame.method == 5 || frame.method == 6) {
      auto known = ledger_.get(frame.request_id);
      state = known.ok() ? known.value().state_ : 4;
    } else if (frame.method == 3 || frame.method == 4 || frame.method == 7) {
      auto known = ledger_.operation(frame.request_id);
      state = !known.ok() ? 4 : !known.value() ? 0 : known.value()->result.empty() ? 1 : 2;
    }
    return failure(frame.method, frame.request_id, code(result.error()), state);
  }
  auto json = encode_transport_frame({frame.method, frame.request_id, result.value(), true, false});
  if (!json.ok())
    return failure(frame.method, frame.request_id, 12, 4);
  return HttpResponse{200, std::string(api_media_type), json.value()};
}
}  // namespace tos::auth
