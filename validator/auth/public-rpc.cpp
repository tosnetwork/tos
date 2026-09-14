#include "public-rpc.h"

#include "api-routes.h"
#include "api-semantics.h"
#include "validator/auth/client-api-common.h"

namespace tos::auth {
namespace {

bool public_client_method(std::uint8_t method) {
  return method >= 8 && method <= 15;
}

Result<std::uint16_t> method_bit(std::uint8_t method) {
  if (method == 0 || method > 15)
    return Error{"unsupported-profile"};
  return static_cast<std::uint16_t>(
      std::uint16_t{1} << static_cast<unsigned>(method - 1));
}

const ApiRoute* route_for(std::string_view path) {
  for (const auto& route : api_routes)
    if (route.path == path)
      return &route;
  return nullptr;
}

}  // namespace

Result<std::unique_ptr<LocalAuthenticatedHttpTransport>>
LocalAuthenticatedHttpTransport::create(
    const std::string& path, uid_t admitted_os_principal,
    Hash authenticated_principal) {
  if (authenticated_principal == Hash{})
    return Error{"api-principal"};

  auto listener = LocalListener::create(path, admitted_os_principal);
  if (!listener.ok())
    return listener.error();

  return std::unique_ptr<LocalAuthenticatedHttpTransport>(
      new LocalAuthenticatedHttpTransport(
          std::move(listener.value()), authenticated_principal));
}

Result<bool> LocalAuthenticatedHttpTransport::serve_one(
    const Handler& handler, unsigned timeout) {
  if (!handler)
    return Error{"api-handler"};

  return listener_->serve_http_one(
      [this, &handler](const HttpRequest& request) {
        return handler(principal_, request);
      },
      timeout);
}

Result<std::unique_ptr<PublicClientService>> PublicClientService::create(
    ChainContext chain, std::vector<ApiAccess> access,
    ScopedObjectStore& objects, ClientRpc& rpc) {
  if (chain.chain_domain == Hash{} || chain.genesis_root == Hash{} ||
      chain.genesis_file == Hash{} || access.empty() ||
      access.size() > public_access_limit)
    return Error{"api-configuration"};

  std::map<Hash, ApiAccess> admitted;
  for (auto& rule : access) {
    if (rule.principal == Hash{} ||
        rule.chain_domain != chain.chain_domain ||
        rule.methods == 0 || (rule.methods & 0x8000) ||
        rule.identities.size() > 4096 ||
        rule.identities.contains(Hash{}) ||
        admitted.contains(rule.principal))
      return Error{"api-configuration"};
    admitted.emplace(rule.principal, std::move(rule));
  }

  return std::unique_ptr<PublicClientService>(
      new PublicClientService(
          std::move(chain), std::move(admitted), objects, rpc));
}

Result<Bytes> PublicClientService::invoke(
    const TransportFrame& frame, const ApiAccess& access,
    std::uint64_t now) {
  const auto method = frame.method;

  if (method >= 8 && method <= 13) {
    auto anchor = client_request_anchor(method, frame.payload);
    if (!anchor.ok())
      return anchor.error();

    ObjectReader reader(
        [&](const ObjectRef& ref, std::uint8_t index) {
          return objects_.get(
              access.principal, anchor.value(), ref, index, now);
        });
    return rpc_.call(
        method, frame.payload, access.principal, now, reader);
  }

  if (method == 14 || method == 15) {
    ObjectReader structural_reader({});
    auto valid =
        validate_api_request(method, frame.payload, structural_reader);
    if (!valid.ok())
      return valid.error();
    if (!valid.value())
      return Error{"api-bad-request"};
  }

  if (method == 14) {
    auto request = decode<ChunkRequest>(frame.payload);
    if (!request.ok())
      return request.error();

    auto data = objects_.get(
        access.principal, request.value().anchor_,
        request.value().manifest_, request.value().index_, now);
    if (!data.ok())
      return data.error();

    auto id = object_id("object_ref", request.value().manifest_);
    if (!id.ok())
      return id.error();

    return encode(
        ChunkResult{
            request.value().anchor_, id.value(),
            request.value().index_, data.value()});
  }

  if (method == 15) {
    auto request = decode<PutChunkRequest>(frame.payload);
    if (!request.ok())
      return request.error();

    auto stored = objects_.put(
        access.principal, request.value().anchor_,
        request.value().manifest_, request.value().index_,
        request.value().data_, now);
    if (!stored.ok())
      return stored.error();

    return encode(
        PutChunkResult{
            request.value().anchor_, stored.value(),
            request.value().index_});
  }

  return Error{"unsupported-profile"};
}

Result<HttpResponse> PublicClientService::dispatch(
    const Hash& principal, const HttpRequest& request,
    std::uint64_t now) {
  const auto* route = route_for(request.path);
  if (route == nullptr)
    return HttpResponse{404, "", ""};

  if (request.verb != route->verb ||
      request.body.size() > 4194304 ||
      (route->method != 1 &&
       request.content_type != api_media_type) ||
      (route->method == 1 && !request.body.empty()))
    return api_failure_response(route->method, {}, 1, 0);

  Result<TransportFrame> parsed(Error{"request"});
  if (route->method == 1) {
    auto raw = encode(CapabilitiesRequest{});
    if (!raw.ok())
      return raw.error();
    parsed =
        TransportFrame{1, {}, raw.value(), false, false};
  } else {
    parsed =
        decode_transport_frame(request.body, route->method);
  }
  if (!parsed.ok())
    return api_failure_response(route->method, {}, 1, 0);

  const auto& frame = parsed.value();
  auto rule = access_.find(principal);
  if (rule == access_.end() ||
      rule->second.chain_domain != chain_.chain_domain)
    return api_failure_response(
        route->method, frame.request_id, 2, 4);

  if (!public_client_method(route->method))
    return api_failure_response(route->method, frame.request_id, 2, 4);

  auto bit = method_bit(route->method);
  if (!bit.ok())
    return bit.error();
  if (!(rule->second.methods & bit.value()))
    return api_failure_response(
        route->method, frame.request_id, 2, 4);

  auto result = invoke(frame, rule->second, now);
  if (!result.ok()) {
    if (result.error().code == "api-unauthorized")
      return api_failure_response(
          frame.method, frame.request_id, 2, 4);
    if (result.error().code == "api-bad-request")
      return api_failure_response(
          frame.method, frame.request_id, 1, 4);
    const auto classification = api_error_code(result.error());
    return api_failure_response(
        frame.method, frame.request_id, classification, 0);
  }

  auto response = encode_transport_frame(
      {frame.method, frame.request_id, result.value(), true, false});
  if (!response.ok())
    return api_failure_response(
        frame.method, frame.request_id, 12, 4);

  return HttpResponse{
      200, std::string(api_media_type), response.value()};
}

Result<bool> PublicClientService::serve_one(
    AuthenticatedHttpTransport& transport, std::uint64_t now,
    unsigned timeout) {
  return transport.serve_one(
      [this, now](
          const Hash& principal,
          const HttpRequest& request) {
        return dispatch(principal, request, now);
      },
      timeout);
}

Result<std::unique_ptr<NativePublicRpcService>>
NativePublicRpcService::create(
    const NativeNodeHistoryAdapter& source,
    std::vector<ApiAccess> access, std::size_t global_storage_bytes,
    std::uint64_t storage_ttl_seconds) {
  auto chain = source.chain_context();
  if (!chain.ok())
    return chain.error();

  auto result = std::unique_ptr<NativePublicRpcService>(
      new NativePublicRpcService(
          source, chain.value().network, global_storage_bytes,
          storage_ttl_seconds));

  auto service = PublicClientService::create(
      chain.value(), std::move(access), result->objects_,
      result->rpc_);
  if (!service.ok())
    return service.error();

  result->service_ = std::move(service.value());
  return result;
}

Result<bool> NativePublicRpcService::serve_one(
    AuthenticatedHttpTransport& transport, std::uint64_t now,
    unsigned timeout) {
  if (!service_)
    return Error{"api-configuration"};
  return service_->serve_one(transport, now, timeout);
}

}  // namespace tos::auth
