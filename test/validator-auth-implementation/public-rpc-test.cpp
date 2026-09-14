#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "validator/auth/api-routes.h"
#include "validator/auth/api-semantics.h"
#include "validator/auth/public-rpc.h"

#include "node-history-adapter-fixture.h"

namespace {
namespace auth = tos::auth;
namespace history_fixture = p0_node_history_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

template <class T>
T require_value(auth::Result<T> result, const std::string& assertion) {
  require(result.ok(), assertion);
  return std::move(result.value());
}

auth::Hash h(std::uint32_t value) {
  auth::Hash result{};
  result[28] = static_cast<std::uint8_t>(value >> 24);
  result[29] = static_cast<std::uint8_t>(value >> 16);
  result[30] = static_cast<std::uint8_t>(value >> 8);
  result[31] = static_cast<std::uint8_t>(value);
  return result;
}

auth::ChainContext chain() {
  return {-239, h(11), h(12), h(13)};
}

std::string hex(const auth::Hash& value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(value.size() * 2);
  for (const auto byte : value) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}

auth::Anchor anchor() {
  return {100, h(21), h(22), h(23)};
}

std::uint16_t methods(std::initializer_list<unsigned> values) {
  std::uint16_t result = 0;
  for (auto method : values) {
    require(method >= 1 && method <= 15, "method-mask-input");
    result = static_cast<std::uint16_t>(
        result | static_cast<std::uint16_t>(
                     std::uint16_t{1} << (method - 1)));
  }
  return result;
}

struct WireRequest {
  std::uint8_t method{};
  auth::Hash request_id{};
  auth::HttpRequest http;
};

WireRequest request(std::uint8_t method, const auth::Bytes& payload) {
  require(method >= 1 && method <= auth::api_routes.size(),
          "wire-method");
  auto id = require_value(
      auth::api_request_id(method, payload), "wire-request-id");
  auto frame = require_value(
      auth::encode_transport_frame(
          {method, id, payload, false, false}),
      "wire-frame");
  const auto& route = auth::api_routes[method - 1];
  return {
      method,
      id,
      {std::string(route.verb), std::string(route.path),
       std::string(auth::api_media_type), frame}};
}

auth::TransportFrame response(
    const WireRequest& request, const auth::HttpResponse& http,
    const std::string& assertion) {
  return require_value(
      auth::decode_transport_frame(
          http.body, request.method, true, &request.request_id),
      assertion);
}

void expect_api_error(
    const WireRequest& request, const auth::HttpResponse& http,
    std::uint16_t code, bool retryable,
    const std::string& assertion) {
  auto frame = response(request, http, assertion);
  require(frame.error, assertion);
  auto error = require_value(
      auth::decode<auth::ApiError>(frame.payload), assertion);
  require(
      error.code_ == code &&
          bool(error.retryable_) == retryable,
      assertion);
}

class ScriptedTransport final
    : public auth::AuthenticatedHttpTransport {
 public:
  auth::Hash principal{};
  auth::HttpRequest request;
  std::optional<auth::HttpResponse> response;

  auth::Result<bool> serve_one(
      const Handler& handler, unsigned) override {
    if (!handler)
      return auth::Error{"fixture-handler"};
    auto result = handler(principal, request);
    if (!result.ok())
      return result.error();
    response = std::move(result.value());
    return true;
  }
};

template <class Service>
auth::HttpResponse serve(
    Service& service, const auth::Hash& principal,
    const auth::HttpRequest& request, std::uint64_t now,
    const std::string& assertion) {
  ScriptedTransport transport;
  transport.principal = principal;
  transport.request = request;
  auto served = service.serve_one(transport, now, 1);
  require(
      served.ok() && served.value() &&
          transport.response.has_value(),
      assertion);
  return std::move(*transport.response);
}

class ProbeRpc final : public auth::ClientRpc {
 public:
  enum class Mode {
    ok,
    budget_over,
    budget_exact,
    source_error,
    archive_error,
  };

  Mode mode = Mode::ok;
  auth::ObjectValue source_value;
  unsigned calls = 0;
  auth::Anchor probe_anchor{};
  auth::Hash probe_digest{}, probe_policy{};

  auth::Result<auth::Bytes> call(
      std::uint8_t, const auth::Bytes&, const auth::Hash&,
      std::uint64_t, auth::ObjectReader& reader) override {
    ++calls;

    if (mode == Mode::archive_error)
      return auth::Error{"archive-offline"};

    if (mode == Mode::source_error) {
      auto loaded = reader.resolve(source_value, 5);
      if (!loaded.ok()) {
        if (reader.source_error())
          return *reader.source_error();
        return loaded.error();
      }
      return auth::Bytes{1};
    }

    if (mode == Mode::budget_over ||
        mode == Mode::budget_exact) {
      auth::ObjectValue inline_value{
          5, auth::Bytes(auth::inline_bytes, 0x5a), {}};
      const std::size_t count =
          mode == Mode::budget_over ? 1025 : 1024;
      for (std::size_t i = 0; i < count; ++i) {
        auto loaded = reader.resolve(inline_value, 5);
        if (!loaded.ok())
          return loaded.error();
      }
    }

    // A canonical method-8 result, not a placeholder. The response is validated
    // on the way out, so returning loose bytes makes every successful path look
    // like a service failure and the case can never show what it claims.
    auth::ProfileResult result;
    result.anchor_ = probe_anchor;
    result.interface_digest_ = probe_digest;
    result.policy_ = probe_policy;
    result.installed_ = {{1, 1}};
    result.active_ = {{1, 1}};
    result.can_parse_ = 1;
    result.can_verify_ = 1;
    result.proof_.anchor_ = probe_anchor;
    result.proof_.kind_ = 1;
    result.proof_.object_id_ = probe_digest;
    result.proof_.proof_hash_ = probe_policy;
    result.proof_.proof_ = auth::ObjectValue{5, auth::Bytes{0x01}, {}};
    auto encoded = auth::encode(result);
    if (!encoded.ok())
      return encoded.error();
    return encoded.value();
  }
};

std::unique_ptr<auth::PublicClientService> public_service(
    auth::ChainContext context, std::vector<auth::ApiAccess> access,
    auth::ScopedObjectStore& objects, auth::ClientRpc& rpc,
    const std::string& assertion) {
  return require_value(
      auth::PublicClientService::create(
          std::move(context), std::move(access), objects, rpc),
      assertion);
}

struct StoredObject {
  auth::Bytes raw;
  auth::ObjectRef manifest;
  auth::ObjectValue carrier;
};

StoredObject small_object(std::uint8_t fill) {
  auth::Bytes raw(auth::inline_bytes + 1, fill);
  auto carrier =
      require_value(auth::object_value(5, raw), "small-object");
  require(
      carrier.reference_.size() == 1, "small-object-manifest");
  return {std::move(raw), carrier.reference_[0],
          std::move(carrier)};
}

WireRequest put(
    const auth::Anchor& scope, const StoredObject& object) {
  auto payload = require_value(
      auth::encode(auth::PutChunkRequest{
          scope, object.manifest, 0, object.raw}),
      "put-request");
  return request(15, payload);
}

WireRequest get(
    const auth::Anchor& scope, const StoredObject& object) {
  auto payload = require_value(
      auth::encode(auth::ChunkRequest{
          scope, object.manifest, 0}),
      "get-request");
  return request(14, payload);
}

WireRequest profile(const auth::Anchor& scope) {
  return request(
      8,
      require_value(
          auth::encode(auth::GetProfileRequest{scope}),
          "profile-request"));
}

std::string raw_http_exchange(
    const std::string& socket_path, const WireRequest& wire,
    std::string_view extra_header,
    const std::string& assertion) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  require(fd >= 0, assertion);

  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  require(
      !socket_path.empty() &&
          socket_path.size() < sizeof(address.sun_path),
      assertion);
  std::copy(
      socket_path.begin(), socket_path.end(),
      address.sun_path);

  if (::connect(
          fd, reinterpret_cast<const sockaddr*>(&address),
          sizeof(address)) != 0) {
    ::close(fd);
    throw AssertionFailure(assertion);
  }

  const auto& request = wire.http;
  std::string head =
      request.verb + " " + request.path +
      " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" +
      "Content-Length: " +
      std::to_string(request.body.size()) + "\r\n";
  if (!request.content_type.empty())
    head += "Content-Type: " + request.content_type + "\r\n";
  if (!extra_header.empty()) {
    head.append(extra_header.data(), extra_header.size());
    head += "\r\n";
  }
  head += "\r\n";

  auto send_all = [&](std::string_view bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
      const auto remaining =
          bytes.size() - offset;
      const auto count = ::send(
          fd, bytes.data() + offset, remaining, 0);
      if (count <= 0) {
        ::close(fd);
        throw AssertionFailure(assertion);
      }
      offset += static_cast<std::size_t>(count);
    }
  };

  send_all(head);
  send_all(request.body);

  std::string response;
  std::array<char, 4096> buffer{};
  for (;;) {
    const auto count =
        ::recv(fd, buffer.data(), buffer.size(), 0);
    if (count == 0)
      break;
    if (count < 0) {
      ::close(fd);
      throw AssertionFailure(assertion);
    }
    response.append(
        buffer.data(), static_cast<std::size_t>(count));
  }
  ::close(fd);

  const auto split = response.find("\r\n\r\n");
  require(split != std::string::npos, assertion);
  return response.substr(split + 4);
}

auth::ObjectRef large_manifest(auth::Bytes& first_chunk) {
  auth::ObjectRef result{
      5, 67108864, h(5000),
      std::vector<auth::Hash>(64, h(5001))};
  first_chunk.assign(auth::chunk_bytes, 0x33);

  auth::Bytes preimage(
      result.object_id_.begin(), result.object_id_.end());
  preimage.push_back(0);
  preimage.insert(
      preimage.end(), first_chunk.begin(), first_chunk.end());

  result.chunk_hashes_[0] = require_value(
      auth::digest("object-chunk", preimage),
      "large-manifest-hash");
  return result;
}

auth::HttpResponse put_large(
    auth::PublicClientService& service,
    const auth::Hash& principal, const auth::Anchor& scope,
    const auth::ObjectRef& manifest, const auth::Bytes& chunk,
    std::uint64_t now, const std::string& assertion) {
  auto payload = require_value(
      auth::encode(auth::PutChunkRequest{
          scope, manifest, 0, chunk}),
      assertion);
  auto wire = request(15, payload);
  return serve(
      service, principal, wire.http, now, assertion);
}

using Test =
    std::pair<std::string, std::function<void()>>;

std::vector<Test> tests(
    const std::filesystem::path& owner_inputs,
    const std::filesystem::path& committee_fixtures) {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("transport_principal_only", [=] {
    const auto context = chain();
    const auto principal = h(100);
    const auto spoofed = h(101);
    const auto scope = anchor();

    auth::ScopedObjectStore objects;
    ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
    auto service = public_service(
        context,
        {
            {principal, context.chain_domain,
             methods({14, 15}), {}},
            {spoofed, context.chain_domain,
             methods({14, 15}), {}},
        },
        objects, rpc, "transport_principal_only");

    std::string directory =
        (std::filesystem::temp_directory_path() /
         "p0-public-rpc-XXXXXX")
            .string();
    require(
        ::mkdtemp(directory.data()) != nullptr,
        "transport_principal_only");
    struct Cleanup {
      std::filesystem::path path;
      ~Cleanup() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
      }
    } cleanup{directory};
    require(
        ::chmod(directory.c_str(), 0700) == 0,
        "transport_principal_only");

    const auto socket =
        (std::filesystem::path(directory) / "rpc.sock").string();
    auto transport = require_value(
        auth::LocalAuthenticatedHttpTransport::create(
            socket, ::geteuid(), principal),
        "transport_principal_only");

    auto object = small_object(7);
    auto upload = put(scope, object);

    auth::Result<bool> served(false);
    std::jthread server([&] {
      served = service->serve_one(
          *transport, 1, 1000);
    });

    const auto spoofed_header =
        std::string("X-Principal: ") + hex(spoofed);
    const auto raw_response = raw_http_exchange(
        socket, upload, spoofed_header,
        "transport_principal_only");
    server.join();

    require(
        served.ok() && served.value(),
        "transport_principal_only");
    auth::HttpResponse uploaded{
        200, std::string(auth::api_media_type),
        raw_response};
    auto uploaded_frame = response(
        upload, uploaded, "transport_principal_only");
    require(
        !uploaded_frame.error,
        "transport_principal_only");

    auto download = get(scope, object);
    auto hidden = serve(
        *service, spoofed, download.http, 1,
        "transport_principal_only");
    expect_api_error(
        download, hidden, 13, false,
        "transport_principal_only");

    auto visible = serve(
        *service, principal, download.http, 1,
        "transport_principal_only");
    auto visible_frame = response(
        download, visible, "transport_principal_only");
    require(
        !visible_frame.error,
        "transport_principal_only");
  });

  add("client_only_methods", [=] {
    const auto context = chain();
    const auto principal = h(200);

    auth::ScopedObjectStore objects;
    ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
    auto service = public_service(
        context,
        {{principal, context.chain_domain, 0x7fff, {}}},
        objects, rpc, "client_only_methods");

    // A well-formed private request, not arbitrary bytes. Three loose bytes are
    // refused by the request grammar before authorisation is ever consulted, so
    // the refusal would prove that the decoder works rather than that a public
    // principal cannot reach a private method.
    auth::PrepareRequest prepare{h(8000), h(8001), 1, 1, 1, 2, 100, 1000, 0, {}, 1};
    auto private_payload =
        require_value(auth::encode(prepare), "client_only_methods");
    auto private_request = request(3, private_payload);
    auto denied = serve(
        *service, principal, private_request.http, 1,
        "client_only_methods");

    require(
        denied.status == 403, "client_only_methods");
    expect_api_error(
        private_request, denied, 2, false,
        "client_only_methods");
    require(rpc.calls == 0, "client_only_methods");
  });

  add("reader_operation_budget", [=] {
    const auto context = chain();
    const auto principal = h(300);
    const auto scope = anchor();

    auth::ScopedObjectStore objects;
    ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
    auto service = public_service(
        context,
        {{principal, context.chain_domain,
          methods({8}), {}}},
        objects, rpc, "reader_operation_budget");

    auto query = profile(scope);

    rpc.mode = ProbeRpc::Mode::budget_over;
    auto bounded = serve(
        *service, principal, query.http, 1,
        "reader_operation_budget");
    expect_api_error(
        query, bounded, 12, true,
        "reader_operation_budget");

    rpc.mode = ProbeRpc::Mode::budget_exact;
    auto first = serve(
        *service, principal, query.http, 1,
        "reader_operation_budget");
    auto first_frame = response(
        query, first, "reader_operation_budget");
    require(
        !first_frame.error, "reader_operation_budget");

    auto second = serve(
        *service, principal, query.http, 1,
        "reader_operation_budget");
    auto second_frame = response(
        query, second, "reader_operation_budget");
    require(
        !second_frame.error, "reader_operation_budget");
  });

  add("source_outage_provenance", [=] {
    const auto context = chain();
    const auto principal = h(400);
    const auto scope = anchor();

    auth::ScopedObjectStore objects;
    ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
    auto service = public_service(
        context,
        {{principal, context.chain_domain,
          methods({8, 15}), {}}},
        objects, rpc, "source_outage_provenance");

    auto object = small_object(9);
    auto upload = put(scope, object);
    auto uploaded = serve(
        *service, principal, upload.http, 10,
        "source_outage_provenance");
    auto upload_frame = response(
        upload, uploaded, "source_outage_provenance");
    require(
        !upload_frame.error, "source_outage_provenance");

    rpc.mode = ProbeRpc::Mode::source_error;
    rpc.source_value = object.carrier;
    auto query = profile(scope);
    auto storage = serve(
        *service, principal, query.http, 9,
        "source_outage_provenance");
    expect_api_error(
        query, storage, 10, true,
        "source_outage_provenance");

    rpc.mode = ProbeRpc::Mode::archive_error;
    auto archive = serve(
        *service, principal, query.http, 10,
        "source_outage_provenance");
    expect_api_error(
        query, archive, 12, true,
        "source_outage_provenance");
  });

  add("quota_classification_and_expiry", [=] {
    const auto context = chain();
    const auto scope = anchor();
    const auto principal = h(500);

    {
      auth::ScopedObjectStore objects;
      ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
      auto service = public_service(
          context,
          {{principal, context.chain_domain,
            methods({15}), {}}},
          objects, rpc,
          "quota_classification_and_expiry");

      for (std::uint8_t fill = 1; fill <= 4; ++fill) {
        auto object = small_object(fill);
        auto upload = put(scope, object);
        auto response_http = serve(
            *service, principal, upload.http, 1,
            "quota_classification_and_expiry");
        auto frame = response(
            upload, response_http,
            "quota_classification_and_expiry");
        require(
            !frame.error,
            "quota_classification_and_expiry");
      }

      auto fifth_object = small_object(5);
      auto fifth = put(scope, fifth_object);
      auto refused = serve(
          *service, principal, fifth.http, 1,
          "quota_classification_and_expiry");
      expect_api_error(
          fifth, refused, 10, true,
          "quota_classification_and_expiry");

      auto reclaimed = serve(
          *service, principal, fifth.http, 62,
          "quota_classification_and_expiry");
      auto reclaimed_frame = response(
          fifth, reclaimed,
          "quota_classification_and_expiry");
      require(
          !reclaimed_frame.error,
          "quota_classification_and_expiry");
    }

    {
      auth::ScopedObjectStore objects;
      ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
      auto service = public_service(
          context,
          {{principal, context.chain_domain,
            methods({15}), {}}},
          objects, rpc,
          "quota_classification_and_expiry");

      auth::Bytes first_chunk;
      auto manifest = large_manifest(first_chunk);
      auto large = put_large(
          *service, principal, scope, manifest, first_chunk, 1,
          "quota_classification_and_expiry");
      auto large_request = request(
          15,
          require_value(
              auth::encode(auth::PutChunkRequest{
                  scope, manifest, 0, first_chunk}),
              "quota_classification_and_expiry"));
      auto large_frame = response(
          large_request, large,
          "quota_classification_and_expiry");
      require(
          !large_frame.error,
          "quota_classification_and_expiry");

      auto small = small_object(6);
      auto small_put = put(scope, small);
      auto bytes_refused = serve(
          *service, principal, small_put.http, 1,
          "quota_classification_and_expiry");
      expect_api_error(
          small_put, bytes_refused, 10, true,
          "quota_classification_and_expiry");
    }

    {
      auto object = small_object(7);
      auth::ScopedObjectStore objects(object.raw.size());
      ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
      const auto first_principal = h(510);
      const auto second_principal = h(511);
      auto service = public_service(
          context,
          {
              {first_principal, context.chain_domain,
               methods({15}), {}},
              {second_principal, context.chain_domain,
               methods({15}), {}},
          },
          objects, rpc,
          "quota_classification_and_expiry");

      auto upload = put(scope, object);
      auto first = serve(
          *service, first_principal, upload.http, 1,
          "quota_classification_and_expiry");
      require(
          !response(
               upload, first,
               "quota_classification_and_expiry")
               .error,
          "quota_classification_and_expiry");

      auto second = serve(
          *service, second_principal, upload.http, 1,
          "quota_classification_and_expiry");
      expect_api_error(
          upload, second, 10, true,
          "quota_classification_and_expiry");
    }

    {
      auto object = small_object(8);
      auth::ScopedObjectStore objects;
      ProbeRpc rpc;
    rpc.probe_anchor = anchor();
    rpc.probe_digest = h(9001);
    rpc.probe_policy = h(9002);
      std::vector<auth::ApiAccess> access;
      access.reserve(1025);
      for (std::uint32_t i = 1; i <= 1025; ++i) {
        access.push_back(
            {h(10000 + i), context.chain_domain,
             methods({15}), {}});
      }
      auto service = public_service(
          context, std::move(access), objects, rpc,
          "quota_classification_and_expiry");

      auto upload = put(scope, object);
      for (std::uint32_t i = 1; i <= 1024; ++i) {
        auto admitted = serve(
            *service, h(10000 + i), upload.http, 1,
            "quota_classification_and_expiry");
        require(
            !response(
                 upload, admitted,
                 "quota_classification_and_expiry")
                 .error,
            "quota_classification_and_expiry");
      }

      const auto next = h(11025);
      auto table_full = serve(
          *service, next, upload.http, 1,
          "quota_classification_and_expiry");
      expect_api_error(
          upload, table_full, 10, true,
          "quota_classification_and_expiry");

      auto after_expiry = serve(
          *service, next, upload.http, 62,
          "quota_classification_and_expiry");
      require(
          !response(
               upload, after_expiry,
               "quota_classification_and_expiry")
               .error,
          "quota_classification_and_expiry");
    }
  });

  add("native_history_composition", [=] {
    auto fixture = history_fixture::make_fixture(
        owner_inputs, committee_fixtures);

    auto history = require_value(
        auth::NativeNodeHistoryAdapter::open(
            fixture.head_state, fixture.head,
            fixture.chain, fixture.readers()),
        "native_history_composition");

    const auto principal = h(600);
    auto service = require_value(
        auth::NativePublicRpcService::create(
            *history,
            {{principal, fixture.chain.chain_domain,
              methods({8}), {}}}),
        "native_history_composition");

    auto query = profile(fixture.head);
    auto http = serve(
        *service, principal, query.http, 1,
        "native_history_composition");
    auto frame = response(
        query, http, "native_history_composition");
    require(
        !frame.error, "native_history_composition");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3 || argc > 4) {
    std::cerr
        << "USAGE: test-p0-public-rpc "
           "OWNER_INPUTS COMMITTEE_FIXTURES "
           "[case-name|--list|--exclude=case]\n";
    return 2;
  }

  const std::filesystem::path owner_inputs(argv[1]);
  const std::filesystem::path committee_fixtures(argv[2]);
  const auto all = tests(owner_inputs, committee_fixtures);

  if (argc == 4 && std::string_view(argv[3]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }

  std::string selected;
  std::string excluded;
  if (argc == 4) {
    std::string argument(argv[3]);
    constexpr std::string_view prefix = "--exclude=";
    if (argument.starts_with(prefix))
      excluded = argument.substr(prefix.size());
    else
      selected = std::move(argument);
  }

  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (!selected.empty() && name != selected)
      continue;
    if (!excluded.empty() && name == excluded)
      continue;

    try {
      std::cout << "SETUP_OK " << name << '\n';
      fn();
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    } catch (const AssertionFailure& error) {
      std::cerr << "ASSERTION_FAILED "
                << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION " << name
                << ": " << error.what() << '\n';
      return 2;
    }
  }

  if (ran == 0) {
    std::cerr << "UNKNOWN_CASE\n";
    return 2;
  }

  std::cout << "SUMMARY cases=" << ran
            << " passed=" << ran << '\n';
  return 0;
}
