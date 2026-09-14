#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "validator/auth/api-routes.h"
#include "validator/auth/api-semantics.h"
#include "validator/auth/crypto.h"
#include "validator/auth/remote-transport.h"

namespace {
namespace auth = tos::auth;

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

template <class T>
T canonical(const T& value, const std::string& assertion) {
  auto raw = require_value(auth::encode(value), assertion);
  auto decoded = require_value(auth::decode<T>(raw), assertion);
  auto roundtrip = require_value(auth::encode(decoded), assertion);
  require(roundtrip == raw, assertion);
  return decoded;
}

auth::Hash h(std::uint32_t value) {
  auth::Hash result{};
  result[28] = static_cast<std::uint8_t>(value >> 24);
  result[29] = static_cast<std::uint8_t>(value >> 16);
  result[30] = static_cast<std::uint8_t>(value >> 8);
  result[31] = static_cast<std::uint8_t>(value);
  return result;
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

auth::Bytes certificate(std::uint8_t marker) {
  auth::Bytes value(64, marker);
  value[0] = 0x30;
  value[1] = 0x3e;
  return value;
}

auth::Hash certificate_id(const auth::Bytes& certificate_bytes) {
  return require_value(
      auth::digest("remote-peer-certificate", certificate_bytes),
      "certificate-id");
}

class LocalConfig final
    : public auth::AuthenticatedLocalRemotePeerConfig {
 public:
  std::vector<auth::RemotePeerBinding> bindings;

  auth::Result<std::vector<auth::RemotePeerBinding>>
  load() const override {
    return bindings;
  }
};

std::unique_ptr<auth::InstalledRemotePeerTrust> trust(
    const auth::Bytes& certificate_bytes,
    const auth::Hash& principal) {
  LocalConfig config;
  config.bindings.push_back(
      {certificate_id(certificate_bytes), principal});
  return require_value(
      auth::InstalledRemotePeerTrust::load(config),
      "installed-remote-trust");
}

auth::RemoteTlsHandshakeOutcome handshake(
    const auth::Bytes& certificate_bytes) {
  return {
      true,
      true,
      auth::remote_tls13_version,
      certificate_bytes};
}

auth::RemoteDecodedRequest canonical_request() {
  auth::Anchor anchor{
      100, h(21), h(22), h(23)};
  anchor = canonical(anchor, "request-anchor");

  auto query = canonical(
      auth::GetProfileRequest{anchor},
      "profile-request");
  auto raw = require_value(
      auth::encode(query), "profile-request-raw");
  auto id = require_value(
      auth::api_request_id(8, raw),
      "profile-request-id");
  auto body = require_value(
      auth::encode_transport_frame(
          {8, id, raw, false, false}),
      "profile-transport-frame");

  const auto& route = auth::api_routes[7];
  auth::RemoteDecodedRequest result;
  result.request = {
      std::string(route.verb),
      std::string(route.path),
      std::string(auth::api_media_type),
      body};
  result.header_bytes = 128;
  result.headers = {
      {"host", "validator.example"},
      {"content-type", std::string(auth::api_media_type)}};
  return result;
}

class HandshakeSource final
    : public auth::RemoteTlsHandshakeSource {
 public:
  auth::RemoteTlsHandshakeOutcome outcome;
  unsigned calls = 0;
  unsigned timeout = 0;
  std::chrono::steady_clock::time_point deadline{};

  auth::Result<auth::RemoteTlsHandshakeOutcome> accept(
      unsigned accept_timeout_ms,
      std::chrono::steady_clock::time_point absolute_io_deadline)
      override {
    ++calls;
    timeout = accept_timeout_ms;
    deadline = absolute_io_deadline;
    return outcome;
  }
};

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests() {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("certificate_principal_only", [] {
    const auto certificate_a = certificate(1);
    const auto principal_a = h(100);
    const auto principal_b = h(101);
    auto installed = trust(certificate_a, principal_a);
    auth::RemoteAuthenticatedRequestGate gate(*installed);

    auto request = canonical_request();
    request.headers.push_back(
        {"x-principal", hex(principal_b)});

    auth::Hash observed{};
    auto response = gate.dispatch(
        handshake(certificate_a), request,
        [&](const auth::Hash& principal,
            const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          observed = principal;
          return auth::HttpResponse{
              200, std::string(auth::api_media_type), ""};
        });

    require(
        response.ok() && observed == principal_a &&
            observed != principal_b,
        "certificate_principal_only");
  });

  add("unmapped_certificate_refused", [] {
    const auto configured = certificate(2);
    const auto unconfigured = certificate(3);
    auto installed = trust(configured, h(200));
    auth::RemoteAuthenticatedRequestGate gate(*installed);

    auto result = gate.authenticate(handshake(unconfigured));
    require(
        !result.ok() &&
            result.error().code == "remote-principal-unmapped",
        "unmapped_certificate_refused");
  });

  add("verified_chain_required", [] {
    const auto certificate_a = certificate(14);
    auto installed = trust(certificate_a, h(250));
    auth::RemoteAuthenticatedRequestGate gate(*installed);

    auto outcome = handshake(certificate_a);
    outcome.certificate_chain_verified = false;
    auto result = gate.authenticate(outcome);
    require(
        !result.ok() &&
            result.error().code ==
                "remote-certificate-unverified",
        "verified_chain_required");
  });

  add("client_certificate_required", [] {
    const auto certificate_a = certificate(4);
    auto installed = trust(certificate_a, h(300));
    auth::RemoteAuthenticatedRequestGate gate(*installed);

    auto outcome = handshake(certificate_a);
    outcome.client_certificate_present = false;
    auto result = gate.authenticate(outcome);
    require(
        !result.ok() &&
            result.error().code ==
                "remote-client-certificate-required",
        "client_certificate_required");
  });

  add("tls13_only", [] {
    const auto certificate_a = certificate(5);
    auto installed = trust(certificate_a, h(400));
    auth::RemoteAuthenticatedRequestGate gate(*installed);

    auto outcome = handshake(certificate_a);
    outcome.negotiated_version = 0x0303;
    auto result = gate.authenticate(outcome);
    require(
        !result.ok() &&
            result.error().code == "remote-tls-version",
        "tls13_only");
  });

  add("header_byte_bound", [] {
    const auto certificate_a = certificate(6);
    auto installed = trust(certificate_a, h(500));
    auth::RemoteAuthenticatedRequestGate gate(*installed);
    auto request = canonical_request();
    request.header_bytes =
        auth::http_transport_max_header_bytes + 1;

    bool invoked = false;
    auto result = gate.dispatch(
        handshake(certificate_a), request,
        [&](const auth::Hash&,
            const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          invoked = true;
          return auth::HttpResponse{};
        });
    require(
        !result.ok() &&
            result.error().code == "http-header-bound" &&
            !invoked,
        "header_byte_bound");
  });

  add("header_count_bound", [] {
    const auto certificate_a = certificate(7);
    auto installed = trust(certificate_a, h(600));
    auth::RemoteAuthenticatedRequestGate gate(*installed);
    auto request = canonical_request();
    request.headers.clear();
    for (std::size_t i = 0;
         i <= auth::http_transport_max_headers; ++i)
      request.headers.push_back(
          {"x-field-" + std::to_string(i), "v"});

    auto result = gate.dispatch(
        handshake(certificate_a), request,
        [](const auth::Hash&,
           const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{};
        });
    require(
        !result.ok() &&
            result.error().code == "http-header",
        "header_count_bound");
  });

  add("body_size_bound", [] {
    const auto certificate_a = certificate(8);
    auto installed = trust(certificate_a, h(700));
    auth::RemoteAuthenticatedRequestGate gate(*installed);

    auth::RemoteDecodedRequest request;
    request.request = {
        "POST", "/bounded-body", "application/octet-stream",
        std::string(
            auth::http_transport_max_body_bytes + 1, 'x')};
    request.header_bytes = 64;
    request.headers = {{"host", "validator.example"}};

    auto result = gate.dispatch(
        handshake(certificate_a), request,
        [](const auth::Hash&,
           const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{};
        });
    require(
        !result.ok() &&
            result.error().code == "http-request-bound",
        "body_size_bound");
  });

  add("absolute_io_deadline", [] {
    const auto start =
        std::chrono::steady_clock::time_point{};
    const auto deadline =
        auth::http_transport_deadline(start);
    require(
        deadline - start == auth::http_transport_io_timeout &&
            auth::bounded_http_accept_timeout(0) == 1 &&
            auth::bounded_http_accept_timeout(6000) ==
                auth::http_transport_max_accept_timeout_ms,
        "absolute_io_deadline");
  });

  add("duplicate_header_refused", [] {
    const auto certificate_a = certificate(9);
    auto installed = trust(certificate_a, h(800));
    auth::RemoteAuthenticatedRequestGate gate(*installed);
    auto request = canonical_request();
    request.headers.push_back({"host", "second.example"});

    auto result = gate.dispatch(
        handshake(certificate_a), request,
        [](const auth::Hash&,
           const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{};
        });
    require(
        !result.ok() &&
            result.error().code == "http-duplicate-header",
        "duplicate_header_refused");
  });

  add("transfer_encoding_refused", [] {
    const auto certificate_a = certificate(10);
    auto installed = trust(certificate_a, h(900));
    auth::RemoteAuthenticatedRequestGate gate(*installed);
    auto request = canonical_request();
    request.headers.push_back(
        {"transfer-encoding", "chunked"});

    auto result = gate.dispatch(
        handshake(certificate_a), request,
        [](const auth::Hash&,
           const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{};
        });
    require(
        !result.ok() &&
            result.error().code == "http-unsupported-framing",
        "transfer_encoding_refused");
  });

  add("compression_refused", [] {
    const auto certificate_a = certificate(11);
    auto installed = trust(certificate_a, h(1000));
    auth::RemoteAuthenticatedRequestGate gate(*installed);
    auto request = canonical_request();
    request.headers.push_back(
        {"content-encoding", "gzip"});

    auto result = gate.dispatch(
        handshake(certificate_a), request,
        [](const auth::Hash&,
           const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{};
        });
    require(
        !result.ok() &&
            result.error().code == "http-unsupported-framing",
        "compression_refused");
  });

  add("redirect_refused", [] {
    require(
        auth::http_transport_response_status_allowed(200) &&
            !auth::http_transport_response_status_allowed(302),
        "redirect_refused");
  });

  add("protocol_upgrade_refused", [] {
    const auto certificate_a = certificate(12);
    auto installed = trust(certificate_a, h(1100));
    auth::RemoteAuthenticatedRequestGate gate(*installed);
    auto request = canonical_request();
    request.headers.push_back(
        {"upgrade", "other-protocol"});

    auto result = gate.dispatch(
        handshake(certificate_a), request,
        [](const auth::Hash&,
           const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{};
        });
    require(
        !result.ok() &&
            result.error().code == "http-unsupported-framing",
        "protocol_upgrade_refused");
  });

  add("framing_boundary_refuses", [] {
    const auto certificate_a = certificate(13);
    auto installed = trust(certificate_a, h(1200));

    HandshakeSource source;
    source.outcome = handshake(certificate_a);
    auth::RemoteTlsAuthenticatedHttpTransport transport(
        *installed, source);

    bool invoked = false;
    auto before = std::chrono::steady_clock::now();
    auto result = transport.serve_one(
        [&](const auth::Hash&,
            const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          invoked = true;
          return auth::HttpResponse{};
        },
        6000);
    auto after = std::chrono::steady_clock::now();

    require(
        !result.ok() &&
            result.error().code == "http2-framing-unavailable" &&
            !invoked && source.calls == 1 &&
            source.timeout ==
                auth::http_transport_max_accept_timeout_ms &&
            source.deadline >= before &&
            source.deadline <=
                auth::http_transport_deadline(after),
        "framing_boundary_refuses");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 2) {
    std::cerr << "USAGE: test-p0-remote-transport "
                 "[case-name|--list|--exclude=case]\n";
    return 2;
  }

  const auto all = tests();
  if (argc == 2 && std::string_view(argv[1]) == "--list") {
    for (const auto& item : all)
      std::cout << item.first << '\n';
    return 0;
  }

  std::string selected;
  std::string excluded;
  if (argc == 2) {
    std::string argument(argv[1]);
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
      std::cerr << "ASSERTION_FAILED " << error.what() << '\n';
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
