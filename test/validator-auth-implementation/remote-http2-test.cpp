#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
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
#include "validator/auth/remote-http2.h"

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

auth::Bytes certificate() {
  auth::Bytes value(64, 0x51);
  value[0] = 0x30;
  value[1] = 0x3e;
  return value;
}

class LocalConfig final : public auth::AuthenticatedLocalRemotePeerConfig {
 public:
  std::vector<auth::RemotePeerBinding> bindings;

  auth::Result<std::vector<auth::RemotePeerBinding>> load() const override {
    return bindings;
  }
};

std::unique_ptr<auth::InstalledRemotePeerTrust> installed(
    const auth::Bytes& cert, const auth::Hash& principal) {
  auto id = require_value(
      auth::digest("remote-peer-certificate", cert), "certificate-id");
  LocalConfig config;
  config.bindings.push_back({id, principal});
  return require_value(
      auth::InstalledRemotePeerTrust::load(config), "remote-trust");
}

auth::RemoteTlsHandshakeOutcome handshake(const auth::Bytes& cert) {
  return {true, true, auth::remote_tls13_version, cert};
}

void append(auth::Bytes& out, std::span<const std::uint8_t> bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_setting(auth::Bytes& out, std::uint16_t id, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(id >> 8));
  out.push_back(static_cast<std::uint8_t>(id));
  out.push_back(static_cast<std::uint8_t>(value >> 24));
  out.push_back(static_cast<std::uint8_t>(value >> 16));
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value));
}

struct Wire {
  auth::Bytes input;
  auth::Bytes body;
  std::string path;
  std::size_t settings_offset = 0;
  std::size_t initial_window_value_offset = 0;
  std::size_t headers_frame_offset = 0;
  std::size_t headers_payload_offset = 0;
  std::size_t first_representation_offset = 0;
  std::size_t first_name_length_offset = 0;
  std::size_t content_length_value_offset = 0;
  std::size_t second_data_frame_offset = 0;
};

void append_literal(
    auth::Bytes& block, std::string_view name, std::string_view value,
    std::optional<std::size_t>& value_offset) {
  auto encoded = require_value(
      auth::encode_remote_http2_literal_header(name, value), "hpack-literal");
  const auto start = block.size();
  append(block, encoded);
  if (value_offset) {
    require(name.size() < 0x7f && value.size() < 0x7f, "hpack-offset-bound");
    *value_offset = start + 1 + 1 + name.size() + 1;
  }
}

Wire valid_wire() {
  auth::Anchor anchor{100, h(21), h(22), h(23)};
  anchor = canonical(anchor, "wire-anchor");
  auto query = canonical(auth::GetProfileRequest{anchor}, "wire-query");
  auto payload = require_value(auth::encode(query), "wire-query-raw");
  auto request_id = require_value(auth::api_request_id(8, payload), "wire-request-id");
  auto body = require_value(
      auth::encode_transport_frame({8, request_id, payload, false, false}),
      "wire-transport-frame");
  require(body.size() >= 2, "wire-body-size");

  Wire wire;
  wire.body.assign(body.begin(), body.end());
  wire.path = std::string(auth::api_routes[7].path);
  append(wire.input, auth::remote_http2_client_preface());

  auth::Bytes settings;
  append_setting(settings, 1, 0);
  append_setting(settings, 3, 1);
  const auto window_setting = settings.size();
  append_setting(settings, 4, auth::remote_http2_initial_window);
  append_setting(settings, 5, auth::remote_http2_frame_bytes);
  append_setting(settings, 6, auth::http_transport_max_header_bytes);
  wire.settings_offset = wire.input.size();
  wire.initial_window_value_offset = wire.settings_offset + 9 + window_setting + 2;
  auto settings_frame = require_value(
      auth::encode_remote_http2_frame(
          auth::RemoteHttp2FrameType::settings, 0, 0, settings),
      "settings-frame");
  append(wire.input, settings_frame);

  auth::Bytes headers;
  std::optional<std::size_t> unused;
  append_literal(headers, ":method", "POST", unused);
  append_literal(headers, ":path", wire.path, unused);
  append_literal(headers, ":scheme", "https", unused);
  append_literal(headers, ":authority", "validator.example", unused);
  append_literal(headers, "content-type", auth::api_media_type, unused);
  std::optional<std::size_t> content_length_offset = 0;
  const auto length = std::to_string(wire.body.size());
  append_literal(headers, "content-length", length, content_length_offset);
  append_literal(headers, "x-principal", "peer-asserted", unused);

  wire.headers_frame_offset = wire.input.size();
  wire.headers_payload_offset = wire.headers_frame_offset + 9;
  wire.first_representation_offset = wire.headers_payload_offset;
  wire.first_name_length_offset = wire.headers_payload_offset + 1;
  wire.content_length_value_offset =
      wire.headers_payload_offset + *content_length_offset;
  auto headers_frame = require_value(
      auth::encode_remote_http2_frame(
          auth::RemoteHttp2FrameType::headers,
          auth::remote_http2_flag_end_headers, 1, headers),
      "headers-frame");
  append(wire.input, headers_frame);

  const auto split = wire.body.size() / 2;
  auto first = require_value(
      auth::encode_remote_http2_frame(
          auth::RemoteHttp2FrameType::data, 0, 1,
          std::span<const std::uint8_t>(wire.body.data(), split)),
      "first-data-frame");
  append(wire.input, first);
  wire.second_data_frame_offset = wire.input.size();
  auto second = require_value(
      auth::encode_remote_http2_frame(
          auth::RemoteHttp2FrameType::data,
          auth::remote_http2_flag_end_stream, 1,
          std::span<const std::uint8_t>(
              wire.body.data() + split, wire.body.size() - split)),
      "second-data-frame");
  append(wire.input, second);
  return wire;
}

class MemorySource final : public auth::RemoteTlsHttp2Source {
 public:
  auth::RemoteTlsHandshakeOutcome outcome;
  auth::Bytes input;
  auth::Bytes output;
  std::size_t offset = 0;
  std::size_t largest_read = 0;
  bool read_past_input = false;

  auth::Result<auth::RemoteTlsHandshakeOutcome> accept(
      unsigned,
      std::chrono::steady_clock::time_point) override {
    return outcome;
  }

  auth::Result<auth::Bytes> read_exact(
      std::size_t bytes,
      std::chrono::steady_clock::time_point) override {
    largest_read = std::max(largest_read, bytes);
    if (offset > input.size() || bytes > input.size() - offset) {
      read_past_input = true;
      return auth::Error{"fixture-eof"};
    }
    auth::Bytes result(input.begin() + static_cast<std::ptrdiff_t>(offset),
                       input.begin() + static_cast<std::ptrdiff_t>(offset + bytes));
    offset += bytes;
    return result;
  }

  auth::Result<bool> write_all(
      std::span<const std::uint8_t> bytes,
      std::chrono::steady_clock::time_point) override {
    output.insert(output.end(), bytes.begin(), bytes.end());
    return true;
  }
};

struct OutputFrame {
  auth::RemoteHttp2FrameType type;
  std::uint8_t flags;
  std::uint32_t stream;
  auth::Bytes payload;
};

OutputFrame output_frame(
    const auth::Bytes& bytes, std::size_t& offset,
    const std::string& assertion) {
  require(offset <= bytes.size() && bytes.size() - offset >= 9, assertion);
  const auto length =
      (static_cast<std::size_t>(bytes[offset]) << 16) |
      (static_cast<std::size_t>(bytes[offset + 1]) << 8) |
      static_cast<std::size_t>(bytes[offset + 2]);
  require(length <= auth::remote_http2_frame_bytes, assertion);
  require(bytes.size() - offset - 9 >= length, assertion);
  const auto type = static_cast<auth::RemoteHttp2FrameType>(bytes[offset + 3]);
  const auto flags = bytes[offset + 4];
  const auto stream =
      (static_cast<std::uint32_t>(bytes[offset + 5] & 0x7f) << 24) |
      (static_cast<std::uint32_t>(bytes[offset + 6]) << 16) |
      (static_cast<std::uint32_t>(bytes[offset + 7]) << 8) |
      static_cast<std::uint32_t>(bytes[offset + 8]);
  const auto begin = offset + 9;
  auth::Bytes payload(bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                      bytes.begin() + static_cast<std::ptrdiff_t>(begin + length));
  offset = begin + length;
  return {type, flags, stream, std::move(payload)};
}

void expect_failure(Wire wire, std::string_view code, const std::string& assertion) {
  const auto cert = certificate();
  auto trust = installed(cert, h(500));
  MemorySource source;
  source.outcome = handshake(cert);
  source.input = std::move(wire.input);
  auth::RemoteHttp2AuthenticatedHttpTransport transport(*trust, source);
  bool invoked = false;
  auto result = transport.serve_one(
      [&](const auth::Hash&, const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
        invoked = true;
        return auth::HttpResponse{200, std::string(auth::api_media_type), "ok"};
      });
  require(!result.ok() && result.error().code == code && !invoked, assertion);
}

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests() {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("single_stream_round_trip", [] {
    auto wire = valid_wire();
    const auto cert = certificate();
    const auto principal = h(600);
    auto trust = installed(cert, principal);
    MemorySource source;
    source.outcome = handshake(cert);
    source.input = wire.input;
    auth::RemoteHttp2AuthenticatedHttpTransport transport(*trust, source);
    auth::Hash observed{};
    auth::HttpRequest request;
    auto served = transport.serve_one(
        [&](const auth::Hash& authenticated,
            const auth::HttpRequest& received) -> auth::Result<auth::HttpResponse> {
          observed = authenticated;
          request = received;
          return auth::HttpResponse{200, std::string(auth::api_media_type), "ok"};
        });
    require(served.ok() && served.value() && observed == principal &&
                request.verb == "POST" && request.path == wire.path &&
                request.body == std::string(wire.body.begin(), wire.body.end()),
            "single_stream_round_trip");

    std::size_t offset = 0;
    auto settings = output_frame(source.output, offset, "single_stream_round_trip");
    auto ack = output_frame(source.output, offset, "single_stream_round_trip");
    auto headers = output_frame(source.output, offset, "single_stream_round_trip");
    auto data = output_frame(source.output, offset, "single_stream_round_trip");
    require(settings.type == auth::RemoteHttp2FrameType::settings &&
                settings.stream == 0 && ack.type == auth::RemoteHttp2FrameType::settings &&
                ack.flags == auth::remote_http2_flag_ack &&
                headers.type == auth::RemoteHttp2FrameType::headers &&
                (headers.flags & auth::remote_http2_flag_end_headers) != 0 &&
                data.type == auth::RemoteHttp2FrameType::data &&
                data.flags == auth::remote_http2_flag_end_stream && data.stream == 1 &&
                std::string(data.payload.begin(), data.payload.end()) == "ok" &&
                offset == source.output.size(),
            "single_stream_round_trip");
  });

  add("preface_required", [] {
    auto wire = valid_wire();
    wire.input[0] ^= 1;
    expect_failure(std::move(wire), "http2-preface", "preface_required");
  });

  add("frame_size_bound", [] {
    auto wire = valid_wire();
    wire.input[wire.headers_frame_offset] = 0;
    wire.input[wire.headers_frame_offset + 1] = 0x40;
    wire.input[wire.headers_frame_offset + 2] = 0x01;
    const auto cert = certificate();
    auto trust = installed(cert, h(700));
    MemorySource source;
    source.outcome = handshake(cert);
    source.input = wire.input;
    auth::RemoteHttp2AuthenticatedHttpTransport transport(*trust, source);
    auto result = transport.serve_one(
        [](const auth::Hash&, const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{};
        });
    require(!result.ok() && result.error().code == "http2-frame-size" &&
                !source.read_past_input,
            "frame_size_bound");
  });

  add("continuation_spanning_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.headers_frame_offset + 4] &=
        static_cast<std::uint8_t>(~auth::remote_http2_flag_end_headers);
    expect_failure(std::move(wire), "http2-continuation",
                   "continuation_spanning_refused");
  });

  add("dynamic_table_setting_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.settings_offset + 9 + 5] = 1;
    expect_failure(std::move(wire), "http2-hpack-dynamic",
                   "dynamic_table_setting_refused");
  });

  add("indexed_field_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.first_representation_offset] = 0x80;
    expect_failure(std::move(wire), "http2-hpack-indexed",
                   "indexed_field_refused");
  });

  add("incremental_indexing_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.first_representation_offset] = 0x40;
    expect_failure(std::move(wire), "http2-hpack-dynamic",
                   "incremental_indexing_refused");
  });

  add("huffman_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.first_name_length_offset] |= 0x80;
    expect_failure(std::move(wire), "http2-hpack-huffman", "huffman_refused");
  });

  add("multiplexing_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.second_data_frame_offset + 8] = 3;
    expect_failure(std::move(wire), "http2-multiplexing", "multiplexing_refused");
  });

  add("trailers_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.second_data_frame_offset + 3] =
        static_cast<std::uint8_t>(auth::RemoteHttp2FrameType::headers);
    expect_failure(std::move(wire), "http2-trailers", "trailers_refused");
  });

  add("push_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.headers_frame_offset + 3] =
        static_cast<std::uint8_t>(auth::RemoteHttp2FrameType::push_promise);
    expect_failure(std::move(wire), "http2-push", "push_refused");
  });

  add("priority_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.headers_frame_offset + 3] =
        static_cast<std::uint8_t>(auth::RemoteHttp2FrameType::priority);
    expect_failure(std::move(wire), "http2-priority", "priority_refused");
  });

  add("window_update_refused", [] {
    auto wire = valid_wire();
    wire.input[wire.second_data_frame_offset + 3] =
        static_cast<std::uint8_t>(auth::RemoteHttp2FrameType::window_update);
    expect_failure(std::move(wire), "http2-flow-control", "window_update_refused");
  });

  add("fixed_initial_window_setting", [] {
    auto wire = valid_wire();
    require(wire.initial_window_value_offset + 4 <= wire.input.size(),
            "fixed_initial_window_setting");
    wire.input[wire.initial_window_value_offset + 3] ^= 1;
    expect_failure(std::move(wire), "http2-flow-control",
                   "fixed_initial_window_setting");
  });

  add("content_length_binding", [] {
    auto wire = valid_wire();
    require(wire.content_length_value_offset < wire.input.size(),
            "content_length_binding");
    auto& digit = wire.input[wire.content_length_value_offset];
    require(digit >= '0' && digit <= '9', "content_length_binding");
    digit = digit == '9' ? '8' : static_cast<std::uint8_t>(digit + 1);
    expect_failure(std::move(wire), "http2-content-length", "content_length_binding");
  });

  add("response_initial_window_bound", [] {
    auto wire = valid_wire();
    const auto cert = certificate();
    auto trust = installed(cert, h(800));
    MemorySource source;
    source.outcome = handshake(cert);
    source.input = wire.input;
    auth::RemoteHttp2AuthenticatedHttpTransport transport(*trust, source);
    auto result = transport.serve_one(
        [](const auth::Hash&, const auth::HttpRequest&) -> auth::Result<auth::HttpResponse> {
          return auth::HttpResponse{
              200, std::string(auth::api_media_type),
              std::string(auth::remote_http2_initial_window + 1, 'x')};
        });
    require(!result.ok() && result.error().code == "http2-response-bound",
            "response_initial_window_bound");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 2) {
    std::cerr << "USAGE: test-p0-remote-http2 [case-name|--list|--exclude=case]\n";
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
      std::cerr << "UNEXPECTED_EXCEPTION " << name << ": " << error.what() << '\n';
      return 2;
    }
  }

  if (ran == 0) {
    std::cerr << "UNKNOWN_CASE\n";
    return 2;
  }
  std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
  return 0;
}