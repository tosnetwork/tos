#include "remote-http2.h"

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace tos::auth {
namespace {

constexpr std::array<std::uint8_t, 24> client_preface{
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
    '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'};

constexpr std::uint8_t flag_padded = 0x08;
constexpr std::uint8_t flag_priority = 0x20;

struct Frame {
  RemoteHttp2FrameType type = RemoteHttp2FrameType::data;
  std::uint8_t flags = 0;
  std::uint32_t stream = 0;
  Bytes payload;
};

Result<Bytes> read_exact(
    RemoteTlsHttp2Source& source, std::size_t size,
    std::chrono::steady_clock::time_point deadline) {
  auto bytes = source.read_exact(size, deadline);
  if (!bytes.ok())
    return bytes.error();
  if (bytes.value().size() != size)
    return Error{"http2-io"};
  return std::move(bytes.value());
}

Result<Frame> read_frame(
    RemoteTlsHttp2Source& source,
    std::chrono::steady_clock::time_point deadline) {
  auto raw_header = read_exact(source, 9, deadline);
  if (!raw_header.ok())
    return raw_header.error();
  const auto& header = raw_header.value();

  const std::size_t length =
      (static_cast<std::size_t>(header[0]) << 16) |
      (static_cast<std::size_t>(header[1]) << 8) |
      static_cast<std::size_t>(header[2]);
  if (length > remote_http2_frame_bytes)
    return Error{"http2-frame-size"};
  if ((header[5] & 0x80) != 0)
    return Error{"http2-stream-id"};

  const std::uint32_t stream =
      (static_cast<std::uint32_t>(header[5]) << 24) |
      (static_cast<std::uint32_t>(header[6]) << 16) |
      (static_cast<std::uint32_t>(header[7]) << 8) |
      static_cast<std::uint32_t>(header[8]);
  auto payload = read_exact(source, length, deadline);
  if (!payload.ok())
    return payload.error();
  if (header[3] > static_cast<std::uint8_t>(RemoteHttp2FrameType::continuation))
    return Error{"http2-frame-type"};
  return Frame{static_cast<RemoteHttp2FrameType>(header[3]), header[4], stream,
               std::move(payload.value())};
}

Result<bool> write_bytes(
    RemoteTlsHttp2Source& source,
    std::span<const std::uint8_t> bytes,
    std::chrono::steady_clock::time_point deadline) {
  auto written = source.write_all(bytes, deadline);
  if (!written.ok())
    return written.error();
  if (!written.value())
    return Error{"http2-io"};
  return true;
}

Result<bool> write_frame(
    RemoteTlsHttp2Source& source, RemoteHttp2FrameType type,
    std::uint8_t flags, std::uint32_t stream,
    std::span<const std::uint8_t> payload,
    std::chrono::steady_clock::time_point deadline) {
  auto frame = encode_remote_http2_frame(type, flags, stream, payload);
  if (!frame.ok())
    return frame.error();
  return write_bytes(source, frame.value(), deadline);
}

void append_setting(Bytes& out, std::uint16_t id, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(id >> 8));
  out.push_back(static_cast<std::uint8_t>(id));
  out.push_back(static_cast<std::uint8_t>(value >> 24));
  out.push_back(static_cast<std::uint8_t>(value >> 16));
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value));
}

Result<bool> send_server_settings(
    RemoteTlsHttp2Source& source,
    std::chrono::steady_clock::time_point deadline) {
  Bytes settings;
  append_setting(settings, 1, 0);
  append_setting(settings, 3, 1);
  append_setting(settings, 4, remote_http2_initial_window);
  append_setting(settings, 5, remote_http2_frame_bytes);
  append_setting(settings, 6, http_transport_max_header_bytes);
  return write_frame(source, RemoteHttp2FrameType::settings, 0, 0, settings, deadline);
}

Result<bool> admit_client_settings(const Frame& frame) {
  if (frame.type != RemoteHttp2FrameType::settings || frame.stream != 0 ||
      (frame.flags & remote_http2_flag_ack) != 0 || frame.flags != 0 ||
      frame.payload.size() % 6 != 0)
    return Error{"http2-settings"};

  for (std::size_t offset = 0; offset < frame.payload.size(); offset += 6) {
    const auto id = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(frame.payload[offset]) << 8) |
        frame.payload[offset + 1]);
    const auto value =
        (static_cast<std::uint32_t>(frame.payload[offset + 2]) << 24) |
        (static_cast<std::uint32_t>(frame.payload[offset + 3]) << 16) |
        (static_cast<std::uint32_t>(frame.payload[offset + 4]) << 8) |
        static_cast<std::uint32_t>(frame.payload[offset + 5]);

    if (id == 1) {
      if (value != 0)
        return Error{"http2-hpack-dynamic"};
    } else if (id == 2) {
      if (value != 0)
        return Error{"http2-push"};
    } else if (id == 3) {
      if (value != 1)
        return Error{"http2-multiplexing"};
    } else if (id == 4) {
      if (value != remote_http2_initial_window)
        return Error{"http2-flow-control"};
    } else if (id == 5) {
      if (value != remote_http2_frame_bytes)
        return Error{"http2-frame-size"};
    } else if (id == 6) {
      if (value < http_transport_max_header_bytes)
        return Error{"http2-header-list"};
    } else {
      return Error{"http2-settings"};
    }
  }
  return true;
}

Result<std::string> hpack_string(
    std::span<const std::uint8_t> block, std::size_t& offset) {
  if (offset >= block.size())
    return Error{"http2-hpack-truncated"};
  const auto lead = block[offset++];
  if ((lead & 0x80) != 0)
    return Error{"http2-hpack-huffman"};
  const std::size_t length = lead & 0x7f;
  if (length == 0x7f)
    return Error{"http2-hpack-length"};
  if (offset > block.size() || length > block.size() - offset)
    return Error{"http2-hpack-truncated"};

  std::string value(
      reinterpret_cast<const char*>(block.data() + offset), length);
  offset += length;
  return value;
}

bool lower_header_name(std::string_view name) {
  if (name.empty())
    return false;
  for (unsigned char c : name)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
      return false;
  return true;
}

struct DecodedHeaders {
  RemoteDecodedRequest request;
  std::optional<std::size_t> content_length;
};

Result<DecodedHeaders> decode_headers(std::span<const std::uint8_t> block) {
  if (block.size() > http_transport_max_header_bytes)
    return Error{"http-header-bound"};

  std::size_t offset = 0;
  std::size_t count = 0;
  bool regular_seen = false;
  std::string method, path, scheme, authority, content_type;
  std::optional<std::size_t> content_length;
  std::map<std::string, std::string> regular;
  std::set<std::string> pseudo_seen;

  while (offset < block.size()) {
    auto representation = block[offset++];
    if ((representation & 0x80) != 0)
      return Error{"http2-hpack-indexed"};
    if ((representation & 0xe0) == 0x20)
      return Error{"http2-hpack-dynamic"};
    if ((representation & 0xc0) == 0x40)
      return Error{"http2-hpack-dynamic"};
    if (representation != 0x00 && representation != 0x10)
      return Error{"http2-hpack-representation"};

    auto name = hpack_string(block, offset);
    if (!name.ok())
      return name.error();
    auto value = hpack_string(block, offset);
    if (!value.ok())
      return value.error();

    if (count >= http_transport_max_headers)
      return Error{"http-header"};
    ++count;

    if (!name.value().empty() && name.value().front() == ':') {
      if (regular_seen)
        return Error{"http2-pseudo-order"};
      auto* target = static_cast<std::string*>(nullptr);
      if (name.value() == ":method")
        target = &method;
      else if (name.value() == ":path")
        target = &path;
      else if (name.value() == ":scheme")
        target = &scheme;
      else if (name.value() == ":authority")
        target = &authority;
      else
        return Error{"http2-pseudo-header"};
      if (!pseudo_seen.insert(name.value()).second)
        return Error{"http-duplicate-header"};
      *target = std::move(value.value());
      continue;
    }

    regular_seen = true;
    if (!lower_header_name(name.value()))
      return Error{"http2-header-name"};
    if (name.value() == "connection" || name.value() == "keep-alive" ||
        name.value() == "proxy-connection" || name.value() == "te" ||
        name.value() == "host")
      return Error{"http-unsupported-framing"};

    auto admitted = admit_http_transport_header(
        regular, name.value(), value.value());
    if (!admitted.ok())
      return admitted.error();
    if (name.value() == "content-type")
      content_type = value.value();
    if (name.value() == "content-length") {
      auto parsed = parse_http_transport_content_length(value.value());
      if (!parsed.ok())
        return parsed.error();
      content_length = parsed.value();
    }
  }

  if ((method != "GET" && method != "POST") || scheme != "https" ||
      authority.empty() || path.empty() ||
      path.size() > http_transport_max_path_bytes ||
      !http_transport_text(path, false) ||
      !http_transport_text(authority, false))
    return Error{"http2-pseudo-header"};

  RemoteDecodedRequest request;
  request.request = {method, path, content_type, {}};
  request.header_bytes = block.size();
  request.headers.reserve(regular.size() + 1);
  request.headers.emplace_back("host", authority);
  for (const auto& [name, value] : regular)
    request.headers.emplace_back(name, value);
  return DecodedHeaders{std::move(request), content_length};
}

Result<std::string> hpack_literal_string(std::string_view value) {
  if (value.size() >= 0x7f)
    return Error{"http2-hpack-length"};
  std::string result;
  result.reserve(value.size() + 1);
  result.push_back(static_cast<char>(value.size()));
  result.append(value);
  return result;
}

Result<bool> append_hpack_literal(
    Bytes& out, std::string_view name, std::string_view value) {
  auto encoded = encode_remote_http2_literal_header(name, value);
  if (!encoded.ok())
    return encoded.error();
  if (out.size() > http_transport_max_header_bytes ||
      encoded.value().size() > http_transport_max_header_bytes - out.size())
    return Error{"http-header-bound"};
  out.insert(out.end(), encoded.value().begin(), encoded.value().end());
  return true;
}

}  // namespace

std::span<const std::uint8_t> remote_http2_client_preface() {
  return client_preface;
}

Result<Bytes> encode_remote_http2_frame(
    RemoteHttp2FrameType type, std::uint8_t flags, std::uint32_t stream,
    std::span<const std::uint8_t> payload) {
  if (payload.size() > remote_http2_frame_bytes || stream > 0x7fffffffU)
    return Error{"http2-frame-size"};
  const auto length = static_cast<std::uint32_t>(payload.size());
  Bytes result{
      static_cast<std::uint8_t>((length >> 16) & 0xff),
      static_cast<std::uint8_t>((length >> 8) & 0xff),
      static_cast<std::uint8_t>(length & 0xff),
      static_cast<std::uint8_t>(type),
      flags,
      static_cast<std::uint8_t>((stream >> 24) & 0x7f),
      static_cast<std::uint8_t>((stream >> 16) & 0xff),
      static_cast<std::uint8_t>((stream >> 8) & 0xff),
      static_cast<std::uint8_t>(stream & 0xff)};
  result.insert(result.end(), payload.begin(), payload.end());
  return result;
}

Result<Bytes> encode_remote_http2_literal_header(
    std::string_view name, std::string_view value, bool never_indexed) {
  auto encoded_name = hpack_literal_string(name);
  if (!encoded_name.ok())
    return encoded_name.error();
  auto encoded_value = hpack_literal_string(value);
  if (!encoded_value.ok())
    return encoded_value.error();
  Bytes result;
  result.reserve(1 + encoded_name.value().size() + encoded_value.value().size());
  result.push_back(never_indexed ? 0x10 : 0x00);
  result.insert(result.end(), encoded_name.value().begin(), encoded_name.value().end());
  result.insert(result.end(), encoded_value.value().begin(), encoded_value.value().end());
  return result;
}

Result<RemoteHttp2Request> receive_remote_http2_request(
    RemoteTlsHttp2Source& source,
    std::chrono::steady_clock::time_point deadline) {
  auto preface = read_exact(source, client_preface.size(), deadline);
  if (!preface.ok())
    return preface.error();
  if (!std::equal(preface.value().begin(), preface.value().end(),
                  client_preface.begin(), client_preface.end()))
    return Error{"http2-preface"};

  auto server_settings = send_server_settings(source, deadline);
  if (!server_settings.ok())
    return server_settings.error();

  auto settings = read_frame(source, deadline);
  if (!settings.ok())
    return settings.error();
  auto admitted_settings = admit_client_settings(settings.value());
  if (!admitted_settings.ok())
    return admitted_settings.error();

  auto ack = write_frame(source, RemoteHttp2FrameType::settings, remote_http2_flag_ack, 0, {}, deadline);
  if (!ack.ok())
    return ack.error();

  Frame headers;
  for (;;) {
    auto next = read_frame(source, deadline);
    if (!next.ok())
      return next.error();
    if (next.value().type == RemoteHttp2FrameType::settings && next.value().stream == 0 &&
        next.value().flags == remote_http2_flag_ack && next.value().payload.empty())
      continue;
    headers = std::move(next.value());
    break;
  }

  if (headers.type == RemoteHttp2FrameType::continuation)
    return Error{"http2-continuation"};
  if (headers.type == RemoteHttp2FrameType::push_promise)
    return Error{"http2-push"};
  if (headers.type == RemoteHttp2FrameType::priority)
    return Error{"http2-priority"};
  if (headers.type == RemoteHttp2FrameType::window_update)
    return Error{"http2-flow-control"};
  if (headers.type != RemoteHttp2FrameType::headers)
    return Error{"http2-frame-type"};
  if (headers.stream == 0 || (headers.stream & 1U) == 0)
    return Error{"http2-stream-id"};
  if ((headers.flags & remote_http2_flag_end_headers) == 0)
    return Error{"http2-continuation"};
  if ((headers.flags & (flag_padded | flag_priority)) != 0 ||
      (headers.flags & ~(remote_http2_flag_end_stream | remote_http2_flag_end_headers)) != 0)
    return Error{"http2-headers-flags"};

  auto decoded = decode_headers(headers.payload);
  if (!decoded.ok())
    return decoded.error();
  const auto declared = decoded.value().content_length;

  Bytes body;
  if ((headers.flags & remote_http2_flag_end_stream) == 0) {
    for (;;) {
      auto next = read_frame(source, deadline);
      if (!next.ok())
        return next.error();
      auto frame = std::move(next.value());
      if (frame.type == RemoteHttp2FrameType::settings && frame.stream == 0 &&
          frame.flags == remote_http2_flag_ack && frame.payload.empty())
        continue;
      if (frame.stream != headers.stream)
        return Error{"http2-multiplexing"};
      if (frame.type == RemoteHttp2FrameType::headers)
        return Error{"http2-trailers"};
      if (frame.type == RemoteHttp2FrameType::continuation)
        return Error{"http2-continuation"};
      if (frame.type == RemoteHttp2FrameType::push_promise)
        return Error{"http2-push"};
      if (frame.type == RemoteHttp2FrameType::priority)
        return Error{"http2-priority"};
      if (frame.type == RemoteHttp2FrameType::window_update)
        return Error{"http2-flow-control"};
      if (frame.type == RemoteHttp2FrameType::rst_stream || frame.type == RemoteHttp2FrameType::ping ||
          frame.type == RemoteHttp2FrameType::goaway)
        return Error{"http2-frame-type"};
      if (frame.type != RemoteHttp2FrameType::data)
        return Error{"http2-frame-type"};
      if ((frame.flags & flag_padded) != 0 ||
          (frame.flags & ~remote_http2_flag_end_stream) != 0)
        return Error{"http2-data-flags"};
      if (body.size() > remote_http2_initial_window ||
          frame.payload.size() > remote_http2_initial_window - body.size())
        return Error{"http2-flow-control"};
      body.insert(body.end(), frame.payload.begin(), frame.payload.end());
      if ((frame.flags & remote_http2_flag_end_stream) != 0)
        break;
    }
  }

  if (declared && *declared != body.size())
    return Error{"http2-content-length"};

  decoded.value().request.request.body.assign(body.begin(), body.end());
  return RemoteHttp2Request{headers.stream, std::move(decoded.value().request)};
}

Result<bool> send_remote_http2_response(
    RemoteTlsHttp2Source& source, std::uint32_t stream,
    const HttpResponse& response,
    std::chrono::steady_clock::time_point deadline) {
  if (stream == 0 || (stream & 1U) == 0)
    return Error{"http2-stream-id"};
  if (!http_transport_response_status_allowed(response.status) ||
      response.body.size() > remote_http2_initial_window ||
      response.content_type.size() > http_transport_max_content_type_bytes ||
      !http_transport_text(response.content_type, true))
    return Error{"http2-response-bound"};

  Bytes headers;
  auto status = append_hpack_literal(headers, ":status",
                                     std::to_string(response.status));
  if (!status.ok())
    return status.error();
  if (!response.content_type.empty()) {
    auto media = append_hpack_literal(headers, "content-type",
                                      response.content_type);
    if (!media.ok())
      return media.error();
  }
  auto length = append_hpack_literal(headers, "content-length",
                                     std::to_string(response.body.size()));
  if (!length.ok())
    return length.error();

  const auto header_flags = static_cast<std::uint8_t>(
      remote_http2_flag_end_headers | (response.body.empty() ? remote_http2_flag_end_stream : 0));
  auto head = write_frame(source, RemoteHttp2FrameType::headers, header_flags, stream,
                          headers, deadline);
  if (!head.ok())
    return head.error();
  if (response.body.empty())
    return true;

  std::size_t offset = 0;
  while (offset < response.body.size()) {
    const auto remaining = response.body.size() - offset;
    const auto count = std::min<std::size_t>(remaining, remote_http2_frame_bytes);
    const bool last = count == remaining;
    auto data = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(response.body.data() + offset),
        count);
    auto sent = write_frame(source, RemoteHttp2FrameType::data,
                            last ? remote_http2_flag_end_stream : 0,
                            stream, data, deadline);
    if (!sent.ok())
      return sent.error();
    offset += count;
  }
  return true;
}

Result<bool> RemoteHttp2AuthenticatedHttpTransport::serve_one(
    const Handler& handler, unsigned timeout) {
  if (!handler)
    return Error{"remote-handler"};

  const auto deadline =
      http_transport_deadline(std::chrono::steady_clock::now());
  auto outcome = source_.accept(
      bounded_http_accept_timeout(timeout), deadline);
  if (!outcome.ok())
    return outcome.error();

  auto principal = gate_.authenticate(outcome.value());
  if (!principal.ok())
    return principal.error();

  auto request = receive_remote_http2_request(source_, deadline);
  if (!request.ok())
    return request.error();

  auto response = gate_.dispatch(
      outcome.value(), request.value().decoded, handler);
  if (!response.ok())
    return response.error();

  return send_remote_http2_response(
      source_, request.value().stream_id, response.value(), deadline);
}

}  // namespace tos::auth
