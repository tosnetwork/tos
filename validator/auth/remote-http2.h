#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "remote-transport.h"

namespace tos::auth {

inline constexpr std::size_t remote_http2_frame_bytes = 16384;
inline constexpr std::size_t remote_http2_initial_window = 65535;

enum class RemoteHttp2FrameType : std::uint8_t {
  data = 0,
  headers = 1,
  priority = 2,
  rst_stream = 3,
  settings = 4,
  push_promise = 5,
  ping = 6,
  goaway = 7,
  window_update = 8,
  continuation = 9,
};

inline constexpr std::uint8_t remote_http2_flag_end_stream = 0x01;
inline constexpr std::uint8_t remote_http2_flag_ack = 0x01;
inline constexpr std::uint8_t remote_http2_flag_end_headers = 0x04;

std::span<const std::uint8_t> remote_http2_client_preface();
Result<Bytes> encode_remote_http2_frame(
    RemoteHttp2FrameType type, std::uint8_t flags, std::uint32_t stream_id,
    std::span<const std::uint8_t> payload);
Result<Bytes> encode_remote_http2_literal_header(
    std::string_view name, std::string_view value, bool never_indexed = false);

// A completed TLS 1.3 mutual-authentication session plus its protected byte
// stream. Concrete socket/TLS ownership stays outside this parser so every
// framing property is testable without a network.
class RemoteTlsHttp2Source : public RemoteTlsHandshakeSource {
 public:
  ~RemoteTlsHttp2Source() override = default;
  virtual Result<Bytes> read_exact(
      std::size_t bytes,
      std::chrono::steady_clock::time_point absolute_io_deadline) = 0;
  virtual Result<bool> write_all(
      std::span<const std::uint8_t> bytes,
      std::chrono::steady_clock::time_point absolute_io_deadline) = 0;
};

struct RemoteHttp2Request {
  std::uint32_t stream_id = 0;
  RemoteDecodedRequest decoded;
};

Result<RemoteHttp2Request> receive_remote_http2_request(
    RemoteTlsHttp2Source&,
    std::chrono::steady_clock::time_point absolute_io_deadline);
Result<bool> send_remote_http2_response(
    RemoteTlsHttp2Source&, std::uint32_t stream_id,
    const HttpResponse&,
    std::chrono::steady_clock::time_point absolute_io_deadline);

// Remote implementation of the existing authenticated transport seam. It
// authenticates the peer first, then admits exactly one HTTP/2 request stream.
class RemoteHttp2AuthenticatedHttpTransport final
    : public AuthenticatedHttpTransport {
 public:
  RemoteHttp2AuthenticatedHttpTransport(
      const InstalledRemotePeerTrust& trust,
      RemoteTlsHttp2Source& source)
      : gate_(trust), source_(source) {
  }

  Result<bool> serve_one(
      const Handler&, unsigned accept_timeout_ms = 1000) override;

 private:
  RemoteAuthenticatedRequestGate gate_;
  RemoteTlsHttp2Source& source_;
};

}  // namespace tos::auth
