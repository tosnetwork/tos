#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>

#include "http-transport-policy.h"
#include "local-channel.h"
namespace tos::auth {
namespace {
constexpr std::size_t max_frame = 2000000;
using Clock = std::chrono::steady_clock;
struct Socket {
  int fd;
  ~Socket() {
    if (fd >= 0)
      ::close(fd);
  }
};
bool prepare(int fd) {
  if (::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    return false;
  auto flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return false;
#ifdef SO_NOSIGPIPE
  int yes = 1;
  if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) < 0)
    return false;
#endif
  return true;
}
Result<uid_t> peer(int fd) {
#if defined(__APPLE__) || defined(__FreeBSD__)
  uid_t uid;
  gid_t gid;
  if (::getpeereid(fd, &uid, &gid) != 0)
    return Error{"local-peer-credentials"};
  return uid;
#elif defined(__linux__)
  struct ucred credentials{};
  socklen_t length = sizeof(credentials);
  if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 || length != sizeof(credentials))
    return Error{"local-peer-credentials"};
  return credentials.uid;
#else
  return Error{"local-peer-unsupported"};
#endif
}
bool ready(int fd, short event, Clock::time_point deadline) {
  for (;;) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    if (left <= 0)
      return false;
    struct pollfd p{fd, event, 0};
    auto result = ::poll(&p, 1, static_cast<int>(std::min<std::int64_t>(left, 5000)));
    if (result < 0 && errno == EINTR)
      continue;
    return result > 0 && (p.revents & event);
  }
}
bool receive(int fd, std::span<std::uint8_t> bytes, Clock::time_point deadline) {
  while (!bytes.empty()) {
    if (!ready(fd, POLLIN, deadline))
      return false;
    auto count = ::recv(fd, bytes.data(), bytes.size(), 0);
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (count <= 0)
      return false;
    bytes = bytes.subspan(static_cast<std::size_t>(count));
  }
  return true;
}
bool transmit(int fd, std::span<const std::uint8_t> bytes, Clock::time_point deadline) {
  while (!bytes.empty()) {
    if (!ready(fd, POLLOUT, deadline))
      return false;
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    auto count = ::send(fd, bytes.data(), bytes.size(), flags);
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (count <= 0)
      return false;
    bytes = bytes.subspan(static_cast<std::size_t>(count));
  }
  return true;
}
Result<Bytes> receive_frame(int fd, Clock::time_point deadline) {
  std::array<std::uint8_t, 8> header{};
  if (!receive(fd, header, deadline))
    return Error{"local-io"};
  if (!std::equal(header.begin(), header.begin() + 4, "P0X1"))
    return Error{"local-version"};
  std::uint32_t size = 0;
  for (unsigned i = 4; i < 8; ++i)
    size = (size << 8) | header[i];
  if (size == 0 || size > max_frame)
    return Error{"local-frame-bound"};
  Bytes body(size);
  if (!receive(fd, body, deadline))
    return Error{"local-io"};
  return body;
}
Result<bool> send_frame(int fd, std::span<const std::uint8_t> body, Clock::time_point deadline) {
  if (body.empty() || body.size() > max_frame)
    return Error{"local-frame-bound"};
  std::array<std::uint8_t, 8> header{'P', '0', 'X', '1', 0, 0, 0, 0};
  for (unsigned i = 0; i < 4; ++i)
    header[7 - i] = static_cast<std::uint8_t>(body.size() >> (i * 8));
  if (!transmit(fd, header, deadline) || !transmit(fd, body, deadline))
    return Error{"local-io"};
  return true;
}
Result<sockaddr_un> address(const std::string& path) {
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  if (path.empty() || path.size() >= sizeof(a.sun_path) || path.find('\0') != std::string::npos)
    return Error{"local-socket-path"};
  std::copy(path.begin(), path.end(), a.sun_path);
  return a;
}
struct HttpHead {
  std::string line;
  std::map<std::string, std::string> fields;
  std::size_t length = 0;
};
Result<HttpHead> receive_head(int fd, Clock::time_point deadline) {
  std::string head;
  while (!head.ends_with("\r\n\r\n")) {
    if (head.size() >= http_transport_max_header_bytes)
      return Error{"http-header-bound"};
    std::uint8_t c = 0;
    if (!receive(fd, std::span<std::uint8_t>(&c, 1), deadline))
      return Error{"local-io"};
    head.push_back(static_cast<char>(c));
  }
  HttpHead parsed;
  auto first = head.find("\r\n");
  if (first == std::string::npos || first == 0)
    return Error{"http-start-line"};
  parsed.line = head.substr(0, first);
  if (!http_transport_text(parsed.line, true))
    return Error{"http-start-line"};
  std::size_t pos = first + 2;
  while (pos + 2 < head.size()) {
    auto end = head.find("\r\n", pos);
    if (end == std::string::npos)
      return Error{"http-header"};
    auto line = head.substr(pos, end - pos);
    pos = end + 2;
    if (line.empty())
      break;
    if (!http_transport_text(line, true))
      return Error{"http-header"};
    auto colon = line.find(':');
    if (colon == std::string::npos || colon == 0)
      return Error{"http-header"};
    std::string name = line.substr(0, colon);
    for (char& c : name) {
      if (c >= 'A' && c <= 'Z')
        c = static_cast<char>(c - 'A' + 'a');
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
        return Error{"http-header"};
    }
    auto value = line.substr(colon + 1);
    while (!value.empty() && value.front() == ' ')
      value.erase(value.begin());
    while (!value.empty() && value.back() == ' ')
      value.pop_back();
    auto admitted =
        admit_http_transport_header(parsed.fields, std::move(name), std::move(value));
    if (!admitted.ok())
      return admitted.error();
  }
  auto length = parsed.fields.find("content-length");
  if (length != parsed.fields.end()) {
    auto parsed_length = parse_http_transport_content_length(length->second);
    if (!parsed_length.ok())
      return parsed_length.error();
    parsed.length = parsed_length.value();
  }
  return parsed;
}
Result<std::string> receive_http_body(int fd, std::size_t size, Clock::time_point deadline) {
  // The private callers pass only lengths admitted by receive_head.
  std::string body(size, '\0');
  auto bytes = std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(body.data()), body.size());
  if (!receive(fd, bytes, deadline))
    return Error{"local-io"};
  return body;
}
Result<HttpRequest> receive_http_request(int fd, Clock::time_point deadline) {
  auto h = receive_head(fd, deadline);
  if (!h.ok())
    return h.error();
  const auto& head = h.value();
  auto first = head.line.find(' ');
  auto second = head.line.find(' ', first == std::string::npos ? 0 : first + 1);
  if (first == std::string::npos || second == std::string::npos || head.line.substr(second + 1) != "HTTP/1.1")
    return Error{"http-request-line"};
  HttpRequest request{head.line.substr(0, first), head.line.substr(first + 1, second - first - 1), {}, {}};
  if ((request.verb != "GET" && request.verb != "POST") || request.path.empty() ||
      request.path.size() > http_transport_max_path_bytes ||
      !http_transport_text(request.path, false) || !head.fields.contains("host") || head.fields.at("host").empty())
    return Error{"http-request-line"};
  if (request.verb == "POST" && !head.fields.contains("content-length"))
    return Error{"http-content-length"};
  if (request.verb == "GET" && head.length != 0)
    return Error{"http-get-body"};
  auto media = head.fields.find("content-type");
  if (media != head.fields.end())
    request.content_type = media->second;
  auto body = receive_http_body(fd, head.length, deadline);
  if (!body.ok())
    return body.error();
  request.body = std::move(body.value());
  return request;
}
Result<bool> send_http_response(int fd, const HttpResponse& response, Clock::time_point deadline) {
  if (response.body.size() > http_transport_max_body_bytes || response.status < 100 || response.status > 599 ||
      response.content_type.size() > http_transport_max_content_type_bytes ||
      !http_transport_text(response.content_type, true))
    return Error{"http-response-bound"};
  std::string head = "HTTP/1.1 " + std::to_string(response.status) +
                     " Response\r\nConnection: close\r\nContent-Length: " + std::to_string(response.body.size()) +
                     "\r\n";
  if (!response.content_type.empty())
    head += "Content-Type: " + response.content_type + "\r\n";
  head += "\r\n";
  if (!transmit(fd, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(head.data()), head.size()),
                deadline) ||
      !transmit(fd,
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(response.body.data()),
                                              response.body.size()),
                deadline))
    return Error{"local-io"};
  return true;
}
Result<int> connect_peer(const std::string& path, uid_t expected, Clock::time_point deadline) {
  auto a = address(path);
  if (!a.ok())
    return a.error();
  Socket server{::socket(AF_UNIX, SOCK_STREAM, 0)};
  if (server.fd < 0 || !prepare(server.fd))
    return Error{"local-socket"};
  auto connected = ::connect(server.fd, reinterpret_cast<const sockaddr*>(&a.value()), sizeof(sockaddr_un));
  if (connected < 0) {
    if (errno != EINPROGRESS || !ready(server.fd, POLLOUT, deadline))
      return Error{"local-connect"};
    int error = 0;
    socklen_t size = sizeof(error);
    if (::getsockopt(server.fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error != 0)
      return Error{"local-connect"};
  }
  auto credentials = peer(server.fd);
  if (!credentials.ok())
    return credentials.error();
  if (credentials.value() != expected)
    return Error{"local-unauthorized"};
  return std::exchange(server.fd, -1);
}
}  // namespace
LocalListener::~LocalListener() {
  if (fd_ >= 0)
    ::close(fd_);
  struct stat info{};
  if (::lstat(path_.c_str(), &info) == 0 && S_ISSOCK(info.st_mode) &&
      static_cast<std::uint64_t>(info.st_dev) == device_ && static_cast<std::uint64_t>(info.st_ino) == inode_)
    ::unlink(path_.c_str());
}
Result<std::unique_ptr<LocalListener>> LocalListener::create(const std::string& path, uid_t principal) {
  auto a = address(path);
  if (!a.ok())
    return a.error();
  auto split = path.find_last_of('/');
  auto parent = split == std::string::npos ? "." : path.substr(0, split);
  struct stat dir{};
  if (::lstat(parent.c_str(), &dir) != 0 || !S_ISDIR(dir.st_mode) || dir.st_uid != ::geteuid() ||
      (dir.st_mode & 0777) != 0700)
    return Error{"local-private-directory"};
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return Error{"local-socket"};
  auto server = std::unique_ptr<LocalListener>(new LocalListener(fd, path, principal));
  if (!prepare(fd) || ::bind(fd, reinterpret_cast<const sockaddr*>(&a.value()), sizeof(sockaddr_un)) < 0)
    return Error{"local-bind"};
  struct stat bound{};
  if (::lstat(path.c_str(), &bound) != 0)
    return Error{"local-socket"};
  server->device_ = static_cast<std::uint64_t>(bound.st_dev);
  server->inode_ = static_cast<std::uint64_t>(bound.st_ino);
  if (::chmod(path.c_str(), 0600) < 0 || ::listen(fd, 16) < 0)
    return Error{"local-listen"};
  return server;
}
Result<bool> LocalListener::serve_stream(const std::function<Result<bool>(int)>& handler, unsigned timeout) {
  auto accepted_at = Clock::now() + std::chrono::milliseconds(bounded_http_accept_timeout(timeout));
  if (!ready(fd_, POLLIN, accepted_at))
    return false;
  Socket client{::accept(fd_, nullptr, nullptr)};
  if (client.fd < 0 || !prepare(client.fd))
    return Error{"local-accept"};
  auto credentials = peer(client.fd);
  if (!credentials.ok())
    return credentials.error();
  if (credentials.value() != principal_)
    return Error{"local-unauthorized"};
  return handler(client.fd);
}
Result<bool> LocalListener::serve_one(const Handler& handler, unsigned timeout) {
  return serve_stream(
      [&](int fd) -> Result<bool> {
        auto deadline = http_transport_deadline(Clock::now());
        auto request = receive_frame(fd, deadline);
        if (!request.ok())
          return request.error();
        auto result = handler(request.value());
        Bytes response;
        if (result.ok()) {
          if (result.value().size() >= max_frame)
            return Error{"local-frame-bound"};
          response.push_back(0);
          response.insert(response.end(), result.value().begin(), result.value().end());
        } else {
          if (result.error().code.empty() || result.error().code.size() > 256)
            return Error{"local-error-bound"};
          response.push_back(1);
          response.insert(response.end(), result.error().code.begin(), result.error().code.end());
        }
        return send_frame(fd, response, deadline);
      },
      timeout);
}
Result<Bytes> local_call(const std::string& path, uid_t expected, std::span<const std::uint8_t> request) {
  if (request.empty() || request.size() > max_frame)
    return Error{"local-frame-bound"};
  auto deadline = http_transport_deadline(Clock::now());
  auto connected = connect_peer(path, expected, deadline);
  if (!connected.ok())
    return connected.error();
  Socket server{connected.value()};
  auto sent = send_frame(server.fd, request, deadline);
  if (!sent.ok())
    return sent.error();
  auto response = receive_frame(server.fd, deadline);
  if (!response.ok())
    return response.error();
  const auto status = response.value()[0];
  response.value().erase(response.value().begin());
  if (status == 0)
    return std::move(response.value());
  if (status != 1 || response.value().empty() || response.value().size() > 256)
    return Error{"local-response"};
  return Error{std::string(response.value().begin(), response.value().end())};
}
Result<bool> LocalListener::serve_http_one(const HttpHandler& handler, unsigned timeout) {
  return serve_stream(
      [&](int fd) -> Result<bool> {
        auto deadline = http_transport_deadline(Clock::now());
        auto request = receive_http_request(fd, deadline);
        if (!request.ok())
          return send_http_response(fd, {400, "", ""}, deadline);
        auto response = handler(request.value());
        if (!response.ok())
          return send_http_response(fd, {500, "", ""}, deadline);
        return send_http_response(fd, response.value(), deadline);
      },
      timeout);
}
Result<HttpResponse> local_http_call(const std::string& path, uid_t expected, const HttpRequest& request) {
  auto request_shape = validate_http_transport_request_shape(request);
  if (!request_shape.ok())
    return request_shape.error();
  auto deadline = http_transport_deadline(Clock::now());
  auto connected = connect_peer(path, expected, deadline);
  if (!connected.ok())
    return connected.error();
  Socket socket{connected.value()};
  std::string head =
      request.verb + " " + request.path +
      " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: " + std::to_string(request.body.size()) +
      "\r\n";
  if (!request.content_type.empty())
    head += "Content-Type: " + request.content_type + "\r\n";
  head += "\r\n";
  if (!transmit(socket.fd,
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(head.data()), head.size()),
                deadline) ||
      !transmit(socket.fd,
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(request.body.data()),
                                              request.body.size()),
                deadline))
    return Error{"local-io"};
  auto header = receive_head(socket.fd, deadline);
  if (!header.ok())
    return header.error();
  const auto& h = header.value();
  if (h.line.size() < 12 || h.line.substr(0, 9) != "HTTP/1.1 " || !h.fields.contains("content-length"))
    return Error{"http-response-line"};
  unsigned status = 0;
  for (unsigned i = 9; i < 12; ++i) {
    char c = h.line[i];
    if (c < '0' || c > '9')
      return Error{"http-response-line"};
    status = status * 10 + static_cast<unsigned>(c - '0');
  }
  if (!http_transport_response_status_allowed(status) ||
      (h.line.size() > 12 && h.line[12] != ' '))
    return Error{"http-response-status"};
  auto body = receive_http_body(socket.fd, h.length, deadline);
  if (!body.ok())
    return body.error();
  auto media = h.fields.find("content-type");
  return HttpResponse{status, media == h.fields.end() ? std::string{} : media->second, std::move(body.value())};
}
}  // namespace tos::auth
