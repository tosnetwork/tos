#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

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
Result<bool> LocalListener::serve_one(const Handler& handler, unsigned timeout) {
  auto accepted_at = Clock::now() + std::chrono::milliseconds(std::clamp(timeout, 1u, 5000u));
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
  auto deadline = Clock::now() + std::chrono::seconds(5);
  auto request = receive_frame(client.fd, deadline);
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
  return send_frame(client.fd, response, deadline);
}
Result<Bytes> local_call(const std::string& path, uid_t expected, std::span<const std::uint8_t> request) {
  if (request.empty() || request.size() > max_frame)
    return Error{"local-frame-bound"};
  auto a = address(path);
  if (!a.ok())
    return a.error();
  Socket server{::socket(AF_UNIX, SOCK_STREAM, 0)};
  if (server.fd < 0 || !prepare(server.fd))
    return Error{"local-socket"};
  auto deadline = Clock::now() + std::chrono::seconds(5);
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
}  // namespace tos::auth
