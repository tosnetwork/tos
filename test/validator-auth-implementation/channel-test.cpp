#include <cerrno>
#include <filesystem>
#include <iostream>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "validator/auth/local-channel.h"
using namespace tos::auth;
void check(bool okay, const char* label) {
  if (!okay)
    throw std::runtime_error(label);
}
template <class T>
T value(Result<T> r, const char* label) {
  check(r.ok(), label);
  return std::move(r.value());
}
void join(pid_t child, const char* label) {
  int status = 0;
  if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) > 1) {
    std::cerr << "HARNESS: child failed\n";
    std::exit(2);
  }
  check(WEXITSTATUS(status) == 0, label);
}
pid_t serve(LocalListener& listener, std::string expected_error = {}) {
  auto child = ::fork();
  check(child >= 0, "fork");
  if (child == 0) {
    auto result = listener.serve_one([](std::span<const std::uint8_t> bytes) { return Result<Bytes>(Bytes{1, 2, 3}); });
    bool expected =
        expected_error.empty() ? result.ok() && result.value() : !result.ok() && result.error().code == expected_error;
    if (expected_error == "local-disconnected")
      expected = !result.ok() && (result.error().code == "local-io" || result.error().code == "local-accept" ||
                                  result.error().code == "local-peer-credentials");
    ::_exit(expected ? 0 : 1);
  }
  return child;
}
int raw_request(const std::string& path, std::size_t bytes, bool version = true) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  check(fd >= 0, "socket");
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::copy(path.begin(), path.end(), addr.sun_path);
  check(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "connect");
  Bytes raw{'P', '0', 'X', static_cast<std::uint8_t>(version ? '1' : '2'), 0, 0, 0, 0};
  for (unsigned i = 0; i < 4; ++i)
    raw[7 - i] = static_cast<std::uint8_t>(bytes >> (i * 8));
  raw.resize(8 + bytes, 42);
  std::size_t offset = 0;
  while (offset < raw.size()) {
    auto n = ::send(fd, raw.data() + offset, raw.size() - offset, 0);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    offset += n;
  }
  ::shutdown(fd, SHUT_WR);
  return fd;
}
int main(int argc, char** argv) {
  try {
    ::signal(SIGPIPE, SIG_IGN);
    ::umask(0);
    check(argc == 2, "temporary-directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory-required");
    ::chmod(dir.c_str(), 0700);
    auto socket = (dir / "socket").string();
    auto listener = value(LocalListener::create(socket, ::geteuid()), "listen");
    struct stat mode{};
    check(::stat(socket.c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0600, "socket-mode");
    check(!LocalListener::create(socket, ::geteuid()).ok(), "socket-no-replacement");
    auto child = serve(*listener);
    auto echo = value(local_call(socket, ::geteuid(), Bytes{1, 2, 3}), "local-echo");
    join(child, "local-echo-server");
    check(echo == Bytes({1, 2, 3}), "local-echo-bytes");
    child = serve(*listener, "local-disconnected");
    auto refused = local_call(socket, static_cast<uid_t>(::geteuid() + 1), Bytes{1});
    join(child, "client-peer-credentials");
    check(!refused.ok() && refused.error().code == "local-unauthorized", "client-peer-credentials");
    child = serve(*listener, "local-frame-bound");
    auto raw_fd = raw_request(socket, 2000001);
    join(child, "preallocation-bound");
    ::close(raw_fd);
    child = serve(*listener, "local-version");
    raw_fd = raw_request(socket, 1, false);
    join(child, "local-version");
    ::close(raw_fd);
    listener.reset();
    check(!std::filesystem::exists(socket), "owned-socket-cleanup");
    listener = value(LocalListener::create(socket, static_cast<uid_t>(::geteuid() + 1)), "other-principal");
    child = serve(*listener, "local-unauthorized");
    refused = local_call(socket, ::geteuid(), Bytes{1});
    join(child, "server-peer-credentials");
    check(!refused.ok(), "server-peer-credentials");
    listener.reset();
    ::chmod(dir.c_str(), 0755);
    check(!LocalListener::create(socket, ::geteuid()).ok(), "private-parent");
    std::cout
        << "PASS: OS peer credentials, private socket, strict version, preallocation limit and finite local channel\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
