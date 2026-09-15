#pragma once
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

#include "validator/auth/provider-channel.h"

#include "service-fixture.h"
namespace p0_process {
inline void send_exact(int fd, std::span<const std::uint8_t> raw) {
  while (!raw.empty()) {
    auto n = ::write(fd, raw.data(), raw.size());
    if (n < 0 && errno == EINTR)
      continue;
    check(n > 0, "pipe-write");
    raw = raw.subspan(n);
  }
}
inline Bytes receive_exact(int fd, std::size_t size) {
  Bytes out(size);
  std::size_t offset = 0;
  while (offset < size) {
    pollfd p{fd, POLLIN, 0};
    check(::poll(&p, 1, 15000) > 0, "child-timeout");
    auto n = ::read(fd, out.data() + offset, size - offset);
    check(n > 0, "child-reply");
    offset += n;
  }
  return out;
}
struct Child {
  pid_t pid = -1;
  explicit Child(pid_t p) : pid(p) {
  }
  Child(const Child&) = delete;
  ~Child() {
    if (pid > 0) {
      ::kill(pid, SIGKILL);
      ::waitpid(pid, nullptr, 0);
    }
  }
  void kill() {
    check(::kill(pid, SIGKILL) == 0, "kill-process");
    int status = 0;
    check(::waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "killed-process");
    pid = -1;
  }
  void wait() {
    int status = 0;
    check(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child-success");
    pid = -1;
  }
};
inline void gate(int fd) {
  send_exact(fd, Bytes{9});
  for (;;)
    ::pause();
}
inline pid_t provider_child(const std::filesystem::path& dir, bool create) {
  int fds[2];
  check(::pipe(fds) == 0, "pipe");
  pid_t pid = ::fork();
  check(pid >= 0, "fork-provider");
  if (pid == 0) {
    ::close(fds[0]);
    try {
      auto witness = value(FileWitness::open((dir / "witness").string(), h(999), create), "provider-witness");
      auto provider = create ? value(C0Provider::provision((dir / "provider").string(), *witness,
                                                           {{state().identities().begin()->first, 2, 1, 0, 1000}}),
                                     "provider-provision")
                             : value(C0Provider::open((dir / "provider").string(), *witness), "provider-reopen");
      auto socket = value(LocalListener::create((dir / "provider.sock").string(), ::geteuid()), "provider-listen");
      ProviderHost host(*witness, *provider);
      send_exact(fds[1], Bytes{1});
      ::close(fds[1]);
      for (;;) {
        auto served = socket->serve_one([&](std::span<const std::uint8_t> raw) { return host.dispatch(raw); }, 1000);
        if (!served.ok() && served.error().code != "local-io")
          std::cerr << "PROVIDER: " << served.error().code << '\n';
      }
    } catch (const std::exception& e) {
      std::cerr << "PROVIDER: " << e.what() << '\n';
      ::_exit(2);
    }
  }
  ::close(fds[1]);
  auto ready = receive_exact(fds[0], 1);
  ::close(fds[0]);
  check(ready == Bytes{1}, "provider-ready");
  return pid;
}
}  // namespace p0_process
