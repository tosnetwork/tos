/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// A loopback TCP port that stays reserved while a test's server listens on it.
//
// Binding port 0, reading the port and closing the socket leaves the port free until
// the server binds it, and the server sockets set SO_REUSEPORT: two test processes
// running at once could then pick the same port and both listen on it, and a client
// would reach the other process's server. This socket stays bound with SO_REUSEPORT,
// which lets the server (SO_REUSEPORT too) bind the port beside it, and without
// SO_REUSEADDR, so the kernel's choice of a port for another bind of port 0 never
// shares it. It never listens.
//
// Release it as soon as the server is listening, before any client connects: on BSD
// and macOS a bound socket that never listens hides a wildcard (0.0.0.0) listener for
// its own address, because the stack matches the exact local address first and then
// drops the SYN at the socket that does not listen. Releasing early loses nothing:
// a port with a listener is not chosen for another bind of port 0, on Linux or macOS.
//
// A server that reports when it listens: call release() right after that. A server that
// does not: before the first client connects, wait for may_release() and call release(),
// or call release_once_listening() from a thread that does not run the server. On Linux
// may_release() waits for the kernel to list a listener on the port (/proc/net/tcp; no
// connection is made); elsewhere it is true at once, since a probing connection would be
// hidden by the reservation itself, which leaves the short window until the server binds.
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

class ReservedTcpPort {
 public:
  ReservedTcpPort() {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
      throw std::runtime_error("cannot open a TCP socket to reserve a port");
    }
    int on = 1;
#ifdef SO_REUSEPORT
    if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0) {
      ::close(fd_);
      throw std::runtime_error("cannot set SO_REUSEPORT on the socket reserving a TCP port");
    }
#endif
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t size = sizeof(address);
    if (::bind(fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
        ::getsockname(fd_, reinterpret_cast<sockaddr *>(&address), &size) != 0) {
      ::close(fd_);
      throw std::runtime_error("cannot reserve a TCP port");
    }
    port_ = ntohs(address.sin_port);
  }
  ~ReservedTcpPort() {
    release();
  }
  // Closes the reserving socket; call it once the server is listening.
  void release() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }
  bool held() const {
    return fd_ >= 0;
  }
  // True once the port has a listener; always true where the kernel's listeners cannot
  // be read without connecting. For a test that polls while it runs its scheduler.
  bool may_release() const {
#if defined(__linux__)
    return has_listener();
#else
    return true;
#endif
  }
  // Waits until may_release() (at most `timeout`), then releases. For a thread that does
  // not run the server's scheduler itself.
  void release_once_listening(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!may_release() && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    release();
  }
  ReservedTcpPort(const ReservedTcpPort &) = delete;
  ReservedTcpPort &operator=(const ReservedTcpPort &) = delete;

  std::uint16_t port() const {
    return port_;
  }

 private:
#if defined(__linux__)
  // Whether /proc/net/tcp or /proc/net/tcp6 lists a socket in LISTEN state (0A) on the
  // port, on any local address.
  bool has_listener() const {
    char suffix[16];
    std::snprintf(suffix, sizeof(suffix), ":%04X", static_cast<unsigned>(port_));
    for (const char *table : {"/proc/net/tcp", "/proc/net/tcp6"}) {
      std::ifstream in(table);
      std::string line;
      std::getline(in, line);  // header
      while (std::getline(in, line)) {
        char local[64] = {0};
        char remote[64] = {0};
        char state[8] = {0};
        if (std::sscanf(line.c_str(), " %*d: %63s %63s %7s", local, remote, state) != 3) {
          continue;
        }
        std::string address(local);
        if (std::string(state) == "0A" && address.size() >= 5 && address.compare(address.size() - 5, 5, suffix) == 0) {
          return true;
        }
      }
    }
    return false;
  }
#endif

  int fd_ = -1;
  std::uint16_t port_ = 0;
};
