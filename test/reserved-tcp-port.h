/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// A loopback TCP port that stays reserved while a test's server listens on it.
//
// Binding port 0, reading the port and closing the socket leaves the port free until
// the server binds it, and the server sockets set SO_REUSEPORT: two test processes
// running at once could then pick the same port and both listen on it, and a client
// would reach the other process's server. This socket stays bound with SO_REUSEPORT,
// which lets the server (SO_REUSEPORT too) bind the port beside it, and without
// SO_REUSEADDR, so the kernel's choice of a port for another bind of port 0 never
// shares it. It never listens, so no connection reaches it. Keep the object alive at
// least until the server is listening; once it listens, the listener itself keeps the
// port from being chosen.
#pragma once

#include <cstdint>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
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
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
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
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }
  ReservedTcpPort(const ReservedTcpPort &) = delete;
  ReservedTcpPort &operator=(const ReservedTcpPort &) = delete;

  std::uint16_t port() const {
    return port_;
  }

 private:
  int fd_ = -1;
  std::uint16_t port_ = 0;
};
