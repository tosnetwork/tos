/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// ReservedTcpPort: while held, no bind of port 0 is given the port and a server binds
// beside it; once the server listens and the reservation is released, a client
// connects to the server.
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "test/reserved-tcp-port.h"

namespace {

[[noreturn]] void fail(const std::string &message) {
  std::fprintf(stderr, "RESERVED_TCP_PORT_FAILURE: %s (errno %d)\n", message.c_str(), errno);
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

sockaddr_in loopback(std::uint16_t port, bool any) {
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(any ? INADDR_ANY : INADDR_LOOPBACK);
  address.sin_port = htons(port);
  return address;
}

// A listener the way the node's servers open one: SO_REUSEADDR and SO_REUSEPORT,
// bound to the wildcard address.
int open_server(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  require(fd >= 0, "server socket");
  int on = 1;
  require(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0, "server SO_REUSEADDR");
#ifdef SO_REUSEPORT
  require(::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == 0, "server SO_REUSEPORT");
#endif
  auto address = loopback(port, true);
  require(::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0,
          "the server could not bind beside the reservation");
  require(::listen(fd, 16) == 0, "server listen");
  return fd;
}

}  // namespace

int main() {
  ReservedTcpPort reserved;
  const auto port = reserved.port();
  require(port != 0, "no port reserved");

  // While held, a bind of port 0 is never given the reserved port.
  for (int i = 0; i < 2000; i++) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    require(fd >= 0, "probe socket");
    auto address = loopback(0, false);
    require(::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "probe bind");
    socklen_t size = sizeof(address);
    require(::getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size) == 0, "probe port");
    require(ntohs(address.sin_port) != port, "a bind of port 0 was given the reserved port");
    ::close(fd);
  }

#if defined(__linux__)
  require(!reserved.may_release(), "the reservation was taken for a listener");
#endif
  int server = open_server(port);
  reserved.release_once_listening();
  require(!reserved.held(), "the reservation was not released");

  // Released after the server listens: a client reaches the server.
  int client = ::socket(AF_INET, SOCK_STREAM, 0);
  require(client >= 0, "client socket");
  auto target = loopback(port, false);
  require(::connect(client, reinterpret_cast<sockaddr *>(&target), sizeof(target)) == 0,
          "the client could not connect after the reservation was released");
  int accepted = ::accept(server, nullptr, nullptr);
  require(accepted >= 0, "the server did not accept the client");
  ::close(accepted);
  ::close(client);
  ::close(server);
  std::printf("RESERVED_TCP_PORT_OK port=%u\n", static_cast<unsigned>(port));
  return 0;
}
