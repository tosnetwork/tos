/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// A send that never waits for the peer, for tests whose clients must keep going while
// the server under test stops reading.
//
// Linux honours MSG_DONTWAIT on send(2). macOS ignores it there and blocks until the
// peer has read enough; once the server drops the client, the blocked call fails with
// EPIPE and the bytes it did write are not reported. There the socket itself is made
// non-blocking for the duration of the call.
#pragma once

#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>

inline ssize_t send_without_waiting(int fd, const void *data, std::size_t size) {
#if defined(__APPLE__)
  const int flags = ::fcntl(fd, F_GETFL);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    return -1;
  }
  const ssize_t sent = ::send(fd, data, size, MSG_NOSIGNAL);
  const int saved = errno;
  if (::fcntl(fd, F_SETFL, flags) != 0) {
    return -1;
  }
  errno = saved;
  return sent;
#else
  return ::send(fd, data, size, MSG_NOSIGNAL | MSG_DONTWAIT);
#endif
}
