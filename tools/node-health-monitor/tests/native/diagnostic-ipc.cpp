#include <cassert>
#include <cstdlib>

#include "metrics/diagnostic-ipc.h"

int main(int argc, char **) {
  using namespace tos::health;
  char directory[] = "/tmp/nhm-c06-ipc-XXXXXX";
  assert(mkdtemp(directory) != nullptr);
  const auto path = std::string(directory) + "/diagnostic.sock";
  const auto server = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(server >= 0);
  int yes = 1;
  assert(setsockopt(server, SOL_SOCKET, SO_PASSCRED, &yes, sizeof(yes)) == 0);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path.data(), path.size());
  assert(bind(server, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  assert(chmod(path.c_str(), 0600) == 0);
  std::array<std::uint8_t, 16> epoch{};
  epoch.fill(0x23);
  diagnostic_ipc = std::make_unique<DiagnosticIpc>(path, getpid() + (argc > 1 ? 1 : 0), epoch, 1);
  assert(diagnostic_ipc->start());
  auto receive = [&](std::array<std::uint8_t, 512> &bytes, sockaddr_un &from) {
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(ucred))> control{};
    iovec iov{bytes.data(), bytes.size()};
    msghdr message{};
    message.msg_name = &from;
    message.msg_namelen = sizeof(from);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    const auto count = recvmsg(server, &message, MSG_DONTWAIT);
    if (count >= 0) {
      const auto c = CMSG_FIRSTHDR(&message);
      assert(c != nullptr && c->cmsg_type == SCM_CREDENTIALS);
      ucred cred{};
      std::memcpy(&cred, CMSG_DATA(c), sizeof(cred));
      assert(cred.pid == getpid() && cred.uid == getuid() && cred.gid == getgid());
      if (count == 20 && std::memcmp(bytes.data(), "THS1", 4) == 0) {
        assert(std::memcmp(bytes.data() + 4, epoch.data(), 16) == 0);
        std::memcpy(bytes.data(), "THA1", 4);
        assert(sendto(server, bytes.data(), 20, MSG_DONTWAIT, reinterpret_cast<sockaddr *>(&from),
                      message.msg_namelen) == 20);
      }
    }
    return count;
  };
  std::array<std::uint8_t, 512> bytes{};
  sockaddr_un from{};
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  bool handshake = false;
  while (std::chrono::steady_clock::now() < deadline) {
    if (receive(bytes, from) == 20) {
      handshake = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  assert(handshake);
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  diagnostic_phase(1, 0, 3);
  if (argc > 1) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(diagnostic_stats.sent == 0 && diagnostic_stats.dropped > 0);
  } else {
    bool delivered = false;
    while (std::chrono::steady_clock::now() < deadline) {
      if (receive(bytes, from) == 68) {
        delivered = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(delivered && wire_get(bytes.data() + 12, 4) == 8 && bytes[64] == 1 && bytes[66] == 3);
    assert(diagnostic_stats.sent > 0);
    for (unsigned i = 0; i < 4096; ++i)
      diagnostic_phase(1, 0, 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    assert(diagnostic_stats.reasons[static_cast<std::size_t>(DiagnosticProducer::Drop::Socket)] > 0);
    assert(close(server) == 0);
    assert(unlink(path.c_str()) == 0);
    const auto prior = diagnostic_stats.dropped.load();
    diagnostic_phase(1, 0, 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    assert(diagnostic_stats.dropped > prior);
  }
  const auto stop = std::chrono::steady_clock::now();
  diagnostic_ipc->stop();
  assert(std::chrono::steady_clock::now() - stop < std::chrono::milliseconds(100));
  assert(diagnostic_stats.enabled == 0 && diagnostic_stats.records == 0 && diagnostic_stats.bytes == 0);
  if (argc > 1) {
    assert(close(server) == 0);
    assert(unlink(path.c_str()) == 0);
  }
  assert(rmdir(directory) == 0);
}
