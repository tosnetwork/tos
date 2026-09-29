#pragma once
#include "diagnostic-producer.h"
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace tos::health {
// A single pump owns the socket. Validator actors only try the scalar ring.
class DiagnosticIpc {
 public:
  DiagnosticIpc(std::string path, pid_t peer, std::array<std::uint8_t,16> epoch,
                std::uint32_t sampling)
      : path_(std::move(path)), peer_(peer), producer_(diagnostic_stats,epoch,sampling), epoch_(epoch) {}
  bool start() {
    if (diagnostic_producer.load() != nullptr || peer_ <= 0 || !private_path()) return false;
    producer_.enable();
    diagnostic_producer.store(&producer_,std::memory_order_release);
    try { worker_=std::thread([this] { pump(); }); }
    catch (...) { producer_.disable(); diagnostic_producer.store(nullptr); return false; }
    return true;
  }
  void stop() noexcept {
    producer_.disable(); stop_.store(true,std::memory_order_release);
    if (worker_.joinable()) worker_.join();
  }
  ~DiagnosticIpc() { stop(); }
 private:
  bool private_path() const noexcept {
    if (path_.empty() || path_[0]!='/' || path_.size()>=sizeof(sockaddr_un::sun_path)) return false;
    const auto slash=path_.find_last_of('/');
    const auto parent=path_.substr(0,slash);
    struct stat st{};
    if (lstat(parent.c_str(),&st)!=0 || !S_ISDIR(st.st_mode) || st.st_uid!=getuid() || (st.st_mode&0077)!=0) return false;
    if (lstat(path_.c_str(),&st)!=0) return errno==ENOENT;
    return S_ISSOCK(st.st_mode) && st.st_uid==getuid() && (st.st_mode&0077)==0;
  }
  bool connect_peer() noexcept {
    if (!private_path()) return false;
    fd_=socket(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (fd_<0) return false;
    int yes=1;
    if (setsockopt(fd_,SOL_SOCKET,SO_PASSCRED,&yes,sizeof(yes))!=0) { disconnect(); return false; }
    sockaddr_un local{}; local.sun_family=AF_UNIX;
    // Linux autobinds an opaque abstract return address. Credentials, rather
    // than that address, authenticate the fixed peer's handshake response.
    if (bind(fd_,reinterpret_cast<sockaddr *>(&local),sizeof(sa_family_t))!=0) { disconnect(); return false; }
    sockaddr_un remote{}; remote.sun_family=AF_UNIX;
    std::memcpy(remote.sun_path,path_.data(),path_.size());
    if (connect(fd_,reinterpret_cast<sockaddr *>(&remote),sizeof(remote))!=0) { disconnect(); return false; }
    std::array<std::uint8_t,20> hello{};
    std::memcpy(hello.data(),"THS1",4); std::memcpy(hello.data()+4,epoch_.data(),16);
    if (send(fd_,hello.data(),hello.size(),MSG_DONTWAIT|MSG_NOSIGNAL)!=static_cast<ssize_t>(hello.size())) {
      disconnect(); return false;
    }
    return true;
  }
  bool authenticated() noexcept {
    std::array<std::uint8_t,20> ack{};
    alignas(cmsghdr) std::array<char,CMSG_SPACE(sizeof(ucred))> control{};
    iovec iov{ack.data(),ack.size()}; msghdr message{};
    message.msg_iov=&iov; message.msg_iovlen=1; message.msg_control=control.data(); message.msg_controllen=control.size();
    const auto size=recvmsg(fd_,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if (size<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return false;
    // Rejection must not leak descriptors installed by recvmsg.
    for (auto item=CMSG_FIRSTHDR(&message); item!=nullptr; item=CMSG_NXTHDR(&message,item)) {
      if (item->cmsg_level==SOL_SOCKET && item->cmsg_type==SCM_RIGHTS && item->cmsg_len>=CMSG_LEN(0)) {
        const auto count=(item->cmsg_len-CMSG_LEN(0))/sizeof(int);
        for (std::size_t i=0;i<count;++i) {
          int descriptor=-1; std::memcpy(&descriptor,CMSG_DATA(item)+i*sizeof(int),sizeof(int));
          if (descriptor>=0) close(descriptor);
        }
      }
    }
    if (size!=20 || (message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0 || std::memcmp(ack.data(),"THA1",4)!=0 ||
        std::memcmp(ack.data()+4,epoch_.data(),16)!=0) { disconnect(); return false; }
    const auto cmsg=CMSG_FIRSTHDR(&message);
    if (cmsg==nullptr || cmsg->cmsg_level!=SOL_SOCKET || cmsg->cmsg_type!=SCM_CREDENTIALS ||
        cmsg->cmsg_len!=CMSG_LEN(sizeof(ucred)) || CMSG_NXTHDR(&message,cmsg)!=nullptr) { disconnect(); return false; }
    ucred creds{}; std::memcpy(&creds,CMSG_DATA(cmsg),sizeof(creds));
    if (creds.pid!=peer_ || creds.uid!=getuid() || creds.gid!=getgid()) { disconnect(); return false; }
    ready_=true; return true;
  }
  void disconnect() noexcept { if (fd_>=0) close(fd_); fd_=-1; ready_=false; }
  void pump() noexcept {
    unsigned handshake_ticks=0, reconnect_ticks=0;
    while (!stop_.load(std::memory_order_acquire)) {
      if (fd_<0 && reconnect_ticks==0) { connect_peer(); reconnect_ticks=100; handshake_ticks=0; }
      if (reconnect_ticks>0) --reconnect_ticks;
      if (fd_>=0 && !ready_ && !authenticated() && ++handshake_ticks>=100) disconnect();
      DiagnosticProducer::Packet packet;
      for (unsigned i=0; i<64 && producer_.pop(packet); ++i) {
        if (!ready_ || send(fd_,packet.bytes.data(),packet.size,MSG_DONTWAIT|MSG_NOSIGNAL)!=packet.size) {
          diagnostic_stats.drop(DiagnosticProducer::Drop::Socket);
          if (fd_>=0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=ENOBUFS) disconnect();
        } else diagnostic_stats.add(diagnostic_stats.sent);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Fixed upper bound; discard rather than flush toward a failed receiver.
    DiagnosticProducer::Packet packet;
    for (unsigned i=0; i<DiagnosticProducer::capacity && producer_.pop(packet); ++i)
      diagnostic_stats.drop(DiagnosticProducer::Drop::Shutdown);
    disconnect();
  }
  std::string path_;
  pid_t peer_;
  DiagnosticProducer producer_;
  std::array<std::uint8_t,16> epoch_;
  std::atomic<bool> stop_{false};
  std::thread worker_;
  int fd_=-1;
  bool ready_=false;
};
// Retained until process teardown: no business actor can see freed storage.
inline std::unique_ptr<DiagnosticIpc> diagnostic_ipc;
}  // namespace tos::health
