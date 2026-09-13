#pragma once
#include <functional>
#include <memory>
#include <sys/types.h>

#include "codec.h"
namespace tos::auth {
// Private process channel for a signer and its provider/witness. This framing is
// not a second public signer API. Public requests retain the frozen JSON/binary
// contract. Only the configured OS principal can reach an internal handler.
class LocalListener {
  int fd_ = -1;
  std::string path_;
  uid_t principal_;
  std::uint64_t device_ = 0, inode_ = 0;
  LocalListener(int fd, std::string path, uid_t principal) : fd_(fd), path_(std::move(path)), principal_(principal) {
  }

 public:
  using Handler = std::function<Result<Bytes>(std::span<const std::uint8_t>)>;
  ~LocalListener();
  LocalListener(const LocalListener&) = delete;
  LocalListener& operator=(const LocalListener&) = delete;
  static Result<std::unique_ptr<LocalListener>> create(const std::string&, uid_t admitted_principal);
  Result<bool> serve_one(const Handler&, unsigned accept_timeout_ms = 1000);
};
Result<Bytes> local_call(const std::string& socket_path, uid_t expected_server, std::span<const std::uint8_t> request);
}  // namespace tos::auth
