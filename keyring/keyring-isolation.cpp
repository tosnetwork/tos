#include "common/errorcode.h"

#include "keyring.hpp"

namespace tos::keyring {
namespace {
auth::Hash isolation_hash(PublicKeyHash key_hash) {
  auth::Hash result{};
  auto bytes = key_hash.as_slice();
  std::copy(bytes.ubegin(), bytes.uend(), result.begin());
  return result;
}
td::Status status(auth::Result<bool> result) {
  return result.ok() && result.value()
             ? td::Status::OK()
             : td::Status::Error(ErrorCode::notready,
                                 result.ok() ? "keyring-isolation-unavailable" : result.error().code);
}
}  // namespace
td::Status KeyringImpl::admit_generic(PublicKeyHash key_hash) {
  if (!protection_waiters_.empty())
    return td::Status::Error(ErrorCode::notready, "keyring-isolation-barrier");
  return status(isolation_.admit(isolation_hash(key_hash)));
}
td::Status KeyringImpl::admit_bulk_export() {
  if (!protection_waiters_.empty())
    return td::Status::Error(ErrorCode::notready, "keyring-isolation-barrier");
  return status(isolation_.admit_export_all());
}
void KeyringImpl::finish_protections() {
  auto promises = std::move(protection_waiters_);
  protection_waiters_.clear();
  for (auto& [key, promise] : promises) {
    auto protected_key = status(isolation_.protect(isolation_hash(key)));
    if (protected_key.is_error())
      promise.set_error(std::move(protected_key));
    else
      promise.set_value(td::Unit());
  }
}
void KeyringImpl::protect_validator_auth_key(PublicKeyHash key_hash, td::Promise<td::Unit> promise) {
  if (protection_waiters_.size() >= 1024)
    return promise.set_error(td::Status::Error(ErrorCode::notready, "keyring-isolation-waiter-bound"));
  protection_waiters_.emplace_back(key_hash, std::move(promise));
  if (raw_inflight_.empty())
    finish_protections();
}
}  // namespace tos::keyring
