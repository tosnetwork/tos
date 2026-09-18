#include "validator-auth-session-store-marker.h"

namespace tos::validator {
namespace {
constexpr td::Slice key() {
  return td::Slice{"tos.state.validator_auth_session_commitment_store.v1"};
}
constexpr td::Slice value() {
  return td::Slice{"provisioned"};
}
}  // namespace

td::Status mark_validator_auth_session_store_provisioned(td::KeyValue& kv) {
  TRY_STATUS(kv.begin_write_batch());
  auto status = kv.set(key(), value());
  if (status.is_error()) {
    kv.abort_write_batch().ignore();
    return status;
  }
  return kv.commit_write_batch();
}

td::Result<bool> validator_auth_session_store_is_provisioned(td::KeyValue& kv) {
  std::string raw;
  TRY_RESULT(found, kv.get(key(), raw));
  if (found == td::KeyValue::GetStatus::NotFound)
    return false;
  if (td::Slice{raw} != value())
    return td::Status::Error("validator-auth session-store marker corrupt");
  return true;
}
}  // namespace tos::validator
