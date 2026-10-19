#pragma once

#include "block/auth-policy.h"

namespace tos::validator {
// Used before publishing a trusted snapshot. Error-valued proof lookups must not
// become null/legacy configurations, including at startup and archive import.
inline td::Status validate_auth_policy_admission(td::Result<td::Ref<vm::Cell>> candidate,
                                                 td::Result<td::Ref<vm::Cell>> previous, bool has_previous) {
  TRY_RESULT(next, std::move(candidate));
  if (!has_previous) {
    return block::validate_auth_policy_config(std::move(next));
  }
  TRY_RESULT(old, std::move(previous));
  if (old.is_null()) {
    return td::Status::Error("previous AUTH configuration root is missing");
  }
  return block::validate_auth_policy_transition(std::move(old), std::move(next));
}
}  // namespace tos::validator
