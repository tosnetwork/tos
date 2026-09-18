#pragma once
#include "td/db/KeyValue.h"

namespace tos::validator {
td::Status mark_validator_auth_session_store_provisioned(td::KeyValue&);
td::Result<bool> validator_auth_session_store_is_provisioned(td::KeyValue&);
}  // namespace tos::validator
