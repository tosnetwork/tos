#pragma once

#include "crypto/block/validator-set.h"
#include "native-session-id-core.h"

namespace tos::auth {

// Produces the exact native identity that ValidatorManagerImpl constructs for
// this validator set and caller-owned identity form. It does not select a form,
// options hash or vertical coordinate from local time or a newer state.
Result<NativeSessionIdentity> derive_native_session_identity(
    td::Ref<block::ValidatorSet> validator_set,
    const NativeSessionIdInput& input);

}  // namespace tos::auth
