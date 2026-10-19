#pragma once

#include "td/utils/Status.h"
#include "td/utils/bits.h"
#include "vm/cells.h"

namespace block {
inline constexpr char auth_policy_profile[] =
    "TOS-AUTH-POLICY-v1;config=48;tag=a1;suite=1;retired=u16;sequence=u64;deadline=u32;network=bits256;monotonic";
struct AuthPolicy {
  td::Bits256 network;
  td::uint64 sequence = 0;
  td::uint16 retired = 0;
  td::uint32 deadline = 0;
};
td::Result<AuthPolicy> unpack_auth_policy(td::Ref<vm::Cell> value);
// Absent on legacy configurations only. Mandatory starting at version 17.
td::Status validate_auth_policy_config(td::Ref<vm::Cell> config);
td::Status validate_auth_policy_transition(td::Ref<vm::Cell> old_config, td::Ref<vm::Cell> new_config);
}  // namespace block
