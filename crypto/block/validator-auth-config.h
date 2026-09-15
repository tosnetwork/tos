#pragma once
#include "td/utils/Status.h"
#include "vm/dict.h"
namespace block {
// These structural gates accompany native execution authority. They neither
// authorize a proposed change nor validate the complete public registry archive.
td::Status validate_validator_auth_root_shape(td::Ref<vm::Cell>);
td::Status validate_validator_auth_config(vm::Dictionary&);
td::Status validate_validator_auth_transition(vm::Dictionary& before, vm::Dictionary& after);
}  // namespace block
