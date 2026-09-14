#include "block/mc-config.h"

#include "manager-session-binding.h"
namespace tos::auth {
namespace {
NativeSessionIdForm form_of(const ManagerSessionInputs& inputs) {
  // The manager selects between three constructors and the identity is the hash
  // of whichever one it chose. Reproducing that selection is not a preference:
  // emitting a different constructor would name a session that never existed
  // even with identical field values.
  if (inputs.new_catchain_ids)
    return NativeSessionIdForm::group_new;
  return inputs.vertical_seqno == 0 ? NativeSessionIdForm::group : NativeSessionIdForm::group_ex;
}
}  // namespace

bool native_session_binding_active(td::Ref<vm::Cell> masterchain_state) {
  if (masterchain_state.is_null())
    return false;
  auto config = block::Config::extract_from_state(masterchain_state, block::Config::needCapabilities);
  if (config.is_error())
    return false;
  return config.ok()->get_global_version() >= 16 && (config.ok()->get_capabilities() & tos::capValidatorAuth) != 0;
}

Result<bool> native_session_identity_confirms(td::Ref<block::ValidatorSet> validator_set, tos::ShardIdFull shard,
                                              const ManagerSessionInputs& inputs, const Hash& manager_identity) {
  if (validator_set.is_null())
    return Error{"manager-session-validator-set"};
  if (manager_identity == Hash{})
    return Error{"manager-session-identity"};
  NativeSessionIdInput input;
  input.native_options_hash = inputs.options_hash;
  input.workchain = shard.workchain;
  input.shard = shard.shard;
  input.maximal_vertical_seqno = inputs.vertical_seqno;
  input.last_key_block_seqno = inputs.key_block_seqno;
  input.form = form_of(inputs);
  auto derived = derive_native_session_identity(std::move(validator_set), input);
  if (!derived.ok())
    return derived.error();
  return derived.value().native_session_id == manager_identity;
}
}  // namespace tos::auth
