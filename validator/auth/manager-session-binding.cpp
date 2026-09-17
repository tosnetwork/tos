#include <set>

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
  // The set this session will run under has to be one the authenticated path
  // would have admitted. Committee derivation refuses an elected member that
  // names no registry identity, because an unbound member is exactly what an
  // election that never reached the registry produces. The identity below is
  // derived from keys, addresses and weights alone and would agree either way,
  // so without this the manager could create a group whose roster the
  // authenticated committee would have refused, and consensus would receive
  // it. Checked here rather than at the call site: the caller is a declared
  // insertion into a frozen file, and this keeps what the confirmation means
  // in one place.
  std::set<td::Bits256> identities, stakes, consensus_keys;
  for (const auto& member : validator_set->export_vector()) {
    if (!member.auth_binding)
      return Error{"manager-session-election-binding"};
    // Derivation refuses a set that names one identity, one stake or one
    // consensus key twice, because a committee cannot say which member a
    // duplicate is. These are the rules it applies to the member list alone,
    // so they can be applied here; the ones that consult the registry cannot,
    // because that needs an independently established anchor this caller does
    // not yet have.
    if (!identities.insert(member.auth_binding->identity).second ||
        !stakes.insert(member.auth_binding->stake_id).second ||
        !consensus_keys.insert(member.key.as_bits256()).second)
      return Error{"manager-session-election-duplicate"};
  }
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
