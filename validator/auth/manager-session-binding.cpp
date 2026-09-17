#include "block/mc-config.h"

#include "manager-session-binding.h"
#include "native-committee.h"
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

Result<bool> native_session_identity_confirms(td::Ref<vm::Cell> masterchain_state,
                                              td::Ref<block::ValidatorSet> validator_set, tos::ShardIdFull shard,
                                              const ManagerSessionInputs& inputs, const Hash& manager_identity) {
  if (validator_set.is_null())
    return Error{"manager-session-validator-set"};
  if (manager_identity == Hash{})
    return Error{"manager-session-identity"};
  // The state this session will run under has to be one the authenticated path
  // admits. Derivation's rules divide into those decided from the state alone
  // and those that need an anchor and an archive read; this caller has the
  // first and not the second, so it applies the first in full, as derivation
  // states them, rather than a hand-kept subset. A subset is the failure: the
  // identity below is a hash of keys, addresses and weights, so it agrees
  // whether or not the election was admissible, and the manager would hand
  // consensus a group whose roster derivation refuses while both sides kept
  // passing their own tests.
  //
  // The registry rules stay out, and that is stated rather than implied: they
  // need an independently established anchor this caller does not yet have,
  // and reaching for an unestablished one would be worse than not checking.
  auto admitted = admit_masterchain_state(std::move(masterchain_state));
  if (!admitted.ok())
    return admitted.error();
  // And the roster itself, under the name derivation gives the same refusal for
  // the members it selects. Every rule above is about the state and reaches the
  // roster only through it, so a roster that did not come from this state would
  // otherwise be carried by an admissible state that says nothing about it.
  //
  // This is the whole of what can be said here about that pairing. Recomputing
  // the selection to prove the roster is this state's needs the shard hashes a
  // full configuration carries, and what is extracted above is a plain one; the
  // caller passes the state its set came from, and the requirement here is that
  // the roster is one derivation would build a committee from.
  for (const auto& member : validator_set->export_vector())
    if (!member.auth_binding)
      return Error{"selected-binding-required"};
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
