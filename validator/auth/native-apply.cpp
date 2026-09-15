#include "native-apply.h"
namespace tos::auth {
Result<bool> NativeLifecycleAuthority::validate_context() const {
  if (current_.chain_domain() != context_.chain.chain_domain || current_.coordinate() == UINT32_MAX)
    return Error{"authority-current-state"};
  if (current_.current_policy() != context_.governing.policy_id())
    return Error{"authority-current-policy"};
  const auto& committee = context_.governing.committee();
  if (committee.workchain_ != -1 || committee.shard_ != 0x8000000000000000ULL)
    return Error{"authority-committee"};
  if (committee.anchor_mc_ > current_.coordinate() || current_.coordinate() - committee.anchor_mc_ > 128)
    return Error{"admin-freshness"};
  auto session = admin_session_id(context_.chain, Hash{});
  if (!session.ok())
    return session.error();
  return true;
}
Result<bool> NativeLifecycleAuthority::owner(const OwnerAuth& proof, const Update& update,
                                             const Identity& identity) const {
  auto valid = validate_context();
  if (!valid.ok())
    return valid.error();
  // An uncommitted same-block state cannot authenticate its own owner approval.
  if (proof.proof_.anchor_.seqno_ >= current_.coordinate())
    return Error{"owner-finality-coordinate"};
  auto anchor = context_.history.finalized_anchor(proof.proof_.anchor_.seqno_);
  if (!anchor.ok())
    return anchor.error();
  auto verified = verify_owner_execution(proof, update, identity, anchor.value(), context_.chain, reader_);
  if (!verified.ok())
    return verified.error();
  return true;
}
Result<bool> NativeLifecycleAuthority::possession(const PossessionAuth& proof, const Update& update,
                                                  const Key& key) const {
  return verify_possession(context_.chain, update, key, proof);
}
Result<bool> NativeLifecycleAuthority::administration(const IdentityAuth& proof, const Update& update,
                                                      const Identity& identity, std::uint32_t inclusion) const {
  auto valid = validate_context();
  if (!valid.ok())
    return valid.error();
  if (inclusion != current_.coordinate())
    return Error{"authority-current-state"};
  auto payload = encode(update);
  if (!payload.ok())
    return payload.error();
  auto session = admin_session_id(context_.chain, identity.identity_);
  if (!session.ok())
    return session.error();
  auto expected = make_duty(context_.chain, context_.governing, session.value(), 5, update.nonce_, payload.value());
  if (!expected.ok())
    return expected.error();
  auto keys = select_identity_keys(identity, current_, inclusion, {{5, 1, 1}});
  if (!keys.ok())
    return keys.error();
  auto raw = reader_.resolve(proof.certificate_, 4);
  if (!raw.ok())
    return raw.error();
  auto certificate = decode<Certificate>(raw.value());
  if (!certificate.ok())
    return certificate.error();
  return verify_identity_certificate(certificate.value(), expected.value(), identity, keys.value(), inclusion);
}
Result<RegistryState> apply_native_identity_block(const RegistryState& parent, std::uint32_t inclusion,
                                                  const std::vector<std::pair<Update, Authorizations>>& updates,
                                                  const NativeIdentityContext& context, ObjectReader& reader) {
  return parent.apply_identity_block(inclusion, updates,
                                     [&](const RegistryState& current, const Update& update,
                                         const Authorizations& evidence) -> Result<IdentityChange> {
                                       NativeLifecycleAuthority authority(current, context, reader);
                                       auto valid = authority.validate_context();
                                       if (!valid.ok())
                                         return valid.error();
                                       auto identity = current.identities().find(update.identity_);
                                       if (identity == current.identities().end())
                                         return Error{"unknown-identity"};
                                       return apply_identity_update(identity->second, current, update, evidence,
                                                                    inclusion, authority);
                                     });
}
}  // namespace tos::auth
