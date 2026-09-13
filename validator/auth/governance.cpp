#include "governance.h"
namespace tos::auth {
Result<VerifiedCertificate> verify_current_governance(const ChainContext& chain, const RegistrySnapshot& governing,
                                                      const RegistryState& current, const Update& update,
                                                      const Authorizations& evidence, std::uint32_t inclusion,
                                                      ObjectReader& reader) {
  if ((update.operation_ != 4 && update.operation_ != 6) || update.identity_ != Hash{})
    return Error{"governance-target"};
  if (!evidence.owner_.empty() || !evidence.possession_.empty() || !evidence.administration_.empty() ||
      evidence.governance_.size() != 1)
    return Error{"governance-authorizations"};
  if (current.coordinate() != inclusion || current.chain_domain() != chain.chain_domain)
    return Error{"governance-current-state"};
  if (current.current_policy() != governing.policy_id())
    return Error{"governance-current-policy"};
  const auto& committee = governing.committee();
  if (committee.workchain_ != -1 || committee.shard_ != 0x8000000000000000ULL)
    return Error{"governance-committee"};
  if (committee.anchor_mc_ > inclusion || inclusion - committee.anchor_mc_ > 128)
    return Error{"admin-freshness"};
  auto id = object_id("update", update);
  if (!id.ok())
    return id.error();
  const auto& auth = evidence.governance_[0];
  if (auth.update_id_ != id.value() || auth.committee_ != governing.committee_id())
    return Error{"governance-binding"};
  auto payload = encode(update);
  if (!payload.ok())
    return payload.error();
  auto session = admin_session_id(chain, Hash{});
  if (!session.ok())
    return session.error();
  auto expected = make_duty(chain, governing, session.value(), 5, update.nonce_, payload.value());
  if (!expected.ok())
    return expected.error();
  auto raw = reader.resolve(auth.certificate_, 4);
  if (!raw.ok())
    return raw.error();
  auto cert = decode<Certificate>(raw.value());
  if (!cert.ok())
    return cert.error();
  auto verified = governing.verify(cert.value(), expected.value());
  if (!verified.ok())
    return verified.error();
  // Old sessions retain consensus authority, but their old role-5 references
  // cannot authorize new governance after an inclusion-time key change.
  for (const auto& record : cert.value().records_) {
    auto identity = current.identities().find(record.identity_);
    if (identity == current.identities().end())
      return Error{"governance-current-identity"};
    auto keys = select_identity_keys(identity->second, current, inclusion, {{5, 1, 1}});
    if (!keys.ok())
      return keys.error();
    auto ref = key_reference(keys.value()[0]);
    if (!ref.ok())
      return ref.error();
    const auto& component = record.components_[0];
    if (ref.value() != Keyref{component.suite_, component.parameters_, component.epoch_, component.key_id_})
      return Error{"governance-current-key"};
  }
  return verified;
}
}  // namespace tos::auth
