#include "governance.h"
namespace tos::auth {
Result<VerifiedCertificate> verify_current_governance(const ChainContext& chain, const RegistrySnapshot& governing,
                                                      const CurrentRegistry& current, const Update& update,
                                                      const Authorizations& evidence, std::uint32_t inclusion,
                                                      ObjectReader& reader, const SignatureMeter* meter) {
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
  auto verified = governing.verify(cert.value(), expected.value(), meter);
  if (!verified.ok())
    return verified.error();
  // Old sessions retain consensus authority, but their old role-5 references
  // cannot authorize new governance after an inclusion-time key change.
  //
  // What has to be shown for each signer is one thing: the administration key
  // that signed is still the one this identity is currently active with. The
  // signature itself was already checked above, against the governing
  // snapshot's own public keys; this is the freshness question, not a second
  // verification.
  //
  // Two reads answer it. The active reference names the role, the suite and
  // parameters, the epoch and the key id -- everything the certificate
  // component names -- and the key itself is read for the one thing the
  // reference does not carry: whether its validity interval covers this
  // coordinate. An expired administration key is still the active one, so the
  // reference alone would admit it.
  //
  // What is no longer done is revalidating the whole identity for every signer.
  // The state was validated in full when it was opened, every key descriptor
  // loaded and checked once; repeating that per record cost seven reads a
  // signer where two answer the question, and on the largest certificate this
  // design admits that was the difference between two thousand eight hundred
  // reads and eight hundred.
  for (const auto& record : cert.value().records_) {
    auto identity = current.lookup_identity(record.identity_);
    if (!identity.ok())
      return identity.error();
    if (!identity.value())
      return Error{"governance-current-identity"};
    auto standing = identity_is_current(*identity.value(), inclusion);
    if (!standing.ok())
      return standing.error();
    const Keyref* active = nullptr;
    for (const auto& ref : identity.value()->active_)
      if (ref.role_ == 5 && ref.key_.suite_ == 1 && ref.key_.parameters_ == 1)
        active = &ref.key_;
    if (active == nullptr)
      return Error{"snapshot-missing"};
    // One comparison, because it is one fact. The epoch and the key id cannot
    // be told apart by a case: the identity's own validation binds the active
    // reference to the key it names, so a state whose reference disagrees with
    // its key does not decode, and a certificate whose component disagrees with
    // the governing snapshot fails the signature binding before reaching here.
    // What remains constructible is the reference having moved since the
    // governing anchor, which is a rotation.
    const auto& component = record.components_[0];
    if (*active != Keyref{component.suite_, component.parameters_, component.epoch_, component.key_id_})
      return Error{"governance-current-key"};
    auto key = current.find(active->key_id_);
    if (!key.ok())
      return key.error();
    if (key.value().valid_from_ > inclusion || key.value().valid_until_ <= inclusion)
      return Error{"snapshot-validity"};
  }
  return verified;
}
}  // namespace tos::auth
