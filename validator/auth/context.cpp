#include "context.h"
namespace tos::auth {
namespace {
Result<bool> chain(const ChainContext& context) {
  if (context.genesis_root == Hash{} || context.genesis_file == Hash{} || context.chain_domain == Hash{})
    return Error{"chain-context"};
  return true;
}
Result<Bytes> prefix(const ChainContext& c) {
  auto valid = chain(c);
  if (!valid.ok())
    return valid.error();
  Writer w;
  w.integer(c.network);
  w.bytes(c.genesis_root);
  w.bytes(c.genesis_file);
  if (!w.ok())
    return Error{w.error};
  return w.data;
}
}  // namespace
Result<Hash> session_id(const ChainContext& c, const RegistrySnapshot& snapshot, const SessionOrigin& origin) {
  auto start = prefix(c);
  if (!start.ok())
    return start.error();
  Writer w;
  w.bytes(start.value());
  w.bytes(snapshot.committee_id());
  w.bytes(origin.native_options_hash);
  w.integer(origin.vertical_seqno);
  w.integer(origin.key_block_seqno);
  if (!w.ok())
    return Error{w.error};
  return digest("session", w.data);
}
Result<Hash> admin_session_id(const ChainContext& c, const Hash& target) {
  auto start = prefix(c);
  if (!start.ok())
    return start.error();
  start.value().insert(start.value().end(), target.begin(), target.end());
  return digest("admin-session", start.value());
}
Result<Duty> make_duty(const ChainContext& c, const RegistrySnapshot& snapshot, const Hash& session, std::uint8_t role,
                       std::uint64_t position, std::span<const std::uint8_t> payload) {
  if (payload.size() > 4096)
    return Error{"payload-bound"};
  auto valid = chain(c);
  if (!valid.ok())
    return valid.error();
  if (session == Hash{})
    return Error{"session"};
  Bytes raw{role};
  raw.insert(raw.end(), payload.begin(), payload.end());
  auto hash = digest("payload", raw);
  if (!hash.ok())
    return hash.error();
  Duty duty{c.network,
            c.genesis_root,
            c.genesis_file,
            snapshot.policy_id(),
            snapshot.committee_id(),
            session,
            snapshot.committee().workchain_,
            snapshot.committee().shard_,
            snapshot.committee().anchor_mc_,
            snapshot.committee().catchain_,
            position,
            role,
            hash.value()};
  if (role == 5) {
    duty.workchain_ = -1;
    duty.shard_ = 0x8000000000000000ULL;
  }
  auto checked = validate_payload(duty, Bytes(payload.begin(), payload.end()));
  if (!checked.ok())
    return checked.error();
  return duty;
}
Result<Bytes> possession_preimage(const ChainContext& c, const Update& update, const Key& key) {
  if (c.chain_domain == Hash{})
    return Error{"chain-domain"};
  auto raw = encode(update);
  if (!raw.ok())
    return raw.error();
  auto id = object_id("key", key);
  if (!id.ok())
    return id.error();
  Writer w;
  constexpr char tag[] = "TOS/P0/pop/v1";
  w.bytes(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(tag), sizeof(tag)));
  w.integer(c.network);
  w.bytes(c.chain_domain);
  w.blob(raw.value(), 32768);
  w.bytes(id.value());
  if (!w.ok())
    return Error{w.error};
  return w.data;
}
Result<bool> verify_possession(const ChainContext& c, const Update& update, const Key& key, const PossessionAuth& pop,
                               const SignatureMeter* meter) {
  if ((update.operation_ != 1 && update.operation_ != 2) || update.identity_ != key.identity_ || key.suite_ != 1 ||
      key.parameters_ != 1 || key.role_ < 1 || key.role_ > 5 || key.capacity_domain_ != Hash{} ||
      key.capacity_limit_ != 0)
    return Error{"possession-key"};
  auto encoded = encode(key);
  if (!encoded.ok())
    return encoded.error();
  if (update.new_key_ != encoded.value())
    return Error{"possession-key"};
  auto uid = object_id("update", update);
  if (!uid.ok())
    return uid.error();
  auto ref = key_reference(key);
  if (!ref.ok())
    return ref.error();
  if (pop.update_id_ != uid.value() || pop.key_ != ref.value())
    return Error{"possession-binding"};
  auto admitted = AdmittedKey::admit(key.suite_, key.parameters_, key.public_key_);
  if (!admitted.ok())
    return admitted.error();
  auto preimage = possession_preimage(c, update, key);
  if (!preimage.ok())
    return preimage.error();
  if (meter)
    (*meter)(admitted.value().suite());
  auto signature = admitted.value().verify(preimage.value(), pop.signature_);
  if (!signature.ok())
    return signature.error();
  if (!signature.value())
    return Error{"possession-signature"};
  return true;
}
Result<bool> verify_identity_certificate(const Certificate& cert, const Duty& expected, const Identity& identity,
                                         const std::vector<Key>& keys, std::uint32_t inclusion,
                                         const SignatureMeter* meter) {
  auto raw = encode(cert);
  if (!raw.ok())
    return raw.error();
  if (raw.value().size() > 524288)
    return Error{"certificate-budget"};
  if (inclusion < expected.anchor_mc_ || inclusion - expected.anchor_mc_ > 128)
    return Error{"admin-freshness"};
  if (cert.duty_ != expected || expected.role_ != 5 || expected.workchain_ != -1 ||
      expected.shard_ != 0x8000000000000000ULL)
    return Error{"identity-context"};
  auto payload = validate_payload(expected, cert.payload_);
  if (!payload.ok())
    return payload.error();
  auto update = decode<Update>(cert.payload_);
  if (!update.ok())
    return update.error();
  if (update.value().identity_ != identity.identity_)
    return Error{"identity-target"};
  if (cert.records_.size() != 1 || cert.records_[0].identity_ != identity.identity_ || keys.size() != 1 ||
      cert.records_[0].components_.size() != 1)
    return Error{"identity-components"};
  const auto& key = keys[0];
  const auto& component = cert.records_[0].components_[0];
  if (key.valid_from_ > inclusion || key.valid_until_ <= inclusion || key.epoch_ == 0 ||
      key.identity_ != identity.identity_ || key.role_ != 5 || key.suite_ != 1 || key.parameters_ != 1)
    return Error{"identity-key"};
  auto ref = key_reference(key);
  if (!ref.ok())
    return ref.error();
  bool active = false;
  for (const auto& current : identity.active_)
    if (current.role_ == 5 && current.key_ == ref.value())
      active = true;
  if (!active || ref.value() != Keyref{component.suite_, component.parameters_, component.epoch_, component.key_id_})
    return Error{"identity-key-binding"};
  auto admitted = AdmittedKey::admit(key.suite_, key.parameters_, key.public_key_);
  if (!admitted.ok())
    return admitted.error();
  auto statement = signing_statement(expected, cert.records_[0]);
  if (!statement.ok())
    return statement.error();
  if (meter)
    (*meter)(admitted.value().suite());
  auto signature = admitted.value().verify(statement.value(), component.signature_);
  if (!signature.ok())
    return signature.error();
  if (!signature.value())
    return Error{"identity-signature"};
  return true;
}
}  // namespace tos::auth
