#include <algorithm>
#include <set>

#include "verify.h"
namespace tos::auth {
namespace {
Result<std::uint64_t> checked_weight_add(std::uint64_t a, std::uint64_t b) {
  std::uint64_t value;
  if (__builtin_add_overflow(a, b, &value))
    return Error{"weight"};
  return value;
}
Result<std::uint64_t> checked_weight_mul(std::uint64_t a, std::uint64_t b) {
  std::uint64_t value;
  if (__builtin_mul_overflow(a, b, &value))
    return Error{"weight"};
  return value;
}
}  // namespace

Result<Keyref> key_reference(const Key& k) {
  auto id = object_id("key", k);
  if (!id.ok())
    return id.error();
  return Keyref{k.suite_, k.parameters_, k.epoch_, id.value()};
}
Result<Bytes> signing_statement(const Duty& duty, const Record& record) {
  std::vector<Keyref> refs;
  for (const auto& c : record.components_)
    refs.push_back({c.suite_, c.parameters_, c.epoch_, c.key_id_});
  return encode(Statement{duty, record.identity_, std::move(refs)});
}
Result<bool> validate_payload(const Duty& duty, const Bytes& payload) {
  Bytes preimage{duty.role_};
  preimage.insert(preimage.end(), payload.begin(), payload.end());
  auto hash = digest("payload", preimage);
  if (!hash.ok())
    return hash.error();
  if (hash.value() != duty.payload_hash_)
    return Error{"payload-hash"};
  if (duty.role_ == 5) {
    auto intent = decode<Update>(payload);
    if (!intent.ok())
      return intent.error();
    if (intent.value().operation_ < 1 || intent.value().operation_ > 7 || intent.value().nonce_ != duty.position_)
      return Error{"admin-payload"};
    return true;
  }
  if (duty.role_ < 1 || duty.role_ > 4 || duty.position_ > 0xffffffffULL)
    return Error{"role-position"};
  constexpr std::array<std::uint8_t, 4> candidate{0x3f, 0xcd, 0x91, 0xb6}, notarize{0xa8, 0x05, 0xf6, 0xcd},
      finalize{0x05, 0xe1, 0xa7, 0x40}, skip{0x26, 0x1f, 0x6b, 0x2f};
  auto role = duty.role_;
  std::size_t size = role == 1 ? 40 : role == 4 ? 8 : 44, offset = role == 2 || role == 3 ? 8 : 4;
  const auto& prefix = role == 1 ? candidate : role == 2 ? notarize : role == 3 ? finalize : skip;
  if (payload.size() != size || !std::equal(prefix.begin(), prefix.end(), payload.begin()))
    return Error{"payload-type"};
  if (offset == 8 && !std::equal(candidate.begin(), candidate.end(), payload.begin() + 4))
    return Error{"payload-type"};
  std::uint32_t slot = 0;
  for (unsigned i = 0; i < 4; ++i)
    slot |= std::uint32_t(payload[offset + i]) << (8 * i);
  if (slot != duty.position_)
    return Error{"payload-position"};
  return true;
}
Result<RegistrySnapshot> RegistrySnapshot::compile(const Committee& committee, const Policy& policy) {
  auto policy_raw = encode(policy);
  if (!policy_raw.ok())
    return policy_raw.error();
  if (policy.phase_ != 0 || policy.suites_ != std::vector<Suite>{{1, 1}})
    return Error{"unsupported-profile"};
  if (policy.interface_digest_ != interface_fingerprint)
    return Error{"interface-digest"};
  if (policy.revision_ == 0 || policy.max_envelope_ != 4096 || policy.max_certificate_ != 524288 ||
      policy.effective_from_ > committee.anchor_mc_)
    return Error{"c0-policy"};
  auto cid = object_id("committee", committee);
  if (!cid.ok())
    return cid.error();
  auto pid = object_id("policy", policy);
  if (!pid.ok())
    return pid.error();
  if (committee.policy_ != pid.value())
    return Error{"registry-policy"};
  if (committee.members_.empty() || committee.members_.size() > 400)
    return Error{"registry-bound"};
  RegistrySnapshot out;
  out.committee_ = committee;
  out.policy_ = policy;
  out.committee_id_ = cid.value();
  out.policy_id_ = pid.value();
  std::set<Hash> stakes;
  Hash previous{};
  for (const auto& member : committee.members_) {
    if (member.identity_ <= previous || member.stake_id_ == Hash{} || !stakes.insert(member.stake_id_).second)
      return Error{"registry-identities"};
    previous = member.identity_;
    auto total = checked_weight_add(out.total_, member.weight_);
    if (!total.ok())
      return total.error();
    if (member.weight_ == 0 || total.value() > max_weight)
      return Error{"weight"};
    out.total_ = total.value();
    if (member.keys_.size() != 5)
      return Error{"registry-keys"};
    Entry entry;
    entry.member = member;
    for (unsigned i = 0; i < 5; ++i) {
      const auto& k = member.keys_[i];
      if (k.role_ != i + 1 || k.suite_ != 1 || k.parameters_ != 1 || k.identity_ != member.identity_ || k.epoch_ == 0 ||
          k.valid_from_ > committee.anchor_mc_ || committee.anchor_mc_ >= k.valid_until_)
        return Error{"key-validity"};
      if (k.capacity_domain_ != Hash{} || k.capacity_limit_ != 0)
        return Error{"c0-capacity"};
      auto admitted = AdmittedKey::admit(k.suite_, k.parameters_, k.public_key_);
      if (!admitted.ok())
        return admitted.error();
      auto ref = key_reference(k);
      if (!ref.ok())
        return ref.error();
      entry.references.push_back(ref.value());
      entry.keys.push_back(admitted.value());
    }
    out.roster_.emplace(member.identity_, std::move(entry));
  }
  return out;
}
Result<std::uint64_t> RegistrySnapshot::verify_records(const Duty& duty, const Bytes& payload,
                                                       const std::vector<Record>& records, const Duty& expected,
                                                       bool quorum) const {
  if (duty != expected)
    return Error{"expected-context"};
  if (duty.committee_ != committee_id_ || duty.policy_ != policy_id_ || duty.workchain_ != committee_.workchain_ ||
      duty.shard_ != committee_.shard_ || duty.anchor_mc_ != committee_.anchor_mc_ ||
      duty.catchain_ != committee_.catchain_)
    return Error{"context-binding"};
  auto body = validate_payload(duty, payload);
  if (!body.ok())
    return body.error();
  if (records.empty() || records.size() > roster_.size())
    return Error{"signer-order"};
  struct Pending {
    const AdmittedKey* key;
    Bytes statement;
    const Bytes* signature;
  };
  std::vector<Pending> pending;
  Hash previous{};
  std::uint64_t weight = 0;
  for (const auto& row : records) {
    if (row.identity_ <= previous)
      return Error{"signer-order"};
    previous = row.identity_;
    auto member = roster_.find(row.identity_);
    if (member == roster_.end())
      return Error{"unknown-signer"};
    if (row.components_.size() != 1)
      return Error{"c0-components"};
    const auto& c = row.components_[0];
    if (Keyref{c.suite_, c.parameters_, c.epoch_, c.key_id_} != member->second.references[duty.role_ - 1])
      return Error{"key-binding"};
    if (c.signature_.size() != 64)
      return Error{"signature-size"};
    auto sum = checked_weight_add(weight, member->second.member.weight_);
    if (!sum.ok())
      return sum.error();
    if (sum.value() > max_weight)
      return Error{"weight"};
    weight = sum.value();
    auto statement = signing_statement(duty, row);
    if (!statement.ok())
      return statement.error();
    pending.push_back({&member->second.keys[duty.role_ - 1], std::move(statement.value()), &c.signature_});
  }
  auto signed_weight = checked_weight_mul(3, weight), required_weight = checked_weight_mul(2, total_);
  if (!signed_weight.ok())
    return signed_weight.error();
  if (!required_weight.ok())
    return required_weight.error();
  if (quorum && signed_weight.value() < required_weight.value())
    return Error{"quorum"};
  for (const auto& p : pending) {
    auto valid = p.key->verify(p.statement, *p.signature);
    if (!valid.ok())
      return valid.error();
    if (!valid.value())
      return Error{"signature"};
  }
  return weight;
}
Result<VerifiedCertificate> RegistrySnapshot::verify(const Certificate& cert, const Duty& expected) const {
  auto raw = encode(cert);
  if (!raw.ok())
    return raw.error();
  if (raw.value().size() > policy_.max_certificate_)
    return Error{"certificate-budget"};
  auto weight = verify_records(cert.duty_, cert.payload_, cert.records_, expected, true);
  if (!weight.ok())
    return weight.error();
  auto id = digest("certificate", raw.value());
  if (!id.ok())
    return id.error();
  std::vector<Hash> signers;
  for (const auto& r : cert.records_)
    signers.push_back(r.identity_);
  return VerifiedCertificate{id.value(), policy_id_, committee_id_, cert.duty_, std::move(signers), weight.value()};
}
Result<std::uint64_t> RegistrySnapshot::verify(const Envelope& env, const Duty& expected) const {
  auto raw = encode(env);
  if (!raw.ok())
    return raw.error();
  if (raw.value().size() > policy_.max_envelope_)
    return Error{"envelope-budget"};
  return verify_records(env.duty_, env.payload_, {env.record_}, expected, false);
}
}  // namespace tos::auth
