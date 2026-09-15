#pragma once
#include "validator/auth/admin-service.h"
#include "validator/auth/api-semantics.h"
#include "validator/auth/service-issuer.h"

#include "service-fixture.h"

class AdminAuthority : public LifecycleAuthority {
 public:
  const RegistryState& registry;
  const KeyHistory* history;
  ChainContext chain;
  RegistrySnapshot snapshot;
  bool allow_owner = true;
  AdminAuthority(const RegistryState& registry, ChainContext chain, RegistrySnapshot snapshot)
      : registry(registry), history(&registry), chain(chain), snapshot(std::move(snapshot)) {
  }
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
    // A controlled owner-execution admission fixture; native account proof and
    // value/timelock admission remain separate native integration work.
    return allow_owner;
  }
  Result<bool> possession(const PossessionAuth& proof, const Update& update, const Key& key) const override {
    return verify_possession(chain, update, key, proof);
  }
  Result<bool> administration(const IdentityAuth& proof, const Update& update, const Identity& identity,
                              std::uint32_t at) const override {
    ObjectReader reader({});
    auto raw = reader.resolve(proof.certificate_, 4);
    if (!raw.ok())
      return raw.error();
    auto cert = decode<Certificate>(raw.value());
    if (!cert.ok())
      return cert.error();
    auto payload = encode(update);
    if (!payload.ok())
      return payload.error();
    auto session = admin_session_id(chain, identity.identity_);
    if (!session.ok())
      return session.error();
    auto expected = make_duty(chain, snapshot, session.value(), 5, update.nonce_, payload.value());
    if (!expected.ok())
      return expected.error();
    auto keys = select_identity_keys(identity, *history, at, {{5, 1, 1}});
    if (!keys.ok())
      return keys.error();
    return verify_identity_certificate(cert.value(), expected.value(), identity, keys.value(), at);
  }
  Authorizations evidence(const Update& update, const Identity& identity, bool owner_required) const {
    auto uid = value(object_id("update", update), "update-id");
    auto admin = value(registry.find(identity.active_[4].key_.key_id_), "admin-key");
    auto ref = value(key_reference(admin), "key-ref");
    auto duty = value(make_duty(chain, snapshot, value(admin_session_id(chain, identity.identity_), "admin-session"), 5,
                                update.nonce_, value(encode(update), "update")),
                      "admin-duty");
    Record record{identity.identity_, {{1, 1, ref.epoch_, ref.key_id_, {}}}};
    record.components_[0].signature_ = signature(value(signing_statement(duty, record), "admin-statement"));
    auto cert = value(encode(Certificate{duty, value(encode(update), "update"), {record}}), "certificate");
    Authorizations result;
    if (owner_required)
      result.owner_.push_back({uid, identity.stake_id_, identity.owner_workchain_, identity.owner_address_, {}});
    result.administration_.push_back({uid, identity.identity_, {4, cert, {}}});
    return result;
  }
};
class CorruptProvider : public C0SigningProvider {
  C0SigningProvider& provider_;

 public:
  explicit CorruptProvider(C0SigningProvider& provider) : provider_(provider) {
  }
  Result<Key> descriptor(const Hash& handle) const override {
    return provider_.descriptor(handle);
  }
  Result<Record> sign(const SignRequest& request) override {
    return provider_.sign(request);
  }
  Result<PossessionAuth> prove_possession(const ChainContext& chain, const StageRequest& request) override {
    auto result = provider_.prove_possession(chain, request);
    if (!result.ok())
      return result.error();
    result.value().signature_[0] ^= 1;
    return result;
  }
};
class ExtraHistory : public KeyHistory {
 public:
  const RegistryState& registry;
  Key key;
  ExtraHistory(const RegistryState& registry, Key key) : registry(registry), key(std::move(key)) {
  }
  Result<Key> find(const Hash& id) const override {
    auto kid = object_id("key", key);
    if (!kid.ok())
      return kid.error();
    return id == kid.value() ? Result<Key>(key) : registry.find(id);
  }
  Result<std::uint64_t> latest_epoch(const Hash& id, KeySlot slot) const override {
    auto old = registry.latest_epoch(id, slot);
    if (!old.ok())
      return old.error();
    if (id == key.identity_ && slot == KeySlot{key.role_, key.suite_, key.parameters_})
      return std::max(old.value(), key.epoch_);
    return old;
  }
  Result<bool> ever_registered(const Hash& id) const override {
    return registry.ever_registered(id);
  }
};
inline RegistrySnapshot admin_snapshot(const RegistryState& registry) {
  Committee committee;
  committee.policy_ = registry.current_policy();
  committee.election_ = h(31);
  committee.workchain_ = -1;
  committee.shard_ = 0x8000000000000000ULL;
  committee.catchain_ = 7;
  committee.anchor_mc_ = 100;
  for (const auto& [id, identity] : registry.identities()) {
    Member member{id, identity.stake_id_, 1, h(100), {}};
    for (const auto& ref : identity.active_)
      member.keys_.push_back(value(registry.find(ref.key_.key_id_), "key"));
    committee.members_.push_back(member);
  }
  return value(RegistrySnapshot::compile(committee, value(registry.policy_at(100), "policy")), "snapshot");
}
