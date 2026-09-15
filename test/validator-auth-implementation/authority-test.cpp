#include <iostream>

#include "validator/auth/service-auth.h"

#include "native-fixture.h"
using namespace p0_fixture;
Bytes sign(std::span<const std::uint8_t> message) {
  auto seed = h(7);
  Hash public_key{};
  std::array<unsigned char, 64> secret{};
  check(crypto_sign_seed_keypair(public_key.data(), secret.data(), seed.data()) == 0, "test-key");
  Bytes signature(64);
  check(crypto_sign_detached(signature.data(), nullptr, message.data(), message.size(), secret.data()) == 0,
        "test-sign");
  return signature;
}
class Witness : public ReceiptWitness {
 public:
  std::map<std::uint64_t, Hash> entries;
  Result<bool> contains(std::uint64_t sequence, const Hash& hash) const override {
    auto i = entries.find(sequence);
    return i != entries.end() && i->second == hash;
  }
};
int main() {
  try {
    auto registry = state();
    auto identity = registry.identities().begin()->second;
    auto old = value(registry.find(identity.active_[0].key_.key_id_), "old-key");
    auto key = old;
    key.epoch_ = 2;
    key.valid_from_ = 1;
    ChainContext chain{-239, h(11), h(12), registry.chain_domain()};
    Update update{2,
                  identity.identity_,
                  0,
                  value(object_id("identity", identity), "predecessor"),
                  1,
                  identity.active_[0].key_.key_id_,
                  value(encode(key), "key"),
                  {},
                  {}};
    auto preimage = value(possession_preimage(chain, update, key), "pop-preimage");
    PossessionAuth pop{value(object_id("update", update), "update"), value(key_reference(key), "keyref"),
                       sign(preimage)};
    value(verify_possession(chain, update, key, pop), "valid-pop");
    auto bad_pop = pop;
    bad_pop.signature_[0] ^= 1;
    check(!verify_possession(chain, update, key, bad_pop).ok(), "pop-signature");
    auto other = chain;
    other.network++;
    check(!verify_possession(other, update, key, pop).ok(), "pop-network");
    auto changed = update;
    changed.nonce_++;
    check(!verify_possession(chain, changed, key, pop).ok(), "pop-update");
    Committee committee;
    committee.policy_ = registry.current_policy();
    committee.election_ = h(31);
    committee.workchain_ = -1;
    committee.shard_ = 0x8000000000000000ULL;
    committee.catchain_ = 7;
    for (const auto& [id, state] : registry.identities()) {
      Member m{id, state.stake_id_, 1, h(100), {}};
      for (const auto& ref : state.active_)
        m.keys_.push_back(value(registry.find(ref.key_.key_id_), "member-key"));
      committee.members_.push_back(m);
    }
    auto snapshot = value(RegistrySnapshot::compile(committee, value(registry.policy_at(0), "policy")), "snapshot");
    auto session = value(admin_session_id(chain, identity.identity_), "admin-session");
    auto payload = value(encode(update), "update-payload");
    auto duty = value(make_duty(chain, snapshot, session, 5, 0, payload), "duty");
    auto admin = value(registry.find(identity.active_[4].key_.key_id_), "admin-key");
    auto ref = value(key_reference(admin), "admin-ref");
    Record row{identity.identity_, {{ref.suite_, ref.parameters_, ref.epoch_, ref.key_id_, {}}}};
    row.components_[0].signature_ = sign(value(signing_statement(duty, row), "admin-statement"));
    Certificate cert{duty, payload, {row}};
    value(verify_identity_certificate(cert, duty, identity, {admin}, 1), "identity-authority");
    check(!snapshot.verify(cert, duty).ok(), "identity-not-governance");
    check(!verify_identity_certificate(cert, duty, identity, {admin}, 129).ok(), "admin-freshness");
    value(verify_identity_certificate(cert, duty, identity, {admin}, 128), "admin-boundary");
    auto rotated = identity;
    rotated.active_[4].key_.epoch_++;
    check(!verify_identity_certificate(cert, duty, rotated, {admin}, 1).ok(), "current-admin-binding");
    auto another = duty;
    another.network_++;
    check(!verify_identity_certificate(cert, another, identity, {admin}, 1).ok(), "admin-context");
    auto consensus_session = value(session_id(chain, snapshot, {}), "consensus-session");
    auto native_options = SessionOrigin{h(1), 0, 0};
    check(consensus_session != value(session_id(chain, snapshot, native_options), "session-options"),
          "session-options-binding");
    check(session != value(admin_session_id(chain, h(2)), "other-admin-session"), "admin-target-session");
    ServicePolicy service{h(100), 1, {}, {{1, 1}}};
    ServiceTrust permit_trust, receipt_trust;
    ServiceKey service_key{h(101), old.public_key_};
    value(permit_trust.install_trusted(service, service_key), "permit-trust");
    value(receipt_trust.install_trusted(service, service_key), "receipt-trust");
    auto policy_id = value(object_id("service_policy", service), "service-policy");
    PermitBody body{service.issuer_,
                    policy_id,
                    h(102),
                    chain.network,
                    chain.genesis_root,
                    chain.genesis_file,
                    {0, h(201), h(202), h(203)},
                    h(204),
                    committee.policy_,
                    snapshot.committee_id(),
                    consensus_session,
                    identity.identity_,
                    5,
                    h(205),
                    128,
                    1};
    Permit permit{body, {{1, 1, service_key.id, sign(value(encode(body), "permit-body"))}}};
    value(verify_permit(permit, body, permit_trust, 0, 1, true), "valid-permit");
    auto unbound = permit;
    unbound.body_.registry_root_ = {};
    unbound.components_[0].signature_ = sign(value(encode(unbound.body_), "unbound-body"));
    check(!verify_permit(unbound, unbound.body_, permit_trust, 0, 1, true).ok(), "permit-registry-shape");
    value(verify_permit(permit, body, permit_trust, 128, 1, true), "permit-boundary");
    check(!verify_permit(permit, body, permit_trust, 129, 1, true).ok(), "permit-expired");
    check(!verify_permit(permit, body, permit_trust, 0, 2, true).ok(), "permit-fence");
    check(!verify_permit(permit, body, permit_trust, 0, 1, false).ok(), "permit-live");
    auto altered = body;
    altered.audience_ = h(999);
    check(!verify_permit(permit, altered, permit_trust, 0, 1, true).ok(), "permit-audience");
    auto fake = permit;
    fake.components_[0].signature_[0] ^= 1;
    check(!verify_permit(fake, body, permit_trust, 0, 1, true).ok(), "permit-signature");
    ReceiptBody receipt_body{service.issuer_,
                             policy_id,
                             h(102),
                             h(301),
                             5,
                             h(302),
                             h(303),
                             1,
                             1,
                             2,
                             value(object_id("permit", permit), "permit-id")};
    Receipt receipt{receipt_body, {{1, 1, service_key.id, sign(value(encode(receipt_body), "receipt-body"))}}};
    Witness witness;
    witness.entries.emplace(1, value(object_id("receipt_body", receipt_body), "receipt-body-id"));
    value(verify_receipt(receipt, receipt_body, receipt_trust, witness), "valid-receipt");
    auto successor = service;
    successor.revision_ = 2;
    successor.previous_ = policy_id;
    value(permit_trust.install_trusted(successor, service_key), "rotate-permit-trust");
    value(receipt_trust.install_trusted(successor, service_key), "rotate-receipt-trust");
    check(!verify_permit(permit, body, permit_trust, 0, 1, true).ok(), "stale-permit-policy");
    value(verify_receipt(receipt, receipt_body, receipt_trust, witness), "historical-receipt-policy");
    witness.entries.clear();
    check(!verify_receipt(receipt, receipt_body, receipt_trust, witness).ok(), "receipt-frontier");
    SignResult result{h(301), h(302), row, 1, receipt};
    RequestState complete{h(301), 2, h(302), 1, {result}, {}};
    RequestState absent{h(301), 0, {}, 0, {}, {}};
    auto pending_receipt = receipt;
    pending_receipt.body_.state_ = 1;
    pending_receipt.body_.result_hash_ = {};
    RequestState reserved{h(301), 1, h(302), 1, {}, {pending_receipt}};
    value(observe_request_state(&reserved, complete, h(301)), "poll-completion");
    value(observe_request_state(&complete, complete, h(301)), "poll-exact-terminal");
    check(!observe_request_state(&complete, absent, h(301)).ok(), "poll-terminal-regression");
    check(!observe_request_state(&reserved, absent, h(301)).ok(), "poll-reserved-regression");
    auto changed_state = complete;
    changed_state.fence_ = 2;
    changed_state.result_[0].fence_ = 2;
    check(!observe_request_state(&reserved, changed_state, h(301)).ok(), "poll-reserved-binding");
    std::cout << "PASS: real PoP, current identity authority, permits and witnessed receipts\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
