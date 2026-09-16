#pragma once
// One governance operation and the committee that authorizes it, built at any
// size. The governance cases exercise its refusals; the gas closure measures
// what the largest legal one costs. Two constructions of it would let one keep
// passing against a shape the other no longer builds.
#include "validator/auth/governance.h"

#include "admin-fixture.h"

namespace governance_fixture {
using namespace tos::auth;
using namespace auth_fixture;

struct Fixture {
  RegistryState current;
  ChainContext chain;
  Committee committee;
  Policy policy;
  Update update;
  Authorizations evidence;
  std::uint32_t inclusion = 0;
};
inline void sign(Fixture& f, unsigned count = 0) {
  auto snapshot = value(RegistrySnapshot::compile(f.committee, f.policy), "fixture-snapshot");
  auto payload = value(encode(f.update), "update");
  auto expected = value(
      make_duty(f.chain, snapshot, value(admin_session_id(f.chain, Hash{}), "session"), 5, f.update.nonce_, payload),
      "duty");
  Certificate cert{expected, payload, {}};
  for (const auto& member : f.committee.members_) {
    const auto& key = member.keys_.at(4);
    auto ref = value(key_reference(key), "ref");
    Record row{member.identity_, {{ref.suite_, ref.parameters_, ref.epoch_, ref.key_id_, {}}}};
    row.components_[0].signature_ = signature(value(signing_statement(expected, row), "statement"));
    cert.records_.push_back(row);
    if (count && cert.records_.size() == count)
      break;
  }
  f.evidence = {};
  f.evidence.governance_.push_back({value(object_id("update", f.update), "update-id"), snapshot.committee_id(),
                                    value(object_value(4, value(encode(cert), "certificate")), "carrier")});
}
inline Fixture fixture(unsigned count = 3) {
  auto registry = state(count);
  Fixture f{registry,
            {-239, h(11), h(12), registry.chain_domain()},
            admin_snapshot(registry).committee(),
            value(registry.policy_at(0), "policy"),
            {},
            {},
            0};
  f.committee.anchor_mc_ = 0;
  f.update.operation_ = 6;
  f.update.nonce_ = 7;
  f.update.previous_ = registry.current_policy();
  Writer raw;
  raw.integer(std::int32_t{16});
  raw.bytes(h(900));
  raw.bytes(h(901));
  check(raw.ok(), "operation-data");
  f.update.operation_data_ = raw.data;
  sign(f);
  return f;
}

// The reader a verification resolves its certificate through. The carrier is
// inline, so nothing has to be stored for it to be found.
inline ObjectReader reader(const Fixture&) {
  return ObjectReader({});
}
}  // namespace governance_fixture
