/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

// Slice 6 Stage 6 capability-grant predicate fixtures.

#include "td/utils/tests.h"

#include <cstdint>
#include <set>

namespace {

constexpr td::uint32 kSelector = 0x43415001;
constexpr td::uint32 kOtherSelector = 0x43415002;

struct Constraints {
  td::uint32 selector = kSelector;
  td::uint64 max_value = 1000;
  td::uint32 valid_from = 10;
  td::uint32 expires_at = 100;
  td::int32 required_workchain = 0;
};

struct Grant {
  td::uint32 target = 1;
  td::uint32 grantee = 2;
  td::uint32 selector = kSelector;
  td::uint64 nonce = 7;
  td::uint64 revocation_epoch = 2;
};

struct Context {
  td::uint32 sender = 2;
  td::uint32 target = 1;
  td::uint32 selector = kSelector;
  td::uint64 value = 100;
  td::uint32 now = 20;
  td::int32 workchain = 0;
};

bool context_ok(const Grant& grant, const Constraints& constraints, const Context& ctx) {
  return grant.target == ctx.target && grant.grantee == ctx.sender && grant.selector == ctx.selector &&
         constraints.selector == ctx.selector && ctx.now >= constraints.valid_from && ctx.now < constraints.expires_at &&
         ctx.value <= constraints.max_value && ctx.workchain == constraints.required_workchain;
}

struct Registry {
  std::set<td::uint64> consumed_nonces;
  std::set<td::uint64> revoked_handles;
  td::uint16 max_revoked = 1;

  bool consume(td::uint64 nonce) {
    return consumed_nonces.insert(nonce).second;
  }

  bool revoke(td::uint64 handle) {
    if (revoked_handles.count(handle) != 0) {
      return true;
    }
    if (revoked_handles.size() >= max_revoked) {
      return false;
    }
    revoked_handles.insert(handle);
    return true;
  }
};

}  // namespace

TEST(Slice6Stage6CapabilityFixtures, SenderBoundContextValidation) {
  CHECK(context_ok(Grant{}, Constraints{}, Context{}));
  Context wrong_sender;
  wrong_sender.sender = 3;
  CHECK(!context_ok(Grant{}, Constraints{}, wrong_sender));
}

TEST(Slice6Stage6CapabilityFixtures, ReplayDifferentTargetAndSelectorFail) {
  Context wrong_target;
  wrong_target.target = 9;
  CHECK(!context_ok(Grant{}, Constraints{}, wrong_target));

  Context wrong_selector;
  wrong_selector.selector = kOtherSelector;
  CHECK(!context_ok(Grant{}, Constraints{}, wrong_selector));
}

TEST(Slice6Stage6CapabilityFixtures, ExpiryAndValueBoundsFail) {
  Context expired;
  expired.now = 100;
  CHECK(!context_ok(Grant{}, Constraints{}, expired));

  Context too_much_value;
  too_much_value.value = 1001;
  CHECK(!context_ok(Grant{}, Constraints{}, too_much_value));
}

TEST(Slice6Stage6CapabilityFixtures, SingleUseNonceRejectsReplay) {
  Registry registry;
  CHECK(registry.consume(7));
  CHECK(!registry.consume(7));
}

TEST(Slice6Stage6CapabilityFixtures, RevocationStorageIsBounded) {
  Registry registry;
  CHECK(registry.revoke(1));
  CHECK(!registry.revoke(2));
}
