/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <algorithm>

#include "adnl/adnl-ext-server-limits.h"
#include "td/utils/tests.h"
#include "validator/liteserver-admission.h"

namespace tos {
namespace {

TEST(LiteServerAdmission, ConnectionCapsAreReleased) {
  adnl::ExtServerConnectionLimits limits(2, 1);
  EXPECT(limits.try_acquire("192.0.2.1"));
  EXPECT(!limits.try_acquire("192.0.2.1"));
  EXPECT(limits.try_acquire("192.0.2.2"));
  EXPECT(!limits.try_acquire("192.0.2.3"));
  limits.release("192.0.2.1");
  EXPECT(limits.try_acquire("192.0.2.3"));
  EXPECT(limits.connections() == 2);
}

TEST(LiteServerAdmission, PerConnectionRateAndInflightCapsCompose) {
  adnl::ExtConnectionQueryLimits limits(1.0, 2, 1);
  auto now = td::Timestamp::at(100.0);
  EXPECT(limits.try_acquire(now));
  EXPECT(!limits.try_acquire(now));
  limits.release();
  EXPECT(limits.try_acquire(now));
  limits.release();
  EXPECT(!limits.try_acquire(now));
  EXPECT(limits.try_acquire(td::Timestamp::at(101.1)));
}

TEST(LiteServerAdmission, ServerQueryCapsComposeAcrossIps) {
  adnl::ExtServerQueryLimits limits(3, 2);
  EXPECT(limits.try_acquire("192.0.2.1"));
  EXPECT(limits.try_acquire("192.0.2.1"));
  EXPECT(!limits.try_acquire("192.0.2.1"));
  EXPECT(limits.try_acquire("192.0.2.2"));
  EXPECT(!limits.try_acquire("192.0.2.3"));
  limits.release("192.0.2.1");
  EXPECT(limits.try_acquire("192.0.2.3"));
  EXPECT(limits.inflight() == 3);
}

TEST(LiteServerAdmission, ServerQueryReleaseIsIdempotentPerIp) {
  adnl::ExtServerQueryLimits limits(2, 2);
  // Releasing an address that never acquired, or releasing more often than it
  // acquired, must not underflow and must not free capacity held by others.
  limits.release("192.0.2.9");
  EXPECT(limits.inflight() == 0);
  EXPECT(limits.try_acquire("192.0.2.1"));
  EXPECT(limits.try_acquire("192.0.2.2"));
  limits.release("192.0.2.1");
  limits.release("192.0.2.1");
  EXPECT(limits.inflight() == 1);
  EXPECT(limits.try_acquire("192.0.2.3"));
  EXPECT(!limits.try_acquire("192.0.2.1"));
  limits.release("192.0.2.2");
  limits.release("192.0.2.3");
  EXPECT(limits.inflight() == 0);
}

TEST(LiteServerAdmission, AnonymousIdentityIsStablePerIp) {
  auto first = adnl::external_peer_ip_identity("192.0.2.1");
  EXPECT(first == adnl::external_peer_ip_identity("192.0.2.1"));
  EXPECT(first != adnl::external_peer_ip_identity("192.0.2.2"));
  // The zero id is the "not yet authenticated" sentinel on the connection, so
  // a derived anonymous identity must never collide with it.
  auto bytes = first.as_slice();
  EXPECT(std::any_of(bytes.begin(), bytes.end(), [](char c) { return c != 0; }));
}

TEST(LiteServerAdmission, UnknownAndExcessHeavyQueriesFailClosed) {
  validator::LiteServerAdmission admission;
  auto now = td::Timestamp::at(200.0);
  EXPECT(!admission.check_rate(0x12345678, 4, now));

  for (size_t i = 0; i < 128; ++i) {
    EXPECT(admission.check_rate(lite_api::liteServer_getState::ID, 4, now));
  }
  EXPECT(!admission.check_rate(lite_api::liteServer_getState::ID, 4, now));
  EXPECT(admission.check_rate(lite_api::liteServer_getState::ID, 4, td::Timestamp::at(201.1)));
}

TEST(LiteServerAdmission, WaitingDoesNotConsumeExecutionCapacity) {
  validator::LiteServerAdmission admission;
  auto now = td::Timestamp::at(300.0);

  // Admission at ingress charges the rate budget but deliberately does not
  // reserve execution capacity while a waitMasterchainSeqno prefix is parked.
  for (size_t i = 0; i < validator::LiteServerAdmission::MAX_INFLIGHT; ++i) {
    EXPECT(admission.check_rate(lite_api::liteServer_getMasterchainInfo::ID, 4, now));
  }
  EXPECT(admission.inflight() == 0);

  for (size_t i = 0; i < validator::LiteServerAdmission::MAX_INFLIGHT; ++i) {
    EXPECT(admission.try_acquire_execution());
  }
  EXPECT(!admission.try_acquire_execution());
  for (size_t i = 0; i < validator::LiteServerAdmission::MAX_INFLIGHT; ++i) {
    admission.release();
  }
  EXPECT(admission.inflight() == 0);
}

}  // namespace
}  // namespace tos
