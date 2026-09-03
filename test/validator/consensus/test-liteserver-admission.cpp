/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

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

TEST(LiteServerAdmission, UnknownAndExcessHeavyQueriesFailClosed) {
  validator::LiteServerAdmission admission;
  auto now = td::Timestamp::at(200.0);
  EXPECT(!admission.try_acquire(0x12345678, 4, now));

  for (size_t i = 0; i < 128; ++i) {
    EXPECT(admission.try_acquire(lite_api::liteServer_getState::ID, 4, now));
    admission.release();
  }
  EXPECT(!admission.try_acquire(lite_api::liteServer_getState::ID, 4, now));
  EXPECT(admission.try_acquire(lite_api::liteServer_getState::ID, 4, td::Timestamp::at(201.1)));
}

}  // namespace
}  // namespace tos
