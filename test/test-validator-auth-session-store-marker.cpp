#include "validator/db/validator-auth-session-store-marker.h"
#include "td/db/RocksDb.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"

using namespace tos::validator;
namespace {
std::string path() {
  auto p=PSTRING()<<"test-validator-auth-session-marker-"<<td::Random::fast_uint32();
  td::rmrf(p).ignore();
  return p;
}
}
TEST(ValidatorAuthSessionStoreMarker, absent_then_round_trip_reopen) {
  auto p=path();
  {
    auto db=td::RocksDb::open(p).move_as_ok();
    auto before=validator_auth_session_store_is_provisioned(db);
    ASSERT_TRUE(before.is_ok()&&!before.ok());
    ASSERT_TRUE(mark_validator_auth_session_store_provisioned(db).is_ok());
    auto after=validator_auth_session_store_is_provisioned(db);
    ASSERT_TRUE(after.is_ok()&&after.ok());
  }
  {
    auto db=td::RocksDb::open(p).move_as_ok();
    auto after=validator_auth_session_store_is_provisioned(db);
    ASSERT_TRUE(after.is_ok()&&after.ok());
  }
  td::rmrf(p).ignore();
}
