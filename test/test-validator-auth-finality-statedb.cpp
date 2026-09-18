#include "validator/db/validator-auth-finality-store.h"
#include "td/db/RocksDb.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
using namespace tos::validator;
namespace{std::string path(){auto p=PSTRING()<<"test-validator-auth-finality-store-"<<td::Random::fast_uint32();td::rmrf(p).ignore();return p;}}
TEST(ValidatorAuthFinalityStore, round_trip_reopen_and_overwrite){
 auto p=path();{auto db=td::RocksDb::open(p).move_as_ok();ASSERT_TRUE(load_validator_auth_finality_journal(db).move_as_ok().empty());ASSERT_TRUE(store_validator_auth_finality_journal(db,"first").is_ok());ASSERT_TRUE(load_validator_auth_finality_journal(db).move_as_ok().as_slice()=="first");}
 {auto db=td::RocksDb::open(p).move_as_ok();ASSERT_TRUE(load_validator_auth_finality_journal(db).move_as_ok().as_slice()=="first");ASSERT_TRUE(store_validator_auth_finality_journal(db,"second").is_ok());ASSERT_TRUE(load_validator_auth_finality_journal(db).move_as_ok().as_slice()=="second");}td::rmrf(p).ignore();
}
TEST(ValidatorAuthFinalityStore, bound_refuses_without_replacing_last_good_value){
 auto p=path();{auto db=td::RocksDb::open(p).move_as_ok();ASSERT_TRUE(store_validator_auth_finality_journal(db,"good").is_ok());std::string big(validator_auth_finality_journal_max_bytes+1,'x');ASSERT_TRUE(store_validator_auth_finality_journal(db,big).is_error());ASSERT_TRUE(store_validator_auth_finality_journal(db,{}).is_error());ASSERT_TRUE(load_validator_auth_finality_journal(db).move_as_ok().as_slice()=="good");}td::rmrf(p).ignore();
}
