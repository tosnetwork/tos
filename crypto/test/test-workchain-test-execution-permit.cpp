#include "block/workchain-execution-dispatch.h"
#include "td/utils/tests.h"

TEST(TestExecutionPermit, DefaultClosedAndInstanceScoped) {
  block::WorkchainExecutionRegistry registry, another_registry;
  auto instance = td::Bits256::zero(); instance.as_slice()[31] = 1;
  auto other = td::Bits256::zero(); other.as_slice()[31] = 2;
  // Test-owned configuration, never a deployment source. The same authorized
  // constructor is used for the enabled and disabled runs below.
  block::WorkchainResourcePolicy resources{4,{64,4096,8,16,16,5},
      {256,16384,128,8192,64},{32,128,8192,256,16384,16},{0,2,2},1};
  auto configuration = block::encode_workchain_engine_parameters(
      {400,instance,resources,vm::CellBuilder().finalize(),10});
  ASSERT_TRUE(configuration.is_ok());
  auto authenticated = block::decode_workchain_engine_parameters(configuration.ok());
  ASSERT_TRUE(authenticated.is_ok());
  ASSERT_TRUE(!registry.test_only_account_instance_execution_enabled(2,instance));
  // Owner's 2026-09-09 test-constructed configuration shape, scoped by D59.
  ASSERT_TRUE(registry.enable_test_only_account_instance_execution(2,authenticated.ok().instance_id,true).is_ok());
  ASSERT_TRUE(registry.test_only_account_instance_execution_enabled(2,instance));
  ASSERT_TRUE(!registry.test_only_account_instance_execution_enabled(2,other));
  ASSERT_TRUE(!registry.test_only_account_instance_execution_enabled(3,instance));
  ASSERT_TRUE(!another_registry.test_only_account_instance_execution_enabled(2,instance));
  ASSERT_TRUE(registry.enable_test_only_account_instance_execution(2,authenticated.ok().instance_id,false).is_ok());
  ASSERT_TRUE(!registry.test_only_account_instance_execution_enabled(2,instance));
  // This tests permit storage, not live activation refusal or its observation.
}
