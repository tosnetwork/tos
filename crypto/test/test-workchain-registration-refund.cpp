#include "block/workchain-registration-refund.h"
#include "td/utils/tests.h"

TEST(RegistrationRefund, HistoricalAmountAndDestination) {
  auto address = td::Bits256::zero();
  address.as_slice()[31] = 7;
  block::WorkchainRegistrationFunding paid{10, -1, address};
  auto result = block::prepare_workchain_registration_refund(paid, 30);
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(result.ok().amount, 10u);
  ASSERT_EQ(result.ok().workchain, -1);
  ASSERT_EQ(result.ok().account, address);
  ASSERT_EQ(result.ok().remaining_refundable_deposits, 20u);
  // Preparation neither mutates the funding record nor accepts today's price.
  ASSERT_EQ(paid.paid_deposit, 10u);
}

TEST(RegistrationRefund, ExactBucketAndDeficit) {
  block::WorkchainRegistrationFunding paid{UINT64_MAX, 0, td::Bits256::zero()};
  auto exact = block::prepare_workchain_registration_refund(paid, UINT64_MAX);
  ASSERT_TRUE(exact.is_ok());
  ASSERT_EQ(exact.ok().remaining_refundable_deposits, 0u);
  auto deficit = block::prepare_workchain_registration_refund(paid, 0);
  ASSERT_TRUE(deficit.is_error());
  ASSERT_EQ(deficit.error().code(),
            static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
}
