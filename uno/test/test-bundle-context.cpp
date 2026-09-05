#include "uno/core/bundle-context.h"
#include "td/utils/tests.h"

using namespace uno_workchain;

TEST(UnoBundleContext, BindPublicValuesAndPermissions) {
  struct Case { BundleContext kind; td::uint64 principal; td::uint64 fee; td::int64 balance; bool spends; };
  for (const auto& c : {Case{BundleContext::Transfer, 0, 3, 3, true},
                        Case{BundleContext::Unshield, 40, 3, 43, true},
                        Case{BundleContext::ShieldClaim, 40, 0, -40, false},
                        Case{BundleContext::WithdrawalRefund, 40, 0, -40, false},
                        Case{BundleContext::Genesis, 40, 0, -40, false},
                        Case{BundleContext::PrivateFeeDistribution, 40, 0, -40, false}}) {
    auto check = [&](td::int64 balance, bool spends, bool outputs) {
      return validate_bundle_context(c.kind, balance, spends, outputs,
                                     Amount::from_nanotomi(c.principal), Amount::from_nanotomi(c.fee));
    };
    ASSERT_TRUE(check(c.balance, c.spends, true).is_ok());
    ASSERT_TRUE(check(1, c.spends, true).is_error());
    ASSERT_TRUE(check(-c.balance, c.spends, true).is_error());
    ASSERT_TRUE(check(c.balance, !c.spends, true).is_error());
    ASSERT_TRUE(check(c.balance, c.spends, false).is_error());
  }
}

TEST(UnoBundleContext, RejectInvalidContextAndRange) {
  auto one = Amount::from_nanotomi(1);
  ASSERT_TRUE(validate_bundle_context(static_cast<BundleContext>(255), 0, false, true, {}, {}).is_error());
  ASSERT_TRUE(validate_bundle_context(BundleContext::Transfer, 1, true, true, one, one).is_error());
  ASSERT_TRUE(validate_bundle_context(BundleContext::ShieldClaim, -1, false, true, one, one).is_error());
  auto max = std::numeric_limits<td::uint64>::max();
  ASSERT_TRUE(validate_bundle_context(BundleContext::Unshield, 0, true, true,
                                     Amount::from_words(max, max), one).is_error());
  auto too_large = Amount::from_nanotomi(9223372036854775808ULL);
  ASSERT_TRUE(validate_bundle_context(BundleContext::ShieldClaim, std::numeric_limits<td::int64>::min(),
                                     false, true, too_large, {}).is_error());
  ASSERT_TRUE(validate_bundle_context(BundleContext::Transfer, 0, true, true, {}, {}).is_ok());
}
