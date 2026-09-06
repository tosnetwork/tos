#include "uno/core/bundle-context.h"
#include "td/utils/tests.h"
#include <fstream>
#include <sstream>
#include <string>

using namespace uno_workchain;

TEST(UnoBundleContext, SharedCrossLanguageVectors) {
  std::ifstream input(UNO_CONTEXT_VECTORS_PATH);
  ASSERT_TRUE(input.is_open());
  std::string line;
  unsigned count = 0;
  while (std::getline(input, line)) {
    std::istringstream row(line);
    std::string name, kind, extra;
    td::uint64 principal_hi, principal_lo, fee_hi, fee_lo;
    td::int64 balance;
    unsigned spends, outputs, accepted;
    ASSERT_TRUE(static_cast<bool>(row >> name >> kind >> principal_hi >> principal_lo >> fee_hi >> fee_lo
                                     >> balance >> spends >> outputs >> accepted));
    ASSERT_TRUE(!(row >> extra));
    ASSERT_TRUE(spends <= 1 && outputs <= 1 && accepted <= 1);
    BundleContext context;
    if (kind == "Transfer") { context = BundleContext::Transfer; }
    else if (kind == "Unshield") { context = BundleContext::Unshield; }
    else if (kind == "ShieldClaim") { context = BundleContext::ShieldClaim; }
    else if (kind == "WithdrawalRefund") { context = BundleContext::WithdrawalRefund; }
    else if (kind == "Genesis") { context = BundleContext::Genesis; }
    else if (kind == "PrivateFeeDistribution") { context = BundleContext::PrivateFeeDistribution; }
    else { ASSERT_TRUE(false); return; }
    auto result = validate_bundle_context(context, balance, spends != 0, outputs != 0,
                                         Amount::from_words(principal_hi, principal_lo),
                                         Amount::from_words(fee_hi, fee_lo));
    ASSERT_EQ(result.is_ok(), accepted != 0);
    ++count;
  }
  ASSERT_TRUE(input.eof());
  ASSERT_EQ(count, 31u);
}

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
