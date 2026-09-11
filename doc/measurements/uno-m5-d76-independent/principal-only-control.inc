TEST(BReview, NativePayoutPrincipalOnlyBudget) {
  for (std::uint64_t ceiling : {0u,99u}) {
    auto legacy=native_payout_exact_fee_fixture({},ceiling);
    auto principal_only=native_payout_exact_fee_fixture({},ceiling,false,137);
    ASSERT_TRUE(legacy.is_error());
    ASSERT_TRUE(principal_only.is_error());
    ASSERT_EQ(principal_only.code(),legacy.code());
    ASSERT_EQ(principal_only.message(),legacy.message());
    std::cout << "B_PRINCIPAL_ONLY ceiling=" << ceiling << " same legacy refusal: " << legacy.message().str() << "\n";
  }
  ASSERT_TRUE(native_payout_exact_fee_fixture({},100,false,137).is_ok());
  ASSERT_TRUE(native_payout_exact_fee_fixture(100,0,false,137).is_ok());
  std::cout << "B_PRINCIPAL_ONLY ceiling100 accepted; exact-q ceiling0 accepted\n";
}
