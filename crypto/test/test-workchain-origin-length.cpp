#include "block/workchain-system-origin.h"
#include "block/workchain-proof-work.h"
#include "td/utils/tests.h"

// D72 expiry boundary: actual codec outputs plus every representable ABI width.
// Scope: current three members and selected content extremes. Not a proof that
// future encoders cannot introduce data-dependent lengths on untested values.
// On expiry, revisit that member's byte metering before accepting a new length.
TEST(SystemOriginLength, FixedByKind) {
  for (std::uint64_t sequence : std::vector<std::uint64_t>{1, 255, UINT64_MAX}) {
    td::Bits256 zero = td::Bits256::zero(), ones;
    ones.as_slice().fill(0xff);
    std::vector<block::WorkchainSystemOrigin> origins{
        block::WorkchainDepositOrigin{ones, sequence},
        block::WorkchainSettlementOrigin{zero, sequence},
        block::WorkchainSweepOrigin{sequence, {2, -1, ones, zero, td::make_refint(1), false}},
        block::WorkchainSweepOrigin{sequence, {2, 0, zero, ones, td::make_refint(UINT64_MAX), true}}};
    for (const auto& origin : origins) {
      auto encoded = block::encode_workchain_system_origin_transcript(origin);
      ASSERT_TRUE(encoded.is_ok());
      const auto& bytes = encoded.ok();
      const unsigned kind = static_cast<unsigned char>(bytes[0]);
      const unsigned expected = kind == 2 ? 115 : 41;
      ASSERT_EQ(bytes.size(), expected);
      for (unsigned width = 0; width <= 116; ++width) {
        UnoCryptoSystemEncryptionRequestV2 request{};
        request.abi_version = 2; request.amount = 1; request.origin_bytes = width;
        std::copy(bytes.begin(), bytes.end(), request.origin);
        auto operations = block::workchain_proof_operations_v4(request);
        if (width != expected) {
          ASSERT_TRUE(operations.is_error());
          ASSERT_EQ(operations.error().code(), -7201);
        } else {
          ASSERT_TRUE(operations.is_ok());
          ASSERT_EQ(operations.ok().context_bytes, 0u);
          ASSERT_EQ(operations.ok().total().move_as_ok(), 7u);
        }
      }
    }
  }
}
