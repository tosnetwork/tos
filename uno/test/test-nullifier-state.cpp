#include "td/utils/tests.h"
#include "uno/core/nullifier-state.h"

using namespace uno_workchain;

namespace {
td::Bits256 key(int last) {
  auto value = td::Bits256::zero();
  value.as_slice()[31] = static_cast<char>(last);
  return value;
}
}  // namespace

TEST(UnoNullifierState, ReservationConflictAndAtomicity) {
  NullifierState empty;
  auto used = empty.with_used({key(1)}).move_as_ok();
  ASSERT_TRUE(used.reserve(key(10), {key(2), key(1)}).is_error());
  ASSERT_TRUE(used.reserve(key(10), {key(2), key(2)}).is_error());
  ASSERT_TRUE(used.reserve(key(10), {}).is_error());
  ASSERT_TRUE(used.owners_root().is_null());
  ASSERT_TRUE(used.reserved_root().is_null());
  auto pending = used.reserve(key(10), {key(2), key(0)}).move_as_ok();
  ASSERT_TRUE(pending.is_reserved(key(0)));
  ASSERT_TRUE(pending.is_reserved(key(2)));
  ASSERT_TRUE(!pending.is_used(key(2)));
  ASSERT_TRUE(pending.with_used({key(3), key(2)}).is_error());
  ASSERT_TRUE(!pending.is_used(key(3)));
  ASSERT_TRUE(pending.reserve(key(11), {key(3), key(2)}).is_error());
  ASSERT_TRUE(!pending.is_reserved(key(3)));
  ASSERT_TRUE(pending.reserve(key(10), {key(4)}).is_error());
  auto other = pending.reserve(key(11), {key(4)}).move_as_ok();
  ASSERT_TRUE(other.is_reserved(key(4)));
  ASSERT_TRUE(other.is_reserved(key(2)));
  auto reversed = used.reserve(key(11), {key(4)}).move_as_ok().reserve(key(10), {key(0), key(2)}).move_as_ok();
  ASSERT_TRUE(reversed.reserved_root()->get_hash() == other.reserved_root()->get_hash());
  ASSERT_TRUE(reversed.owners_root()->get_hash() == other.owners_root()->get_hash());
}

TEST(UnoNullifierState, CompleteRefundAndPaidRelease) {
  auto pending = NullifierState{}
                     .with_used({key(1)})
                     .move_as_ok()
                     .reserve(key(10), {key(0), key(2)})
                     .move_as_ok()
                     .reserve(key(11), {key(3)})
                     .move_as_ok();
  ASSERT_TRUE(pending.refund(key(12)).is_error());
  ASSERT_TRUE(pending.paid(key(12)).is_error());
  auto refunded = pending.refund(key(10)).move_as_ok();
  for (auto n : {0, 1, 2}) {
    ASSERT_TRUE(refunded.is_used(key(n)));
    ASSERT_TRUE(!refunded.is_reserved(key(n)));
    ASSERT_TRUE(refunded.with_used({key(n)}).is_error());
  }
  ASSERT_TRUE(refunded.is_reserved(key(3)));
  ASSERT_TRUE(!refunded.is_used(key(3)));
  ASSERT_TRUE(refunded.refund(key(10)).is_error());
  ASSERT_TRUE(refunded.paid(key(10)).is_error());
  ASSERT_TRUE(refunded.reserve(key(10), {key(4)}).is_error());
  ASSERT_TRUE(pending.is_reserved(key(2)));
  ASSERT_TRUE(!pending.is_used(key(2)));
  auto paid = pending.paid(key(10)).move_as_ok();
  ASSERT_TRUE(paid.is_used(key(1)));
  for (auto n : {0, 2}) {
    ASSERT_TRUE(!paid.is_used(key(n)));
    ASSERT_TRUE(!paid.is_reserved(key(n)));
  }
  ASSERT_TRUE(paid.is_reserved(key(3)));
  ASSERT_TRUE(paid.with_used({key(0), key(2)}).is_ok());
  ASSERT_TRUE(paid.reserve(key(12), {key(0), key(2)}).is_ok());
  ASSERT_TRUE(paid.reserve(key(10), {key(4)}).is_error());
  ASSERT_TRUE(paid.refund(key(10)).is_error());
  ASSERT_TRUE(paid.paid(key(10)).is_error());
  ASSERT_TRUE(paid.owners_root()->get_hash() != refunded.owners_root()->get_hash());
  auto complete = refunded.paid(key(11)).move_as_ok();
  ASSERT_TRUE(complete.reserved_root().is_null());
  ASSERT_TRUE(complete.owners_root().not_null());
}
