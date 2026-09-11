#include "td/utils/tests.h"
#include "block/workchain-withdrawal-account.h"
#include "block/workchain-operation-fees.h"
#include "workchain-m3-assertions.h"
#include <fstream>
using namespace block;
inline td::Status check_m4_backing(const td::RefInt256& actual,
                                   const td::RefInt256& locked, const td::RefInt256& pending_deposit) {
  if (actual.is_null() || locked.is_null() || pending_deposit.is_null() ||
      !actual->is_valid() || !locked->is_valid() || !pending_deposit->is_valid() ||
      td::sgn(actual) < 0 || td::sgn(locked) < 0 || td::sgn(pending_deposit) != 0 || td::cmp(actual, locked) != 0) {
    return td::Status::Error("M4 per-block backing mismatch or nonzero cross-block D");
  }
  return td::Status::OK();
}
TEST(BReview, ActualArtifactPairing) {
 std::ifstream in("doc/measurements/uno-m5-prepare-independent-review/debit-authenticated-state.boc",std::ios::binary);
 std::string bytes((std::istreambuf_iterator<char>(in)),{}); ASSERT_TRUE(!bytes.empty());
 auto root=vm::std_boc_deserialize(td::Slice(bytes)).move_as_ok();
 gen::ShardStateUnsplit::Record state;ASSERT_TRUE(::tlb::unpack_cell(root,state));
 vm::AugmentedDictionary dict(vm::load_cell_slice_ref(state.accounts),256,block::tlb::aug_ShardAccounts);
 uint64_t n=0,p=0,w=0;td::Bits256 custody;
 for(unsigned byte:{0x11u,0x22u}) {
  td::Bits256 key;key.as_slice().fill(byte);auto leaf=dict.lookup(key);if(leaf.is_null())continue;
  Account account(2,key.bits());ASSERT_TRUE(account.unpack(leaf,state.gen_utime,false));
  WorkchainWithdrawalAccount decoded;
  bool special=false;auto slice=vm::load_cell_slice_special(account.data,special);ASSERT_TRUE(!special);
  if(slice.prefetch_ulong(32)==gen::UnoV2AccountStateWithdrawals::cons_tag[0])
   decoded=decode_workchain_withdrawal_account(account.data,100).move_as_ok(); // decoding ceiling ONLY, not policy admission
  else {decoded.account=decode_workchain_confidential_account(account.data).move_as_ok();}
  custody=decoded.account.bindings.custody;
  if(!decoded.control.withdrawals.empty()) {
   const auto& original=decoded.control.withdrawals.front();
   ASSERT_EQ(original.principal,137u); ASSERT_EQ(original.costs.outward_fee_paid,100u); ASSERT_EQ(original.costs.original_reserve,23u);
   for(int component=0;component<3;++component) {
    auto altered=decoded;auto& r=altered.control.withdrawals.front();
    if(component==0) ++r.principal;
    if(component==1) ++r.costs.outward_fee_paid;
    if(component==2) {++r.costs.original_reserve;++r.costs.refundable_reserve;} // preserve independent reserve-reconciliation codec invariant
    auto encoded=encode_workchain_withdrawal_account(altered,100).move_as_ok();
    ASSERT_TRUE(encoded->get_hash()!=account.data->get_hash());
    auto reread=decode_workchain_withdrawal_account(encoded,100).move_as_ok();
    const auto& rr=reread.control.withdrawals.front();
    auto pp=m3_test::checked_sum(999999506,rr.principal).move_as_ok();
    auto ww=m3_test::checked_sum(999999483,m3_test::checked_sum(rr.principal,rr.costs.original_reserve).move_as_ok()).move_as_ok();
    auto check=check_m4_backing(td::make_refint(pp),td::make_refint(ww),td::make_refint(0));
    ASSERT_EQ(check.is_error(),component==2);
    std::cout<<"B_ROOT_MUTATION component="<<component<<" decoded=OK pair_error="<<check.is_error()<<"\n";
   }
  }

  m3_test::Point secret{};secret[0]=byte==0x11?101:223;
  auto add=[&](const WorkchainCiphertext& ct){ n=m3_test::checked_sum(n,m3_test::decrypt(ct,secret,2000000000).move_as_ok()).move_as_ok();};
  add(decoded.account.available);for(auto& e:decoded.account.pending)add(e.ciphertext);
  for(auto& e:decoded.account.system_pending)add(e.ciphertext);for(auto& e:decoded.origin_pending)add(e.ciphertext);
  for(auto& r:decoded.control.withdrawals){p=m3_test::checked_sum(p,r.principal).move_as_ok();w=m3_test::checked_sum(w,m3_test::checked_sum(r.principal,r.costs.original_reserve).move_as_ok()).move_as_ok();}
 }
 Account native(2,custody.bits());ASSERT_TRUE(native.unpack(dict.lookup(custody),state.gen_utime,false));
 auto R=native.balance.tomis->to_long();
 std::cout<<"B_ARTIFACT R="<<R<<" N="<<n<<" P="<<p<<" W="<<w<<"\n";
 auto pair=[&](uint64_t pp,uint64_t ww){return check_m4_backing(td::make_refint(R)+td::make_refint(pp),td::make_refint(n)+td::make_refint(ww),td::make_refint(0));};
 ASSERT_TRUE(pair(p,w).is_ok());
 ASSERT_TRUE(pair(p+1,w+1).is_ok()); // same record principal in P and W cancels
 ASSERT_TRUE(pair(p,w+1).is_error()); // isolated reserve change
 ASSERT_TRUE(pair(p,w).is_ok()); // q is not a P/W input
 std::cout<<"B_ORACLE principal-cancel=OK reserve-perturb=ERROR q-absent=OK\n";
}
