#include "td/utils/tests.h"
#include "block/workchain-withdrawal-account.h"
#include "block/workchain-operation-fees.h"
#include "block/workchain-native-inbox.h"
#include "test/workchain-m3-business-config.h"
#include "block/mc-config.h"
#include "block/workchain-execution-dispatch.h"
#include <fstream>
#include "block/workchain-failed-funded.h"
#include "test/workchain-proof-test-access.h"
#include "block/transaction.h"
#include "crypto/common/bitstring.h"
#include "tl-utils/common-utils.hpp"
#include "tos/tos-tl.hpp"
#include "td/utils/filesystem.h"
using namespace block;
static td::Ref<vm::Cell> read_boc(const std::string& name) {
  std::ifstream in("/tmp/uno-m3-live-6igzl00b/"+name,std::ios::binary);CHECK(in.good());
  std::string s((std::istreambuf_iterator<char>(in)),{});return vm::std_boc_deserialize(td::Slice(s)).move_as_ok();
}
TEST(BReview, FailedActualComponents) {
 auto zero=read_boc("zerostate.boc");tos::BlockIdExt zid{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},zero->get_hash().bits(),td::Bits256::zero()};
 auto config=ConfigInfo::extract_config(zero,zid,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();
 auto ingress=load_workchain_native_ingress_table(*config).move_as_ok().at(2);
 auto params=decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
 auto policy=m3_test::decode_m3_test_business_parameters(params.parameters).move_as_ok();CHECK(policy.failed&&policy.deposit&&policy.operation_tariff);
 uint64_t g,h;CHECK(!__builtin_mul_overflow(policy.operation_tariff->base,policy.failed->issuance_billing_units,&g));CHECK(!__builtin_add_overflow(policy.deposit->slot_fee,g,&h));CHECK(g>0);
 gen::CommonMsgInfo::Record_int_msg_info msg;CHECK(::tlb::unpack_cell_inexact(read_boc("failed-bounce.boc"),msg));CurrencyCollection actual;CHECK(actual.unpack(msg.value));auto y=actual.tomis;
 gen::ShardStateUnsplit::Record old,now;CHECK(::tlb::unpack_cell(read_boc("debit-authenticated-state.boc"),old));CHECK(::tlb::unpack_cell(read_boc("accepted-state.boc"),now));
 vm::AugmentedDictionary before(vm::load_cell_slice_ref(old.accounts),256,block::tlb::aug_ShardAccounts),after(vm::load_cell_slice_ref(now.accounts),256,block::tlb::aug_ShardAccounts);
 td::Bits256 alice;alice.as_slice().fill(0x11);Account a0(2,alice.bits()),a1(2,alice.bits());CHECK(a0.unpack(before.lookup(alice),old.gen_utime,false));CHECK(a1.unpack(after.lookup(alice),now.gen_utime,false));
 auto w0=decode_workchain_withdrawal_account(a0.data,policy.failed->withdrawal_limit).move_as_ok();auto w1=decode_workchain_withdrawal_account(a1.data,policy.failed->withdrawal_limit).move_as_ok();CHECK(w0.control.withdrawals.size()==1);CHECK(w1.control.withdrawals.empty());CHECK(w1.origin_pending.size()==1);
 auto record=w0.control.withdrawals.front(); CHECK(record.costs.original_reserve==1000000);auto receipt=w1.origin_pending.front(); CHECK(receipt.amount < record.principal);auto z=y+td::make_refint(record.costs.original_reserve)-td::make_refint(h);CHECK(td::cmp(z,td::make_refint(receipt.amount))==0);
 td::RefInt256 custody0,custody1;
 for(auto key:{*ingress.custody_address,ingress.executor_address}){
  Account n0(2,key.bits()),n1(2,key.bits());CHECK(n0.unpack(before.lookup(key),old.gen_utime,false));CHECK(n1.unpack(after.lookup(key),now.gen_utime,false));
  auto delta=n1.balance.tomis-n0.balance.tomis;
  if(key==*ingress.custody_address){custody0=n0.balance.tomis;custody1=n1.balance.tomis;CHECK(td::cmp(delta,y-td::make_refint(h))==0);}
  else CHECK(td::cmp(delta,td::make_refint(policy.deposit->slot_fee))==0);
  std::cout<<(key==*ingress.custody_address?"CUSTODY":"COORDINATOR")<<" before="<<n0.balance.tomis<<" after="<<n1.balance.tomis<<" delta="<<delta<<"\n";
 }
 gen::Block::Record blk;gen::BlockExtra::Record extra;CHECK(::tlb::unpack_cell(read_boc("accepted-block.boc"),blk));CHECK(::tlb::unpack_cell(blk.extra,extra));
 gen::ValueFlow::Record_value_flow flow;
 if (::tlb::unpack_cell(blk.value_flow,flow)) {CurrencyCollection f;CHECK(f.unpack(flow.fees_collected));std::cout<<"BLOCK_FEES_COLLECTED="<<f.tomis<<"\n";}
 else {gen::ValueFlow::Record_value_flow_v2 flow2;CHECK(::tlb::unpack_cell(blk.value_flow,flow2));CurrencyCollection f;CHECK(f.unpack(flow2.fees_collected));std::cout<<"BLOCK_FEES_COLLECTED="<<f.tomis<<"\n";}
 vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(extra.account_blocks),256,block::tlb::aug_ShardAccountBlocks);
 for(auto key:{*ingress.custody_address,ingress.executor_address}){
  auto leaf=blocks.lookup(key);gen::AccountBlock::Record ab;CHECK(gen::t_AccountBlock.unpack(leaf.write(),ab));vm::AugmentedDictionary txs(vm::DictNonEmpty(),ab.transactions,64,block::tlb::aug_AccountTransactions);
  unsigned count=0;CHECK(txs.check_for_each([&](td::Ref<vm::CellSlice> v,td::ConstBitPtr,int){++count;gen::Transaction::Record tx;CHECK(::tlb::unpack_cell(v->prefetch_ref(),tx));CurrencyCollection paid;CHECK(paid.unpack(tx.total_fees));
   if(key==*ingress.custody_address){CHECK(td::cmp(paid.tomis,td::make_refint(g))==0);std::cout<<"ACTUAL_CUSTODY_TX_FEE="<<paid.tomis<<"\n";}
   else {gen::TransactionDescr::Record_trans_workchain_entry_v3 entry;CHECK(::tlb::unpack_cell(tx.description,entry));gen::UnoV2HostEffects::Record eff;CHECK(::tlb::unpack_cell(entry.effects,eff));auto native=decode_workchain_native_effects(eff.native).move_as_ok();CHECK(native.fees); vm::Dictionary transfers(native.transfers,32); CHECK(transfers.is_empty()); std::cout<<"NATIVE_EXPLICIT_TRANSFERS=0\n";CHECK(td::cmp(native.fees->compute_fee,td::make_refint(g))==0);CHECK(td::cmp(native.fees->state_fee,td::make_refint(policy.deposit->slot_fee))==0);
    gen::UnoV2HostInput::Record host;gen::UnoV2HostIdentity::Record hid;gen::UnoV2HostDomain::Record dom;
    CHECK(::tlb::unpack_cell(entry.input,host));CHECK(::tlb::unpack_cell(host.identity,hid));CHECK(::tlb::unpack_cell(hid.domain,dom));
    auto inboxes=decode_workchain_batch_inbound(host.inbox->prefetch_ref()).move_as_ok();
    Account co0(2,ingress.executor_address.bits());CHECK(co0.unpack(before.lookup(ingress.executor_address),old.gen_utime,false));
    for(unsigned variant=0;variant<7;++variant){
      WorkchainFailedFundedPolicy varied{policy.failed->withdrawal_limit,policy.deposit->system_slots,policy.deposit->slot_fee,policy.operation_tariff->base,policy.failed->issuance_billing_units};
      if(variant==1)++varied.base_compute;if(variant==2)++varied.issuance_billing_units;if(variant==3)++varied.slot_fee;
      if(variant==4)varied.base_compute=UINT64_MAX;
      if(variant==5)varied.slot_fee=UINT64_MAX;
      if(variant==6){varied.slot_fee=10996071;varied.base_compute=0;}
      if(variant>=4){auto v=WorkchainProofTestAccess::create(100);
        auto bad=prepare_workchain_failed_funded({inboxes,0},a0.data,co0.data,varied,policy.domain,
          {dom.global_id,dom.genesis_hash,dom.instance_id},*ingress.custody_address,ingress.executor_address,now.seq_no,v);
        CHECK(bad.is_error()); CHECK(bad.error().message()=="Failed no-issuance or arithmetic branch unsupported");
        std::cout<<"ARITHMETIC_REFUSAL variant="<<variant<<" stage="<<bad.error().message().str()<<"\n";continue;}
      uint64_t expected_g,expected_h;CHECK(!__builtin_mul_overflow(varied.base_compute,varied.issuance_billing_units,&expected_g));CHECK(!__builtin_add_overflow(varied.slot_fee,expected_g,&expected_h));
      auto verifier=WorkchainProofTestAccess::create(100);
      auto outcome=prepare_workchain_failed_funded({inboxes,0},a0.data,co0.data,varied,policy.domain,
          {dom.global_id,dom.genesis_hash,dom.instance_id},*ingress.custody_address,ingress.executor_address,now.seq_no,verifier);
      if(outcome.is_error())std::cerr<<outcome.error().message().str()<<"\n";CHECK(outcome.is_ok());
      CHECK(td::cmp(outcome.ok().fees.compute_fee,td::make_refint(expected_g))==0);
      CHECK(td::cmp(outcome.ok().fees.state_fee,td::make_refint(varied.slot_fee))==0);
      CHECK(td::cmp(td::make_refint(outcome.ok().receipt.amount),y+td::make_refint(record.costs.original_reserve)-td::make_refint(expected_h))==0);
      std::cout<<"PARAMETER_CONTROL variant="<<variant<<" base="<<varied.base_compute<<" units="<<varied.issuance_billing_units<<" g="<<outcome.ok().fees.compute_fee<<" slot="<<outcome.ok().fees.state_fee<<" receipt="<<outcome.ok().receipt.amount<<"\n";
    }
}
   return true;}));CHECK(count==1);
 }
 auto archive=tos::fetch_tl_object<tos::tos_api::db_candidate>(td::read_file("/tmp/uno-m3-live-6igzl00b/payout-recipient.candidate").move_as_ok(),true).move_as_ok();
 auto recipient_root=vm::std_boc_deserialize(archive->data_.as_slice()).move_as_ok();
 auto archive_id=tos::create_block_id(archive->id_);CHECK(archive_id.root_hash==recipient_root->get_hash().bits());
 gen::Block::Record rb;gen::BlockExtra::Record re;CHECK(::tlb::unpack_cell(recipient_root,rb));CHECK(::tlb::unpack_cell(rb.extra,re));
 vm::AugmentedDictionary raccounts(vm::load_cell_slice_ref(re.account_blocks),256,block::tlb::aug_ShardAccountBlocks);
 unsigned matches=0;{auto leaf=raccounts.lookup(record.destination.account);gen::AccountBlock::Record ab;CHECK(gen::t_AccountBlock.unpack(leaf.write(),ab));vm::AugmentedDictionary txs(vm::DictNonEmpty(),ab.transactions,64,block::tlb::aug_AccountTransactions);
  CHECK(txs.check_for_each([&](td::Ref<vm::CellSlice> leaf,td::ConstBitPtr,int){gen::Transaction::Record tx;CHECK(::tlb::unpack_cell(leaf->prefetch_ref(),tx));vm::Dictionary outs(tx.r1.out_msgs,15);
   bool matched=false;CHECK(outs.check_for_each([&](td::Ref<vm::CellSlice> out,td::ConstBitPtr,int){if(out->prefetch_ref()->get_hash()==read_boc("failed-bounce.boc")->get_hash())matched=true;return true;}));
   if(!matched)return true; ++matches;
   CHECK(tx.r1.in_msg->prefetch_ref()->get_hash()==read_boc("prepare-payout.boc")->get_hash());
   gen::TransactionDescr::Record_trans_ord desc;CHECK(::tlb::unpack_cell(tx.description,desc));auto bs=*desc.bounce;CHECK(bs.fetch_ulong(1)==1);gen::TrBouncePhase::Record_tr_phase_bounce_ok bounce;CHECK(gen::t_TrBouncePhase.unpack(bs,bounce));
   auto collected=block::tlb::t_Tomis.as_integer(bounce.msg_fees),forwarded=block::tlb::t_Tomis.as_integer(bounce.fwd_fees);
   CHECK(td::cmp(collected+forwarded,td::make_refint(record.principal)-y)==0);
   std::cout<<"ACTUAL_NATIVE_BOUNCE collected="<<collected<<" forwarded="<<forwarded<<" sum="<<(collected+forwarded)<<" matched_inbound_and_outbound=1\n";return true;}));}CHECK(matches==1);
 CHECK(td::cmp(y,td::make_refint(record.principal))!=0);
 std::cout<<"COMPONENTS x="<<record.principal<<" y="<<y<<" b="<<record.costs.original_reserve<<" base="<<policy.operation_tariff->base<<" units="<<policy.failed->issuance_billing_units<<" g="<<g<<" slot="<<policy.deposit->slot_fee<<" installed_receipt="<<receipt.amount<<"\n";
}
