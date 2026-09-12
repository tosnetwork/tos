#include "block/workchain-execution-dispatch.h"
#include "td/utils/tests.h"
#include "block/workchain-withdrawal-account.h"
#include "block/workchain-operation-fees.h"
#include "block/workchain-native-inbox.h"
#include "test/workchain-m3-business-config.h"
#include "test/workchain-m3-assertions.h"
#include "test/workchain-m4-deposit-input.h"
#include "test/workchain-m5-failed-input.h"
#include "test/workchain-m5-debit.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include <fstream>
using namespace block;
static td::Ref<vm::Cell> boc(const std::string& n) {
 std::ifstream f("/tmp/uno-m3-live-wifgx0up/"+n,std::ios::binary);CHECK(f.good());
 std::string b((std::istreambuf_iterator<char>(f)),{});return vm::std_boc_deserialize(td::Slice(b)).move_as_ok();
}
static uint64_t plus(uint64_t a,uint64_t b){uint64_t c;CHECK(!__builtin_add_overflow(a,b,&c));return c;}
static uint64_t minus(uint64_t a,uint64_t b){uint64_t c;CHECK(!__builtin_sub_overflow(a,b,&c));return c;}
struct Entry {gen::UnoV2HostInput::Record host;gen::UnoV2HostEffects::Record effects;};
static Entry entry(td::Ref<vm::Cell> root,td::Bits256 coordinator) {
 gen::Block::Record b;gen::BlockExtra::Record x;CHECK(::tlb::unpack_cell(root,b));CHECK(::tlb::unpack_cell(b.extra,x));
 vm::AugmentedDictionary as(vm::load_cell_slice_ref(x.account_blocks),256,block::tlb::aug_ShardAccountBlocks);
 auto leaf=as.lookup(coordinator);gen::AccountBlock::Record ab;CHECK(gen::t_AccountBlock.unpack(leaf.write(),ab));
 vm::AugmentedDictionary txs(vm::DictNonEmpty(),ab.transactions,64,block::tlb::aug_AccountTransactions);Entry out;unsigned count=0;
 CHECK(txs.check_for_each([&](auto v,td::ConstBitPtr,int){++count;gen::Transaction::Record tx;gen::TransactionDescr::Record_trans_workchain_entry_v3 d;
 CHECK(::tlb::unpack_cell(v->prefetch_ref(),tx));CHECK(::tlb::unpack_cell(tx.description,d));CHECK(::tlb::unpack_cell(d.input,out.host));CHECK(::tlb::unpack_cell(d.effects,out.effects));return true;}));CHECK(count==1);return out;
}
TEST(BD78, ActualArtifacts) {
 auto z=boc("zerostate.boc");tos::BlockIdExt zid{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},z->get_hash().bits(),td::Bits256::zero()};
 auto cfg=ConfigInfo::extract_config(z,zid,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();auto ing=load_workchain_native_ingress_table(*cfg).move_as_ok().at(2);
 auto params=decode_workchain_engine_parameters(ing.engine_configuration).move_as_ok();auto policy=m3_test::decode_m3_test_business_parameters(params.parameters).move_as_ok();CHECK(policy.failed&&policy.deposit&&policy.operation_tariff);
 uint64_t g,h;CHECK(!__builtin_mul_overflow(policy.operation_tariff->base,policy.failed->issuance_billing_units,&g));h=plus(policy.deposit->slot_fee,g);
 gen::CommonMsgInfo::Record_int_msg_info info;CHECK(::tlb::unpack_cell_inexact(boc("failed-bounce.boc"),info));CurrencyCollection value;CHECK(value.unpack(info.value));CHECK(info.bounced);CHECK(value.tomis->unsigned_fits_bits(63));auto y=uint64_t(value.tomis->to_long());
 gen::ShardStateUnsplit::Record states[2];CHECK(::tlb::unpack_cell(boc("debit-authenticated-state.boc"),states[0]));CHECK(::tlb::unpack_cell(boc("accepted-state.boc"),states[1]));
 uint64_t native[2],hidden[2],p[2],w[2],coord[2],receipt=0,x=0,q=0;
 for(unsigned stage=0;stage<2;++stage){auto& s=states[stage];vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(s.accounts),256,block::tlb::aug_ShardAccounts);
  Account cu(2,ing.custody_address->bits()),co(2,ing.executor_address.bits());CHECK(cu.unpack(accounts.lookup(*ing.custody_address),s.gen_utime,false));CHECK(co.unpack(accounts.lookup(ing.executor_address),s.gen_utime,false));
  native[stage]=cu.balance.tomis->to_long();coord[stage]=co.balance.tomis->to_long();hidden[stage]=p[stage]=w[stage]=0;
  for(unsigned byte:{0x11u,0x22u}){td::Bits256 key;key.as_slice().fill(byte);auto leaf=accounts.lookup(key);CHECK(leaf.not_null());Account a(2,key.bits());CHECK(a.unpack(leaf,s.gen_utime,false));
   WorkchainWithdrawalAccount account;bool special=false;auto slice=vm::load_cell_slice_special(a.data,special);CHECK(!special);
   if(slice.prefetch_ulong(32)==gen::UnoV2AccountStateWithdrawalsV2::cons_tag[0]) account=decode_workchain_withdrawal_account(a.data,policy.failed->withdrawal_limit).move_as_ok();
   else account.account=decode_workchain_confidential_account(a.data).move_as_ok();
   m3_test::Point secret{};secret[0]=byte==0x11?101:223;
   auto add=[&](const WorkchainCiphertext& c){hidden[stage]=plus(hidden[stage],m3_test::decrypt(c,secret,2000000000).move_as_ok());};
   add(account.account.available);for(auto& r:account.account.pending)add(r.ciphertext);for(auto& r:account.account.system_pending)add(r.ciphertext);for(auto& r:account.origin_pending){add(r.ciphertext);receipt=r.amount;}
   for(auto& r:account.control.withdrawals){p[stage]=plus(p[stage],r.principal);w[stage]=plus(w[stage],r.principal);x=r.principal;q=r.costs.outward_fee_paid;}
  }
 }
 CHECK(receipt==minus(y,h));CHECK(minus(p[0],p[1])==x);CHECK(minus(w[0],w[1])==x);CHECK(minus(native[1],native[0])==receipt);CHECK(minus(hidden[1],hidden[0])==receipt);CHECK(minus(coord[1],coord[0])==policy.deposit->slot_fee);
 // Independent ledger from permanent candidates and actual imported Message value.
 uint64_t book=0,book_at_prepare=0;
 for(unsigned n=1;n<=states[1].seq_no;++n){auto e=entry(boc("m4-blocks/"+std::to_string(n)+".boc"),ing.executor_address);
  if(m3_test::is_m4_test_deposit(e.host.candidate)) book=plus(book,m3_test::decode_m4_test_deposit(e.host.candidate).move_as_ok().principal);
  else if(m3_test::is_m5_test_failed(e.host.candidate)){auto native=decode_workchain_native_effects(e.effects.native).move_as_ok();CHECK(native.fees);vm::Dictionary transfers(native.transfers,32);unsigned count=0;CHECK(transfers.check_for_each([&](auto,td::ConstBitPtr,int){++count;return true;}));CHECK(count==0);CHECK(td::cmp(native.fees->state_fee,td::make_refint(policy.deposit->slot_fee))==0);CHECK(td::cmp(native.fees->compute_fee,td::make_refint(g))==0);
   auto inboxes=decode_workchain_batch_inbound(e.host.inbox->prefetch_ref()).move_as_ok();CHECK(inboxes.size()==1);block::tlb::MsgEnvelope::Record_std envelope;CHECK(::tlb::unpack_cell(inboxes[0],envelope));CHECK(envelope.msg->get_hash()==boc("failed-bounce.boc")->get_hash());
   book=plus(book,minus(y,h));std::cout<<"FAILED_EXPLICIT_TRANSFERS="<<count<<" S="<<native.fees->state_fee<<" C="<<native.fees->compute_fee<<"\n";
  }else{auto replay=m3_test::decode_m5_accounting_replay(e.host.candidate).move_as_ok();if(auto a=std::get_if<WorkchainWithdrawalInput>(&replay)){book=minus(book,plus(plus(a->data.amounts.principal,a->data.amounts.outward_fee),a->data.amounts.operation_fee));CHECK(a->data.amounts.principal==x&&a->data.amounts.outward_fee==q);}else if(auto a=std::get_if<WorkchainTransferInput>(&std::get<WorkchainReplayInput>(replay)))book=minus(book,workchain_transfer_claims(a->data).authorized_fee);}
  if(n==states[0].seq_no)book_at_prepare=book;
 }
 CHECK(book_at_prepare==native[0]);CHECK(book==native[1]);
 for(unsigned i=0;i<2;++i){CHECK(plus(native[i],p[i])==plus(hidden[i],w[i]));std::cout<<"COMPONENTS stage="<<i<<" R_actual="<<native[i]<<" R_book="<<(i?book:book_at_prepare)<<" N_decrypted="<<hidden[i]<<" P="<<p[i]<<" W="<<w[i]<<" D=0(structural)\n";}
 gen::Block::Record final_block;gen::BlockExtra::Record final_extra;gen::ValueFlow::Record_value_flow flow;
 CHECK(::tlb::unpack_cell(boc("accepted-block.boc"),final_block));CHECK(::tlb::unpack_cell(final_block.extra,final_extra));
 CurrencyCollection collected;if(::tlb::unpack_cell(final_block.value_flow,flow)){CHECK(collected.unpack(flow.fees_collected));}else{gen::ValueFlow::Record_value_flow_v2 flow2;CHECK(::tlb::unpack_cell(final_block.value_flow,flow2));CHECK(collected.unpack(flow2.fees_collected));}
 vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(final_extra.account_blocks),256,block::tlb::aug_ShardAccountBlocks);auto custody_leaf=blocks.lookup(*ing.custody_address);gen::AccountBlock::Record ab;CHECK(gen::t_AccountBlock.unpack(custody_leaf.write(),ab));
 vm::AugmentedDictionary transactions(vm::DictNonEmpty(),ab.transactions,64,block::tlb::aug_AccountTransactions);unsigned count=0;
 CHECK(transactions.check_for_each([&](auto leaf,td::ConstBitPtr,int){++count;gen::Transaction::Record tx;CHECK(::tlb::unpack_cell(leaf->prefetch_ref(),tx));CurrencyCollection fee;CHECK(fee.unpack(tx.total_fees));CHECK(td::cmp(fee.tomis,td::make_refint(g))==0);return true;}));CHECK(count==1);
 std::cout<<"ACTUAL_CUSTODY_FEE="<<g<<" BLOCK_FEES="<<collected.tomis<<"\n";
 std::cout<<"RETURN x="<<x<<" y="<<y<<" slot="<<policy.deposit->slot_fee<<" base="<<policy.operation_tariff->base<<" units="<<policy.failed->issuance_billing_units<<" g="<<g<<" receipt="<<receipt<<"\n";
}
