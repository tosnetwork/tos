#pragma once
// Test adapter: read committed Native artifacts, not proposed result amounts.
#include "m5-live-failed.h"
#include "test/workchain-m5-sweep-input.h"
#include "test/workchain-m5-sweep.h"
#include <map>
#include <sstream>

namespace m3_live::completion {
using namespace block;
inline std::uint64_t u64(const td::RefInt256& value) {
  CHECK(value.not_null() && value->unsigned_fits_bits(63));
  return static_cast<std::uint64_t>(value->to_long());
}
inline std::uint64_t add(std::uint64_t a, std::uint64_t b) {
  std::uint64_t result; CHECK(!__builtin_add_overflow(a,b,&result)); return result;
}
inline std::uint64_t sub(std::uint64_t a, std::uint64_t b) {
  std::uint64_t result; CHECK(!__builtin_sub_overflow(a,b,&result)); return result;
}
inline std::uint64_t mul(std::uint64_t a, std::uint64_t b) {
  std::uint64_t result; CHECK(!__builtin_mul_overflow(a,b,&result)); return result;
}
inline WorkchainUnexpectedBucket observed_bucket(const td::Ref<vm::Cell>& root,int budget) {
  bool special=false;auto bits=vm::load_cell_slice_special(root,special);
  CHECK(!special && bits.size()>=112);bits.advance(48);
  WorkchainUnexpectedLimits counts{static_cast<std::uint32_t>(bits.fetch_ulong(32)),
                                  static_cast<std::uint32_t>(bits.fetch_ulong(32))};
  return decode_workchain_unexpected_bucket(root,counts,budget).move_as_ok();
}
inline block::m3_test::M3TestBusinessParameters observed_policy(const std::filesystem::path& fixture,int* budget=nullptr) {
  auto zero=load(fixture/"zerostate.boc");
  tos::BlockIdExt id{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},zero->get_hash().bits(),td::Bits256::zero()};
  auto config=ConfigInfo::extract_config(zero,id,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();
  auto ingress=load_workchain_native_ingress_table(*config).move_as_ok().at(2);
  auto parameters=decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
  CHECK(parameters.resources.state.max_cells<=INT_MAX);
  if(budget)*budget=static_cast<int>(parameters.resources.state.max_cells);
  return m3_test::decode_m3_test_business_parameters(parameters.parameters).move_as_ok();
}
inline std::string quote(const std::string& value) {
  // All strings written here are fixed identifiers, hexadecimal hashes or
  // canonical numeric addresses. Do not admit arbitrary diagnostic text.
  CHECK(value.find_first_of("\"\\\n\r\t") == std::string::npos);
  return "\"" + value + "\"";
}
inline Account native_account(const td::Ref<vm::Cell>& state_root, const td::Bits256& key) {
  gen::ShardStateUnsplit::Record state; CHECK(::tlb::unpack_cell(state_root,state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts),256,block::tlb::aug_ShardAccounts);
  Account account(2,key.bits()); CHECK(account.unpack(accounts.lookup(key),state.gen_utime,false)); return account;
}
inline gen::UnoV2HostEffects::Record effects(const td::Ref<vm::Cell>& root) {
  gen::Block::Record b; gen::BlockExtra::Record e; CHECK(::tlb::unpack_cell(root,b)&&::tlb::unpack_cell(b.extra,e));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(e.account_blocks),256,block::tlb::aug_ShardAccountBlocks);
  auto leaf=accounts.lookup(td::Bits256::zero()); gen::AccountBlock::Record ab;
  CHECK(gen::t_AccountBlock.unpack(leaf.write(),ab));
  vm::AugmentedDictionary txs(vm::DictNonEmpty(),ab.transactions,64,block::tlb::aug_AccountTransactions);
  gen::UnoV2HostEffects::Record result; unsigned count=0;
  CHECK(txs.check_for_each([&](auto value,td::ConstBitPtr,int){
    ++count; gen::Transaction::Record tx; gen::TransactionDescr::Record_trans_workchain_entry_v3 d;
    CHECK(::tlb::unpack_cell(value->prefetch_ref(),tx)&&::tlb::unpack_cell(tx.description,d)&&::tlb::unpack_cell(d.effects,result));
    return true;
  })); CHECK(count==1); return result;
}
inline td::Ref<vm::Cell> block_at(const std::filesystem::path& fixture,unsigned height) {
  auto path=fixture/"m4-blocks"/(std::to_string(height)+".boc");
  td::Ref<vm::Cell> root;
  if(std::filesystem::exists(path)) root=load(path);
  else {
    auto candidate=tos::fetch_tl_object<tos::tos_api::db_candidate>(
        td::read_file((fixture/"enabled.candidate").string()).move_as_ok(),true).move_as_ok();
    const auto id=tos::create_block_id(candidate->id_);
    root=vm::std_boc_deserialize(candidate->data_.as_slice()).move_as_ok();
    CHECK(td::Bits256(root->get_hash().bits())==id.root_hash && td::sha256_bits256(candidate->data_)==id.file_hash);
  }
  gen::Block::Record b; gen::BlockInfo::Record info;
  CHECK(::tlb::unpack_cell(root,b)&&::tlb::unpack_cell(b.info,info)&&info.seq_no==height); return root;
}
inline std::map<std::uint64_t,std::uint64_t> payout_values(const std::filesystem::path& fixture,
    unsigned height,const td::Bits256& custody) {
  std::map<std::uint64_t,std::uint64_t> values;
  for(unsigned n=1;n<=height;++n) {
    gen::Block::Record b;gen::BlockExtra::Record e;
    CHECK(::tlb::unpack_cell(block_at(fixture,n),b)&&::tlb::unpack_cell(b.extra,e));
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(e.account_blocks),256,block::tlb::aug_ShardAccountBlocks);
    auto leaf=accounts.lookup(custody);if(leaf.is_null())continue;
    gen::AccountBlock::Record ab;CHECK(gen::t_AccountBlock.unpack(leaf.write(),ab));
    vm::AugmentedDictionary txs(vm::DictNonEmpty(),ab.transactions,64,block::tlb::aug_AccountTransactions);
    CHECK(txs.check_for_each([&](auto cell,td::ConstBitPtr,int){
      gen::Transaction::Record tx;CHECK(::tlb::unpack_cell(cell->prefetch_ref(),tx));vm::Dictionary messages(tx.r1.out_msgs,15);
      CHECK(messages.check_for_each([&](auto message,td::ConstBitPtr,int){
        gen::CommonMsgInfo::Record_int_msg_info info;CHECK(::tlb::unpack_cell_inexact(message->prefetch_ref(),info));
        CurrencyCollection value;CHECK(value.unpack(info.value));
        CHECK(values.emplace(info.created_lt,u64(value.tomis)).second);return true;
      }));return true;
    }));
  }
  return values;
}
inline std::uint64_t book(const std::filesystem::path& fixture, unsigned height,const td::Bits256& custody) {
  std::uint64_t total=0;
  for(unsigned n=1;n<=height;++n) {
    auto root=block_at(fixture,n);
    auto candidate=m4_recorded_candidate(root);
    if(m3_test::is_m4_test_deposit(candidate)) {
      if(!m4_deposit_was_rejected(root)) total=add(total,m3_test::decode_m4_test_deposit(candidate).move_as_ok().principal);
    } else if(m3_test::is_m5_test_failed(candidate)) {
      const auto native=decode_workchain_native_effects(effects(root).native).move_as_ok();
      auto retained=u64(m5_recorded_return(root).tomis);
      if(native.fees)retained=sub(retained,add(add(u64(native.fees->state_fee),u64(native.fees->compute_fee)),u64(native.fees->tip)));
      // Bucket forwarding is an explicit custody debit. Empty transfer map is
      // the ordinary direct return; unknown/non-custody moves are not ignored.
      vm::Dictionary transfers(native.transfers,32);
      CHECK(transfers.check_for_each([&](auto value,td::ConstBitPtr,int){
        gen::UnoV2NativeTransfer::Record move; CHECK(::tlb::unpack_cell(value->prefetch_ref(),move));
        CHECK(move.source == custody);
        CurrencyCollection moved; CHECK(moved.unpack(move.value));
        retained=sub(retained,u64(moved.tomis)); return true;
      }));
      total=add(total,retained);
    } else if(m3_test::is_m5_test_sweep(candidate)) {
      m3_test::decode_m5_test_sweep(candidate).ensure();
      // One selected-entry sweep is the scope of this fixture. Bind the saved
      // predecessor through the real Merkle update, not a proposed effects list.
      auto before=load(fixture/"completion-sweep-before-state.boc");
      gen::ShardStateUnsplit::Record state;CHECK(::tlb::unpack_cell(before,state)&&add(state.seq_no,1)==n);
      gen::Block::Record b;CHECK(::tlb::unpack_cell(root,b));
      auto linked=vm::MerkleUpdate::apply(before,b.state_update).move_as_ok();CHECK(linked.not_null());
      int budget;auto policy=observed_policy(fixture,&budget);CHECK(policy.sweep&&policy.deposit&&policy.operation_tariff);
      CHECK(policy.sweep->count==1);
      auto coordinator=decode_workchain_coordinator_state(native_account(before,td::Bits256::zero()).data).move_as_ok();
      auto bucket=observed_bucket(coordinator.unexpected,budget);
      CHECK(!bucket.entries.empty()&&bucket.entries.front().account_id&&!bucket.entries.front().return_failed);
      const auto fee=add(policy.deposit->slot_fee,mul(policy.operation_tariff->base,policy.sweep->issuance_billing_units));
      // R_book comes from the old entry and authenticated prices. It must not
      // copy the actual transfer: omitting that transfer must remain visible.
      total=add(total,sub(u64(bucket.entries.front().tomis),fee));
    } else {
      auto replay=m3_test::decode_m5_accounting_replay(candidate).move_as_ok();
      if(auto withdrawal=std::get_if<WorkchainWithdrawalInput>(&replay)) {
        const auto& a=withdrawal->data.amounts;
        total=sub(total,add(add(a.principal,a.outward_fee),a.operation_fee));
      } else if(auto transfer=std::get_if<WorkchainTransferInput>(&std::get<WorkchainReplayInput>(replay))) {
        total=sub(total,workchain_transfer_claims(transfer->data).authorized_fee);
      }
    }
  }
  return total;
}
struct Snapshot {
  std::uint64_t reserve, ledger, hidden=0, p=0, w=0, coordinator, holdings, refundable, sequence;
  std::map<std::string,std::uint64_t> records;
  std::map<std::string,std::pair<std::string,std::uint64_t>> pending;
  std::string user_root, system_root;
  WorkchainUnexpectedBucket bucket;
  std::size_t user_count=0;
};
inline std::string cell_list_hash(const std::vector<td::Ref<vm::Cell>>& cells) {
  // A canonical hash chain includes every encoded field, not only amounts.
  td::Ref<vm::Cell> chain=vm::CellBuilder().finalize();
  for(const auto& cell:cells) chain=vm::CellBuilder().store_ref(chain).store_ref(cell).finalize();
  return chain->get_hash().to_hex();
}
inline Snapshot snapshot(const std::filesystem::path& fixture,const td::Ref<vm::Cell>& state,
                         const td::Bits256& custody,std::uint32_t limit,int cell_budget) {
  gen::ShardStateUnsplit::Record parsed; CHECK(::tlb::unpack_cell(state,parsed));
  auto co=native_account(state,td::Bits256::zero());
  auto config=decode_workchain_coordinator_state(co.data).move_as_ok(); CHECK(config.deposit_sequence);
  Snapshot out;out.reserve=u64(native_account(state,custody).balance.tomis);out.ledger=book(fixture,parsed.seq_no,custody);
  out.coordinator=u64(co.balance.tomis);out.refundable=config.refundable_deposits;out.sequence=*config.deposit_sequence;
  // Observer limits come from the encoded counts, not a production-capacity
  // default; the exact decoder independently enumerates those counts.
  bool special=false;auto bucket_bits=vm::load_cell_slice_special(config.unexpected,special);
  CHECK(!special && bucket_bits.size()>=112);bucket_bits.advance(48);
  WorkchainUnexpectedLimits sizes{static_cast<std::uint32_t>(bucket_bits.fetch_ulong(32)),
                                  static_cast<std::uint32_t>(bucket_bits.fetch_ulong(32))};
  auto bucket=decode_workchain_unexpected_bucket(config.unexpected,sizes,cell_budget).move_as_ok();
  out.holdings=u64(workchain_unexpected_balance(bucket).move_as_ok().tomis);out.bucket=bucket;
  const auto payments=payout_values(fixture,parsed.seq_no,custody);
  for(unsigned owner:{0u,1u}) {
    const auto key=wallet_account(owner);
    auto account=m5_live_account(account_data(state,key),limit);
    auto amount=[&](const auto& c){return m3_test::decrypt(c,test_secret(key),2000000000).move_as_ok();};
    out.hidden=add(out.hidden,amount(account.account.available));
    std::vector<td::Ref<vm::Cell>> users,systems;
    for(const auto& r:account.account.pending){out.hidden=add(out.hidden,amount(r.ciphertext));users.push_back(encode_workchain_pending_receipt(r).move_as_ok());}
    for(const auto& r:account.account.system_pending){auto v=amount(r.ciphertext);out.hidden=add(out.hidden,v);systems.push_back(encode_workchain_deposit_receipt(r).move_as_ok());if(owner==0)out.pending.emplace(r.receipt_id.to_hex(),std::make_pair(key.to_hex(),v));}
    for(const auto& r:account.origin_pending){auto v=amount(r.ciphertext);out.hidden=add(out.hidden,v);systems.push_back(encode_workchain_system_receipt(r).move_as_ok());if(owner==0)out.pending.emplace(r.receipt_id.to_hex(),std::make_pair(key.to_hex(),v));}
    for(const auto& r:account.control.withdrawals){out.w=add(out.w,r.principal);CHECK(payments.count(r.timing.payout_created_lt)==1);out.p=add(out.p,payments.at(r.timing.payout_created_lt));if(owner==0)out.records.emplace(r.withdrawal_id.to_hex(),r.principal);}
    if(owner==0){out.user_count=users.size();out.user_root=cell_list_hash(users);out.system_root=cell_list_hash(systems);}
  }
  return out;
}
inline std::string bucket_entry_json(const WorkchainUnexpectedEntry& e) {
  std::ostringstream out;out<<"{\"kind\":"<<(e.account_id?2:1)<<",\"src\":"
    <<quote(std::to_string(e.sender.workchain)+":"+e.sender.account.to_hex());
  if(e.account_id)out<<",\"account_id\":"<<quote(e.account_id->to_hex());
  out<<",\"tomis\":"<<u64(e.tomis)<<",\"return_failed\":"<<(e.return_failed?"true":"false")<<'}';return out.str();
}
inline std::string actual_return_path(const std::filesystem::path& fixture,const td::Bits256& inbound) {
  // Only execution log from this invocation is eligible; never select a path
  // from Q, phase, post-state, or a proposed result label.
  std::ifstream trace(fixture/"completion-execution.log");CHECK(trace.good());std::string line,route;
  const std::map<std::string,std::string> names{{"admit_workchain_late_return","late-return-admission"},
    {"window_return","within-window-failed"},{"type2_bucket_disposition","type2-bucket-disposition"}};
  unsigned matches=0;
  while(std::getline(trace,line))for(const auto& [callee,name]:names)
    if(line.find("WORKCHAIN_RETURN_CALLEE "+callee+" inbound="+inbound.to_hex())!=std::string::npos){
      CHECK(route.empty()||route==name);route=name;++matches;
    }
  CHECK(matches>0);
  return route;
}
inline std::string snapshot_json(const Snapshot& s,std::uint64_t issuance_fees,
                                 const std::vector<std::string>& order) {
  std::ostringstream o;
  o<<"{\"R_actual\":"<<s.reserve<<",\"R_book\":"<<s.ledger<<",\"N_book\":"<<s.hidden
   <<",\"P\":"<<s.p<<",\"W\":"<<s.w<<",\"D\":0,\"coordinator\":"<<s.coordinator
   <<",\"holdings\":"<<s.holdings<<",\"refundable\":"<<s.refundable<<",\"issuance_fees\":"<<issuance_fees
   <<",\"sequence\":"<<s.sequence<<",\"records\":{";
  bool comma=false;for(const auto& [id,value]:s.records){if(comma)o<<',';comma=true;o<<quote(id)<<':'<<value;}
  o<<"},\"pending\":[";comma=false;
  for(const auto& id:order){auto it=s.pending.find(id);if(it==s.pending.end())continue;if(comma)o<<',';comma=true;
    o<<"{\"target\":"<<quote(it->second.first)<<",\"amount\":"<<it->second.second<<'}';}
  o<<"],\"user_pending_root\":"<<quote(s.user_root)<<",\"system_pending_root\":"<<quote(s.system_root)
   <<",\"user_count\":"<<s.user_count<<",\"system_count\":"<<s.pending.size()<<'}';return o.str();
}

struct SweepNativeObservation {
  std::uint64_t transferred=0, transaction_fees=0, block_fees=0;
  unsigned transfer_count=0, other_transfer_count=0;
  std::string batch_id;
};
inline SweepNativeObservation sweep_native_observation(const td::Ref<vm::Cell>& root,
    const td::Bits256& coordinator,const td::Bits256& custody) {
  // Read the accepted block's transfer records and all actual transaction fees.
  // In this isolated sweep fixture there are no unrelated messages whose fees
  // could be silently included in the issuance cost. Do not infer the fee
  // destination merely from coordinator balance loss.
  SweepNativeObservation out;
  out.batch_id=root->get_hash().to_hex();
  const auto native=decode_workchain_native_effects(effects(root).native).move_as_ok();
  vm::Dictionary transfers(native.transfers,32);
  CHECK(transfers.check_for_each([&](auto cell,td::ConstBitPtr,int){
    gen::UnoV2NativeTransfer::Record transfer;
    CHECK(::tlb::unpack_cell(cell->prefetch_ref(),transfer));
    CurrencyCollection value;CHECK(value.unpack(transfer.value));
    if(transfer.source==coordinator && transfer.destination==custody){
      out.transferred=add(out.transferred,u64(value.tomis));
      CHECK(out.transfer_count==0);++out.transfer_count;
    }else{
      // Keep a misrouted but validly encoded transfer observable. The physical
      // credit oracle, not an earlier parser CHECK, must judge that mutation.
      CHECK(out.other_transfer_count<UINT_MAX);++out.other_transfer_count;
    }
    return true;
  }));
  gen::Block::Record b;gen::BlockExtra::Record e;
  CHECK(::tlb::unpack_cell(root,b)&&::tlb::unpack_cell(b.extra,e));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(e.account_blocks),256,block::tlb::aug_ShardAccountBlocks);
  CHECK(accounts.check_for_each([&](auto leaf,td::ConstBitPtr,int){
    // Iteration carries the augmentation; unlike lookup(), it does not strip
    // the leading CurrencyCollection before the AccountBlock value.
    leaf=accounts.extract_value(leaf);CHECK(leaf.not_null());
    gen::AccountBlock::Record account;CHECK(gen::t_AccountBlock.unpack(leaf.write(),account));
    vm::AugmentedDictionary txs(vm::DictNonEmpty(),account.transactions,64,block::tlb::aug_AccountTransactions);
    CHECK(txs.check_for_each([&](auto cell,td::ConstBitPtr,int){
      gen::Transaction::Record tx;CHECK(::tlb::unpack_cell(cell->prefetch_ref(),tx));
      CurrencyCollection fees;CHECK(fees.unpack(tx.total_fees));
      out.transaction_fees=add(out.transaction_fees,u64(fees.tomis));return true;
    }));return true;
  }));
  ValueFlow flow;CHECK(flow.unpack(vm::load_cell_slice_ref(b.value_flow)));
  out.block_fees=u64(flow.fees_collected.tomis);
  return out;
}
} // namespace m3_live::completion

namespace m3_live {
inline void write_sweep_completion_observation(const std::filesystem::path& fixture,
                                                const std::filesystem::path& output) {
  using namespace block;using namespace completion;
  CHECK(!std::filesystem::exists(output));
  const auto validation=td::read_file_str((fixture/"enabled.result.validation.result").string());
  if(validation.is_error()||validation.ok()!="validate accept\n") {
    td::write_file(output.string(),"{\"input\":{},\"observed\":{\"published\":false}}\n").ensure();return;
  }
  auto before=load(fixture/"completion-sweep-before-state.boc");
  CHECK(before->get_hash()==load(fixture/"completion-before-state.boc")->get_hash());
  auto accepted=read_accepted_step(fixture/"enabled.candidate",before);
  m3_test::decode_m5_test_sweep(m4_recorded_candidate(accepted.block)).ensure();
  auto zero=load(fixture/"zerostate.boc");
  tos::BlockIdExt id{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},zero->get_hash().bits(),td::Bits256::zero()};
  auto config=ConfigInfo::extract_config(zero,id,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();
  auto ingress=load_workchain_native_ingress_table(*config).move_as_ok().at(2);CHECK(ingress.custody_address);
  int budget;auto policy=observed_policy(fixture,&budget);
  CHECK(policy.sweep&&policy.failed&&policy.deposit&&policy.operation_tariff&&policy.sweep->count==1);
  auto a=snapshot(fixture,before,*ingress.custody_address,policy.failed->withdrawal_limit,budget);
  auto z=snapshot(fixture,accepted.state,*ingress.custody_address,policy.failed->withdrawal_limit,budget);
  CHECK(!a.bucket.entries.empty());const auto& entry=a.bucket.entries.front();
  CHECK(entry.account_id&&*entry.account_id==wallet_account(0)&&!entry.return_failed);
  CHECK(a.bucket.sweep_sequence&&z.bucket.sweep_sequence);
  std::vector<std::string> order;for(const auto& [key,value]:a.pending)order.push_back(key);
  for(const auto& [key,value]:z.pending)if(!a.pending.count(key))order.push_back(key);
  auto native=sweep_native_observation(accepted.block,ingress.executor_address,*ingress.custody_address);
  // D60 spendable surplus distinguishes retained slot income from the g that
  // passes through coordinator. Both protected components are independently read.
  auto difference=[](std::uint64_t after,std::uint64_t before){
    CHECK(after<=INT64_MAX&&before<=INT64_MAX);std::int64_t result;
    CHECK(!__builtin_sub_overflow(static_cast<std::int64_t>(after),static_cast<std::int64_t>(before),&result));
    return result;
  };
  // Preserve a negative observed surplus delta for the named oracle. Rejecting
  // it here would hide a missing-holdings mutation behind adapter arithmetic.
  auto income=difference(z.coordinator,a.coordinator);std::int64_t next;
  CHECK(!__builtin_sub_overflow(income,difference(z.holdings,a.holdings),&next));income=next;
  CHECK(!__builtin_sub_overflow(income,difference(z.refundable,a.refundable),&next));income=next;
  auto batch=accepted.block->get_hash().to_hex();
  gen::ShardStateUnsplit::Record state;CHECK(::tlb::unpack_cell(accepted.state,state));
  const auto old_authorization=m3_test::verify_m5_sweep_authorization(*policy.sweep,a.bucket,state.seq_no);
  const auto new_authorization=m3_test::verify_m5_sweep_authorization(*policy.sweep,z.bucket,state.seq_no);
  // In this isolated no-import/no-payout sweep, custody's actual balance delta
  // is the received transfer. Keep the committed instruction separate: a
  // correct instruction alone does not prove that Native applied the credit.
  std::ostringstream out;
  out<<"{\"input\":{\"x\":0,\"withdrawal_id\":"<<quote(td::Bits256::zero().to_hex())
     <<",\"y\":"<<u64(entry.tomis)<<",\"slot\":"<<policy.deposit->slot_fee
     <<",\"base\":"<<policy.operation_tariff->base<<",\"units\":"<<policy.sweep->issuance_billing_units
     <<",\"account_id\":"<<quote(entry.account_id->to_hex())
     <<"},\"observed\":{\"published\":true,\"before\":"<<snapshot_json(a,0,order)
     <<",\"after\":"<<snapshot_json(z,native.block_fees,order)
     <<",\"custody_transfer\":"<<difference(z.reserve,a.reserve)
     <<",\"declared_native_transfer\":"<<native.transferred
     <<",\"other_native_transfers\":"<<native.other_transfer_count
     <<",\"operator_slot_income\":"<<income
     <<",\"native_transaction_fees\":"<<native.transaction_fees
     <<",\"committed_batch_id\":"<<quote(batch)<<",\"component_batch_ids\":["
     <<quote(native.transfer_count?batch:"")<<','<<quote(batch)<<','<<quote(native.batch_id)<<','<<quote(batch)
     <<"],\"sweep_sequence_before\":"<<*a.bucket.sweep_sequence
     <<",\"sweep_sequence_after\":"<<*z.bucket.sweep_sequence
     <<",\"authorized_sequence\":"<<policy.sweep->sequence
     <<",\"height\":"<<state.seq_no<<",\"earliest_height\":"<<policy.sweep->earliest_height
     <<",\"authorization_before_ok\":"<<(old_authorization.is_ok()?"true":"false")
     <<",\"authorization_after_same_height_code\":"<<(new_authorization.is_error()?new_authorization.code():0)
     <<"},\"provenance\":{\"before\":"<<quote(before->get_hash().to_hex())
     <<",\"after\":"<<quote(accepted.state->get_hash().to_hex())<<",\"block\":"<<quote(batch)
     <<",\"old_entry\":"<<bucket_entry_json(entry)
     <<",\"D\":\"structural atomic-operation zero, not a persisted counter\"}}\n";
  td::write_file(output.string(),out.str()).ensure();
}
inline void write_paid_completion_observation(const std::filesystem::path& fixture,
                                               const std::filesystem::path& output, bool row5_predecessor=false) {
  using namespace block; using namespace completion;
  CHECK(!std::filesystem::exists(output));
  CHECK(td::read_file_str((fixture/"enabled.result.validation.result").string()).move_as_ok()=="validate accept\n");
  const auto before=load(fixture/"completion-before-state.boc");
  const auto accepted=read_accepted_step(fixture/"enabled.candidate",before);
  const auto after=accepted.state,current=accepted.block;
  auto zero=load(fixture/"zerostate.boc");
  tos::BlockIdExt zid{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},zero->get_hash().bits(),td::Bits256::zero()};
  auto config=ConfigInfo::extract_config(zero,zid,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();
  auto ingress=load_workchain_native_ingress_table(*config).move_as_ok().at(2); CHECK(ingress.custody_address);
  auto params=decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
  auto policy=m3_test::decode_m3_test_business_parameters(params.parameters).move_as_ok();
  CHECK(policy.prepare && policy.operation_tariff && params.resources.state.max_cells<=INT_MAX);
  const auto limit=policy.prepare->withdrawal_limit;
  auto old=m5_live_account(account_data(before,wallet_account(0)),limit);
  gen::CommonMsgInfo::Record_int_msg_info original;
  CHECK(::tlb::unpack_cell_inexact(load(fixture/"completion-original-payout.boc"),original));
  auto selected=std::find_if(old.control.withdrawals.begin(),old.control.withdrawals.end(),
      [&](const auto& r){return r.timing.payout_created_lt==original.created_lt;});
  CHECK(selected!=old.control.withdrawals.end()); const auto record=*selected;
  const auto untouched=load(fixture/"completion-untouched-state.boc");
  CHECK(untouched->get_hash()==before->get_hash());
  auto established=load(fixture/"completion-record-state.boc");
  gen::ShardStateUnsplit::Record es,bs,ns;
  CHECK(::tlb::unpack_cell(established,es)&&::tlb::unpack_cell(before,bs)&&::tlb::unpack_cell(after,ns));
  CHECK((row5_predecessor ? es.seq_no<=bs.seq_no : es.seq_no<bs.seq_no) && ns.seq_no==add(bs.seq_no,1));
  CHECK(account_data(established,wallet_account(0))->get_hash()==account_data(untouched,wallet_account(0))->get_hash());
  auto chained=established;
  for(unsigned n=es.seq_no+1;n<=bs.seq_no;++n){gen::Block::Record b;CHECK(::tlb::unpack_cell(block_at(fixture,n),b));chained=vm::MerkleUpdate::apply(chained,b.state_update).move_as_ok();}
  CHECK(chained->get_hash()==untouched->get_hash());
  // Row5 needs a proved prior closure, not the separate row4 untouched-expiry scenario.
  // Keep that stricter scenario unchanged for the formal row4 carrier.
  CHECK((row5_predecessor ? ns.seq_no : bs.seq_no)>add(record.timing.queue_removed_height,record.timing.settlement_blocks));
  auto replay=m3_test::decode_m5_accounting_replay(m4_recorded_candidate(current)).move_as_ok();
  const auto* trigger=std::get_if<WorkchainWithdrawalInput>(&replay); CHECK(trigger);
  CHECK(trigger->data.claims.source.account==wallet_account(0) && trigger->claimed_operation_id!=record.withdrawal_id);
  const auto& amounts=trigger->data.amounts;
  auto a=snapshot(fixture,before,*ingress.custody_address,limit,static_cast<int>(params.resources.state.max_cells));
  auto z=snapshot(fixture,after,*ingress.custody_address,limit,static_cast<int>(params.resources.state.max_cells));
  const auto raw=z;
  CHECK(z.records.count(trigger->claimed_operation_id.to_hex())==1 && z.records.at(trigger->claimed_operation_id.to_hex())==amounts.principal);
  const auto debit=add(add(amounts.principal,amounts.outward_fee),amounts.operation_fee);
  // Remove only the separately authorized trigger. Actual installed state,
  // serialized payout and authenticated S are independent of settlement.
  z.reserve=add(z.reserve,debit);z.ledger=add(z.ledger,debit);z.hidden=add(z.hidden,debit);
  z.p=sub(z.p,amounts.principal);z.w=sub(z.w,amounts.principal);
  z.coordinator=sub(z.coordinator,policy.prepare->state_fee);
  z.records.erase(trigger->claimed_operation_id.to_hex());
  auto installed=m5_live_account(account_data(after,wallet_account(0)),limit);
  auto fresh=std::find_if(installed.control.withdrawals.begin(),installed.control.withdrawals.end(),
      [&](const auto& r){return r.withdrawal_id==trigger->claimed_operation_id;}); CHECK(fresh!=installed.control.withdrawals.end());
  gen::Transaction::Record tx;CHECK(::tlb::unpack_cell(accepted_transaction(accepted,*ingress.custody_address),tx));
  CurrencyCollection fees;CHECK(fees.unpack(tx.total_fees));
  vm::Dictionary messages(tx.r1.out_msgs,15);std::vector<std::string> movements;unsigned matched=0;std::uint64_t forwarded=0;
  CHECK(messages.check_for_each([&](auto cell,td::ConstBitPtr,int){
    auto message=cell->prefetch_ref();gen::CommonMsgInfo::Record_int_msg_info info;CHECK(::tlb::unpack_cell_inexact(message,info));
    if(info.created_lt==fresh->timing.payout_created_lt){CurrencyCollection value;CHECK(value.unpack(info.value));CHECK(u64(value.tomis)==amounts.principal);forwarded=u64(block::tlb::t_Tomis.as_integer(info.fwd_fee));++matched;}
    else movements.push_back(message->get_hash().to_hex());return true;
  })); CHECK(matched==1);
  auto native=decode_workchain_native_effects(effects(current).native).move_as_ok();
  vm::Dictionary transfers(native.transfers,32);
  CHECK(transfers.check_for_each([&](auto value,td::ConstBitPtr,int){movements.push_back(value->prefetch_ref()->get_hash().to_hex());return true;}));
  const auto trigger_collected=add(sub(amounts.operation_fee,policy.prepare->state_fee),sub(amounts.outward_fee,forwarded));
  const auto settlement_collected=sub(u64(fees.tomis),trigger_collected);
  std::set<std::string> closures;std::ifstream log(fixture/"completion-execution.log");CHECK(log.good());std::string line;bool lazy_called=false;
  const std::string prefix="WORKCHAIN_RETURN_CALLEE paid_expiry withdrawal=";
  while(std::getline(log,line)){
    if(line.find("WORKCHAIN_RETURN_CALLEE lazy_owner_settlement owner="+wallet_account(0).to_hex())!=std::string::npos)lazy_called=true;
    auto pos=line.find(prefix);if(pos!=std::string::npos){auto id=line.substr(pos+prefix.size(),64);CHECK(id.size()==64 && id.find_first_not_of("0123456789ABCDEFabcdef")==std::string::npos);closures.insert(id);}}
  std::vector<std::string> order;for(const auto& [id,value]:a.pending)order.push_back(id);for(const auto& [id,value]:z.pending)if(!a.pending.count(id))order.push_back(id);
  std::ostringstream out;
  out<<"{\"input\":{\"x\":"<<record.principal<<",\"Q\":"<<record.timing.queue_removed_height
     <<",\"window\":"<<record.timing.settlement_blocks<<",\"phase\":"<<unsigned(record.timing.phase)
     <<",\"withdrawal_limit\":"<<limit
     <<",\"height\":"<<ns.seq_no<<",\"withdrawal_id\":"<<quote(record.withdrawal_id.to_hex())
     <<"},\"observed\":{\"published\":true,\"dispatch\":[";
  if(lazy_called)out<<quote("lazy-owner-settlement");out<<"],\"closure_events\":[";
  bool comma=false;for(const auto& id:closures){if(comma)out<<',';comma=true;out<<quote(id);}out<<"],\"value_movements\":[";
  comma=false;for(const auto& value:movements){if(comma)out<<',';comma=true;out<<quote(value);}
  out<<"],\"before\":"<<snapshot_json(a,0,order)<<",\"after\":"<<snapshot_json(z,settlement_collected,order)
     <<"},\"provenance\":{\"raw_after\":"<<snapshot_json(raw,u64(fees.tomis),order)
     <<",\"trigger_debit\":"<<debit<<",\"trigger_principal\":"<<amounts.principal
     <<",\"trigger_state_fee\":"<<policy.prepare->state_fee<<",\"trigger_collected\":"<<trigger_collected
     <<",\"untouched_height\":"<<bs.seq_no<<",\"before\":"<<quote(before->get_hash().to_hex())
     <<",\"after\":"<<quote(after->get_hash().to_hex())<<",\"block\":"<<quote(current->get_hash().to_hex())<<"}}\n";
  td::write_file(output.string(),out.str()).ensure();
}

inline void write_completion_observation(const std::string& which,const std::filesystem::path& fixture,
                                         const std::filesystem::path& output) {
  if(which=="row4" || which=="row5-paid"){write_paid_completion_observation(fixture,output,which=="row5-paid");return;}
  if(which=="sweep-atomic"){write_sweep_completion_observation(fixture,output);return;}
  using namespace block;using namespace completion;
  CHECK(which=="row6" || which=="row5" || which=="bucket-small" || which=="bucket-full" || which=="bucket-closed");
  CHECK(!std::filesystem::exists(output));
  const auto inbound=td::Bits256(load(fixture/"failed-bounce.boc")->get_hash().bits());
  const auto route_at_entry=actual_return_path(fixture,inbound);
  const auto validation=td::read_file_str((fixture/"enabled.result.validation.result").string());
  if(validation.is_error() || validation.ok()!="validate accept\n") {
    // A real callee ran but no validator-accepted disposition exists. This is
    // not a claim that arbitrary in-memory side effects were impossible.
    td::write_file(output.string(),"{\"input\":{},\"observed\":{\"published\":false,\"dispatch\":["+
                   quote(route_at_entry)+"]}}\n").ensure();
    return;
  }
  const auto before=load(fixture/"completion-before-state.boc");
  // Reconstruct from the exported, validator-accepted candidate itself. The
  // harness saves accepted-state only after its other assertions have passed;
  // those cached files may still describe the preceding operation.
  const auto accepted=read_accepted_step(fixture/"enabled.candidate",before);
  const auto after=accepted.state,current=accepted.block;
  gen::Block::Record block;CHECK(::tlb::unpack_cell(current,block));
  auto applied=vm::MerkleUpdate::apply(before,block.state_update).move_as_ok();CHECK(applied->get_hash()==after->get_hash());
  gen::ShardStateUnsplit::Record old_state,new_state;CHECK(::tlb::unpack_cell(before,old_state)&&::tlb::unpack_cell(after,new_state));
  CHECK(new_state.seq_no==add(old_state.seq_no,1));
  // Require the real validator acceptance result, in addition to Merkle linkage.
  CHECK(td::read_file_str((fixture/"enabled.result.validation.result").string()).move_as_ok()=="validate accept\n");
  auto zero=load(fixture/"zerostate.boc");
  tos::BlockIdExt zero_id{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},zero->get_hash().bits(),td::Bits256::zero()};
  auto config=ConfigInfo::extract_config(zero,zero_id,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();
  auto ingress=load_workchain_native_ingress_table(*config).move_as_ok().at(2);CHECK(ingress.custody_address);
  auto parameters=decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
  auto policy=m3_test::decode_m3_test_business_parameters(parameters.parameters).move_as_ok();
  CHECK(policy.failed&&policy.deposit&&policy.operation_tariff);
  const auto limit=policy.failed->withdrawal_limit;
  auto old_owner=m5_live_account(account_data(before,wallet_account(0)),limit);
  auto reference=old_owner;
  const auto described=describe_workchain_late_return(load(fixture/"failed-bounce.boc"),2,
                                                      *ingress.custody_address).move_as_ok();
  auto matches=[&](const auto& candidate){return candidate.timing.payout_created_lt==described.payout_created_lt;};
  if(std::none_of(reference.control.withdrawals.begin(),reference.control.withdrawals.end(),matches)) {
    auto historical=load(fixture/"completion-record-state.boc");
    gen::ShardStateUnsplit::Record historical_state;CHECK(::tlb::unpack_cell(historical,historical_state));
    CHECK(historical_state.seq_no<old_state.seq_no);
    // Reapply every recorded intervening update. A hand-written phase1 root
    // cannot satisfy this linkage to the actual authenticated predecessor.
    auto chained=historical;
    for(unsigned n=historical_state.seq_no+1;n<=old_state.seq_no;++n){
      gen::Block::Record h;CHECK(::tlb::unpack_cell(block_at(fixture,n),h));
      chained=vm::MerkleUpdate::apply(chained,h.state_update).move_as_ok();
    }
    CHECK(chained->get_hash()==before->get_hash());
    reference=m5_live_account(account_data(historical,wallet_account(0)),limit);
  }
  CHECK(std::count_if(reference.control.withdrawals.begin(),reference.control.withdrawals.end(),matches)==1);
  const auto& record=*std::find_if(reference.control.withdrawals.begin(),reference.control.withdrawals.end(),matches);
  auto selector=m3_test::decode_m5_test_failed(m4_recorded_candidate(current)).move_as_ok();
  CHECK(selector.owner.account==wallet_account(0));
  auto bounce=load(fixture/"failed-bounce.boc");CHECK(td::Bits256(bounce->get_hash().bits())==selector.inbound_message);
  gen::CommonMsgInfo::Record_int_msg_info info;CHECK(::tlb::unpack_cell_inexact(bounce,info)&&info.bounced);
  tos::WorkchainId src_wc;td::Bits256 src;CHECK(block::tlb::t_MsgAddressInt.extract_std_address(info.src,src_wc,src));
  const auto y=u64(m5_recorded_return(current).tomis);
  CHECK(parameters.resources.state.max_cells<=INT_MAX);
  const auto a=snapshot(fixture,before,*ingress.custody_address,limit,static_cast<int>(parameters.resources.state.max_cells));
  const auto z=snapshot(fixture,after,*ingress.custody_address,limit,static_cast<int>(parameters.resources.state.max_cells));
  std::vector<std::string> order;for(const auto& [id,unused]:a.pending)order.push_back(id);
  for(const auto& [id,unused]:z.pending)if(!a.pending.count(id))order.push_back(id);
  AcceptedStep step{{},current,after};gen::Transaction::Record custody_tx;
  CHECK(::tlb::unpack_cell(accepted_transaction(step,*ingress.custody_address),custody_tx));
  CurrencyCollection paid;CHECK(paid.unpack(custody_tx.total_fees));
  const auto route=actual_return_path(fixture,selector.inbound_message);
  std::string bucket_extra;std::uint64_t bucket_cost=0;
  if(which.starts_with("bucket-")) {
    const auto actual=decode_workchain_native_effects(effects(current).native).move_as_ok();
    vm::Dictionary transfers(actual.transfers,32);std::uint64_t moved=0;
    CHECK(transfers.check_for_each([&](auto cell,td::ConstBitPtr,int){
      gen::UnoV2NativeTransfer::Record transfer;CHECK(::tlb::unpack_cell(cell->prefetch_ref(),transfer));
      CHECK(transfer.source==*ingress.custody_address && transfer.destination==ingress.executor_address);
      CurrencyCollection value;CHECK(value.unpack(transfer.value));moved=add(moved,u64(value.tomis));return true;
    }));
    bucket_cost=sub(y,moved);
    std::ostringstream extra;extra<<",\"bucket_native_credit\":"<<moved<<",\"bucket_entries_added\":[";
    CHECK(z.bucket.entries.size()>=a.bucket.entries.size());bool comma=false;
    for(std::size_t n=0;n<z.bucket.entries.size();++n){
      auto entry=bucket_entry_json(z.bucket.entries[n]);
      if(n<a.bucket.entries.size()){CHECK(entry==bucket_entry_json(a.bucket.entries[n]));continue;}
      if(comma)extra<<',';comma=true;extra<<entry;
    }
    extra<<']';bucket_extra=extra.str();
  }
  std::string closed_provenance;
  if(which=="bucket-closed") {
    auto close_before=load(fixture/"completion-account-close-before-state.boc");
    auto close_after=load(fixture/"completion-account-close-after-state.boc");
    CHECK(td::read_file_str((fixture/"completion-account-close-validation.result").string()).move_as_ok()=="validate accept\n");
    auto close=read_accepted_step(fixture/"completion-account-close-candidate",close_before);
    CHECK(close.state->get_hash()==close_after->get_hash());
    auto active=m5_live_account(account_data(close_before,wallet_account(0)),limit);
    auto closed=m5_live_account(account_data(close_after,wallet_account(0)),limit);
    CHECK(std::holds_alternative<WorkchainAccountActive>(active.account.lifecycle));
    CHECK(std::holds_alternative<WorkchainAccountClosed>(closed.account.lifecycle));
    CHECK(closed.control.withdrawals.empty() && closed.account.pending.empty() &&
          closed.account.system_pending.empty() && closed.origin_pending.empty());
    gen::ShardStateUnsplit::Record cs;CHECK(::tlb::unpack_cell(close_after,cs));
    CHECK(cs.seq_no<=old_state.seq_no);
    auto chain=close_after;
    for(unsigned n=cs.seq_no+1;n<=old_state.seq_no;++n){gen::Block::Record b;CHECK(::tlb::unpack_cell(block_at(fixture,n),b));chain=vm::MerkleUpdate::apply(chain,b.state_update).move_as_ok();}
    CHECK(chain->get_hash()==before->get_hash());
    // The arrival must not resurrect or otherwise rewrite the closed account.
    CHECK(account_data(before,wallet_account(0))->get_hash()==account_data(after,wallet_account(0))->get_hash());
    closed_provenance=",\"real_account_closure\":true";
  }
  std::string freed_slot;
  if(std::filesystem::exists(fixture/"completion-full-before-collect.boc")) {
    auto full=load(fixture/"completion-full-before-collect.boc");
    auto collected=load(fixture/"completion-full-after-collect.boc");
    CHECK(td::read_file_str((fixture/"free-one-slot-enabled.result.validation.result").string()).move_as_ok()=="validate accept\n");
    const auto step=read_accepted_step(fixture/"free-one-slot-enabled.candidate",full);
    CHECK(step.state->get_hash()==collected->get_hash());
    auto left=m5_live_account(account_data(full,wallet_account(0)),limit);
    auto right=m5_live_account(account_data(collected,wallet_account(0)),limit);
    // This collection precedes account migration and operates on real Deposit entries.
    CHECK(left.origin_pending.empty() && right.origin_pending.empty());
    CHECK(left.account.system_pending.size()==policy.deposit->system_slots &&
          right.account.system_pending.size()+1==left.account.system_pending.size());
    auto selected=td::read_file_str((fixture/"full-slot-3.receipt.id").string()).move_as_ok();
    while(!selected.empty() && (selected.back()=='\n' || selected.back()=='\r')) selected.pop_back();
    auto selected_bytes=td::hex_decode(selected).move_as_ok(); CHECK(selected_bytes.size()==32);
    td::Bits256 selected_id; selected_id.as_slice().copy_from(selected_bytes); selected=selected_id.to_hex();
    std::map<std::string,std::string> expected,actual;
    for(const auto& r:left.account.system_pending)
      expected.emplace(r.receipt_id.to_hex(),encode_workchain_deposit_receipt(r).move_as_ok()->get_hash().to_hex());
    CHECK(expected.erase(selected)==1);
    for(const auto& r:right.account.system_pending)
      actual.emplace(r.receipt_id.to_hex(),encode_workchain_deposit_receipt(r).move_as_ok()->get_hash().to_hex());
    CHECK(actual==expected);
    gen::ShardStateUnsplit::Record cs;CHECK(::tlb::unpack_cell(collected,cs));
    CHECK(cs.seq_no<=old_state.seq_no);
    auto chain=collected;
    for(unsigned n=cs.seq_no+1;n<=old_state.seq_no;++n){gen::Block::Record b;CHECK(::tlb::unpack_cell(block_at(fixture,n),b));chain=vm::MerkleUpdate::apply(chain,b.state_update).move_as_ok();}
    CHECK(chain->get_hash()==before->get_hash());
    CHECK(a.pending.size()==right.account.system_pending.size());
    freed_slot=",\"collected_one_real_slot\":true";
  }
  std::ostringstream out;
  out<<"{\"input\":{\"x\":"<<record.principal<<",\"y\":"<<y<<",\"slot\":"<<policy.deposit->slot_fee
     <<",\"base\":"<<policy.operation_tariff->base<<",\"units\":"<<policy.failed->issuance_billing_units
     <<",\"Q\":"<<record.timing.queue_removed_height<<",\"window\":"<<record.timing.settlement_blocks
     <<",\"height\":"<<new_state.seq_no<<",\"phase\":"<<unsigned(record.timing.phase)
     <<",\"withdrawal_id\":"<<quote(record.withdrawal_id.to_hex())<<",\"account_id\":"<<quote(wallet_account(0).to_hex())
     <<",\"src\":"<<quote(std::to_string(src_wc)+":"+src.to_hex())<<",\"system_count\":"<<a.pending.size()
     <<",\"system_limit\":"<<policy.deposit->system_slots<<",\"native_bucket_cost\":"<<bucket_cost<<",\"account_closed\":"
     <<(std::holds_alternative<WorkchainAccountClosed>(old_owner.account.lifecycle)?"true":"false")
     <<"},\"observed\":{\"published\":true,\"dispatch\":["<<quote(route)<<"],\"before\":"
     <<snapshot_json(a,0,order)<<",\"after\":"<<snapshot_json(z,u64(paid.tomis),order)<<bucket_extra
     <<"},\"provenance\":{\"before\":"<<quote(before->get_hash().to_hex())<<",\"after\":"<<quote(after->get_hash().to_hex())
     <<",\"block\":"<<quote(current->get_hash().to_hex())<<",\"inbound\":"<<quote(selector.inbound_message.to_hex())
     <<closed_provenance<<freed_slot<<",\"D\":\"structural atomic-operation zero, not a persisted counter\"}}\n";
  td::write_file(output.string(),out.str()).ensure();
}
} // namespace m3_live
