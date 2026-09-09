#include <iostream>
#include <fstream>
#include <sstream>
#include <iterator>
#include <source_location>
#include <stdexcept>
#include "block/workchain-candidate-construction.h"
#include "block/workchain-payout-overlay.h"
#include "block/workchain-outbound-queues.h"
#include "vm/boc.h"
#include "vm/cells/MerkleUpdate.h"
#include "td/utils/logging.h"
#include "block/workchain-native-disposal.h"

namespace {
using Root = td::Ref<vm::Cell>;
using Stage = block::WorkchainConstructionStage;
using Point = block::WorkchainConstructionPoint;
struct Failed { int identity; };
void check(bool ok, int id, std::source_location where=std::source_location::current()) {
  if (!ok) { std::cerr<<"assertion line "<<where.line()<<" identity "<<id<<'\n';throw Failed{id}; }
}
template<class T> T take(td::Result<T> r) {
  if (r.is_error()) { std::cerr << r.error().to_string() << '\n'; throw Failed{10}; }
  return r.move_as_ok();
}
Root number(unsigned n) { return vm::CellBuilder().store_long(n, 64).finalize(); }
td::Bits256 key(unsigned n) { auto k=td::Bits256::zero(); k.bits().store_uint(n,8); return k; }
Root envelope(unsigned n) {
  vm::CellBuilder b;
  b.store_long(6,4).store_long(4,3).store_long(0,8).store_zeroes(255).store_long(1,1)
   .store_long(4,3).store_long(2,8).store_bits(td::Bits256::ones().bits(),256);
  check(block::CurrencyCollection(300).store(b),10);
  auto msg=b.store_long(0,4).store_long(1,4).store_long(67,8).store_long(n,64)
      .store_long(1,32).store_zeroes(2).store_long(n,64).finalize();
  check(block::gen::t_Message_Any.validate_ref(4096,msg),10);
  block::tlb::MsgEnvelope::Record_std env{0x60,0x60,td::make_refint(67),msg,{}, {}};
  Root result; check(tlb::pack_cell(result,env),10); return result;
}
struct NativeFixture {
  Root accounts, input, effects, request;
  std::vector<block::WorkchainStorageWrite> writes;
  block::SerializeConfig cfg;
  block::ActionPhaseConfig prices;
  block::WorkchainSet workchains;
  unsigned offset;
  std::uint64_t after;
  NativeFixture(unsigned offset_ = 0, Root previous = {}) : offset(offset_), after(offset_ ? 5 : 20) {
    vm::AugmentedDictionary dictionary(256,block::tlb::aug_ShardAccounts);
    block::WorkchainAccountDeclarations access;
    block::WorkchainAccountEffects changes;
    for (unsigned n : {16u,32u,64u,144u,160u,192u}) {
      vm::CellBuilder b;
      b.store_long(1,1).store_long(4,3).store_long(2,8).store_bits(key(n).bits(),256)
          .store_zeroes(42).store_long(2,64);
      check(block::CurrencyCollection(1000).store(b),10);
      auto state=take(block::encode_workchain_executor_state({number(40),{}, {}}));
      auto account=b.store_long(1,1).store_zeroes(3).store_long(1,1).store_ref(state).store_long(0,1).finalize();
      check(block::gen::t_Account.validate_ref(4096,account),10);
      vm::CellBuilder entry; entry.store_ref(account).store_zeroes(256).store_long(1,64);
      check(dictionary.set_builder(key(n),entry),10);
      if ((n >= 128) != (offset != 0)) continue;
      auto hash=td::Bits256(account->get_hash().bits());
      access.reads.push_back({key(n),hash}); access.writes.push_back(key(n));
      writes.push_back({key(n),hash,number(n)}); changes.updates.push_back({key(n),number(n)});
    }
    accounts=previous.not_null() ? previous : dictionary.get_wrapped_dict_root();
    if (previous.not_null()) {
      vm::AugmentedDictionary actual(vm::load_cell_slice_ref(accounts),256,block::tlb::aug_ShardAccounts);
      for (std::size_t i=0;i<writes.size();++i) {
        auto entry=actual.lookup(writes[i].account); check(entry.not_null(),10);
        auto hash=td::Bits256(entry->prefetch_ref()->get_hash().bits());
        writes[i].old_account_hash=hash; access.reads[i].old_account_hash=hash;
      }
    }
    vm::CellBuilder payout;
    payout.store_long(6,4).store_zeroes(2).store_long(4,3).store_long(-1,8).store_zeroes(256);
    check(block::CurrencyCollection(137).store(payout),10);
    check(block::tlb::t_Tomis.store_integer_ref(payout,td::make_refint(3)),10);
    request=payout.store_zeroes(4).store_zeroes(96).store_zeroes(2).store_bits(key(16+offset).bits(),256).finalize();
    changes.payout_request=request;
    effects=take(block::encode_workchain_account_effects(changes,3,2,4096));
    auto candidate=number(11); auto hash=td::Bits256(candidate->get_hash().bits());
    block::InputPolicyIdentity pid{candidate->get_hash(),false,17,9,2,1};
    auto policy=block::ResolvedInputPolicy::from_resolved_fields({10,1024,1},pid);
    check(std::holds_alternative<block::ResolvedInputPolicy>(policy),10);
    block::CandidateAdmissionSession session(candidate,std::get<block::ResolvedInputPolicy>(policy));
    auto& admission=session.evaluate(); check(std::holds_alternative<block::AdmittedInput>(admission),10);
    block::WorkchainHostIdentity identity{-1,hash,hash,2,tos::shardIdAll,hash,false,17,9,2,1,hash,1,10,after,number(1)};
    input=take(block::encode_workchain_host_input(identity,std::get<block::AdmittedInput>(admission),access,
                                                {envelope(offset ? 1 : 4),envelope(offset ? 2 : 5)},3,3,2));
    cfg.global_version=16; cfg.disable_anycast=true;
    td::Ref<block::WorkchainInfo> wc{true};
    wc.write().workchain=0; wc.write().basic=wc.write().active=wc.write().accept_msgs=true;
    wc.write().min_addr_len=wc.write().max_addr_len=256; wc.write().addr_len_step=0; workchains.emplace(0,wc);
    prices.global_version=16; prices.bounce_msg_body=256;
    prices.fwd_std=block::MsgPrices(200,0,0,0,16384,0); prices.fwd_mc=block::MsgPrices(100,0,0,0,16384,0);
    prices.workchains=&workchains;
    prices.disable_custom_fess=prices.disable_anycast=prices.extra_currency_v2=true;
    prices.action_fine_enabled=prices.bounce_on_fail_enabled=prices.message_skip_enabled=true;
  }
  td::Result<block::WorkchainPayoutOverlay> build(const block::WorkchainConstructionObserver& observer) {
    block::NativeDisposalProfile profile{block::NativeDisposalSource::OriginalDestination,
        {0,-block::ComputePhase::sk_no_state,{}},false};
    block::WorkchainDisposalEntryContext context{key(32+offset),prices,workchains,profile,2,3};
    return block::build_workchain_payout_overlay(accounts,2,10,after,td::Bits256(input->get_hash().bits()),
        td::Bits256(effects->get_hash().bits()),writes,key(32+offset),key(16+offset),request,td::make_refint(100),
        3,3,2,4096,cfg,prices,input,effects,2,&context,observer);
  }
};
Root empty(int bits,const vm::dict::AugmentationData& aug) {
  return vm::AugmentedDictionary(bits,aug).get_wrapped_dict_root();
}
block::WorkchainOutboundQueueRoots empty_queues() {
  return {empty(256,block::tlb::aug_OutMsgDescrDefault),empty(352,block::tlb::aug_OutMsgQueue),
          empty(256,block::tlb::aug_DispatchQueue)};
}
td::Result<block::WorkchainOutboundQueueResult> enqueue(const block::WorkchainOutboundQueueRoots& old,
    const std::vector<block::NewOutMsg>& outputs,const block::WorkchainConstructionObserver& observer) {
  std::vector<block::WorkchainQueuedOutput> supplied;
  for (const auto& output:outputs) {
    block::gen::CommonMsgInfo::Record_int_msg_info info; block::gen::MsgAddressInt::Record_addr_std source;
    check(tlb::unpack_cell_inexact(output.msg,info)&&tlb::csr_unpack(info.src,source),10);
    supplied.push_back({output,source.address==td::Bits256::ones()});
  }
  return block::build_workchain_outbound_queues(old,supplied,{td::Bits256::ones()},
      {{2,tos::shardIdAll},10,16,false,true,3},observer);
}
block::CurrencyCollection balance(Root accounts) {
  vm::AugmentedDictionary d(vm::load_cell_slice_ref(accounts),256,block::tlb::aug_ShardAccounts);
  auto extra=d.get_root_extra(); check(extra.write().fetch_ulong(5)==0,10);
  block::CurrencyCollection value; check(value.unpack(extra),10); return value;
}
Root shard(Root accounts,const block::WorkchainOutboundQueueRoots& queues,std::uint64_t lt, const block::CurrencyCollection& fees=block::CurrencyCollection(0)) {
  vm::CellBuilder q;
  q.append_cellslice(vm::load_cell_slice(queues.outgoing)).store_long(0,1)
   .store_long(1,1).store_long(0,4).append_cellslice(vm::load_cell_slice(queues.dispatch)).store_long(0,1);
  auto queue=q.finalize(); check(block::gen::t_OutMsgQueueInfo.validate_ref(100000,queue),10);
  vm::CellBuilder aux; aux.store_zeroes(128);check(balance(accounts).store(aux),10);
  check(fees.store(aux),10);
  auto tail=aux.store_zeroes(2).finalize();
  auto result=vm::CellBuilder().store_long(0x9023afe2,32).store_long(1,32).store_zeroes(8).store_long(2,32)
     .store_zeroes(64).store_long(1,32).store_zeroes(32).store_long(10,32).store_long(lt,64).store_zeroes(32)
     .store_ref(queue).store_long(0,1).store_ref(accounts).store_ref(tail).store_long(0,1).finalize();
  check(block::gen::t_ShardStateUnsplit.validate_ref(100000,result),10);return result;
}
using Contents=block::WorkchainCandidateContents;
using Field=block::WorkchainCandidateField;
Root& root(Contents& c,Field f) {return c.roots[static_cast<std::size_t>(f)];}
Root root(const Contents& c,Field f) {return c.roots[static_cast<std::size_t>(f)];}
Root flow(Root before,Root after,Root blocks,Root out,const block::CurrencyCollection& imported, const block::CurrencyCollection& import_fees=block::CurrencyCollection(0)) {
  block::ValueFlow f{block::ValueFlow::SetZero{}};
  f.from_prev_blk=balance(before); f.to_next_blk=balance(after);f.imported=imported;
  vm::AugmentedDictionary tx(vm::load_cell_slice_ref(blocks),256,block::tlb::aug_ShardAccountBlocks);
  vm::AugmentedDictionary msgs(vm::load_cell_slice_ref(out),256,block::tlb::aug_OutMsgDescrDefault);
  check(f.fees_collected.unpack(tx.get_root_extra())&&f.exported.unpack(msgs.get_root_extra()),10);
  block::CurrencyCollection total_fees;
  check(block::CurrencyCollection::add(f.fees_collected,import_fees,total_fees),10);
  f.fees_collected=std::move(total_fees);
  check(f.validate(),10);vm::CellBuilder b;check(f.store(b),10);return b.finalize();
}
Root metadata(std::uint64_t lt,std::uint64_t queued,std::uint64_t deferred,Root input,Root effects) {
  // Explicit private-fixture processing inputs, not the full collator metadata
  // schema and not a newly assigned consensus wire format.
  return vm::CellBuilder().store_long(lt,64).store_long(queued,64).store_long(deferred,64)
      .store_ref(input).store_ref(effects).finalize();
}
struct Prepared {
  NativeFixture seed{128};
  block::WorkchainPayoutOverlay prior=take(seed.build({}));
  block::WorkchainOutboundQueueResult previous=take(enqueue(empty_queues(),prior.exports,{}));
  NativeFixture batch{0,prior.state.accounts};
  Contents before{0,7};
  Prepared() {
    root(before,Field::Accounts)=prior.state.accounts;
    root(before,Field::AccountBlocks)=empty(256,block::tlb::aug_ShardAccountBlocks);
    root(before,Field::InMsgDescr)=empty(256,block::tlb::aug_InMsgDescrDefault);
    root(before,Field::OutMsgDescr)=empty(256,block::tlb::aug_OutMsgDescrDefault);
    root(before,Field::OutQueue)=previous.roots.outgoing;
    root(before,Field::DispatchQueue)=previous.roots.dispatch;
    root(before,Field::ShardState)=shard(prior.state.accounts,previous.roots,prior.state.end_lt);
    root(before,Field::ShardUpdate)=vm::CellBuilder::create_merkle_update(
        root(before,Field::ShardState),root(before,Field::ShardState));
    root(before,Field::ValueFlow)=flow(prior.state.accounts,prior.state.accounts,
        root(before,Field::AccountBlocks),root(before,Field::OutMsgDescr),block::CurrencyCollection(0));
    root(before,Field::ProcessingMetadata)=metadata(20,previous.queued,previous.deferred,seed.input,seed.effects);
    before.batch_identity=seed.input;
    before.pending_messages=std::make_shared<const block::WorkchainCandidateMessages>(prior.exports);
    before.committed_batch_count=0;before.revision=7;
  }
  td::Status build(const Contents& old,Contents& draft,const block::WorkchainConstructionObserver& probe) {
    TRY_RESULT(settled,batch.build(probe));
    root(draft,Field::Accounts)=settled.state.accounts;
    root(draft,Field::AccountBlocks)=settled.state.account_blocks;
    root(draft,Field::InMsgDescr)=settled.imports.in_msg_descr;
    TRY_RESULT(queued,enqueue({root(old,Field::OutMsgDescr),root(old,Field::OutQueue),root(old,Field::DispatchQueue)},
                        settled.exports,probe));
    root(draft,Field::OutMsgDescr)=queued.roots.descriptors;
    root(draft,Field::OutQueue)=queued.roots.outgoing;root(draft,Field::DispatchQueue)=queued.roots.dispatch;
    auto pending=old.pending_messages->items();pending.insert(pending.end(),settled.exports.begin(),settled.exports.end());
    draft.pending_messages=std::make_shared<const block::WorkchainCandidateMessages>(pending);
    root(draft,Field::ValueFlow)=flow(root(old,Field::Accounts),settled.state.accounts,settled.state.account_blocks,
        queued.roots.descriptors,settled.imports.value_imported,settled.imports.fees_collected);
    TRY_STATUS(probe({Stage::ValueFlowFreeze,0}));
    block::WorkchainAccountDictionary original(root(old,Field::Accounts)),next(settled.state.accounts);
    TRY_RESULT(changed,original.changed_accounts(next,3));
    check(changed==std::vector<td::Bits256>({key(16),key(32),key(64)}),10);
    TRY_STATUS(probe({Stage::CoverageFreeze,0}));
    block::ValueFlow frozen_flow; check(frozen_flow.unpack(vm::load_cell_slice_ref(root(draft,Field::ValueFlow))),10);
    root(draft,Field::ShardState)=shard(settled.state.accounts,queued.roots,settled.state.end_lt,frozen_flow.fees_collected);
    root(draft,Field::ShardUpdate)=vm::CellBuilder::create_merkle_update(root(old,Field::ShardState),root(draft,Field::ShardState));
    check(take(vm::MerkleUpdate::apply(root(old,Field::ShardState),root(draft,Field::ShardUpdate)))->get_hash()==
          root(draft,Field::ShardState)->get_hash(),10);
    TRY_STATUS(probe({Stage::ShardUpdateBuild,0}));
    root(draft,Field::ProcessingMetadata)=metadata(settled.state.end_lt,queued.queued,queued.deferred,batch.input,batch.effects);
    draft.batch_identity=batch.input;draft.committed_batch_count=1;draft.revision=8;
    // A concrete fixture output-size check, not a D31 admission certificate.
    for(const auto& r:draft.roots) check(take(vm::std_boc_serialize(r)).size()<=1048576,10);
    TRY_STATUS(probe({Stage::FinalBudgetCheck,0}));
    return td::Status::OK();
  }
};
std::string bytes(Root cell) {
  if(cell.is_null()) return "null";
  return take(vm::std_boc_serialize(cell)).as_slice().str();
}
void append(std::string& out,const std::string& field) {
  out+=std::to_string(field.size())+":"+field;
}
std::string state_bytes(const Contents& state) {
  std::string out=std::to_string(state.revision)+":"+std::to_string(state.committed_batch_count)+":";
  append(out,bytes(state.batch_identity));
  for(const auto& r:state.roots) append(out,bytes(r));
  return out;
}
std::string message_bytes(const std::vector<block::NewOutMsg>& messages) {
  std::string out=std::to_string(messages.size())+":";
  for(const auto& msg:messages) {
    append(out,std::to_string(msg.lt));append(out,std::to_string(msg.msg_idx));
    append(out,bytes(msg.msg));append(out,bytes(msg.trans));append(out,bytes(msg.msg_env_from_dispatch_queue));
    if(msg.metadata) {vm::CellBuilder b;check(msg.metadata.value().pack(b),10);append(out,bytes(b.finalize()));}
    else append(out,"no metadata");
  }
  return out;
}
// This same-block reader obtains the actual installed context, not the draft,
// an expected-result object, or a test-maintained visible-state model.
std::string same_block_messages(const block::WorkchainCandidateConstruction& candidate) {
  auto generation=candidate.snapshot();
  return message_bytes(generation->pending_messages->items());
}
std::vector<Point> schedule() {
  std::vector<Point> points;
  for(std::size_t i=0;i<3;++i) for(auto s:{Stage::ParticipantFinalize,Stage::AccountBlockStage,Stage::AccountRootStage})
    points.push_back({s,i});
  for(std::size_t i=0;i<2;++i) points.push_back({Stage::InboundStage,i});
  for(std::size_t i=0;i<3;++i) for(auto s:{Stage::OutboundDescriptorStage,Stage::OutboundQueueStage}) points.push_back({s,i});
  for(auto s:{Stage::ValueFlowFreeze,Stage::CoverageFreeze,Stage::ShardUpdateBuild,Stage::FinalBudgetCheck,
              Stage::GenerationCheck,Stage::BeforeCandidateInstall}) points.push_back({s,0});
  return points;
}
std::string read(const std::string& path) {
  std::ifstream f(path,std::ios::binary);check(bool(f),92);
  std::string result{std::istreambuf_iterator<char>(f),{}};check(!f.bad()&&!result.empty(),92);return result;
}
void write(const std::string& path,const std::string& data) {
  std::ofstream f(path,std::ios::binary);check(bool(f),92);f.write(data.data(),data.size());check(bool(f),92);
}
void execute(unsigned which,const std::string& dir,bool freeze) {
  Prepared fixture;
  block::WorkchainCandidateConstruction candidate(fixture.before);
  const auto predecessor=candidate.snapshot();
  const auto before_state=state_bytes(*predecessor);
  const auto before_messages=same_block_messages(candidate);
  check(predecessor->pending_messages->items().size()==3,10);
  const auto expected_schedule=schedule();
  check(expected_schedule.size()==23,10);
  if(freeze) {
    write(dir+"/before.state",before_state);write(dir+"/before.messages",before_messages);
  }
  const auto oracle_before_state=read(dir+"/before.state");
  const auto oracle_before_messages=read(dir+"/before.messages");
  check(before_state==oracle_before_state&&before_messages==oracle_before_messages,90);
  std::vector<Point> visited;
  bool state_seen=false,messages_seen=false,snapshot_seen=false;
  unsigned exception_identity=0;
  std::size_t state_reads=0,message_reads=0;
  auto observe_state=[&]{++state_reads;return state_bytes(*candidate.snapshot());};
  auto observe_messages=[&]{++message_reads;return same_block_messages(candidate);};
  const int injected=-71000-static_cast<int>(which);
  auto observer=[&](Point point) -> td::Status {
    visited.push_back(point);
    snapshot_seen |= candidate.snapshot()!=predecessor;
    state_seen |= observe_state()!=oracle_before_state;
    messages_seen |= observe_messages()!=oracle_before_messages;
    if(which>=1&&which<=23&&point==expected_schedule[which-1]) return td::Status::Error(injected,"construction test fault");
    return td::Status::OK();
  };
  td::Status status;
  if(which<=23) {
    status=candidate.construct(predecessor,[&](const Contents& old,Contents& draft,const auto& probe){
      return fixture.build(old,draft,probe);
    },observer);
  } else if(which==24) {
    bool threw=false;
    try {
      status=candidate.construct(predecessor,[&](const Contents& old,Contents& draft,const auto& probe)->td::Status {
        TRY_STATUS(fixture.build(old,draft,probe));throw Failed{124};
      },observer);
    } catch(Failed f) {check(f.identity==124,93);threw=true;exception_identity=f.identity;}
    check(threw,93);
  } else if(which==25) {
    status=candidate.construct(predecessor,[&](const Contents&,Contents& draft,const auto& probe) {
      draft.revision=8;
      auto ignored=probe({Stage::ValueFlowFreeze,0});(void)ignored;
      return td::Status::OK();
    },[&](Point p){return p.stage==Stage::ValueFlowFreeze ? td::Status::Error(injected,"sticky test fault"):td::Status::OK();});
    check(status.is_error()&&status.code()==injected,94);
  } else if(which==26) {
    const auto stale=std::make_shared<const Contents>(*predecessor);
    status=candidate.construct(stale,[](const Contents&,Contents&,const auto&){return td::Status::OK();});
    check(status.is_error(),95);
  } else if(which==27) {
    bool rejected=false;
    status=candidate.construct(predecessor,[&](const Contents&,Contents&,const auto&) {
      auto inner=candidate.construct(predecessor,[](const Contents&,Contents&,const auto&){return td::Status::OK();});
      rejected=inner.is_error();return td::Status::Error(injected,"outer test fault");
    });check(rejected,96);
  } else if(which==28) {
    status=candidate.construct(predecessor,[](const Contents&,Contents& draft,const auto&){
      draft.committed_batch_count=19;return td::Status::OK();
    });
    check(status.is_ok()&&candidate.snapshot()->committed_batch_count==19,97);
    // Carrying a deliberately false submitted count is not I13a validation.
    std::cout<<"{\"case\":28,\"supplied_count\":19,\"stored_count\":19}\n";return;
  } else if(which==29) {
    auto external=fixture.prior.exports;
    const block::WorkchainCandidateMessages frozen(external);
    const auto original=message_bytes(frozen.items());
    external[0].msg=number(999);
    check(message_bytes(frozen.items())==original,98);
    std::cout<<"{\"case\":29,\"provider_alias_isolated\":true}\n";return;
  } else if(which>=30&&which<=32) {
    status=candidate.construct(predecessor,[&](const Contents&,Contents& draft,const auto&){
      if(which==30) root(draft,Field::Accounts).clear();
      if(which==31) draft.pending_messages.reset();
      if(which==32) draft.batch_identity.clear();
      return td::Status::OK();
    });check(status.is_error(),which==30?99:103);
  } else if(which==33) {
    status=candidate.construct(predecessor,[&](const Contents&,Contents&,const auto&){
      return td::Status::Error(injected,"ordinary builder failure without observer failure");
    });check(status.is_error()&&status.code()==injected,71);
  } else {throw Failed{10};}
  const auto actual_state=state_bytes(*candidate.snapshot());
  const auto actual_messages=same_block_messages(candidate);
  // Sticky observations precede final-state checks: rollback cannot erase them.
  std::cout<<"{\"case\":"<<which<<",\"visited\":"<<visited.size()
      <<",\"intermediate_state\":"<<state_seen<<",\"intermediate_messages\":"<<messages_seen
      <<",\"final_state_changed\":"<<(actual_state!=oracle_before_state)
      <<",\"final_messages_changed\":"<<(actual_messages!=oracle_before_messages)
      <<",\"intermediate_snapshot_identity\":"<<snapshot_seen
      <<",\"final_snapshot_identity_changed\":"<<(candidate.snapshot()!=predecessor)
      <<",\"status_returned\":"<<(exception_identity==0)<<",\"status_code\":"<<status.code()
      <<",\"exception_identity\":"<<exception_identity<<",\"points\":[";
  constexpr const char* stage_names[]={"ParticipantFinalize","AccountBlockStage","AccountRootStage","InboundStage",
      "OutboundDescriptorStage","OutboundQueueStage","ValueFlowFreeze","CoverageFreeze","ShardUpdateBuild",
      "FinalBudgetCheck","GenerationCheck","BeforeCandidateInstall"};
  for(std::size_t i=0;i<visited.size();++i) {
    const auto index=static_cast<unsigned>(visited[i].stage);check(index<std::size(stage_names),10);
    if(i) std::cout<<',';
    std::cout<<"[\""<<stage_names[index]<<"\","<<visited[i].occurrence<<']';
  }
  std::cout<<"]}\n";
  if(which<=24) {check(state_reads==visited.size(),75);check(message_reads==visited.size(),74);}
  check(!(state_seen&&messages_seen),82);check(!state_seen,80);check(!messages_seen,81);check(!snapshot_seen,102);
  if(which==0) {
    check(status.is_ok(),70);check(visited==expected_schedule,76);
    if(freeze) {write(dir+"/after.state",actual_state);write(dir+"/after.messages",actual_messages);}
    check(actual_state==read(dir+"/after.state")&&actual_state!=oracle_before_state,86);
    check(actual_messages==read(dir+"/after.messages")&&actual_messages!=oracle_before_messages,87);
    check(candidate.snapshot()->pending_messages->items().size()==6,88);
  } else {
    check(actual_state==oracle_before_state&&actual_messages==oracle_before_messages,83);
    if(which<=23) {
      check(status.is_error()&&status.code()==injected,71);
      check(visited==std::vector<Point>(expected_schedule.begin(),expected_schedule.begin()+which),76);
    }
    check(candidate.snapshot()==predecessor,101);
    // Poll the same downstream surface after private temporaries are destroyed.
    check(same_block_messages(candidate)==oracle_before_messages&&state_bytes(*candidate.snapshot())==oracle_before_state,89);
  }
  if(which==24) {
    auto retry=candidate.construct(predecessor,[&](const Contents&,Contents&,const auto&){
      return td::Status::Error(injected,"post-exception construction probe");
    });check(retry.is_error()&&retry.code()==injected,100);
  }
  check(state_bytes(*predecessor)==oracle_before_state&&message_bytes(predecessor->pending_messages->items())==oracle_before_messages,91);
}
}
int main(int argc,char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_FATAL);
  try {
    check(argc==3,10);
    const bool freeze=std::string(argv[1])=="freeze";
    const unsigned which=freeze?0:static_cast<unsigned>(std::stoul(argv[1]));
    execute(which,argv[2],freeze);return 0;
  } catch(Failed f) {std::cerr<<"failure "<<f.identity<<'\n';return f.identity;}
}
