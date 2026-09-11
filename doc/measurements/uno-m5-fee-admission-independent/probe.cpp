#include "workchain-m3-node-engine.h"
#include "workchain-proof-test-access.h"
#include "workchain-m3-assertions.h"
#include "td/utils/misc.h"
#include "vm/vm.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iostream>
using namespace block;
namespace fs=std::filesystem;
const fs::path fixture="/tmp/uno-m3-live-grcv32yz";
std::string read(const fs::path& p){std::ifstream in(p);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
auto load(const fs::path& p){return vm::std_boc_deserialize(td::Slice(read(p))).move_as_ok();}
std::map<std::string,std::string> fields(const fs::path& p){std::map<std::string,std::string> out;std::istringstream in(read(p));std::string s;while(std::getline(in,s)){auto n=s.find('=');CHECK(n!=std::string::npos);out[s.substr(0,n)]=s.substr(n+1);}return out;}
void write(const fs::path& p,const std::map<std::string,std::string>& f){std::ofstream out(p);for(auto& [k,v]:f)out<<k<<"="<<v<<"\n";}
std::vector<td::Bits256> words(std::string text){auto bytes=td::hex_decode(text).move_as_ok();CHECK(bytes.size()%32==0);std::vector<td::Bits256> out;for(size_t i=0;i<bytes.size();i+=32){td::Bits256 p;std::memcpy(p.as_slice().data(),bytes.data()+i,32);out.push_back(p);}return out;}
int main(int argc,char** argv){
 CHECK(argc==4);vm::init_vm().ensure();std::string mode=argv[1];fs::path dir=argv[2];bool low=std::string(argv[3])=="low";fs::create_directories(dir);
 auto zero=load(fixture/"zerostate.boc");tos::BlockIdExt zid{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},zero->get_hash().bits(),td::Bits256::zero()};
 auto config=ConfigInfo::extract_config(zero,zid,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();
 auto ingress=load_workchain_native_ingress_table(*config).move_as_ok().at(2);
 auto parameters=decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
 auto business=m3_test::decode_m3_test_business_parameters(parameters.parameters).move_as_ok();CHECK(business.prepare && business.operation_tariff);
 uint64_t floor;CHECK(!__builtin_add_overflow(business.prepare->state_fee,business.operation_tariff->base,&floor));CHECK(floor>0);uint64_t fee=floor;if(low)CHECK(!__builtin_sub_overflow(floor,uint64_t{1},&fee));
 std::cout<<"AUTHENTICATED_FLOOR state="<<business.prepare->state_fee<<" base="<<business.operation_tariff->base<<" units=1 floor="<<floor<<" fee="<<fee<<std::endl;
 if(mode=="init"){auto req=fields(fixture/"operation.request.txt");req["fee"]=std::to_string(fee);write(dir/"request.txt",req);return 0;}
 auto original=m3_test::decode_m5_test_debit(load(fixture/"operation.candidate.boc")).move_as_ok();
 auto points=words(fields(dir/"points.txt").at("points"));CHECK(points.size()==3);
 original.data.amounts.operation_fee=fee;original.data.claims.authorized_fee=fee;original.data.available={points[0],points[1]};original.data.auxiliary=points[2];
 gen::Block::Record block;gen::BlockExtra::Record extra;CHECK(::tlb::unpack_cell(load(fixture/"debit-authenticated-block.boc"),block));CHECK(::tlb::unpack_cell(block.extra,extra));
 vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(extra.account_blocks),256,block::tlb::aug_ShardAccountBlocks);
 auto leaf=blocks.lookup(ingress.executor_address);gen::AccountBlock::Record ab;CHECK(gen::t_AccountBlock.unpack(leaf.write(),ab));
 vm::AugmentedDictionary txs(vm::DictNonEmpty(),ab.transactions,64,block::tlb::aug_AccountTransactions);td::Ref<vm::Cell> host_root;
 CHECK(txs.check_for_each([&](td::Ref<vm::CellSlice> cell,td::ConstBitPtr,int){gen::Transaction::Record tx;CHECK(::tlb::unpack_cell(cell->prefetch_ref(),tx));gen::TransactionDescr::Record_trans_workchain_entry_v3 entry;CHECK(::tlb::unpack_cell(tx.description,entry));CHECK(host_root.is_null());host_root=entry.input;return true;}));CHECK(host_root.not_null());
 gen::UnoV2HostInput::Record host;gen::UnoV2HostIdentity::Record identity;gen::UnoV2HostDomain::Record domain;gen::UnoV2HostPolicy::Record policy;gen::UnoV2HostContext::Record clock;
 CHECK(::tlb::unpack_cell(host_root,host)&&::tlb::unpack_cell(host.identity,identity)&&::tlb::unpack_cell(identity.domain,domain)&&::tlb::unpack_cell(identity.policy,policy)&&::tlb::unpack_cell(identity.context,clock));
 gen::ShardStateUnsplit::Record state;CHECK(::tlb::unpack_cell(load(fixture/"current-state.boc"),state));vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts),256,block::tlb::aug_ShardAccounts);
 std::vector<WorkchainAccountSnapshot> snapshots;WorkchainConfidentialAccount old;
 for(auto key:{original.data.claims.source.account,ingress.executor_address,*ingress.custody_address}){Account a(2,key.bits());CHECK(a.unpack(accounts.lookup(key),clock.gen_utime,false));snapshots.push_back({key,a.total_state});if(key==original.data.claims.source.account)old=decode_workchain_confidential_account(a.data).move_as_ok();}
 std::sort(snapshots.begin(),snapshots.end(),[](auto& a,auto& b){return a.account<b.account;});
 gen::UnoV2TransferProfilesV1::Record profiles{policy.configuration_hash,business.generator_profile,business.range_profile};
 WorkchainTransferEnvironment env{business.limits,business.domain,{2,1,1,2,5,domain.global_id,2,domain.genesis_hash,domain.instance_id},business.rules,profiles,business.fee_profile,business.fee_effective_height,clock.height,fee,16,business.account_schema,business.relation_profile,business.proof_profile};
 auto context=m3_test::m5_debit_context(env,*business.prepare,old,original).move_as_ok();
 if(mode=="context"){auto req=fields(dir/"request.txt");req["context"]=td::hex_encode(context);req["domain"]=td::hex_encode(td::Slice(env.domain.data(),env.domain.size()));req["withdrawal_id"]=td::hex_encode(original.claimed_operation_id.as_slice());req["attempt_id"]=td::hex_encode(original.claimed_attempt_id.as_slice());write(dir/"request.txt",req);return 0;}
 auto proof=fields(dir/"proof.txt");original.authorization={words(proof.at("commitments")),words(proof.at("responses")),td::hex_decode(proof.at("range_proof")).move_as_ok()};
 if(mode=="badproof") original.authorization.responses.front().as_slice()[0] ^= 1;
 auto verifier=WorkchainProofTestAccess::create(100000);auto checked=m3_test::execute_m5_test_debit(env,*business.prepare,old,original,verifier);if(mode=="badproof"){CHECK(checked.is_error());CHECK(checked.error().code()==-7200);CHECK(checked.error().message()=="Withdrawal cryptographic proof rejected");CHECK(verifier.consumed()>0);std::cout<<"REAL_KERNEL_BAD_PROOF_REJECTED\n";return 0;}CHECK(checked.is_ok());CHECK(verifier.consumed()>0);std::cout<<"KERNEL_MATCHING_PROOF_OK fee="<<fee<<" units="<<verifier.consumed()<<std::endl;
 host.candidate=m3_test::wrap_m5_test_debit(encode_workchain_withdrawal_input(original).move_as_ok());auto changed=confidential_state_detail::pack(host).move_as_ok();
 m3_test::M3NodeEngine engine({WorkchainFormat::Basic,0x434e5431},(dir/"engine.calls").string());
 auto descriptor=normalize_workchain_descriptor(*config->get_workchain_list().at(2)).move_as_ok();
 auto resolved=engine.validate_and_resolve_config(descriptor,*config,ingress.engine_configuration).move_as_ok();
 WorkchainAccountReadView view(std::move(snapshots));auto execution_verifier=WorkchainProofTestAccess::create(100000);
 auto result=engine.execute_metered_accounts(changed,view,*resolved,execution_verifier);
 if(low){CHECK(result.is_error());CHECK(result.error().code()==-7200);CHECK(result.error().message()=="Withdrawal public fee below authenticated fee floor");CHECK(execution_verifier.consumed()==0);std::cout<<"FEE_ADMISSION_EXACT_REJECTION -7200, proof prechecked; engine proof units=0\n";}
 else {if(result.is_error())std::cerr<<result.error().message().str()<<std::endl;CHECK(result.is_ok());CHECK(execution_verifier.consumed()>0);CHECK(result.ok().fees);CHECK(result.ok().fees->state_fee->to_long()==business.prepare->state_fee);CHECK(result.ok().fees->compute_fee->to_long()==business.operation_tariff->base);CHECK(result.ok().fees->tip->to_long()==0);std::cout<<"FEE_ADMISSION_EXACT_FLOOR_ACCEPTED effects produced\n";}
}
