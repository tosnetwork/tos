#include "workchain-m3-node-engine.h"
#include "vm/vm.h"
#include <fstream>
#include <iostream>
using namespace block;
td::Ref<vm::Cell> load(const std::string& path){std::ifstream f(path,std::ios::binary);CHECK(f.good());std::string s{std::istreambuf_iterator<char>(f),{}};return vm::std_boc_deserialize(td::Slice(s)).move_as_ok();}
int main(int argc,char** argv){
 CHECK(argc==2);vm::init_vm().ensure();auto root=load("/tmp/uno-m3-live-ec7zmf8s/zerostate.boc");
 tos::BlockIdExt zero{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},root->get_hash().bits(),td::Bits256::zero()};
 auto config=ConfigInfo::extract_config(root,zero,Config::needWorkchainInfo|Config::needCapabilities).move_as_ok();
 WorkchainExecutionRegistry registry;registry.register_account_engine(std::make_unique<m3_test::M3NodeEngine>(WorkchainEngineKey{WorkchainFormat::Basic,0x434e5431},"/tmp/b-d76-independent/reserve.calls")).ensure();
 auto resolved=registry.resolve_scoped_workchain(2,*config).move_as_ok();CHECK(resolved&&std::holds_alternative<ResolvedWorkchainAccountBinding>(*resolved));auto& binding=std::get<ResolvedWorkchainAccountBinding>(*resolved);
 auto params=decode_workchain_engine_parameters(binding.ingress.engine_configuration).move_as_ok();auto business=m3_test::decode_m3_test_business_parameters(params.parameters).move_as_ok();CHECK(business.prepare&&business.prepare->max_bounce_cost);CHECK(*business.prepare->max_bounce_cost==23);
 auto original=load("/tmp/uno-m3-live-ec7zmf8s/operation.candidate.boc");auto input=m3_test::decode_m5_test_debit(original).move_as_ok();CHECK(input.data.amounts.return_reserve==23);
 auto call=[&](const td::Ref<vm::Cell>& value){return binding.executor->proof_work(value,binding.input_policy.identity(),*binding.engine_config);};
 CHECK(call(original).is_ok());std::cout<<"B_REGISTERED_POSITIVE b=23 OK (pre-proof hook)"<<std::endl;
 auto value=std::stoull(argv[1]);CHECK(value==22||value==24);input.data.amounts.return_reserve=value;
 auto changed=m3_test::wrap_m5_test_debit(encode_workchain_withdrawal_input(input).move_as_ok());auto result=call(changed);
 if(result.is_error())std::cout<<result.error().code()<<" "<<result.error().message().str()<<std::endl;
 CHECK(result.is_error());CHECK(result.error().code()==-7200);CHECK(result.error().message()=="Withdrawal reserve differs from authenticated max_bounce_cost");
 std::cout<<"B_REGISTERED_RESERVE b="<<value<<" -7200 at authenticated reserve equality"<<std::endl;
}
