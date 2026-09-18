#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "auto/tl/tos_api.hpp"
#include "crypto/Ed25519.h"
#include "keys/keys.hpp"
#include "validator/auth/manager-finality-receipt.h"

namespace {
namespace auth = tos::auth;

td::Bits256 bits(unsigned char value) {
  td::Bits256 out;
  out.as_slice().fill(static_cast<char>(value));
  return out;
}
struct Failure : std::runtime_error { using std::runtime_error::runtime_error; };
void need(bool value,const char* name){if(!value)throw Failure(name);}

struct Fixture {
  std::vector<td::Ed25519::PrivateKey> secrets;
  td::Ref<block::ValidatorSet> current;
  td::Ref<block::ValidatorSet> wrong_next;
  tos::BlockIdExt block{{tos::masterchainId,tos::shardIdAll,7},bits(0x31),bits(0x32)};
  td::uint32 cc=11;

  Fixture() {
    std::vector<tos::ValidatorDescr> nodes;
    for(int i=0;i<3;++i){
      secrets.emplace_back(td::SecureString(std::string(32,static_cast<char>(i+1))));
      auto pk=secrets.back().get_public_key().move_as_ok();
      tos::PublicKey key{tos::pubkeys::Ed25519{std::move(pk)}};
      nodes.emplace_back(tos::Ed25519_PublicKey{key.ed25519_value().raw()},1);
    }
    current=td::make_ref<block::ValidatorSet>(cc,tos::ShardIdFull{tos::masterchainId},nodes);
    std::vector<tos::ValidatorDescr> other=nodes;
    other[0].weight=2;
    wrong_next=td::make_ref<block::ValidatorSet>(cc+1,tos::ShardIdFull{tos::masterchainId},std::move(other));
  }
  td::Ref<block::BlockSignatureSet> final_set(td::uint32 cc_override=0,td::uint32 hash_override=0,bool corrupt=false) const {
    auto data=tos::create_serialize_tl_object<tos::tos_api::tos_blockId>(block.root_hash,block.file_hash);
    std::vector<tos::BlockSignature> rows;
    auto exported=current->export_vector();
    for(int i=0;i<2;++i){
      auto sig=td::BufferSlice(secrets[i].sign(data).move_as_ok());
      if(corrupt && i==1)sig.as_slice()[0]^=1;
      tos::PublicKey key{tos::pubkeys::Ed25519{exported[i].key}};
      rows.emplace_back(key.compute_short_id().bits256_value(),std::move(sig));
    }
    return block::BlockSignatureSet::create_ordinary(
        std::move(rows),cc_override?cc_override:current->get_catchain_seqno(),
        hash_override?hash_override:current->get_validator_set_hash());
  }
};

using Case=std::pair<std::string,std::function<void()>>;
std::vector<Case> cases(){
 std::vector<Case> out;auto add=[&](std::string n,std::function<void()> f){out.emplace_back(std::move(n),std::move(f));};
 add("exact_final_receipt",[]{
   Fixture f;auto r=auth::verify_manager_finality_receipt(f.block,f.final_set(),{},f.current);
   need(r.ok()&&r.value().block==f.block&&r.value().kind==auth::NativeSignatureSetKind::final&&
        r.value().catchain==f.current->get_catchain_seqno()&&
        r.value().validator_set_hash==f.current->get_validator_set_hash()&&
        r.value().signed_weight==2&&r.value().total_weight==3,"exact_final_receipt");
 });
 add("current_set_is_the_explicit_fallback",[]{
   Fixture f;auto r=auth::verify_manager_finality_receipt(f.block,f.final_set(),f.wrong_next,f.current);
   need(r.ok()&&r.value().catchain==f.current->get_catchain_seqno()&&
        r.value().validator_set_hash==f.current->get_validator_set_hash(),"current_set_is_the_explicit_fallback");
 });
 add("metadata_mismatch_is_not_a_receipt",[]{
   Fixture f;auto wrong_cc=f.final_set(f.cc+9);auto a=auth::verify_manager_finality_receipt(f.block,wrong_cc,{},f.current);
   auto wrong_hash=f.final_set(0,f.current->get_validator_set_hash()^1);auto b=auth::verify_manager_finality_receipt(f.block,wrong_hash,{},f.current);
   need(!a.ok()&&!b.ok()&&a.error().code=="manager-finality-signatures"&&b.error().code=="manager-finality-signatures",
        "metadata_mismatch_is_not_a_receipt");
 });
 add("invalid_signature_is_not_a_receipt",[]{
   Fixture f;auto r=auth::verify_manager_finality_receipt(f.block,f.final_set(0,0,true),{},f.current);
   need(!r.ok()&&r.error().code=="manager-finality-signatures","invalid_signature_is_not_a_receipt");
 });
 return out;
}
}
int main(int argc,char**argv){
 auto all=cases(); if(argc==2&&std::string_view(argv[1])=="--list"){for(auto&x:all)std::cout<<x.first<<'\n';return 0;}
 std::string sel,exc;if(argc==2){std::string a=argv[1];if(a.starts_with("--exclude="))exc=a.substr(10);else sel=a;}
 size_t ran=0;for(auto&[n,fn]:all){if(!sel.empty()&&sel!=n)continue;if(!exc.empty()&&exc==n)continue;std::cout<<"SETUP_OK "<<n<<'\n';try{fn();}catch(const Failure&e){std::cerr<<"ASSERTION_FAILED "<<e.what()<<'\n';return 1;}catch(const std::exception&e){std::cerr<<"UNEXPECTED_EXCEPTION "<<n<<": "<<e.what()<<'\n';return 2;}std::cout<<"CASE_PASS "<<n<<'\n';++ran;}if(!ran)return 2;std::cout<<"SUMMARY cases="<<ran<<" passed="<<ran<<'\n';return 0;
}
