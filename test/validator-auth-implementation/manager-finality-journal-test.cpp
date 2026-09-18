#include <iostream>
#include <stdexcept>
#include "validator/auth/manager-finality-journal.h"
namespace{namespace a=tos::auth;struct F:std::runtime_error{using std::runtime_error::runtime_error;};void need(bool x,const char*n){if(!x)throw F(n);}
a::Hash h(unsigned x){a::Hash r{};r.fill(static_cast<std::uint8_t>(x));return r;}
a::ChainContext chain(){return {42,h(1),h(2),h(3)};}
a::NativeFinalityVerification receipt(){return {tos::BlockIdExt{tos::BlockId{tos::masterchainId,tos::shardIdAll,9},td::Bits256(td::ConstBitPtr(h(4).data())),td::Bits256(td::ConstBitPtr(h(5).data()))},a::NativeSignatureSetKind::final,7,11,2,3};}
}
int main(){
 try{
  auto c=chain(),v=receipt();auto enc=a::encode_manager_finality_journal(c,v);need(enc.ok(),"roundtrip");
  auto dec=a::decode_manager_finality_journal(enc.value(),c);need(dec.ok()&&dec.value().block==v.block&&dec.value().catchain==7&&dec.value().validator_set_hash==11&&dec.value().signed_weight==2&&dec.value().total_weight==3,"roundtrip");
  auto other=c;other.chain_domain=h(9);need(!a::decode_manager_finality_journal(enc.value(),other).ok(),"chain-binding");
  auto truncated=enc.value();truncated.pop_back();need(!a::decode_manager_finality_journal(truncated,c).ok(),"shape");
  auto weak=v;weak.signed_weight=1;need(!a::encode_manager_finality_journal(c,weak).ok(),"quorum");
  auto approval=v;approval.kind=a::NativeSignatureSetKind::approval;need(!a::encode_manager_finality_journal(c,approval).ok(),"final-only");
  std::cout<<"SUMMARY cases=5 passed=5\n";return 0;
 }catch(const std::exception&e){std::cerr<<"ASSERTION_FAILED "<<e.what()<<'\n';return 1;}
}
