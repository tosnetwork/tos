#include "manager-finality-journal.h"
#include "tos/quorum.h"

namespace tos::auth {
namespace {
constexpr std::array<std::uint8_t,4> magic{'M','F','H','1'};
void u32(Bytes& out,std::uint32_t v){for(int s=24;s>=0;s-=8)out.push_back(static_cast<std::uint8_t>(v>>s));}
void u64(Bytes& out,std::uint64_t v){for(int s=56;s>=0;s-=8)out.push_back(static_cast<std::uint8_t>(v>>s));}
void hash(Bytes& out,const Hash& h){out.insert(out.end(),h.begin(),h.end());}
void bits(Bytes& out,const td::Bits256& h){auto s=h.as_slice();out.insert(out.end(),s.ubegin(),s.uend());}
struct JournalReader{
 std::span<const std::uint8_t> v;std::size_t at=0;
 bool take(std::uint8_t& x){if(at>=v.size())return false;x=v[at++];return true;}
 bool u32(std::uint32_t& x){if(v.size()-at<4)return false;x=0;for(int i=0;i<4;++i)x=(x<<8)|v[at++];return true;}
 bool u64(std::uint64_t& x){if(v.size()-at<8)return false;x=0;for(int i=0;i<8;++i)x=(x<<8)|v[at++];return true;}
 bool hash(Hash& x){if(v.size()-at<32)return false;std::copy(v.begin()+at,v.begin()+at+32,x.begin());at+=32;return true;}
 bool bits(td::Bits256& x){if(v.size()-at<32)return false;std::copy(v.begin()+at,v.begin()+at+32,reinterpret_cast<std::uint8_t*>(x.data()));at+=32;return true;}
 bool done()const{return at==v.size();}
};
bool receipt_ok(const NativeFinalityVerification& r){
 return r.block.is_masterchain_ext()&&r.block.seqno()>0&&r.kind==NativeSignatureSetKind::final&&
        r.total_weight>0&&r.signed_weight<=r.total_weight&&tos::has_quorum(r.signed_weight,r.total_weight);
}
}
Result<Bytes> encode_manager_finality_journal(
    const ChainContext& chain,const NativeFinalityVerification& receipt){
 if(chain.network==0||chain.genesis_root==Hash{}||chain.genesis_file==Hash{}||chain.chain_domain==Hash{})
  return Error{"manager-finality-journal-chain"};
 if(!receipt_ok(receipt))return Error{"manager-finality-journal-receipt"};
 Bytes out;out.insert(out.end(),magic.begin(),magic.end());
 u32(out,static_cast<std::uint32_t>(chain.network));hash(out,chain.genesis_root);hash(out,chain.genesis_file);hash(out,chain.chain_domain);
 u32(out,static_cast<std::uint32_t>(receipt.block.id.workchain));u64(out,receipt.block.id.shard);u32(out,receipt.block.id.seqno);
 bits(out,receipt.block.root_hash);bits(out,receipt.block.file_hash);
 out.push_back(1);u32(out,receipt.catchain);u32(out,receipt.validator_set_hash);u64(out,receipt.signed_weight);u64(out,receipt.total_weight);
 return out;
}
Result<NativeFinalityVerification> decode_manager_finality_journal(
    std::span<const std::uint8_t> raw,const ChainContext& chain){
 JournalReader r{raw};for(auto expected:magic){std::uint8_t got=0;if(!r.take(got)||got!=expected)return Error{"manager-finality-journal-magic"};}
 std::uint32_t network=0;if(!r.u32(network)||static_cast<std::int32_t>(network)!=chain.network)return Error{"manager-finality-journal-chain"};
 Hash genesis_root{},genesis_file{},domain{};
 if(!r.hash(genesis_root)||!r.hash(genesis_file)||!r.hash(domain)||
    genesis_root!=chain.genesis_root||genesis_file!=chain.genesis_file||domain!=chain.chain_domain)
  return Error{"manager-finality-journal-chain"};
 std::uint32_t wc=0,seq=0,catchain=0,vhash=0;std::uint64_t shard=0,signed_weight=0,total_weight=0;td::Bits256 root,file;std::uint8_t kind=0;
 if(!r.u32(wc)||!r.u64(shard)||!r.u32(seq)||!r.bits(root)||!r.bits(file)||!r.take(kind)||
    !r.u32(catchain)||!r.u32(vhash)||!r.u64(signed_weight)||!r.u64(total_weight)||!r.done())
  return Error{"manager-finality-journal-shape"};
 if(kind!=1)return Error{"manager-finality-journal-kind"};
 NativeFinalityVerification out{
   tos::BlockIdExt{tos::BlockId{static_cast<tos::WorkchainId>(static_cast<std::int32_t>(wc)),shard,seq},root,file},
   NativeSignatureSetKind::final,catchain,vhash,signed_weight,total_weight};
 if(!receipt_ok(out))return Error{"manager-finality-journal-receipt"};
 return out;
}
}  // namespace tos::auth
