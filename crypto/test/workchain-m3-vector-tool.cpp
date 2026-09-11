// TEST VECTOR generator/packer. Known test balances and keys, never live chain data.
// No execution or authorization decision: the host independently authenticates
// these fixture roots and reconstructs its own statement before applying effects.
#include "block/workchain-transfer-statement.h"
#include "vm/boc.h"
#include "td/utils/misc.h"
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

namespace fs = std::filesystem;
using Text = std::map<std::string, std::string>;
using namespace block;

Text read_text(const fs::path& path) {
  std::ifstream f(path); CHECK(f.good());
  Text values; std::string line;
  while (std::getline(f,line)) {
    if (line.empty() || line[0]=='#') continue;
    auto pos=line.find('='); CHECK(pos!=std::string::npos);
    CHECK(values.emplace(line.substr(0,pos),line.substr(pos+1)).second);
  }
  return values;
}
void write_text(const fs::path& path,const Text& values) {
  std::ofstream f(path); CHECK(f.good()); f << "# TEST VECTOR ONLY. Not real chain data.\n";
  for (const auto& [key,value]:values) f << key << '=' << value << '\n';
  CHECK(f.good());
}
std::uint64_t integer(const Text& t,const std::string& key) {
  const auto& text=t.at(key); std::uint64_t result;
  auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
  CHECK(parsed.ec==std::errc{} && parsed.ptr==text.data()+text.size()); return result;
}
td::Bits256 word(const std::string& hex) {
  auto bytes=td::hex_decode(hex).move_as_ok(); CHECK(bytes.size()==32);
  td::Bits256 result; result.as_slice().copy_from(bytes); return result;
}
std::vector<td::Bits256> words(const std::string& hex) {
  auto bytes=td::hex_decode(hex).move_as_ok(); CHECK(bytes.size()%32==0);
  td::Slice cursor(bytes); std::vector<td::Bits256> result;
  while (!cursor.empty()) result.push_back(confidential_input_detail::read_word(cursor));
  return result;
}
std::string hex_words(const std::vector<td::Bits256>& values) {
  std::string result; for (const auto& v:values) result+=td::hex_encode(v.as_slice()); return result;
}
std::string hex(const td::Bits256& value) { return td::hex_encode(value.as_slice()); }
td::Bits256 named(const std::string& name) {
  return vm::CellBuilder().store_bytes("M3 TEST VECTOR / "+name).finalize()->get_hash().bits();
}
void write_boc(const fs::path& path,const td::Ref<vm::Cell>& root) {
  auto bytes=vm::std_boc_serialize(root,0).move_as_ok(); std::ofstream f(path,std::ios::binary); CHECK(f.good());
  f.write(bytes.as_slice().data(),static_cast<std::streamsize>(bytes.size())); CHECK(f.good());
}
td::Ref<vm::Cell> read_boc(const fs::path& path) {
  std::ifstream f(path,std::ios::binary); CHECK(f.good());
  std::string bytes((std::istreambuf_iterator<char>(f)),{});
  return vm::std_boc_deserialize(bytes).move_as_ok();
}
WorkchainConfidentialAccount account(const std::string& name,const Text& p) {
  const bool alice=name=="alice";
  return {1,1,2,37,named("genesis"),{2,named(name+" account"),named(name+" incarnation")},
      {named("asset"),named("custody"),named("policy")}, {10000000000ULL,0,named(name+" refund")},
      word(p.at(name+"_p")),alice?2u:3u,{word(p.at(name+"_c")),word(p.at(name+"_d"))},
      alice?7u:9u,alice?12u:15u,{},WorkchainAccountActive{}};
}
WorkchainPendingReceipt receipt(unsigned index,const Text& p,const WorkchainConfidentialAccount& bob) {
  const auto suffix=std::to_string(index);
  auto source=WorkchainConfidentialAddress{2,named("origin "+suffix),named("origin incarnation "+suffix)};
  auto operation=derive_workchain_operation_id({37,named("genesis"),named("workchain instance")},source,1,21+index).move_as_ok();
  auto id=derive_workchain_receipt_id(source.instance,operation,0).move_as_ok();
  return {id,source,21+index,bob.address.instance,bob.key_epoch,bob.bindings.asset,
      {word(p.at("pending_"+suffix+"_c")),word(p.at("pending_"+suffix+"_d"))},operation,0,0};
}
Text environment() {
  Text e{{"test_only","1"},{"global_id","37"},{"workchain_id","2"},{"current_height","1234"},
      {"engine_version","2"},{"relation_version","1"},{"wire_version","1"},{"proof_version","2"},
      {"account_schema","1"},{"relation_profile","1"},{"proof_profile","2"},{"fee_effective_height","1200"},{"max_balance","1000000"},{"max_value","10000"},
      {"max_collect","8"},{"max_context_bytes","1024"},{"max_proof_bytes","4096"},{"pending_capacity","16"}};
  for (const auto& key:{"asset","custody","policy","configuration","generator_profile","range_profile","fee_profile"}) e[key]=hex(named(key));
  e["genesis_hash"]=hex(named("genesis")); e["workchain_instance"]=hex(named("workchain instance"));
  // Explicit fixture configuration; this is not a production domain generator.
  std::string domain="TOS/UNO/M3/TEST-VECTORS/v1"; domain.resize(80,'!'); e["domain"]=td::hex_encode(domain);
  return e;
}
void prepare(const std::string& scenario,const fs::path& dir) {
  auto public_data=read_text(dir/"public.txt"); CHECK(public_data.at("scenario")==scenario);
  auto alice=account("alice",public_data),bob=account("bob",public_data);
  for (unsigned i=0;i<4;++i) bob.pending.push_back(receipt(i,public_data,bob));
  auto alice_cell=encode_workchain_confidential_account(alice).move_as_ok();
  auto bob_cell=encode_workchain_confidential_account(bob).move_as_ok();
  write_boc(dir/"alice.boc",alice_cell); write_boc(dir/"bob.boc",bob_cell);
  vm::Dictionary accounts(256);
  CHECK(accounts.set_ref(alice.address.account,alice_cell,vm::Dictionary::SetMode::Add));
  CHECK(accounts.set_ref(bob.address.account,bob_cell,vm::Dictionary::SetMode::Add));
  auto prestate=vm::CellBuilder().append_cellslice(std::move(accounts).extract_root()).finalize();
  write_boc(dir/"prestate.boc",prestate);
  auto env=environment(); env["prestate_hash"]=hex(prestate->get_hash().bits());
  env["alice_account"]=hex(alice.address.account); env["bob_account"]=hex(bob.address.account);
  env["execution_fee"]=public_data.at("fee"); env["kind"]=scenario=="send"?"1":"2"; write_text(dir/"environment.txt",env);
  const bool send=scenario=="send"; auto& source=send?alice:bob;
  auto original_points=words(public_data.at("points"));
  WorkchainTransferClaims claims{source.address,source.auth_nonce,source.available_revision,source.key_epoch,1300,integer(public_data,"fee")};
  WorkchainTransferData data; std::vector<WorkchainPendingReceipt> selected;
  std::vector<td::Bits256> points,ids; std::string order;
  if (send) {
    data=WorkchainSendData{claims,bob.address,bob.key_epoch,{original_points[4],original_points[5]},
                           {original_points[6],original_points[7],original_points[8]},original_points[9]};
    points=original_points;
  } else {
    const unsigned k=scenario=="collect1"?1:3; CHECK(scenario=="collect1" || scenario=="collect3");
    std::vector<unsigned> indices; for (unsigned i=0;i<k;++i) indices.push_back(i);
    // Wallet/generator selection order, not a codec or host validity rule.
    std::sort(indices.begin(),indices.end(),[&](auto a,auto b){return bob.pending[a].receipt_id<bob.pending[b].receipt_id;});
    std::vector<WorkchainCollectItem> items;
    points.assign(original_points.begin(),original_points.begin()+6);
    for (auto i:indices) {
      const auto& r=bob.pending[i]; auto j=word(public_data.at("pending_"+std::to_string(i)+"_j"));
      items.push_back({r.receipt_id,j}); selected.push_back(r); ids.push_back(r.receipt_id);
      points.insert(points.end(),{r.ciphertext.commitment,r.ciphertext.handle,j});
      if (!order.empty()) order+=','; order+=std::to_string(i);
    }
    data=WorkchainCollectData{claims,{original_points[3],original_points[4]},original_points[5],items};
  }
  const unsigned kind=send?1:2;
  auto operation=derive_workchain_operation_id({37,named("genesis"),named("workchain instance")},source.address,kind,source.auth_nonce).move_as_ok();
  auto semantic=encode_workchain_transfer_data(data).move_as_ok(); write_boc(dir/"semantic.boc",semantic);
  WorkchainTransferOldStatement old{source.public_key,source.available,source.key_epoch,source.auth_nonce,source.available_revision,
                                   bob.public_key,bob.key_epoch,{selected.begin(),selected.end()}};
  auto old_hash=hash_workchain_transfer_old_statement(kind,old).move_as_ok();
  WorkchainTransferContext context{{2,1,1,2,kind,37,2,named("genesis"),named("workchain instance")},
      {source.bindings.asset,source.bindings.custody,source.bindings.policy},
      {named("configuration"),named("generator_profile"),named("range_profile")},
      {operation,semantic->get_hash().bits(),old_hash},named("fee_profile"),1200};
  auto context_bytes=encode_workchain_transfer_context(context).move_as_ok();
  Text request;
  for (const auto& key:{"max_balance","max_value","max_collect","max_context_bytes","max_proof_bytes","domain"}) request[key]=env.at(key);
  request["context"]=td::hex_encode(context_bytes); request["points"]=hex_words(points); request["receipt_ids"]=hex_words(ids);
  request["order"]=order; request["fee"]=public_data.at("fee"); request["operation_id"]=hex(operation);
  request["kind"]=std::to_string(kind); write_text(dir/"request.txt",request);
  write_text(dir/"expected.txt",{{"old_source_balance",public_data.at(send?"alice_old":"bob_old")},
      {"new_source_balance",public_data.at("new_balance")},{"selected_count",std::to_string(ids.size())},
      {"initial_recipient_pending","4"},{"operation_id",hex(operation)}, {"txid",hex(semantic->get_hash().bits())}});
}
void finish(const fs::path& dir,const std::string& name) {
  auto request=read_text(dir/"request.txt"),proof=read_text(dir/"authorization.txt"); CHECK(proof.at("abi_status")=="0");
  auto env=read_text(dir/"environment.txt"); auto prestate=read_boc(dir/"prestate.boc");
  CHECK(td::Bits256(prestate->get_hash().bits())==word(env.at("prestate_hash")));
  vm::Dictionary accounts(vm::load_cell_slice_ref(prestate),256);
  for (const auto& name:{"alice","bob"}) {
    auto state=read_boc(dir/(std::string(name)+".boc"));
    auto entry=accounts.lookup_ref(word(env.at(std::string(name)+"_account")));
    CHECK(entry.not_null() && entry->get_hash()==state->get_hash());
    CHECK(decode_workchain_confidential_account(entry).is_ok());
  }
  auto data=decode_workchain_transfer_data(read_boc(dir/"semantic.boc")).move_as_ok();
  WorkchainTransferInput input{word(request.at("operation_id")),data,
      {words(proof.at("commitments")),words(proof.at("responses")),td::hex_decode(proof.at("range_proof")).move_as_ok()}};
  auto candidate=encode_workchain_transfer_input(input).move_as_ok(); write_boc(dir/(name+".boc"),candidate);
  // Verify the actual persisted candidate's authorization, not the pre-pack file.
  auto decoded=decode_workchain_transfer_input(read_boc(dir/(name+".boc"))).move_as_ok();
  CHECK(encode_workchain_transfer_data(decoded.data).move_as_ok()->get_hash()==encode_workchain_transfer_data(data).move_as_ok()->get_hash());
  CHECK(check_workchain_claimed_operation_id(decoded,word(request.at("operation_id"))).is_ok());
  if (name=="candidate-2") {
    auto first=decode_workchain_transfer_input(read_boc(dir/"candidate-1.boc")).move_as_ok();
    CHECK(decoded.claimed_operation_id==first.claimed_operation_id);
    CHECK(workchain_transfer_txid(decoded.data).move_as_ok()==workchain_transfer_txid(first.data).move_as_ok());
    CHECK(decoded.authorization.commitments!=first.authorization.commitments);
  }
  request["commitments"]=hex_words(decoded.authorization.commitments);
  request["responses"]=hex_words(decoded.authorization.responses);
  request["range_proof"]=td::hex_encode(decoded.authorization.range_proof);
  write_text(dir/(name+".verify.txt"),request);
  std::cout<<name<<": candidate_boc_bytes="<<fs::file_size(dir/(name+".boc"))<<'\n';
}
int main(int argc,char** argv) {
  if (argc!=4) {std::cerr<<"usage: uno-m3-vector-tool prepare SCENARIO DIR | finish DIR NAME\n";return 1;}
  if (std::string(argv[1])=="prepare" && argc==4) prepare(argv[2],argv[3]);
  else if (std::string(argv[1])=="finish" && argc==4) finish(argv[2],argv[3]);
  else return 1;
  return 0;
}
