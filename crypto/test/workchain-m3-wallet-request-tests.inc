// Include after the existing v2 host confidential-execution Fixture definition.
#include "workchain-m3-wallet-requests.h"
TEST(M3WalletRequests, FormalVectorFields) {
  for (const std::string name:{"send","collect1","collect3"}) {
    Fixture f(name);
    auto original=f.input();
    auto request=read_text(f.path/"request.txt");
    std::vector<td::Bits256> points;
    const auto& text=request.at("points");
    CHECK(text.size()%64==0);
    for (std::size_t i=0;i<text.size();i+=64) points.push_back(word(text.substr(i,64)));
    const auto& claims=workchain_transfer_claims(original.data);
    const auto& owner=name=="send" ? f.alice : f.bob;
    ASSERT_EQ(owner.address.workchain_id,claims.source.workchain_id);
    ASSERT_EQ(owner.address.account,claims.source.account);
    ASSERT_EQ(owner.address.instance,claims.source.instance);
    auto prepared=[&]() -> td::Result<block::m3_test::M3PreparedWalletTransfer> {
      if (name=="send") return block::m3_test::prepare_m3_test_send(f.env,f.alice,f.bob,claims.expiry_height,points);
      std::vector<td::Bits256> selected;
      for (const auto& item:std::get<block::WorkchainCollectData>(original.data).selected) selected.push_back(item.receipt_id);
      return block::m3_test::prepare_m3_test_collect(f.env,owner,claims.expiry_height,selected,points);
    }().move_as_ok();
    ASSERT_EQ(prepared.input.claimed_operation_id,original.claimed_operation_id);
    ASSERT_EQ(prepared.prover_fields.at("points"),request.at("points"));
    ASSERT_EQ(prepared.prover_fields.at("context"),request.at("context"));
    ASSERT_EQ(prepared.prover_fields.at("domain"),request.at("domain"));
    ASSERT_EQ(prepared.prover_fields.at("receipt_ids"),request.at("receipt_ids"));
    auto finished=block::m3_test::finish_m3_test_transfer(prepared,original.authorization).move_as_ok();
    ASSERT_EQ(finished->get_hash(),boc(f.path/"candidate-1.boc")->get_hash());
    ASSERT_EQ(workchain_transfer_claims(prepared.input.data).expiry_height,claims.expiry_height);
    ASSERT_EQ(workchain_transfer_claims(prepared.input.data).available_revision,owner.available_revision);
  }
}
