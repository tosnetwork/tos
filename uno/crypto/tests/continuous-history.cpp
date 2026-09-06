#include "uno/core/private-transfer-state.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include <fstream>
#include <iostream>

using namespace uno_workchain;
namespace {
CryptoBundle load_history(unsigned round) {
  std::ifstream input(std::string(UNO_HISTORY_DIRECTORY) + "/history-" + std::to_string(round) + ".bin",
                      std::ios::binary | std::ios::ate);
  ASSERT_TRUE(input.good());
  ASSERT_EQ(input.tellg(),std::streampos(9145));
  input.seekg(0);
  auto read = [&](auto& bytes) {
    input.read(reinterpret_cast<char*>(std::data(bytes)),std::size(bytes));
    ASSERT_TRUE(input.good());
  };
  std::array<char,8> magic{};
  read(magic);
  ASSERT_TRUE((magic == std::array<char,8>{'U','N','O','A','B','I','T','0'}));
  CryptoBundle bundle;
  std::array<td::uint8,1> flags{};
  read(flags);
  bundle.flags = flags[0];
  std::array<td::uint8,8> balance{};
  read(balance);
  bundle.value_balance = round == 0 ? -5000 : 100;
  // This reader accepts only these fixed fixtures, not arbitrary signed wire values.
  const auto expected = static_cast<std::uint64_t>(bundle.value_balance);
  for (unsigned i = 0; i < 8; ++i) ASSERT_EQ(balance[i],(expected >> (i * 8)) & 255u);
  read(bundle.anchor);
  read(bundle.binding_signature);
  bundle.proof.resize(7264);
  read(bundle.proof);
  bundle.actions.resize(2);
  for (auto& action : bundle.actions) {
    read(action.cv_net); read(action.nullifier); read(action.rk); read(action.cmx); read(action.epk);
    read(action.enc_ciphertext); read(action.out_ciphertext); read(action.spend_signature);
  }
  ASSERT_EQ(input.peek(),std::char_traits<char>::eof());
  return bundle;
}
NoteState::SpendEffects effects(const CryptoBundle& bundle) {
  NoteState::SpendEffects result{bundle.anchor,{}};
  for (const auto& action : bundle.actions) {
    NoteState::Action output;
    std::copy(std::begin(action.nullifier),std::end(action.nullifier),output.nullifier.as_slice().ubegin());
    std::copy(std::begin(action.cmx),std::end(action.cmx),output.commitment.begin());
    result.actions.push_back(output);
  }
  return result;
}
}

TEST(UnoRealHistory, RestoredStateMatchesNextProofAnchor) {
  std::array<td::uint8,32> digest{};
  digest.fill(42);
  const auto first = load_history(0);
  ASSERT_TRUE(verify_crypto_bundle(first,BundleContext::ShieldClaim,Amount::from_nanotomi(5000),{},
                                 digest,{2,7264}).move_as_ok());
  // Test-only bootstrap: proof validity does not authorize a Deposit or mint.
  auto empty = NoteTreeState::empty().move_as_ok();
  auto genesis = AnchorWindow::genesis(3,3,empty.root()).move_as_ok();
  auto notes = NoteState::assemble(empty,{},genesis).move_as_ok()
      .apply_spend_effects(1,{effects(first)},{1,2,2}).move_as_ok();
  auto state = PrivateTransferState::assemble(notes,{Amount::from_nanotomi(5000),{}, {}}).move_as_ok();
  const std::uint64_t expected_notes[]{5000,4900,4800,4700};
  const std::uint64_t expected_fees[]{0,100,200,300};
  const std::uint64_t expected_leaves[]{2,4,6,8};
  const std::uint64_t heights[]{1,2,3,4};
  std::vector<td::Bits256> all_keys;
  for (unsigned round = 0; round < 4; ++round) {
    const auto bundle = load_history(round);
    if (round != 0) {
      ASSERT_TRUE(bundle.anchor == state.notes().tree().root());
      auto verified = CryptoVerifiedTransfer::verify(bundle,Amount::from_nanotomi(100),digest,{2,7264})
          .move_as_ok();
      ASSERT_TRUE(verified.has_value());
      const auto before = state.to_cell().move_as_ok()->get_hash();
      auto next = state.apply_block(heights[round],{*verified},{1,2,2}).move_as_ok();
      ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == before);
      state = std::move(next);
    }
    for (const auto& action : effects(bundle).actions) all_keys.push_back(action.nullifier);
    auto cell = state.to_cell().move_as_ok();
    auto bytes = vm::std_boc_serialize(cell).move_as_ok();
    auto restored = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
    state = PrivateTransferState::from_cell(restored,3,3,{8,0,0,0}).move_as_ok();
    ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == cell->get_hash());
    ASSERT_EQ(state.accounting().notes.high(),0u);
    ASSERT_EQ(state.accounting().notes.low(),expected_notes[round]);
    ASSERT_EQ(state.accounting().fees.high(),0u);
    ASSERT_EQ(state.accounting().fees.low(),expected_fees[round]);
    ASSERT_EQ(state.notes().tree().next_position(),expected_leaves[round]);
    ASSERT_EQ(state.notes().nullifiers().used_count(),expected_leaves[round]);
    for (const auto& key : all_keys) ASSERT_TRUE(state.notes().nullifiers().try_is_used(key).move_as_ok());
  }
  std::cout << "real history restored across four bundles; all anchors, balances and spent keys match\n";
  std::cout.flush();
  ASSERT_TRUE(std::cout.good());
}
