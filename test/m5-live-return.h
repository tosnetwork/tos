#pragma once
// Test observation of an actual wc0 receiving transaction. No synthetic bounce.
#include "m3-live-state.h"

namespace m3_live {
inline void observe_m5_payout_recipient(const std::filesystem::path& fixture) {
  const auto payout = load(fixture / "prepare-payout.boc");
  block::gen::CommonMsgInfo::Record_int_msg_info sent;
  CHECK(tlb::unpack_cell_inexact(payout, sent));
  CHECK(block::tlb::t_Tomis.as_integer(sent.extra_flags)->to_long() == 3);
  block::gen::Message::Record sent_wire;
  CHECK(tlb::type_unpack_cell(payout, block::gen::t_Message_Any, sent_wire));
  auto sent_body = *sent_wire.body;
  auto original_body = sent_body.fetch_ulong(1) ? sent_body.fetch_ref()
      : vm::CellBuilder().append_cellslice(sent_body).finalize();
  tos::WorkchainId wc; td::Bits256 recipient;
  CHECK(block::tlb::t_MsgAddressInt.extract_std_address(sent.dest, wc, recipient) && wc == 0);
  auto archive = tos::fetch_tl_object<tos::tos_api::db_candidate>(
      td::read_file((fixture / "payout-recipient.candidate").string()).move_as_ok(), true).move_as_ok();
  const auto id = tos::create_block_id(archive->id_);
  const auto root = vm::std_boc_deserialize(archive->data_.as_slice()).move_as_ok();
  CHECK(id.id.workchain == wc && td::Bits256(root->get_hash().bits()) == id.root_hash &&
        td::sha256_bits256(archive->data_) == id.file_hash);
  block::gen::Block::Record header;
  block::gen::BlockExtra::Record extra;
  CHECK(tlb::unpack_cell(root, header) && tlb::unpack_cell(header.extra, extra));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(extra.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
  auto leaf = accounts.lookup(recipient);
  block::gen::AccountBlock::Record account;
  CHECK(leaf.not_null() && block::gen::t_AccountBlock.unpack(leaf.write(), account));
  vm::AugmentedDictionary txs(vm::DictNonEmpty(), account.transactions, 64, block::tlb::aug_AccountTransactions);
  unsigned matched = 0;
  CHECK(txs.check_for_each_extra([&](auto value, auto, td::ConstBitPtr, int) {
    block::gen::Transaction::Record tx;
    CHECK(tlb::unpack_cell(value->prefetch_ref(), tx));
    auto input = *tx.r1.in_msg;
    if (input.fetch_ulong(1) != 1 || input.fetch_ref()->get_hash() != payout->get_hash()) return true;
    ++matched;
    block::gen::TransactionDescr::Record_trans_ord ordinary;
    CHECK(tlb::unpack_cell(tx.description, ordinary));
    auto bounce = *ordinary.bounce;
    CHECK(bounce.fetch_ulong(1) == 1);
    vm::Dictionary outputs(tx.r1.out_msgs, 15);
    if (bounce.prefetch_ulong(1) == 0) {
      CHECK(bounce.fetch_ulong(2) == 1); // Native nofunds, NOT a produced bounce.
      CHECK(tx.outmsg_cnt == 0 && outputs.is_empty());
      std::cout << "M5_NATIVE_RETURN_NOFUNDS payout=" << payout->get_hash().to_hex()
                << " original_lt=" << sent.created_lt << " out_msgs=0\n";
      return true;
    }
    CHECK(tx.outmsg_cnt == 1);
    auto message = outputs.lookup_ref(td::BitArray<15>::zero());
    block::gen::Message::Record wire;
    block::gen::CommonMsgInfo::Record_int_msg_info info;
    CHECK(message.not_null() && tlb::type_unpack_cell(message, block::gen::t_Message_Any, wire) &&
          tlb::csr_unpack(wire.info, info) && info.bounced);
    auto body = *wire.body;
    auto body_root = body.fetch_ulong(1) ? body.fetch_ref() : vm::CellBuilder().append_cellslice(body).finalize();
    block::gen::NewBounceBody::Record rich;
    block::gen::NewBounceOriginalInfo::Record original;
    CHECK(tlb::unpack_cell(body_root, rich) && tlb::unpack_cell(rich.original_info, original));
    CHECK(original.created_lt == sent.created_lt);
    CHECK(rich.original_body->get_hash() == original_body->get_hash());
    CHECK(info.dest->contents_equal(*sent.src) && info.src->contents_equal(*sent.dest));
    block::CurrencyCollection received;
    CHECK(received.unpack(info.value));
    save(fixture / "failed-bounce.boc", message);
    std::cout << "M5_NATIVE_RETURN payout=" << payout->get_hash().to_hex()
              << " bounce=" << message->get_hash().to_hex() << " original_lt=" << original.created_lt
              << " recovered=" << received.tomis << " original_body=exact payout_flags=3\n";
    return true;
  }));
  CHECK(matched == 1);
}
} // namespace m3_live
