/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The external-message pool recognises known wallet code by hash so it can
// pre-check seqno and valid_until before admitting a message. This chain's
// wallets prefix every signed body with the network's global_id, which shifts
// those fields by 32 bits relative to the older layouts. These tests pin two
// things: the admission table keys on the hashes of the wallet code actually
// compiled from this repository (a wallet source change without a table
// update goes red here), and the parsers read seqno/valid_until from the
// shifted positions.

#include "smc-envelope/SmartContractCode.h"
#include "td/utils/tests.h"
#include "validator/impl/external-message.hpp"
#include "vm/cells.h"

namespace {

td::Bits256 code_hash(tos::SmartContractCode::Type type) {
  auto code = tos::SmartContractCode::get_code(type);
  CHECK(code.not_null());
  return code->get_hash().bits();
}

// ext_in_msg_info$10 src:addr_none dest:addr_std import_fee:0, no StateInit,
// body stored as a reference.
td::Ref<vm::Cell> make_ext_message(td::Ref<vm::Cell> body) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(2, 2));                  // ext_in_msg_info$10
  CHECK(cb.store_long_bool(0, 2));                  // src addr_none$00
  CHECK(cb.store_long_bool(2, 2));                  // dest addr_std$10
  CHECK(cb.store_long_bool(0, 1 + 8));              // no anycast, workchain 0
  cb.store_zeroes(256);                             // address
  CHECK(cb.store_long_bool(0, 4));                  // import_fee 0
  CHECK(cb.store_long_bool(0, 1));                  // no StateInit
  CHECK(cb.store_long_bool(1, 1));                  // body in reference
  CHECK(cb.store_ref_bool(std::move(body)));
  return cb.finalize();
}

td::Ref<vm::Cell> make_v3_style_body(td::uint32 valid_until, td::uint32 seqno) {
  vm::CellBuilder cb;
  cb.store_zeroes(512);            // signature
  CHECK(cb.store_long_bool(1, 32));  // global_id
  CHECK(cb.store_long_bool(698983191, 32));  // subwallet_id
  CHECK(cb.store_long_bool(valid_until, 32));
  CHECK(cb.store_long_bool(seqno, 32));
  return cb.finalize();
}

td::Ref<vm::Cell> make_v5_body(td::uint32 valid_until, td::uint32 seqno) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0x7369676E, 32));  // signed_external prefix
  CHECK(cb.store_long_bool(1, 32));           // global_id
  CHECK(cb.store_long_bool(698983191, 32));   // wallet_id
  CHECK(cb.store_long_bool(valid_until, 32));
  CHECK(cb.store_long_bool(seqno, 32));
  cb.store_zeroes(512);                       // signature at the tail
  return cb.finalize();
}

}  // namespace

TEST(WalletMessageProcessor, admission_table_tracks_compiled_wallet_code) {
  auto* v3 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV3));
  ASSERT_TRUE(v3 != nullptr);
  ASSERT_EQ("wallet-v3-network-bound", v3->name());

  auto* v4 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV4));
  ASSERT_TRUE(v4 != nullptr);
  ASSERT_EQ("wallet-v4-network-bound", v4->name());

  auto* v5 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV5));
  ASSERT_TRUE(v5 != nullptr);
  ASSERT_EQ("wallet-v5-network-bound", v5->name());
}

TEST(WalletMessageProcessor, network_bound_layouts_parse_seqno_and_valid_until) {
  auto* v3 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV3));
  auto parsed3 = v3->parse_message(make_ext_message(make_v3_style_body(1789434000, 7)));
  ASSERT_TRUE(parsed3.is_ok());
  ASSERT_EQ(7u, parsed3.ok().first);
  ASSERT_EQ(1789434000u, parsed3.ok().second);

  auto* v4 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV4));
  auto parsed4 = v4->parse_message(make_ext_message(make_v3_style_body(4242, 3)));
  ASSERT_TRUE(parsed4.is_ok());
  ASSERT_EQ(3u, parsed4.ok().first);
  ASSERT_EQ(4242u, parsed4.ok().second);

  auto* v5 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV5));
  auto parsed5 = v5->parse_message(make_ext_message(make_v5_body(999999, 11)));
  ASSERT_TRUE(parsed5.is_ok());
  ASSERT_EQ(11u, parsed5.ok().first);
  ASSERT_EQ(999999u, parsed5.ok().second);

  // Too-short bodies are an error, not a misread. v3/v4 need at least the
  // signature plus four 32-bit fields; v5 needs five 32-bit fields.
  auto short_v3_body = vm::CellBuilder().store_zeroes(512 + 96).finalize();
  ASSERT_TRUE(v3->parse_message(make_ext_message(short_v3_body)).is_error());
  auto short_v5_body = vm::CellBuilder().store_zeroes(128).finalize();
  ASSERT_TRUE(v5->parse_message(make_ext_message(short_v5_body)).is_error());
}

TEST(WalletMessageProcessor, wallet_seqno_round_trip) {
  auto* v3 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV3));
  // v3 data: seqno(32) subwallet_id(32) public_key(256)
  vm::CellBuilder db;
  CHECK(db.store_long_bool(5, 32) && db.store_long_bool(698983191, 32));
  db.store_zeroes(256);
  auto data = db.finalize();
  ASSERT_EQ(5u, v3->get_wallet_seqno(data).ok());
  auto bumped = v3->set_wallet_seqno(data, 6).move_as_ok();
  ASSERT_EQ(6u, v3->get_wallet_seqno(bumped).ok());

  auto* v5 = tos::validator::WalletMessageProcessor::get(code_hash(tos::SmartContractCode::WalletV5));
  // v5 data: is_signature_allowed(1) seqno(32) wallet_id(32) public_key(256) extensions(1)
  vm::CellBuilder db5;
  CHECK(db5.store_long_bool(1, 1) && db5.store_long_bool(9, 32) && db5.store_long_bool(698983191, 32));
  db5.store_zeroes(256);
  CHECK(db5.store_long_bool(0, 1));
  auto data5 = db5.finalize();
  ASSERT_EQ(9u, v5->get_wallet_seqno(data5).ok());
  auto bumped5 = v5->set_wallet_seqno(data5, 10).move_as_ok();
  ASSERT_EQ(10u, v5->get_wallet_seqno(bumped5).ok());
}
