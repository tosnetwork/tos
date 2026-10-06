/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/boc.h"

#include "external-message.hpp"

namespace tos::validator {
using td::Ref;

ExtMessageQ::ExtMessageQ(td::BufferSlice data, td::Ref<vm::Cell> root, AccountIdPrefixFull addr_prefix,
                         tos::WorkchainId wc, tos::StdSmcAddress addr, Hash hash, Hash hash_norm)
    : root_(std::move(root))
    , addr_prefix_(addr_prefix)
    , data_(std::move(data))
    , hash_(hash)
    , hash_norm_(hash_norm)
    , wc_(wc)
    , addr_(addr) {
}

td::Result<td::Bits256> get_ext_in_msg_hash_norm(td::Ref<vm::Cell> ext_in_msg_cell) {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(ext_in_msg_cell, block::gen::t_Message_Any, message)) {
    return td::Status::Error("Failed to unpack Message");
  }
  auto tag = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (tag != block::gen::CommonMsgInfo::ext_in_msg_info) {
    return td::Status::Error("CommonMsgInfo tag is not ext_in_msg_info");
  }
  block::gen::CommonMsgInfo::Record_ext_in_msg_info msg_info;
  if (!tlb::csr_unpack(message.info, msg_info)) {
    return td::Status::Error("Failed to unpack CommonMsgInfo::ext_in_msg_info");
  }

  td::Ref<vm::Cell> body;
  auto body_cs = message.body.write();
  if (body_cs.fetch_ulong(1) == 1) {
    body = body_cs.fetch_ref();
  } else {
    body = vm::CellBuilder().append_cellslice(body_cs).finalize();
  }

  vm::CellBuilder cb;
  bool ok = cb.store_long_bool(2, 2) &&  // message$_ -> info:CommonMsgInfo -> ext_in_msg_info$10
            cb.store_long_bool(0, 2) &&  // message$_ -> info:CommonMsgInfo -> src:MsgAddressExt -> addr_none$00
            cb.append_cellslice_bool(msg_info.dest) &&  // message$_ -> info:CommonMsgInfo -> dest:MsgAddressInt
            cb.store_long_bool(0, 4) &&                 // message$_ -> info:CommonMsgInfo -> import_fee:Tomis -> 0
            cb.store_long_bool(0, 1) &&  // message$_ -> init:(Maybe (Either StateInit ^StateInit)) -> nothing$0
            cb.store_long_bool(1, 1) &&  // message$_ -> body:(Either X ^X) -> right$1
            cb.store_ref_bool(body);
  if (!ok) {
    return td::Status::Error("Failed to build normalized message");
  }
  return cb.finalize()->get_hash().bits();
}

td::Result<Ref<ExtMessageQ>> ExtMessageQ::create_ext_message(td::BufferSlice data,
                                                             block::SizeLimitsConfig::ExtMsgLimits limits) {
  if (data.size() > limits.max_size) {
    return td::Status::Error("external message too large, rejecting");
  }
  // Round 167 (claude review) LOW fix: pass max_roots=1 so the
  // header-parse step rejects a multi-root BoC up front instead of
  // letting BagOfCells::deserialize allocate the full roots vector
  // (up to the default cap of 16384 entries, ~256 KiB) and parse
  // every declared cell before we discover the wrong root_count on
  // the next line.  std_boc_deserialize already uses max_roots=1
  // for the same reason (crypto/vm/boc.cpp:992); the direct
  // BagOfCells caller here was bypassing that early-reject and
  // amplifying max-size-bound DoS pressure per accepted ext-msg.
  vm::BagOfCells boc;
  auto res = boc.deserialize(data.as_slice(), 1);
  if (res.is_error()) {
    return res.move_as_error();
  }
  if (boc.get_root_count() != 1) {
    return td::Status::Error("external message is not a valid bag of cells");  // not a valid bag-of-Cells
  }
  auto ext_msg = boc.get_root_cell();
  if (ext_msg->get_level() != 0) {
    return td::Status::Error("external message must have zero level");
  }
  if (ext_msg->get_depth() >= limits.max_depth) {
    return td::Status::Error("external message is too deep");
  }
  vm::CellSlice cs{vm::NoVmOrd{}, ext_msg};
  if (cs.prefetch_ulong(2) != 2) {  // ext_in_msg_info$10
    return td::Status::Error("external message must begin with ext_in_msg_info$10");
  }
  tos::Bits256 hash{ext_msg->get_hash().bits()};
  if (!block::gen::t_Message_Any.validate_ref(128, ext_msg)) {
    return td::Status::Error("external message is not a (Message Any) according to automated checks");
  }
  if (!block::tlb::t_Message.validate_ref(128, ext_msg)) {
    return td::Status::Error("external message is not a (Message Any) according to hand-written checks");
  }
  block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
  if (!tlb::unpack_cell_inexact(ext_msg, info)) {
    return td::Status::Error("cannot unpack external message header");
  }
  auto dest_prefix = block::tlb::t_MsgAddressInt.get_prefix(info.dest);
  if (!dest_prefix.is_valid()) {
    return td::Status::Error("destination of an inbound external message is an invalid blockchain address");
  }
  tos::StdSmcAddress addr;
  tos::WorkchainId wc;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(info.dest, wc, addr)) {
    return td::Status::Error(PSLICE() << "Can't parse destination address");
  }

  // Engine-specific admission checks require ConfigParam 12 and therefore run
  // in ExtMessagePool::check_message, after this structural parse has produced
  // the destination workchain and address.

  TRY_RESULT(hash_norm, get_ext_in_msg_hash_norm(ext_msg));
  return Ref<ExtMessageQ>{true, std::move(data), std::move(ext_msg), dest_prefix, wc, addr, hash, hash_norm};
}

td::Result<Ref<ExtMessageQ>> ExtMessageQ::create_ext_message(Ref<vm::Cell> root) {
  vm::CellSlice cs{vm::NoVmOrd{}, root};
  if (cs.prefetch_ulong(2) != 2) {
    return td::Status::Error("external message must begin with ext_in_msg_info$10");
  }
  tos::Bits256 hash{root->get_hash().bits()};
  block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
  if (!tlb::unpack_cell_inexact(root, info)) {
    return td::Status::Error("cannot unpack external message header");
  }
  auto dest_prefix = block::tlb::t_MsgAddressInt.get_prefix(info.dest);
  if (!dest_prefix.is_valid()) {
    return td::Status::Error("destination of an inbound external message is an invalid blockchain address");
  }
  tos::StdSmcAddress addr;
  tos::WorkchainId wc;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(info.dest, wc, addr)) {
    return td::Status::Error(PSLICE() << "Can't parse destination address");
  }
  TRY_RESULT(hash_norm, get_ext_in_msg_hash_norm(root));
  TRY_RESULT(data, vm::std_boc_serialize(root));
  return Ref<ExtMessageQ>{true, std::move(data), std::move(root), dest_prefix, wc, addr, hash, hash_norm};
}

}  // namespace tos::validator
