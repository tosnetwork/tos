/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Emits the authoritative byte-exact vectors for the post-quantum validator
// descriptor. The C++ side produces them; both implementations must reproduce the
// same cell for the same fields, so the wire format cannot drift between them.
#include <cstdio>
#include <string>

#include "block/block-auto.h"
#include "crypto/pq/pq-bytes.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"

int main() {
  // line format:
  // <validator_id_hex> <algorithm_id> <key_id_hex> <public_key_hex> <weight> <adnl_hex> <root_hash_hex> <boc_hex>
  struct Case {
    unsigned char vid, kid, pk, adnl;
    int algorithm_id;
    unsigned long long weight;
    std::size_t key_len;
  };
  const Case cases[] = {
      {0x01, 0x02, 0x03, 0x09, 1, 1234, 1312},
      {0xff, 0x00, 0xaa, 0x5c, 1, 1, 1312},
      {0x7f, 0x80, 0x01, 0xfe, 1, 0xffffffffffffffffULL, 1312},
  };
  for (const auto& c : cases) {
    const std::string vid(32, static_cast<char>(c.vid)), kid(32, static_cast<char>(c.kid));
    const std::string pk(c.key_len, static_cast<char>(c.pk)), adnl(32, static_cast<char>(c.adnl));
    vm::CellBuilder cb;
    cb.store_long(0xb3, 8);
    cb.store_bytes(vid);
    cb.store_long(c.algorithm_id, 16);
    cb.store_bytes(kid);
    cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(pk), tos::pq::pq_bytes_hard_max).move_as_ok());
    cb.store_long(static_cast<long long>(c.weight), 64);
    cb.store_bytes(adnl);
    auto cell = cb.finalize();

    // Refuse to record a vector the schema itself would not accept.
    vm::CellSlice check(vm::NoVm(), cell);
    if (!block::gen::t_ValidatorDescr.validate_skip(nullptr, check, false) || !check.empty_ext()) {
      fprintf(stderr, "generated descriptor does not validate against the schema\n");
      return 1;
    }

    auto boc = vm::std_boc_serialize(cell, 31).move_as_ok();
    printf("%s %d %s %s %llu %s %s %s\n", td::hex_encode(td::Slice(vid)).c_str(), c.algorithm_id,
           td::hex_encode(td::Slice(kid)).c_str(), td::hex_encode(td::Slice(pk)).c_str(), c.weight,
           td::hex_encode(td::Slice(adnl)).c_str(), td::hex_encode(cell->get_hash().as_slice()).c_str(),
           td::hex_encode(boc.as_slice()).c_str());
  }
  return 0;
}
