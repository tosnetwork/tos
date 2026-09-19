/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Emits validator sets that must be accepted or refused, as whole encoded sets rather
// than as descriptions to be rebuilt. Both implementations read these same bytes and
// must reach the same verdict: a set one accepts while the other refuses is a split.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "block/mc-config.h"
#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-consensus.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

td::Bits256 key_id_of(const std::string& public_key) {
  auto derived = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, public_key);
  td::Bits256 out;
  out.set_zero();
  if (derived) {
    std::memcpy(out.data(), derived->data(), derived->size());
  }
  return out;
}

// The derivation an attacker can perform: plain SHA-256 over the frozen preimage, with
// none of the fail-closed checks the node applies. It is needed so a case can break one
// rule while satisfying the key-identity binding, which would otherwise reject it first
// and leave the rule under test unexercised.
td::Bits256 raw_key_id(int algorithm_id, const std::string& public_key) {
  std::string preimage(tos::pq::key_id_domain);
  preimage.push_back(static_cast<char>(algorithm_id & 0xff));
  preimage.push_back(static_cast<char>((algorithm_id >> 8) & 0xff));
  preimage += public_key;
  td::Bits256 out;
  td::sha256(td::Slice(preimage), out.as_slice());
  return out;
}

// Deliberately builds whatever it is told to, including sets that must be refused.
td::Ref<vm::Cell> descriptor(const td::Bits256& validator_id, int algorithm_id, const td::Bits256& key_id,
                             const std::string& public_key, td::uint64 weight, const td::Bits256& adnl_addr) {
  vm::CellBuilder cb;
  cb.store_long(0xb3, 8);
  cb.store_bits_bool(validator_id.cbits(), 256);
  cb.store_long(algorithm_id, 16);
  cb.store_bits_bool(key_id.cbits(), 256);
  cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(public_key), tos::pq::pq_bytes_hard_max).move_as_ok());
  cb.store_long(static_cast<long long>(weight), 64);
  cb.store_bits_bool(adnl_addr.cbits(), 256);
  return cb.finalize();
}

td::Ref<vm::Cell> validator_set(const std::vector<td::Ref<vm::Cell>>& descriptors, td::uint64 total_weight) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < descriptors.size(); i++) {
    td::BitArray<16> key;
    key.store_ulong(i);
    auto cs = vm::load_cell_slice_ref(descriptors[i]);
    dict.set(key.cbits(), 16, cs);
  }
  vm::CellBuilder cb;
  cb.store_long(0x12, 8);
  cb.store_long(100, 32);
  cb.store_long(200, 32);
  cb.store_long(static_cast<long long>(descriptors.size()), 16);
  cb.store_long(static_cast<long long>(descriptors.size()), 16);
  cb.store_long(static_cast<long long>(total_weight), 64);
  cb.store_maybe_ref(dict.get_root_cell());
  return cb.finalize();
}

void emit(const char* name, const char* verdict, td::Ref<vm::Cell> set) {
  // line format: <name> <accept|reject> <set_boc_hex>
  printf("%s %s %s\n", name, verdict, td::hex_encode(vm::std_boc_serialize(set, 31).move_as_ok().as_slice()).c_str());
}

}  // namespace

int main() {
  const std::string key_a(tos::pq::mldsa44_public_key_bytes, '\x11');
  const std::string key_b(tos::pq::mldsa44_public_key_bytes, '\x33');
  const auto kid_a = key_id_of(key_a), kid_b = key_id_of(key_b);
  const auto vid_a = fill(0xa0), vid_b = fill(0xa5);
  const auto adnl_a = fill(0xc0), adnl_b = fill(0xc5);
  auto good_a = [&] { return descriptor(vid_a, 1, kid_a, key_a, 5, adnl_a); };
  auto good_b = [&] { return descriptor(vid_b, 1, kid_b, key_b, 7, adnl_b); };

  emit("valid", "accept", validator_set({good_a(), good_b()}, 12));
  emit("duplicate-validator-id", "reject",
       validator_set({good_a(), descriptor(vid_a, 1, kid_b, key_b, 7, adnl_b)}, 12));
  emit("duplicate-key-id", "reject", validator_set({good_a(), descriptor(vid_b, 1, kid_a, key_a, 7, adnl_b)}, 12));
  emit("duplicate-public-key", "reject",
       validator_set({good_a(), descriptor(vid_b, 1, key_id_of(key_a), key_a, 7, adnl_b)}, 12));
  emit("key-id-mismatch", "reject", validator_set({descriptor(vid_a, 1, kid_b, key_a, 5, adnl_a)}, 5));
  // The key identity matches what this algorithm would derive, so nothing but the
  // algorithm rule itself can refuse it.
  emit("unknown-algorithm", "reject", validator_set({descriptor(vid_a, 7, raw_key_id(7, key_a), key_a, 5, adnl_a)}, 5));
  // Same again: the identity matches the key that is present, so only its length is wrong.
  const std::string short_key(tos::pq::mldsa44_public_key_bytes - 1, '\x11');
  const std::string long_key(tos::pq::mldsa44_public_key_bytes + 1, '\x11');
  emit("short-key", "reject", validator_set({descriptor(vid_a, 1, raw_key_id(1, short_key), short_key, 5, adnl_a)}, 5));
  emit("long-key", "reject", validator_set({descriptor(vid_a, 1, raw_key_id(1, long_key), long_key, 5, adnl_a)}, 5));
  emit("zero-validator-id", "reject", validator_set({descriptor(fill(0), 1, kid_a, key_a, 5, adnl_a)}, 5));
  emit("zero-adnl", "reject", validator_set({descriptor(vid_a, 1, kid_a, key_a, 5, fill(0))}, 5));
  emit("zero-weight", "reject", validator_set({good_a(), descriptor(vid_b, 1, kid_b, key_b, 0, adnl_b)}, 5));
  // Over the protocol cap but nowhere near overflowing a u64, so the cap is the only
  // thing that can refuse it.
  emit("weight-over-protocol-cap", "reject",
       validator_set({descriptor(vid_a, 1, kid_a, key_a, 0x4000000000000000ULL, adnl_a),
                      descriptor(vid_b, 1, kid_b, key_b, 0x4000000000000000ULL, adnl_b)},
                     0x8000000000000000ULL));
  emit("declared-total-mismatch", "reject", validator_set({good_a()}, 6));
  return 0;
}
