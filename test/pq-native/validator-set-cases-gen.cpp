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
td::Ref<vm::Cell> descriptor_with_key_cell(const td::Bits256& validator_id, int algorithm_id,
                                           const td::Bits256& key_id, td::Ref<vm::Cell> stored_key,
                                           td::uint64 weight, const td::Bits256& adnl_addr,
                                           int tag = 0xb3, bool trailing_bit = false) {
  vm::CellBuilder cb;
  cb.store_long(tag, 8);
  cb.store_bits_bool(validator_id.cbits(), 256);
  cb.store_long(algorithm_id, 16);
  cb.store_bits_bool(key_id.cbits(), 256);
  cb.store_ref(stored_key);
  cb.store_long(static_cast<long long>(weight), 64);
  cb.store_bits_bool(adnl_addr.cbits(), 256);
  if (trailing_bit) {
    cb.store_long(1, 1);
  }
  return cb.finalize();
}

td::Ref<vm::Cell> descriptor(const td::Bits256& validator_id, int algorithm_id, const td::Bits256& key_id,
                             const std::string& public_key, td::uint64 weight, const td::Bits256& adnl_addr) {
  return descriptor_with_key_cell(validator_id, algorithm_id, key_id,
                                  tos::pq::pack_pq_bytes(td::Slice(public_key), tos::pq::pq_bytes_hard_max).move_as_ok(),
                                  weight, adnl_addr);
}

td::Ref<vm::Cell> validator_set_with_header(const std::vector<td::Ref<vm::Cell>>& descriptors,
                                            td::uint64 total_weight, int stated_total, int stated_main,
                                            int first_index = 0) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < descriptors.size(); i++) {
    td::BitArray<16> key;
    key.store_ulong(i + first_index);
    auto cs = vm::load_cell_slice_ref(descriptors[i]);
    dict.set(key.cbits(), 16, cs);
  }
  vm::CellBuilder cb;
  cb.store_long(0x12, 8);
  // The shared BOCs are also offered to the launch config contract. Its
  // Elector entry point requires a future interval, not the node decoder's
  // otherwise-valid historical 100..200 interval.
  cb.store_long(4000000000LL, 32);
  cb.store_long(4000100000LL, 32);
  cb.store_long(stated_total, 16);
  cb.store_long(stated_main, 16);
  cb.store_long(static_cast<long long>(total_weight), 64);
  cb.store_maybe_ref(dict.get_root_cell());
  return cb.finalize();
}

td::Ref<vm::Cell> validator_set(const std::vector<td::Ref<vm::Cell>>& descriptors, td::uint64 total_weight) {
  return validator_set_with_header(descriptors, total_weight, static_cast<int>(descriptors.size()),
                                   static_cast<int>(descriptors.size()));
}

void emit(const char* name, const char* verdict, td::Ref<vm::Cell> set) {
  // line format: <name> <accept|reject> <set_boc_hex>
  printf("%s %s %s\n", name, verdict, td::hex_encode(vm::std_boc_serialize(set, 31).move_as_ok().as_slice()).c_str());
}

}  // namespace

int main() {
  const std::string key_a(tos::pq::mldsa44_public_key_bytes, '\x11');
  const std::string key_b(tos::pq::mldsa44_public_key_bytes, '\x33');
  const std::string key_c(tos::pq::mldsa44_public_key_bytes, '\x44');
  const std::string key_d(tos::pq::mldsa44_public_key_bytes, '\x55');
  const auto kid_a = key_id_of(key_a), kid_b = key_id_of(key_b);
  const auto kid_c = key_id_of(key_c), kid_d = key_id_of(key_d);
  const auto vid_a = fill(0xa0), vid_b = fill(0xa5), vid_c = fill(0xaa), vid_d = fill(0xaf);
  const auto adnl_a = fill(0xc0), adnl_b = fill(0xc5), adnl_c = fill(0xca), adnl_d = fill(0xcf);
  auto good_a = [&] { return descriptor(vid_a, 1, kid_a, key_a, 5, adnl_a); };
  auto good_b = [&] { return descriptor(vid_b, 1, kid_b, key_b, 7, adnl_b); };
  auto good_c = [&] { return descriptor(vid_c, 1, kid_c, key_c, 11, adnl_c); };
  auto good_d = [&] { return descriptor(vid_d, 1, kid_d, key_d, 13, adnl_d); };
  auto set_four = [&](td::Ref<vm::Cell> first, td::Ref<vm::Cell> second, td::uint64 stated_weight = 36) {
    return validator_set({first, second, good_c(), good_d()}, stated_weight);
  };

  emit("valid", "accept", set_four(good_a(), good_b()));
  emit("duplicate-validator-id", "reject", set_four(good_a(), descriptor(vid_a, 1, kid_b, key_b, 7, adnl_b)));
  emit("duplicate-key-id", "reject", set_four(good_a(), descriptor(vid_b, 1, kid_a, key_a, 7, adnl_b)));
  emit("duplicate-public-key", "reject",
       set_four(good_a(), descriptor(vid_b, 1, key_id_of(key_a), key_a, 7, adnl_b)));
  // Everything else about the second member is distinct, so a shared transport identity is
  // the only thing left that can refuse this set.
  emit("duplicate-adnl", "reject", set_four(good_a(), descriptor(vid_b, 1, kid_b, key_b, 7, adnl_a)));
  emit("key-id-mismatch", "reject", set_four(descriptor(vid_a, 1, fill(0xee), key_a, 5, adnl_a), good_b()));
  // The key identity matches what this algorithm would derive, so nothing but the
  // algorithm rule itself can refuse it.
  emit("unknown-algorithm", "reject", set_four(descriptor(vid_a, 7, raw_key_id(7, key_a), key_a, 5, adnl_a), good_b()));
  // Same again: the identity matches the key that is present, so only its length is wrong.
  const std::string short_key(tos::pq::mldsa44_public_key_bytes - 1, '\x11');
  const std::string long_key(tos::pq::mldsa44_public_key_bytes + 1, '\x11');
  emit("short-key", "reject", set_four(descriptor(vid_a, 1, raw_key_id(1, short_key), short_key, 5, adnl_a), good_b()));
  emit("long-key", "reject", set_four(descriptor(vid_a, 1, raw_key_id(1, long_key), long_key, 5, adnl_a), good_b()));
  // A length header without its required continuation is not a stored public key.
  // The declared length is valid, so rejection must come from the encoding check.
  vm::CellBuilder malformed_key;
  malformed_key.store_long(tos::pq::mldsa44_public_key_bytes, 32);
  emit("malformed-key-encoding", "reject",
       set_four(descriptor_with_key_cell(vid_a, 1, kid_a, malformed_key.finalize(), 5, adnl_a), good_b()));
  auto packed_key_a = [&] { return tos::pq::pack_pq_bytes(td::Slice(key_a), tos::pq::pq_bytes_hard_max).move_as_ok(); };
  emit("wrong-descriptor-tag", "reject",
       set_four(descriptor_with_key_cell(vid_a, 1, kid_a, packed_key_a(), 5, adnl_a, 0xb4), good_b()));
  emit("descriptor-trailing-bit", "reject",
       set_four(descriptor_with_key_cell(vid_a, 1, kid_a, packed_key_a(), 5, adnl_a, 0xb3, true), good_b()));
  emit("zero-validator-id", "reject", set_four(descriptor(fill(0), 1, kid_a, key_a, 5, adnl_a), good_b()));
  emit("zero-adnl", "reject", set_four(descriptor(vid_a, 1, kid_a, key_a, 5, fill(0)), good_b()));
  emit("zero-weight", "reject", set_four(good_a(), descriptor(vid_b, 1, kid_b, key_b, 0, adnl_b), 29));
  // Over the protocol cap but nowhere near overflowing a u64, so the cap is the only
  // thing that can refuse it.
  emit("weight-over-protocol-cap", "reject",
       set_four(descriptor(vid_a, 1, kid_a, key_a, 0x4000000000000000ULL, adnl_a),
                descriptor(vid_b, 1, kid_b, key_b, 0x4000000000000000ULL, adnl_b),
                0x8000000000000018ULL));
  // The old "declared-total-mismatch" row actually changed total *weight*.
  // Keep its bytes and verdict but give it a name that identifies the rule.
  emit("declared-weight-mismatch", "reject", set_four(good_a(), good_b(), 37));
  emit("zero-total-weight", "reject", set_four(good_a(), good_b(), 0));
  emit("declared-count-mismatch", "reject",
       validator_set_with_header({good_a(), good_b(), good_c(), good_d()}, 36, 5, 4));
  emit("index-gap", "reject", validator_set_with_header({good_a(), good_b(), good_c(), good_d()}, 36, 4, 4, 1));
  emit("zero-main-count", "reject", validator_set_with_header({good_a(), good_b(), good_c(), good_d()}, 36, 4, 0));
  emit("main-exceeds-total", "reject", validator_set_with_header({good_a(), good_b(), good_c(), good_d()}, 36, 4, 5));
  return 0;
}
