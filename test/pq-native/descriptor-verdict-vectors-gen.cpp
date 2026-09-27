/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Descriptors and the verdicts the node reaches about them, so the contracts can be held
// to the same answers.
//
// Every verdict here is produced by running the node's own decoder over a set containing
// the descriptor, not by restating a rule. A contract that accepts what the node refuses
// writes validator sets that every node then rejects, which is a halt; a contract that
// refuses what the node accepts cannot elect anyone.
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

td::Bits256 derived_key_id(const std::string& public_key) {
  auto value = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, public_key);
  td::Bits256 out;
  out.set_zero();
  if (value) {
    std::memcpy(out.data(), value->data(), value->size());
  }
  return out;
}

// Deliberately builds whatever it is told to, including descriptors that must be refused.
td::Ref<vm::Cell> descriptor(unsigned tag, const td::Bits256& validator_id, int algorithm_id, const td::Bits256& key_id,
                             const td::Ref<vm::Cell>& stored_key, td::uint64 weight, const td::Bits256& adnl_addr) {
  vm::CellBuilder cb;
  cb.store_long(tag, 8);
  cb.store_bits_bool(validator_id.cbits(), 256);
  cb.store_long(algorithm_id, 16);
  cb.store_bits_bool(key_id.cbits(), 256);
  cb.store_ref(stored_key);
  cb.store_long(static_cast<long long>(weight), 64);
  cb.store_bits_bool(adnl_addr.cbits(), 256);
  return cb.finalize();
}

td::Ref<vm::Cell> single_set(const td::Ref<vm::Cell>& descr, td::uint64 total_weight) {
  vm::Dictionary dict{16};
  td::BitArray<16> key;
  key.store_ulong(0);
  auto cs = vm::load_cell_slice_ref(descr);
  dict.set(key, cs, vm::Dictionary::SetMode::Add);
  vm::CellBuilder cb;
  cb.store_long(0x12, 8);
  cb.store_long(100, 32);
  cb.store_long(200, 32);
  cb.store_long(1, 16);
  cb.store_long(1, 16);
  cb.store_long(static_cast<long long>(total_weight), 64);
  cb.store_maybe_ref(dict.get_root_cell());
  return cb.finalize();
}

// A stored key with a chosen chunking, so a non-canonical chain can be built on purpose.
td::Ref<vm::Cell> stored_key(const std::string& bytes, std::size_t first_chunk) {
  std::vector<std::string> chunks;
  std::size_t offset = 0;
  bool first = true;
  while (offset < bytes.size()) {
    std::size_t take = std::min(first ? first_chunk : tos::pq::pq_bytes_chunk, bytes.size() - offset);
    chunks.push_back(bytes.substr(offset, take));
    offset += take;
    first = false;
  }
  td::Ref<vm::Cell> tail;
  for (auto it = chunks.rbegin(); it != chunks.rend(); ++it) {
    vm::CellBuilder cb;
    cb.store_bytes(*it);
    if (tail.not_null()) {
      cb.store_ref(tail);
    }
    tail = cb.finalize();
  }
  vm::CellBuilder root;
  root.store_long(static_cast<long long>(bytes.size()), 32);
  if (tail.not_null()) {
    root.store_ref(tail);
  }
  return root.finalize();
}

int failures = 0;

void emit(const char* name, const char* verdict, const td::Ref<vm::Cell>& descr, td::uint64 total_weight) {
  // The verdict is the node's, taken by decoding a set that contains this descriptor.
  const bool accepted = block::Config::unpack_validator_set(single_set(descr, total_weight), false).is_ok();
  const bool expect_accept = std::string(verdict) == "accept";
  if (accepted != expect_accept) {
    std::fprintf(stderr, "%s: the node %s a descriptor recorded as %s\n", name, accepted ? "accepted" : "refused",
                 verdict);
    failures++;
    return;
  }
  std::printf("%s\t%s\t%s\n", name, verdict,
              td::hex_encode(vm::std_boc_serialize(descr, 31).move_as_ok().as_slice()).c_str());
}

}  // namespace

int main() {
  const std::string key_a(tos::pq::mldsa44_public_key_bytes, '\x11');
  const std::string key_b(tos::pq::mldsa44_public_key_bytes, '\x22');
  const std::string short_key(tos::pq::mldsa44_public_key_bytes - 1, '\x11');
  const auto vid = fill(0xa0), adnl = fill(0xc0);
  const auto kid_a = derived_key_id(key_a), kid_b = derived_key_id(key_b);
  const auto canonical_a = stored_key(key_a, tos::pq::pq_bytes_chunk);

  std::printf("# Descriptors and the verdict the node's decoder reaches about each one.\n");
  std::printf("# A contract is held to these answers: accepting what the node refuses writes a\n");
  std::printf("# validator set every node then rejects, which halts the chain rather than\n");
  std::printf("# registering something bad.\n");
  std::printf("#\n");
  std::printf("# name\tverdict\tdescriptor_boc_hex\n");

  emit("valid", "accept", descriptor(0xb3, vid, 1, kid_a, canonical_a, 5, adnl), 5);
  emit("valid-max-weight", "accept", descriptor(0xb3, vid, 1, kid_a, canonical_a, 0x3fffffffffffffffULL, adnl),
       0x3fffffffffffffffULL);
  emit("key-id-of-another-key", "reject", descriptor(0xb3, vid, 1, kid_b, canonical_a, 5, adnl), 5);
  emit("unknown-algorithm", "reject", descriptor(0xb3, vid, 7, derived_key_id(key_a), canonical_a, 5, adnl), 5);
  emit("short-key", "reject",
       descriptor(0xb3, vid, 1, derived_key_id(short_key), stored_key(short_key, tos::pq::pq_bytes_chunk), 5, adnl), 5);
  // Same bytes, chunked differently. The identity derived from it is unchanged, because
  // the hash does not depend on the boundaries, so only the shape rule can refuse it.
  emit("non-canonical-chunking", "reject", descriptor(0xb3, vid, 1, kid_a, stored_key(key_a, 64), 5, adnl), 5);
  emit("zero-validator-id", "reject", descriptor(0xb3, fill(0), 1, kid_a, canonical_a, 5, adnl), 5);
  emit("zero-adnl", "reject", descriptor(0xb3, vid, 1, kid_a, canonical_a, 5, fill(0)), 5);
  emit("zero-weight", "reject", descriptor(0xb3, vid, 1, kid_a, canonical_a, 0, adnl), 0);
  emit("classical-tag", "reject", descriptor(0x73, vid, 1, kid_a, canonical_a, 5, adnl), 5);

  return failures == 0 ? 0 : 1;
}
