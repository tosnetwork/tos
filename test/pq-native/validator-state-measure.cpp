/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// What a post-quantum validator set and a post-quantum elector actually cost in account
// state, measured with the accounting the node itself applies rather than estimated.
//
// These figures are a resource budget, not a pass or fail against a ceiling. The elector
// and the configuration contract are special accounts, and the action phase exempts
// special accounts from the account-state cell limit in both executors: transaction.cpp's
// enforce_state_limits returns early for them, and the Rust executor guards its check with
// !is_special. So max_mc_acc_state_cells does not bound either account. It is printed only
// as the yardstick an ordinary masterchain account is held to, which is the nearest thing
// to a scale these numbers have.
//
// What they do say is how much state every node carries and re-serialises whenever the
// configuration changes, which is a validator-resource question for launch sizing. A 1312-byte
// consensus key does not fit in a cell, so every key is a chain of them.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-consensus.h"
#include "crypto/pq/pq-elector.h"
#include "td/utils/crypto.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace {

// What an ORDINARY masterchain account may hold, from SizeLimitsConfig, which applies
// because the zerostate does not set ConfigParam 43. Not enforced for the two accounts
// measured here.
constexpr unsigned long long ordinary_mc_account_state_cell_limit = 1u << 11;
constexpr unsigned long long message_cell_limit = 1u << 13;
constexpr unsigned long long message_bit_limit = 1u << 21;

// Masterchain storage prices from the zerostate (bit 1000, cell 500000, both scaled by
// 2^16 per second).
//
// The configuration and elector accounts are registered through make_special in the
// zerostate, so ConfigParam 31 marks them special and compute_storage_fees returns zero
// for them. These prices therefore do NOT bill these two accounts. They are reported only
// to say what this much state would weigh at masterchain prices, because the number that
// actually binds is the cell count.
constexpr unsigned long long mc_bit_price_ps = 1000;
constexpr unsigned long long mc_cell_price_ps = 500000;
constexpr unsigned long long seconds_per_year = 31536000;

struct Size {
  unsigned long long cells;
  unsigned long long bits;
};

Size measure(const td::Ref<vm::Cell>& root) {
  vm::CellStorageStat stat;
  auto status = stat.add_used_storage(root);
  assert(status.is_ok());
  return Size{stat.cells, stat.bits};
}

double nanotomi_per_year(const Size& size) {
  const auto per_second = (size.bits * mc_bit_price_ps + size.cells * mc_cell_price_ps);
  return static_cast<double>(per_second) * static_cast<double>(seconds_per_year) / 65536.0;
}

// Distinct keys, because identical cells are counted once and a measurement taken over
// repeated keys would flatter the result by exactly the thing that never happens.
std::string distinct_key(std::size_t index, std::size_t length) {
  std::string key;
  key.reserve(length);
  td::Bits256 block;
  std::string seed = "state-measure-" + std::to_string(index);
  while (key.size() < length) {
    td::sha256(td::Slice(seed), block.as_slice());
    key.append(reinterpret_cast<const char*>(block.data()), 32);
    seed.assign(reinterpret_cast<const char*>(block.data()), 32);
  }
  key.resize(length);
  return key;
}

td::Bits256 bits_from(const std::string& seed) {
  td::Bits256 out;
  td::sha256(td::Slice(seed), out.as_slice());
  return out;
}

td::Ref<vm::Cell> pq_descriptor(std::size_t index, const std::string& public_key) {
  auto key_id = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, public_key);
  assert(key_id.has_value());
  td::Bits256 key_id_bits;
  std::memcpy(key_id_bits.data(), key_id->data(), key_id->size());
  vm::CellBuilder cb;
  cb.store_long(0xb3, 8);
  cb.store_bits_bool(bits_from("validator-" + std::to_string(index)).cbits(), 256);
  cb.store_long(1, 16);
  cb.store_bits_bool(key_id_bits.cbits(), 256);
  cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(public_key), tos::pq::pq_bytes_hard_max).move_as_ok());
  cb.store_long(1, 64);
  cb.store_bits_bool(bits_from("adnl-" + std::to_string(index)).cbits(), 256);
  return cb.finalize();
}

td::Ref<vm::Cell> classical_descriptor(std::size_t index) {
  vm::CellBuilder cb;
  cb.store_long(0x73, 8);
  cb.store_long(0x8e81278a, 32);
  cb.store_bits_bool(bits_from("classical-" + std::to_string(index)).cbits(), 256);
  cb.store_long(1, 64);
  cb.store_bits_bool(bits_from("adnl-" + std::to_string(index)).cbits(), 256);
  return cb.finalize();
}

td::Ref<vm::Cell> validator_set(const std::vector<td::Ref<vm::Cell>>& descriptors) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < descriptors.size(); i++) {
    td::BitArray<16> key;
    key.store_ulong(i);
    auto ok = dict.set_ref(key, descriptors[i], vm::Dictionary::SetMode::Add);
    assert(ok);
  }
  vm::CellBuilder cb;
  cb.store_long(0x12, 8);
  cb.store_long(100, 32);
  cb.store_long(200, 32);
  cb.store_long(static_cast<long long>(descriptors.size()), 16);
  cb.store_long(static_cast<long long>(descriptors.size()), 16);
  cb.store_long(static_cast<long long>(descriptors.size()), 64);
  auto root = dict.get_root_cell();
  cb.store_long(root.is_null() ? 0 : 1, 1);
  if (root.not_null()) {
    cb.store_ref(root);
  }
  return cb.finalize();
}

// The member record the rulings describe: stake, timestamp, max factor, algorithm, the
// contract-derived key identity, the key itself and the transport address. The dictionary
// key is the validator identity, so the controller address is not repeated in the value.
td::Ref<vm::Cell> member_record(std::size_t index, const std::string& public_key) {
  auto key_id = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, public_key);
  assert(key_id.has_value());
  td::Bits256 key_id_bits;
  std::memcpy(key_id_bits.data(), key_id->data(), key_id->size());
  vm::CellBuilder cb;
  cb.store_long(8, 4);                // coins length prefix
  cb.store_long(100000000000ll, 64);  // stake
  cb.store_long(1789434000, 32);      // timestamp
  cb.store_long(0x10000, 32);         // max_factor
  cb.store_long(1, 16);               // algorithm_id
  cb.store_bits_bool(key_id_bits.cbits(), 256);
  cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(public_key), tos::pq::pq_bytes_hard_max).move_as_ok());
  cb.store_bits_bool(bits_from("adnl-" + std::to_string(index)).cbits(), 256);
  return cb.finalize();
}

// The classical elector record as the contract writes it today: stake, timestamp,
// max_factor, controller address and ADNL address, with no key blob because the key is
// the dictionary key. Measured so the post-quantum number can be read as a delta rather
// than as a verdict on a limit that may already bind.
td::Ref<vm::Cell> classical_member_record(std::size_t index) {
  vm::CellBuilder cb;
  cb.store_long(8, 4);
  cb.store_long(100000000000ll, 64);
  cb.store_long(1789434000, 32);
  cb.store_long(0x10000, 32);
  cb.store_bits_bool(bits_from("controller-" + std::to_string(index)).cbits(), 256);
  cb.store_bits_bool(bits_from("adnl-" + std::to_string(index)).cbits(), 256);
  return cb.finalize();
}

// What a past election freezes per member: controller, weight, stake, banned flag. No
// key, in either design, which is why past elections are not part of the key problem.
td::Ref<vm::Cell> frozen_record(std::size_t index) {
  vm::CellBuilder cb;
  cb.store_bits_bool(bits_from("controller-" + std::to_string(index)).cbits(), 256);
  cb.store_long(1, 64);
  cb.store_long(8, 4);
  cb.store_long(100000000000ll, 64);
  cb.store_long(0, 1);
  return cb.finalize();
}

td::Ref<vm::Cell> classical_dict(std::size_t count, bool frozen) {
  vm::Dictionary dict{256};
  for (std::size_t i = 0; i < count; i++) {
    auto key = bits_from("classical-" + std::to_string(i));
    auto ok = dict.set_ref(key.cbits(), 256, frozen ? frozen_record(i) : classical_member_record(i),
                           vm::Dictionary::SetMode::Add);
    assert(ok);
  }
  return dict.get_root_cell();
}

struct ElectorState {
  td::Ref<vm::Cell> members;
  td::Ref<vm::Cell> key_owner;
};

ElectorState elector_state(std::size_t count, const std::vector<std::string>& keys) {
  vm::Dictionary members{256};
  vm::Dictionary key_owner{256};
  for (std::size_t i = 0; i < count; i++) {
    auto validator_id = bits_from("validator-" + std::to_string(i));
    auto derived = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, keys[i]);
    assert(derived.has_value());
    td::Bits256 key_id_bits;
    std::memcpy(key_id_bits.data(), derived->data(), derived->size());

    auto added = members.set_ref(validator_id.cbits(), 256, member_record(i, keys[i]), vm::Dictionary::SetMode::Add);
    assert(added);
    vm::CellBuilder owner;
    owner.store_bits_bool(validator_id.cbits(), 256);
    added = key_owner.set_builder(key_id_bits.cbits(), 256, owner, vm::Dictionary::SetMode::Add);
    assert(added);
  }
  return ElectorState{members.get_root_cell(), key_owner.get_root_cell()};
}

void report(const char* what, std::size_t count, const Size& size, unsigned long long limit) {
  std::printf("%-34s %4zu  cells=%-7llu bits=%-9llu  %5.2fx an ordinary account's %llu  (%.0f TOS/yr if billed)\n",
              what, count, size.cells, size.bits, static_cast<double>(size.cells) / static_cast<double>(limit), limit,
              nanotomi_per_year(size) / 1e9);
}

}  // namespace

int main() {
  std::vector<std::string> keys;
  keys.reserve(400);
  for (std::size_t i = 0; i < 400; i++) {
    keys.push_back(distinct_key(i, tos::pq::mldsa44_public_key_bytes));
  }

  std::printf("== Config34 validator set in the configuration account ==\n");
  std::printf("   yardstick: max_mc_acc_state_cells = %llu, what an ORDINARY masterchain account may\n",
              ordinary_mc_account_state_cell_limit);
  std::printf("   hold. It is NOT enforced here: these are special accounts, exempted by the action\n");
  std::printf("   phase in both executors, and not billed for storage either. Nothing below is a\n");
  std::printf("   limit being approached; it is state every node carries.\n\n");
  for (std::size_t count : {21u, 45u, 100u, 400u}) {
    std::vector<td::Ref<vm::Cell>> pq, classical;
    for (std::size_t i = 0; i < count; i++) {
      pq.push_back(pq_descriptor(i, keys[i]));
      classical.push_back(classical_descriptor(i));
    }
    auto pq_size = measure(validator_set(pq));
    auto classical_size = measure(validator_set(classical));
    report("post-quantum set, validators", count, pq_size, ordinary_mc_account_state_cell_limit);
    report("classical set, validators", count, classical_size, ordinary_mc_account_state_cell_limit);
    // The configuration account rotates 36 -> 34 -> 32 and only then drops 36, so between
    // an election closing and the next set activating it holds three sets at once. The
    // peak is what has to fit, not the steady state.
    Size both{pq_size.cells * 2, pq_size.bits * 2};
    report("post-quantum 34+36", count, both, ordinary_mc_account_state_cell_limit);
    Size peak{pq_size.cells * 3, pq_size.bits * 3};
    report("post-quantum 32+34+36 peak", count, peak, ordinary_mc_account_state_cell_limit);
    std::printf("\n");
  }

  std::printf("== Elector active election: members + key_owner ==\n\n");
  for (std::size_t count : {21u, 100u, 400u}) {
    auto state = elector_state(count, keys);
    auto members = measure(state.members);
    auto owner = measure(state.key_owner);
    Size total{members.cells + owner.cells, members.bits + owner.bits};
    report("members dictionary, candidates", count, members, ordinary_mc_account_state_cell_limit);
    report("key_owner reverse index", count, owner, ordinary_mc_account_state_cell_limit);
    report("elector registration total", count, total, ordinary_mc_account_state_cell_limit);
    auto classical_members = measure(classical_dict(count, false));
    auto classical_frozen = measure(classical_dict(count, true));
    report("classical members (today)", count, classical_members, ordinary_mc_account_state_cell_limit);
    report("one past election, frozen", count, classical_frozen, ordinary_mc_account_state_cell_limit);
    std::printf("\n");
  }

  std::printf("== One stake request message body ==\n\n");
  {
    vm::CellBuilder cb;
    cb.store_long(tos::pq::elector_pq_stake_op, 32);
    cb.store_long(0, 64);  // query_id
    cb.store_long(1, 16);  // algorithm_id
    cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(keys[0]), tos::pq::pq_bytes_hard_max).move_as_ok());
    cb.store_long(1789434000, 32);  // stake_at
    cb.store_long(0x10000, 32);     // max_factor
    cb.store_bits_bool(bits_from("adnl-0").cbits(), 256);
    auto signature = distinct_key(1000, tos::pq::mldsa44_signature_bytes);
    cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(signature), tos::pq::pq_bytes_hard_max).move_as_ok());
    auto size = measure(cb.finalize());
    std::printf("%-34s %4s  cells=%-7llu bits=%-9llu  %5.1f%% of %llu cells, %4.1f%% of %llu bits\n",
                "key 1312 B + signature 2420 B", "", size.cells, size.bits,
                100.0 * static_cast<double>(size.cells) / static_cast<double>(message_cell_limit), message_cell_limit,
                100.0 * static_cast<double>(size.bits) / static_cast<double>(message_bit_limit), message_bit_limit);
  }

  std::printf("\nVALIDATOR_STATE_MEASURE_DONE\n");
  return 0;
}
