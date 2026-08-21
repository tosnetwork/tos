/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.
*/

// =============================================================================
// Slice 6 Stage 1 delivery-failure foundation fixtures.
//
// These are predicate-level fixtures for https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-delivery-sla-policy.md v0.2.
// They do not activate delivery-SLA protocol behavior; they lock the canonical
// cell shapes that later scheduler/monitor/supervision stages will reference.
// =============================================================================

#include "crypto/vm/boc.h"
#include "td/utils/tests.h"
#include "tol/extra-flags-constants.h"
#include "vm/cells.h"
#include "vm/cells/CellSlice.h"

#include <array>
#include <cstdint>

namespace {

constexpr td::uint32 kDeliveryIdInputTag = 0xd601;
constexpr td::uint32 kBackPressureAdviceTag = 0xb601;

std::array<td::uint8, 32> make_hash(td::uint8 fill) {
  std::array<td::uint8, 32> h;
  h.fill(fill);
  return h;
}

void store_hash(vm::CellBuilder& cb, const std::array<td::uint8, 32>& hash) {
  for (auto byte : hash) {
    cb.store_long(byte, 8);
  }
}

void store_std_addr(vm::CellBuilder& cb, td::int8 workchain, const std::array<td::uint8, 32>& hash) {
  cb.store_long(0b10, 2);  // addr_std
  cb.store_long(0, 1);     // no anycast
  cb.store_long(workchain, 8);
  store_hash(cb, hash);
}

void store_coins(vm::CellBuilder& cb, td::uint64 nanotomis) {
  if (nanotomis == 0) {
    cb.store_long(0, 4);
    return;
  }
  int bytes = 0;
  for (auto v = nanotomis; v != 0; v >>= 8) {
    ++bytes;
  }
  cb.store_long(bytes, 4);
  for (int i = bytes - 1; i >= 0; --i) {
    cb.store_long(static_cast<td::uint8>((nanotomis >> (i * 8)) & 0xff), 8);
  }
}

td::Ref<vm::Cell> build_origin(td::uint16 action_index) {
  vm::CellBuilder cb;
  cb.store_long(12345678901LL, 64);
  store_hash(cb, make_hash(0x01));
  cb.store_long(action_index, 16);
  cb.store_long(0, 8);   // attempt_kind = immediate
  cb.store_long(0, 16);  // attempt_seq
  return cb.finalize();
}

td::Ref<vm::Cell> build_route(td::uint16 extra_flags = 0) {
  vm::CellBuilder cb;
  store_std_addr(cb, 0, make_hash(0xaa));
  store_std_addr(cb, 0, make_hash(0xbb));
  cb.store_long(0, 16);  // send_mode
  cb.store_long(extra_flags, 16);
  return cb.finalize();
}

td::Ref<vm::Cell> build_payload(td::uint32 body_marker = 0xcc) {
  vm::CellBuilder body;
  body.store_long(body_marker, 32);
  const auto body_hash = body.finalize()->get_hash().as_array();

  vm::CellBuilder cb;
  store_coins(cb, 1000000000ULL);
  cb.store_long(0, 1);  // empty extra-currency dictionary
  cb.store_long(0, 1);  // state_init_hash = none
  store_hash(cb, body_hash);
  cb.store_long(0, 32);  // not_before_mc_seqno
  cb.store_long(0, 32);  // expire_after_blocks
  return cb.finalize();
}

td::Ref<vm::Cell> build_delivery_id_input(td::uint16 action_index, td::uint16 extra_flags = 0,
                                          td::uint32 body_marker = 0xcc) {
  vm::CellBuilder cb;
  cb.store_long(kDeliveryIdInputTag, 16);
  cb.store_ref(build_origin(action_index));
  cb.store_ref(build_route(extra_flags));
  cb.store_ref(build_payload(body_marker));
  return cb.finalize();
}

td::Ref<vm::Cell> build_back_pressure_advice(td::Ref<vm::Cell> delivery_input, td::uint8 bucket,
                                             td::uint32 retry_blocks) {
  vm::CellBuilder cb;
  cb.store_long(kBackPressureAdviceTag, 16);
  store_hash(cb, delivery_input->get_hash().as_array());
  cb.store_long(bucket, 8);
  cb.store_long(1, 8);  // shard-route scope
  cb.store_long(retry_blocks, 32);
  cb.store_long(120, 32);
  store_hash(cb, make_hash(0xab));
  return cb.finalize();
}

}  // namespace

TEST(Slice6Stage1DeliveryFixtures, StableDeliveryIdForSameAttempt) {
  auto a = build_delivery_id_input(0);
  auto b = build_delivery_id_input(0);
  CHECK(a->get_hash() == b->get_hash());
}

TEST(Slice6Stage1DeliveryFixtures, ActionIndexChangesDeliveryId) {
  auto a = build_delivery_id_input(0);
  auto b = build_delivery_id_input(1);
  CHECK(a->get_hash() != b->get_hash());
}

TEST(Slice6Stage1DeliveryFixtures, RefPackedDeliveryIdInputFitsCellBounds) {
  auto root = build_delivery_id_input(0);
  auto root_cs = vm::load_cell_slice(root);
  CHECK(root_cs.size() == 16);
  CHECK(root_cs.size_refs() == 3);
  CHECK(root->get_depth() > 0);

  auto route = build_route();
  auto route_cs = vm::load_cell_slice(route);
  CHECK(route_cs.size() <= 1023);
  CHECK(route_cs.size_refs() <= 4);
}

TEST(Slice6Stage1DeliveryFixtures, BackPressureAdviceRoundtrip) {
  auto delivery_input = build_delivery_id_input(0);
  auto advice = build_back_pressure_advice(delivery_input, 2, 10);
  auto boc = vm::std_boc_serialize(advice, 0);
  CHECK(boc.is_ok());
  auto parsed = vm::std_boc_deserialize(boc.ok().as_slice());
  CHECK(parsed.is_ok());

  auto cs = vm::load_cell_slice(parsed.move_as_ok());
  CHECK(cs.fetch_ulong(16) == kBackPressureAdviceTag);
  cs.skip_first(256);  // delivery_id
  CHECK(cs.fetch_ulong(8) == 2);
  cs.skip_first(8);  // scope
  CHECK(cs.fetch_ulong(32) == 10);
}

TEST(Slice6Stage1DeliveryFixtures, Stage1DoesNotActivateExtraFlagsBit3) {
  CHECK(tol::EXTRA_FLAGS_VALID_MASK == 3);
  CHECK((8 & tol::EXTRA_FLAGS_VALID_MASK) != 8);
}
