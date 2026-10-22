/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>
#include <chrono>
#include <thread>

#include "block/auth-policy.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "crypto/pq/pq-bytes.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"
#include "vm/dict.h"

#include "control-getter-executor.h"
#include "json-rpc-explorer.h"
using namespace tos::explorer;
namespace {
td::Ref<vm::Cell> code(const std::string& family) {
  for (const auto& entry : registry())
    if (entry.family == family)
      return entry.code;
  CHECK(false);
  return {};
}
td::Ref<vm::Cell> key(std::size_t size) {
  std::string bytes(size, 'k');
  td::Ref<vm::Cell> tail;
  while (size) {
    auto count = size % 127;
    if (!count)
      count = 127;
    size -= count;
    vm::CellBuilder builder;
    builder.store_bytes(td::Slice(bytes.data() + size, count));
    if (tail.not_null())
      builder.store_ref(tail);
    tail = builder.finalize();
  }
  return tail;
}
td::Ref<vm::Cell> module_data() {
  return vm::CellBuilder()
      .store_long(1, 8)
      .store_long(42, 32)
      .store_bits(registry_network_tag().cbits(), 256)
      .store_long(1, 8)
      .store_ref(key(1312))
      .store_zeroes(256)
      .store_long(2, 8)
      .finalize();
}
td::Ref<vm::Cell> fee_public_key() {
  return vm::CellBuilder().store_long(1, 32).store_long(8, 32).store_long(3, 32).store_zeroes(384).finalize();
}
td::Ref<vm::Cell> fee() {
  return vm::CellBuilder()
      .store_long(1, 8)
      .store_long(1, 8)
      .store_zeroes(256)
      .store_long(123, 32)
      .store_long(3600, 32)
      .store_long(4, 16)
      .store_ref(fee_public_key())
      .finalize();
}
td::Ref<vm::Cell> wallet_data(td::Ref<vm::Cell> module_code) {
  auto witness = vm::CellBuilder().store_long(6, 5).store_ref(module_code).store_ref(module_data()).finalize();
  auto auth = vm::CellBuilder()
                  .store_long(4, 8)
                  .store_long(2, 2)
                  .store_long(0xffff, 16)
                  .store_long(-1, 64)
                  .store_long(-1, 64)
                  .store_long(-1, 64)
                  .store_ref(witness)
                  .store_ref(fee())
                  .finalize();
  return vm::CellBuilder()
      .store_long(0, 1)
      .store_long(0xffffffff, 32)
      .store_long(0xffffffff, 32)
      .store_zeroes(256)
      .store_long(0, 1)
      .store_ref(auth)
      .finalize();
}
td::Ref<vm::Cell> vault_data(bool wrong_parties = false, bool wrong_module = false) {
  auto parties = vm::CellBuilder().store_long(4, 3).store_long(0, 8).store_zeroes(512).finalize();
  auto prefix = vm::CellBuilder()
                    .store_long(0x41553252, 32)
                    .store_long(42, 32)
                    .store_zeroes(248)
                    .store_long(123, 8)
                    .store_long(4, 3)
                    .store_long(0, 8)
                    .store_zeroes(256)
                    .store_zeroes(248)
                    .store_long(wrong_module ? 1 : 0, 8)
                    .store_long(2, 8)
                    .finalize();
  vm::CellBuilder root;
  root.store_long(3, 8)
      .store_long(1048576, 32)
      .store_zeroes(256)
      .store_long(123, 32)
      .store_long(4, 3)
      .store_long(0, 8)
      .store_zeroes(256);
  if (wrong_parties)
    root.store_zeroes(256);
  else
    root.store_bits(parties->get_hash().bits(), 256);
  return root.store_ref(fee_public_key()).store_ref(prefix).finalize();
}
void expect_state_invalid(const std::string& family, td::Ref<vm::Cell> data) {
  auto result = decode_public_state(code(family), data);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().code(), static_cast<int>(Failure::StateInvalid));
}
}  // namespace
TEST(JsonRpcExplorer, selectors_are_strict_and_pin_all_hashes) {
  td::Bits256 address_hash;
  address_hash.as_slice().fill(static_cast<char>(0xab));
  ASSERT_EQ(raw_address(0, address_hash),
            std::string("0:") + std::string("abababababababababababababababababababababababababababababababab"));
  const tos::BlockIdExt id{-1, tos::shardIdAll, 12, td::Bits256::zero(), td::Bits256::zero()};
  for (auto text :
       {"{\"seqno\":true}", "{\"seqno\":1.2}", "{\"seqno\":2147483648}", "{\"seqno\":\"12\"}", "{\"seqno\":-1}"}) {
    std::string input(text);
    auto parsed = td::json_decode(td::MutableSlice(input));
    ASSERT_TRUE(parsed.is_ok());
    ASSERT_TRUE(parse_selector(parsed.ok().get_object(), true).is_error());
  }
  std::string input = "{\"seqno\":12,\"block_id\":" + block_json(id) + "}";
  auto parsed = td::json_decode(td::MutableSlice(input));
  ASSERT_TRUE(parsed.is_ok());
  auto selected = parse_selector(parsed.ok().get_object(), true);
  ASSERT_TRUE(selected.is_ok());
  ASSERT_TRUE(selected.ok().check(id).is_ok());
  auto fork = id;
  fork.file_hash.as_slice()[0] = 1;
  auto failure = selected.ok().check(fork);
  ASSERT_TRUE(failure.is_error());
  ASSERT_EQ(failure.code(), static_cast<int>(Failure::BlockIdMismatch));
  fork = id;
  fork.root_hash.as_slice()[0] = 1;
  ASSERT_TRUE(selected.ok().check(fork).is_error());
  input = "{\"seqno\":13,\"block_id\":" + block_json(id) + "}";
  parsed = td::json_decode(td::MutableSlice(input));
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(parse_selector(parsed.ok().get_object(), true).is_error());
  input = "{\"seqno\":0}";
  parsed = td::json_decode(td::MutableSlice(input));
  ASSERT_TRUE(parsed.is_ok());
  selected = parse_selector(parsed.ok().get_object());
  ASSERT_TRUE(selected.is_ok());
  ASSERT_TRUE(selected.ok().seqno.has_value());
  ASSERT_EQ(*selected.ok().seqno, 0);
  ASSERT_TRUE(parse_hash(std::string(42, 'A') + "B=").is_error());  // noncanonical pad bits
}
TEST(JsonRpcExplorer, exact_registry_precedes_public_state_decoding) {
  ASSERT_EQ(registry().size(), 6u);
  auto data = module_data();
  auto unknown_code = vm::CellBuilder().store_long(1, 1).finalize();
  auto unknown = decode_public_state(unknown_code, data);
  ASSERT_TRUE(unknown.is_ok());
  ASSERT_TRUE(unknown.ok().family.empty());
  auto absent = decode_public_state({}, {});
  ASSERT_TRUE(absent.is_ok());
  ASSERT_TRUE(absent.ok().family.empty());
  for (const auto& entry : registry())
    expect_state_invalid(entry.family, vm::CellBuilder().finalize());
  auto module = decode_public_state(code("quantum_module_v1"), data);
  ASSERT_TRUE(module.is_ok());
  ASSERT_TRUE(module.ok().json.find("\"policy\":\"required\"") != std::string::npos);
  auto wallet = decode_public_state(code("quantum_wallet_v4"), wallet_data(code("quantum_module_v1")));
  ASSERT_TRUE(wallet.is_ok());
  ASSERT_EQ(wallet.ok().seqno.value(), 0xffffffffu);
  ASSERT_TRUE(wallet.ok().json.find("18446744073709551615") != std::string::npos);
  ASSERT_TRUE(wallet.ok().json.find("\"retired_flags\":65535") != std::string::npos);
  expect_state_invalid("quantum_wallet_v4", wallet_data(unknown_code));
  auto vault = decode_public_state(code("quantum_fee_vault_v3"), vault_data());
  ASSERT_TRUE(vault.is_ok());
  ASSERT_TRUE(vault.ok().json.find("\"next_leaf\":1048576") != std::string::npos);
  expect_state_invalid("quantum_fee_vault_v3", vault_data(true));
  expect_state_invalid("quantum_fee_vault_v3", vault_data(false, true));
  auto ml = vm::CellBuilder().store_long(-239, 32).store_ref(key(1312)).finalize();
  ASSERT_TRUE(decode_public_state(code("mldsa44_auth_module_v1"), ml).is_ok());
  auto falcon = vm::CellBuilder().store_long(-239, 32).store_long(1, 16).store_ref(key(897)).finalize();
  ASSERT_TRUE(decode_public_state(code("falcon512_padded_auth_module_v1"), falcon).is_ok());
  auto high_key = tos::pq::pack_pq_bytes(td::Slice(std::string(1312, 'k')), 1312);
  ASSERT_TRUE(high_key.is_ok());
  auto high = vm::CellBuilder()
                  .store_long(0xffffffff, 32)
                  .store_long(0, 2)
                  .store_long(-1, 64)
                  .store_long(0x3fffff, 22)
                  .store_ref(high_key.ok())
                  .finalize();
  auto high_state = decode_public_state(code("pq_highload_mldsa44_v1"), high);
  ASSERT_TRUE(high_state.is_ok());
  ASSERT_TRUE(!high_state.ok().seqno.has_value());
  auto trailing = vm::CellBuilder().append_cellslice(vm::load_cell_slice(ml)).store_long(0, 1).finalize();
  expect_state_invalid("mldsa44_auth_module_v1", trailing);
  expect_state_invalid("mldsa44_auth_module_v1", vm::CellBuilder().store_long(42, 32).store_ref(key(1311)).finalize());
}
TEST(JsonRpcExplorer, inspection_has_depth_and_exotic_limits) {
  auto data = vm::CellBuilder().finalize();
  for (unsigned i = 0; i < 128; ++i)
    data = vm::CellBuilder().store_ref(data).finalize();
  ASSERT_TRUE(inspect_cells({}, data).is_ok());
  data = vm::CellBuilder().store_ref(data).finalize();
  auto result = inspect_cells({}, data);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.code(), static_cast<int>(Failure::ResourceLimit));
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  result = inspect_cells({}, library);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.code(), static_cast<int>(Failure::StateInvalid));
}
TEST(JsonRpcExplorer, config_absence_defaults_and_retirement_are_exact) {
  auto absent = decode_config(43, {}, 16, 1000);
  ASSERT_TRUE(absent.is_ok());
  ASSERT_TRUE(absent.ok().find("\"wire_version\":null,\"configured\":null") != std::string::npos);
  ASSERT_TRUE(absent.ok().find("\"max_ext_msg_size\":65535") != std::string::npos);
  for (unsigned wire : {1u, 2u, 3u}) {
    vm::CellBuilder builder;
    builder.store_long(wire, 8)
        .store_long(100, 32)
        .store_long(200, 32)
        .store_long(300, 32)
        .store_long(400, 16)
        .store_long(500, 32)
        .store_long(600, 16);
    if (wire >= 2)
      builder.store_long(700, 32)
          .store_long(800, 32)
          .store_long(900, 32)
          .store_long(1000, 32)
          .store_long(1100, 32)
          .store_long(8, 8)
          .store_long(1300, 32);
    if (wire == 3)
      builder.store_long(0, 1).store_long(1400, 32).store_long(1500, 32).store_long(1600, 32).store_long(1700, 32);
    auto decoded = decode_config(43, builder.finalize(), 16, 1000);
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_TRUE(decoded.ok().find("\"wire_version\":" + std::to_string(wire)) != std::string::npos);
    if (wire == 3) {
      ASSERT_TRUE(decoded.ok().find("\"defaulted_fields\":[]") != std::string::npos);
      ASSERT_TRUE(decoded.ok().find("\"out_msg_queue_size_hard_limit\":1600,\"out_msg_queue_size_soft_limit\":1700}") !=
                  std::string::npos);
    } else {
      ASSERT_TRUE(decoded.ok().find("\"out_msg_queue_size_soft_limit\"]") != std::string::npos);
    }
  }
  ASSERT_TRUE(decode_config(8, {}, 16, 1000).is_error());
  ASSERT_TRUE(decode_config(48, {}, 15, 1000).is_ok());
  auto missing = decode_config(48, {}, 16, 1000);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().code(), static_cast<int>(Failure::StateInvalid));
  td::Bits256 profile;
  td::sha256(block::auth_policy_profile, profile.as_slice());
  auto policy = vm::CellBuilder()
                    .store_long(0xa1, 8)
                    .store_zeroes(256)
                    .store_long(-1, 64)
                    .store_long(2, 16)
                    .store_long(0, 1)
                    .store_bits(profile.cbits(), 256)
                    .finalize();
  auto decoded = decode_config(48, policy, 16, 1000);
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_TRUE(decoded.ok().find("\"primary_status\":\"retired\"") != std::string::npos);
  vm::Dictionary controllers(256);
  for (unsigned i = 0; i < 9; ++i) {
    td::Bits256 hash;
    hash.set_zero();
    hash.as_slice()[31] = static_cast<char>(i);
    ASSERT_TRUE(controllers.set(hash.cbits(), 256, vm::load_cell_slice_ref(vm::CellBuilder().finalize())));
    vm::CellBuilder builder;
    ASSERT_TRUE(builder.store_maybe_ref(controllers.get_root_cell()));
    auto cell = builder.finalize();
    auto result = decode_config(47, cell, 17, 1000);
    ASSERT_EQ(result.is_ok(), i < 8);
  }
}
TEST(JsonRpcExplorer, policy_deadline_uses_authenticated_chain_time) {
  vm::Dictionary deadlines(8);
  td::BitArray<8> primary{1};
  ASSERT_TRUE(
      deadlines.set(primary.cbits(), 8, vm::load_cell_slice_ref(vm::CellBuilder().store_long(1000, 32).finalize())));
  td::Bits256 profile;
  td::sha256(block::auth_policy_profile, profile.as_slice());
  auto policy = vm::CellBuilder()
                    .store_long(0xa1, 8)
                    .store_zeroes(256)
                    .store_long(1, 64)
                    .store_long(0, 16)
                    .store_long(1, 1)
                    .store_bits(profile.cbits(), 256)
                    .store_ref(deadlines.get_root_cell())
                    .finalize();
  auto before = decode_config(48, policy, 16, 999);
  ASSERT_TRUE(before.is_ok());
  ASSERT_TRUE(before.ok().find("\"primary_status\":\"not_retired\"") != std::string::npos);
  auto at_deadline = decode_config(48, policy, 16, 1000);
  ASSERT_TRUE(at_deadline.is_ok());
  const bool at_deadline_retired = at_deadline.ok().find("\"primary_status\":\"retired\"") != std::string::npos;
  ASSERT_TRUE(at_deadline_retired);
  auto after = decode_config(48, policy, 16, 1001);
  ASSERT_TRUE(after.is_ok());
  ASSERT_TRUE(after.ok().find("\"primary_status\":\"retired\"") != std::string::npos);
}
TEST(JsonRpcExplorer, cancelled_running_jobs_keep_process_permits) {
  const auto jobs = WorkPermit::limit();
  auto executor = tos::control_getter::Executor::create(0, jobs);
  ASSERT_TRUE(executor.is_ok());
  std::atomic<unsigned> started{0}, finished{0};
  std::atomic<bool> release{false};
  std::vector<std::unique_ptr<tos::control_getter::Executor::Admission>> admissions;
  for (unsigned i = 0; i < jobs; ++i) {
    auto permit = WorkPermit::acquire();
    ASSERT_TRUE(permit != nullptr);
    auto admission = executor.ok()->admit();
    ASSERT_TRUE(admission.is_ok());
    auto result = dispatch_work(
        *admission.ok(), permit,
        [&started, &release] {
          ++started;
          while (!release.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          return td::Status::OK();
        },
        [&finished](td::Status status) {
          ASSERT_TRUE(status.is_ok());
          ++finished;
        });
    ASSERT_TRUE(result.is_ok());
    admissions.push_back(admission.move_as_ok());
  }
  for (unsigned i = 0; i < 3000 && started < jobs; ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  ASSERT_EQ(started.load(), jobs);
  for (auto& admission : admissions)
    admission->cancel();
  admissions.clear();
  auto premature = WorkPermit::acquire();
  auto queued = executor.ok()->admit();
  release = true;
  executor.ok()->shutdown();
  ASSERT_EQ(finished.load(), jobs);
  ASSERT_TRUE(premature == nullptr);
  ASSERT_TRUE(queued.is_error());
  std::vector<std::shared_ptr<WorkPermit>> recovered;
  for (unsigned i = 0; i < jobs; ++i) {
    auto permit = WorkPermit::acquire();
    ASSERT_TRUE(permit != nullptr);
    recovered.push_back(std::move(permit));
  }
  ASSERT_TRUE(WorkPermit::acquire() == nullptr);
}

TEST(JsonRpcExplorer, ordinary_predecessor_requires_the_backward_state_proof) {
  auto bytes = td::read_file(EXPLORER_TEST_DATA_DIR "/ordinary-predecessor.tl");
  auto metadata = td::read_file(EXPLORER_TEST_DATA_DIR "/ordinary-predecessor.json");
  ASSERT_TRUE(bytes.is_ok());
  ASSERT_TRUE(metadata.is_ok());
  auto metadata_bytes = metadata.move_as_ok();
  auto document = td::json_decode(metadata_bytes.as_slice());
  ASSERT_TRUE(document.is_ok());
  auto root = document.move_as_ok();
  auto anchor_json = root.get_object().extract_required_field("anchor", td::JsonValue::Type::Object);
  auto target_json = root.get_object().extract_required_field("target", td::JsonValue::Type::Object);
  ASSERT_TRUE(anchor_json.is_ok() && target_json.is_ok());
  auto anchor = parse_selector(anchor_json.ok().get_object(), true);
  auto target = parse_selector(target_json.ok().get_object(), true);
  ASSERT_TRUE(anchor.is_ok() && target.is_ok());
  auto verified = inspect_finality_reply(bytes.ok().clone(), *anchor.ok().block_id, *target.ok().block_id, true);
  ASSERT_TRUE(verified.is_ok());
  auto object = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(bytes.ok().clone(), true);
  ASSERT_TRUE(object.is_ok());
  ASSERT_EQ(object.ok()->steps_.size(), 2u);
  ASSERT_EQ(object.ok()->steps_[0]->get_id(), tos::lite_api::liteServer_blockLinkBack::ID);
  ASSERT_EQ(object.ok()->steps_[1]->get_id(), tos::lite_api::liteServer_blockLinkForward::ID);
  auto& backward = static_cast<tos::lite_api::liteServer_blockLinkBack&>(*object.ok()->steps_[0]);
  auto& forward = static_cast<tos::lite_api::liteServer_blockLinkForward&>(*object.ok()->steps_[1]);
  // A well-formed Merkle proof of the key block's state cannot authenticate
  // the ordinary predecessor's state. Skipping backward-link validation must
  // make this very rejection go red while the final certificate remains valid.
  backward.state_proof_ = forward.config_proof_.clone();
  auto altered = tos::serialize_tl_object(object.ok(), true);
  auto refused = inspect_finality_reply(std::move(altered), *anchor.ok().block_id, *target.ok().block_id, false);
  ASSERT_TRUE(refused.is_error());
  ASSERT_EQ(refused.error().code(), static_cast<int>(Failure::EvidenceInvalid));
}

TEST(JsonRpcExplorer, native_failures_map_without_matching_diagnostic_strings) {
  auto missing = upstream_error(td::Status::Error(tos::ErrorCode::notready, "unrelated bounded diagnostic"));
  auto timeout = upstream_error(td::Status::Error(tos::ErrorCode::timeout, "same bounded diagnostic"));
  ASSERT_EQ(missing.code(), static_cast<int>(Failure::BlockUnavailable));
  ASSERT_EQ(timeout.code(), static_cast<int>(Failure::UpstreamUnavailable));
  ASSERT_TRUE(!retryable(missing));
  ASSERT_TRUE(retryable(timeout));
}

// Signature evidence for a block is built from that block's state and its
// predecessor's. Once the node has garbage-collected either, the query path
// fails with a plain error code; only the shared message tells it apart from a
// transient fault, and it is a history limit, not something a retry can fix.
TEST(JsonRpcExplorer, garbage_collected_evidence_is_unavailable_history) {
  auto gone = upstream_error(td::Status::Error(tos::ErrorCode::error, td::Slice(tos::kStateGarbageCollected)));
  ASSERT_EQ(gone.code(), static_cast<int>(Failure::BlockUnavailable));
  ASSERT_TRUE(!retryable(gone));
  ASSERT_EQ(std::string(error_kind(gone).reason), "BLOCK_UNAVAILABLE");
  ASSERT_EQ(error_kind(gone).code, -32004);
  auto other = upstream_error(td::Status::Error(tos::ErrorCode::error, "connection reset"));
  ASSERT_EQ(other.code(), static_cast<int>(Failure::UpstreamUnavailable));
  ASSERT_TRUE(retryable(other));
}
