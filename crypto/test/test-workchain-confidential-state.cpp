#include "block/workchain-confidential-state.h"
#include "block/workchain-coordinator-state.h"
#include "td/utils/tests.h"
#include "td/utils/misc.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "vm/boc.h"
#include "block/workchain-confidential-input.h"
#include "block/workchain-confidential-native.h"
#include "block/block-parse.h"
#include "block/transaction.h"

namespace {
td::Bits256 bits(unsigned value) {
  td::Bits256 result;
  result.set_zero();
  result.as_slice()[31] = static_cast<char>(value);
  return result;
}
td::Bits256 public_point() {
  auto bytes = td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76");
  CHECK(bytes.is_ok());
  td::Bits256 result;
  result.as_slice().copy_from(bytes.ok());
  return result;
}
block::WorkchainConfidentialAccount account() {
  return {1, 1, 2, -23903, bits(1), {2, bits(2), bits(3)}, {bits(4), bits(5), bits(6)},
      {10000000000ULL, 0, bits(7)}, public_point(), 0, {bits(0), bits(0)}, 0, 0, {}, block::WorkchainAccountActive{}};
}
block::WorkchainPendingReceipt receipt(unsigned index) {
  auto id = block::derive_workchain_receipt_id(bits(9), bits(10), index);
  CHECK(id.is_ok());
  return {id.move_as_ok(), {2, bits(8), bits(9)}, 11, bits(3), 0, bits(4),
      {public_point(), public_point()}, bits(10), index, 0};
}
void sort_pending(block::WorkchainConfidentialAccount& value) {
  std::sort(value.pending.begin(), value.pending.end(),
      [](const auto& a, const auto& b) { return a.receipt_id < b.receipt_id; });
}
}

TEST(ConfidentialState, ReceiptIdentityAndRecovery) {
  auto r = receipt(0);
  auto encoded = block::encode_workchain_pending_receipt(r);
  ASSERT_TRUE(encoded.is_ok());
  auto decoded = block::decode_workchain_pending_receipt(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().source.workchain_id, 2);
  ASSERT_EQ(decoded.ok().source.account, bits(8));
  ASSERT_EQ(decoded.ok().source.instance, bits(9));
  ASSERT_EQ(decoded.ok().source_operation_nonce, 11u);
  ASSERT_EQ(decoded.ok().target_instance, bits(3));
  ASSERT_EQ(decoded.ok().target_key_epoch, 0u);
  ASSERT_EQ(decoded.ok().asset, bits(4));
  ASSERT_EQ(decoded.ok().ciphertext.commitment, public_point());
  ASSERT_EQ(decoded.ok().ciphertext.handle, public_point());
  ASSERT_EQ(decoded.ok().operation_id, bits(10));
  ASSERT_EQ(decoded.ok().output_index, 0u);
  ASSERT_EQ(decoded.ok().status, 0u);
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(12), bits(10), 0).move_as_ok() != r.receipt_id);
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(9), bits(10), 1).move_as_ok() != r.receipt_id);
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(9), bits(10), UINT32_MAX).is_ok());
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(9), bits(10), std::uint64_t{1} << 32).is_error());
  r.receipt_id = bits(0);
  ASSERT_TRUE(block::encode_workchain_pending_receipt(r).is_error());
  block::gen::UnoV2PendingReceipt::Record_uno_v2_pending_receipt raw;
  ASSERT_TRUE(block::resource_policy_detail::unpack_exact(encoded.ok(), raw));
  raw.receipt_id = bits(0);
  td::Ref<vm::Cell> malformed;
  ASSERT_TRUE(tlb::pack_cell(malformed, raw));
  auto bad = block::decode_workchain_pending_receipt(malformed);
  ASSERT_TRUE(bad.is_error());
  ASSERT_EQ(bad.error().message(), "pending receipt identity mismatch");
}

TEST(ConfidentialState, AccountRoundtripAndLifecycle) {
  auto value = account();
  value.auth_nonce = UINT64_MAX;
  value.available_revision = UINT64_MAX;
  value.lifecycle = block::WorkchainAccountReadOnly{};
  for (unsigned i = 0; i < 16; ++i) value.pending.push_back(receipt(i));
  sort_pending(value);
  auto encoded = block::encode_workchain_confidential_account(value);
  ASSERT_TRUE(encoded.is_ok());
  std::reverse(value.pending.begin(), value.pending.end());
  ASSERT_EQ(block::encode_workchain_confidential_account(value).move_as_ok()->get_hash(), encoded.ok()->get_hash());
  auto decoded = block::decode_workchain_confidential_account(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  const auto& out = decoded.ok();
  ASSERT_EQ(out.schema_version, 1u);
  ASSERT_EQ(out.relation_profile, 1u);
  ASSERT_EQ(out.proof_profile, 2u);
  ASSERT_EQ(out.global_id, value.global_id);
  ASSERT_EQ(out.genesis_hash, value.genesis_hash);
  ASSERT_EQ(out.address.account, value.address.account);
  ASSERT_EQ(out.address.instance, value.address.instance);
  ASSERT_EQ(out.bindings.policy, value.bindings.policy);
  ASSERT_EQ(out.bindings.custody, value.bindings.custody);
  ASSERT_EQ(out.funding.paid_deposit, value.funding.paid_deposit);
  ASSERT_EQ(out.funding.refund_account, value.funding.refund_account);
  ASSERT_EQ(out.public_key, value.public_key);
  ASSERT_EQ(out.auth_nonce, UINT64_MAX);
  ASSERT_EQ(out.available_revision, UINT64_MAX);
  ASSERT_EQ(out.pending.size(), 16u);
  ASSERT_TRUE(std::holds_alternative<block::WorkchainAccountReadOnly>(out.lifecycle));
  ASSERT_EQ(block::encode_workchain_confidential_account(out).move_as_ok()->get_hash(), encoded.ok()->get_hash());
  for (const block::WorkchainConfidentialLifecycle& lifecycle : {
      block::WorkchainConfidentialLifecycle{block::WorkchainAccountActive{}},
      block::WorkchainConfidentialLifecycle{block::WorkchainAccountClosed{}},
      block::WorkchainConfidentialLifecycle{block::WorkchainAccountMigrated{{2, bits(18), bits(19)}, bits(20)}}}) {
    auto encoded_lifecycle = block::encode_workchain_account_lifecycle(lifecycle);
    ASSERT_TRUE(encoded_lifecycle.is_ok());
    auto decoded_lifecycle = block::decode_workchain_account_lifecycle(encoded_lifecycle.ok());
    ASSERT_TRUE(decoded_lifecycle.is_ok());
    ASSERT_EQ(decoded_lifecycle.ok().index(), lifecycle.index());
    ASSERT_EQ(block::encode_workchain_account_lifecycle(decoded_lifecycle.ok()).move_as_ok()->get_hash(),
              encoded_lifecycle.ok()->get_hash());
  }
}

TEST(ConfidentialState, RejectMalformedAndExcessiveState) {
  auto value = account();
  auto encoded = block::encode_workchain_confidential_account(value);
  ASSERT_TRUE(encoded.is_ok());  // Initial (0,0) ciphertext is canonical.
  auto bad_key = value;
  bad_key.public_key = bits(0);
  ASSERT_TRUE(block::encode_workchain_confidential_account(bad_key).is_error());
  bad_key.public_key = td::Bits256::ones();
  ASSERT_TRUE(block::encode_workchain_confidential_account(bad_key).is_error());
  value.available.commitment = td::Bits256::ones();
  ASSERT_TRUE(block::encode_workchain_confidential_account(value).is_error());
  ASSERT_TRUE(block::decode_workchain_confidential_account({}).is_error());
  ASSERT_TRUE(block::decode_workchain_confidential_account(vm::CellBuilder().store_long(0, 32).finalize()).is_error());
  ASSERT_TRUE(block::decode_workchain_account_lifecycle(vm::CellBuilder().store_long(0, 32).finalize()).is_error());
  block::gen::UnoV2AccountState::Record raw;
  ASSERT_TRUE(block::resource_policy_detail::unpack_exact(encoded.ok(), raw));
  for (unsigned defect = 0; defect < 4; ++defect) {
    auto changed = raw;
    if (defect == 0) changed.schema_version = 2;
    if (defect == 1) changed.pending_count = 1;
    if (defect == 2) changed.crypto = vm::CellBuilder().finalize();
    if (defect == 3) changed.lifecycle = vm::CellBuilder().store_long(0, 32).finalize();
    td::Ref<vm::Cell> bad;
    ASSERT_TRUE(tlb::pack_cell(bad, changed));
    ASSERT_TRUE(block::decode_workchain_confidential_account(bad).is_error());
  }
  value = account();
  for (unsigned i = 0; i < 17; ++i) value.pending.push_back(receipt(i));
  sort_pending(value);
  auto excessive = block::encode_workchain_confidential_account(value);
  ASSERT_TRUE(excessive.is_error());
  ASSERT_EQ(excessive.error().message(), "pending capacity exceeded");
  value.pending = {receipt(0), receipt(0)};
  ASSERT_TRUE(block::encode_workchain_confidential_account(value).is_error());
  value.pending = {receipt(0)};
  value.pending[0].target_instance = bits(18);
  ASSERT_TRUE(block::encode_workchain_confidential_account(value).is_error());
}

TEST(ConfidentialState, RegistrationDepositWire) {
  block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {0,2,2}, 1};
  auto business = vm::CellBuilder().finalize();
  for (std::uint64_t deposit : {std::uint64_t{0}, std::uint64_t{10000000000ULL}, std::uint64_t{UINT64_MAX}}) {
    auto encoded = block::encode_workchain_engine_parameters({400, bits(1), resources, business, deposit});
    ASSERT_TRUE(encoded.is_ok());
    auto cs = vm::load_cell_slice(encoded.ok());
    ASSERT_EQ(cs.size(), 384u);
    ASSERT_EQ(cs.fetch_ulong(32), block::gen::UnoV2EngineConfiguration::cons_tag[0]);
    ASSERT_EQ(cs.fetch_ulong(32), 400u);
    ASSERT_EQ(cs.fetch_ulong(64), deposit);  // Independent wire-order check.
    auto decoded = block::decode_workchain_engine_parameters(encoded.ok());
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.ok().registration_deposit, deposit);
  }
  auto policy = block::encode_workchain_resource_policy(resources).move_as_ok();
  auto old = vm::CellBuilder().store_long(0x41868cd4, 32).store_long(400, 32)
      .store_bits(bits(1).bits(), 256).store_ref(policy).store_ref(business).finalize();
  auto retired = block::decode_workchain_engine_parameters(old);
  ASSERT_TRUE(retired.is_error());
  ASSERT_EQ(retired.error().message(), "unrecognized engine configuration constructor tag");
  auto missing = vm::CellBuilder().store_long(block::gen::UnoV2EngineConfiguration::cons_tag[0], 32)
      .store_long(400, 32).store_bits(bits(1).bits(), 256).store_ref(policy).store_ref(business).finalize();
  auto incomplete = block::decode_workchain_engine_parameters(missing);
  ASSERT_TRUE(incomplete.is_error());
  ASSERT_EQ(incomplete.error().message(), "missing fields in registration_deposit layout");
  static_assert(!std::is_constructible_v<block::WorkchainEngineParameters, std::uint32_t, td::Bits256,
      block::WorkchainResourcePolicy, td::Ref<vm::Cell>>);
}

TEST(ConfidentialState, CoordinatorDepositMigration) {
  block::WorkchainCoordinatorState state{2, {1, 1000000, 3, 0}, 30000000000ULL};
  auto encoded = block::encode_workchain_coordinator_state(state);
  ASSERT_TRUE(encoded.is_ok());
  auto decoded = block::decode_workchain_coordinator_state(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().refundable_deposits, state.refundable_deposits);
  ASSERT_EQ(decoded.ok().system.registered_accounts, 3u);
  block::gen::UnoV2CoordinatorDeposits::Record raw;
  ASSERT_TRUE(block::resource_policy_detail::unpack_exact(encoded.ok(), raw));
  auto missing = vm::CellBuilder().store_long(block::gen::UnoV2CoordinatorDeposits::cons_tag[0], 32)
      .store_long(2, 16).store_ref(raw.system).finalize();
  ASSERT_TRUE(block::decode_workchain_coordinator_state(missing).is_error());
  raw.budget = vm::CellBuilder().finalize();
  td::Ref<vm::Cell> malformed;
  ASSERT_TRUE(tlb::pack_cell(malformed, raw));
  ASSERT_TRUE(block::decode_workchain_coordinator_state(malformed).is_error());
  for (bool empty : {true, false}) {
    td::Ref<vm::Cell> system, legacy;
    ASSERT_TRUE(tlb::pack_cell(system, block::gen::UnoV2SystemState::Record{1, 1000000, empty ? 0ULL : 1ULL, 0}));
    ASSERT_TRUE(tlb::pack_cell(legacy, block::gen::UnoV2CoordinatorState::Record{1, system}));
    ASSERT_TRUE(block::decode_workchain_coordinator_state(legacy).is_error());  // No fallback.
    auto migrated = block::migrate_empty_workchain_coordinator_state(legacy);
    ASSERT_EQ(migrated.is_ok(), empty);
    if (empty) {
      auto current = block::decode_workchain_coordinator_state(migrated.ok());
      ASSERT_TRUE(current.is_ok());
      ASSERT_EQ(current.ok().layout_version, 2u);
      ASSERT_EQ(current.ok().system.layout_version, 1);
      ASSERT_EQ(current.ok().system.base_compute, 1000000u);
      ASSERT_EQ(current.ok().system.registered_accounts, 0u);
      ASSERT_EQ(current.ok().refundable_deposits, 0u);
    } else {
      ASSERT_EQ(migrated.error().message(), "legacy coordinator is not empty");
    }
  }
}

TEST(ConfidentialState, DepositOriginAndUnifiedCapacity) {
  using namespace block;
  auto a = account();
  a.schema_version = 2;
  for (unsigned i = 0; i < 16; ++i) a.pending.push_back(receipt(i));
  for (unsigned i = 1; i <= 4; ++i) {
    auto id = derive_workchain_deposit_id(bits(100 + i), i).move_as_ok();
    a.system_pending.push_back({id, bits(100+i), i, 1000000000ULL, a.address.instance,
        a.key_epoch, a.bindings.asset, {public_point(), public_point()}, 0});
  }
  auto root = encode_workchain_confidential_account(a).move_as_ok();
  auto decoded = decode_workchain_confidential_account(root).move_as_ok();
  ASSERT_EQ(decoded.pending.size(), 16u);
  ASSERT_EQ(decoded.system_pending.size(), 4u);
  ASSERT_EQ(encode_workchain_confidential_account(decoded).move_as_ok()->get_hash(), root->get_hash());
  auto single = encode_workchain_deposit_receipt(a.system_pending[0]).move_as_ok();
  auto r = decode_workchain_deposit_receipt(single).move_as_ok();
  ASSERT_EQ(r.inbound_message, a.system_pending[0].inbound_message);
  ASSERT_EQ(r.sequence, 1u);
  ASSERT_EQ(r.amount, 1000000000ULL);
  ASSERT_TRUE(derive_workchain_deposit_id(bits(1), 0).is_error());
  r.receipt_id = bits(0);
  ASSERT_EQ(encode_workchain_deposit_receipt(r).error().message(), "deposit receipt identity mismatch");
  a.system_pending.push_back(a.system_pending[0]);
  ASSERT_EQ(encode_workchain_confidential_account(a).error().message(), "pending capacity exceeded");
  a.system_pending.pop_back();
  a.system_pending[1] = a.system_pending[0];
  ASSERT_EQ(encode_workchain_confidential_account(a).error().message(), "duplicate pending dictionary key");
  gen::UnoV2AccountStateDeposits::Record raw;
  ASSERT_TRUE(resource_policy_detail::unpack_exact(root, raw));
  raw.system_pending_count = 3;
  td::Ref<vm::Cell> wrong_count;
  ASSERT_TRUE(::tlb::pack_cell(wrong_count, raw));
  ASSERT_EQ(decode_workchain_confidential_account(wrong_count).error().message(), "system pending count mismatch");
  // A single dictionary cannot install a second origin at the same key. No Set
  // overwrite is used even when the two values have different constructors.
  vm::Dictionary dict(256);
  ASSERT_TRUE(dict.set_ref(r.receipt_id, single, vm::Dictionary::SetMode::Add));
  auto send = encode_workchain_pending_receipt(receipt(0)).move_as_ok();
  ASSERT_TRUE(!dict.set_ref(r.receipt_id, send, vm::Dictionary::SetMode::Add));
  ASSERT_EQ(dict.lookup_ref(r.receipt_id)->get_hash(), single->get_hash());
}

TEST(ConfidentialState, CoordinatorIngressRequiresExplicitState) {
  using namespace block;
  auto buckets = vm::CellBuilder().store_long(17, 8).finalize(); // Opaque TEST bucket codec owned by host.
  WorkchainCoordinatorState a{3, {1, 0, 2, 0}, 20, 7, buckets};
  auto root = encode_workchain_coordinator_state(a).move_as_ok();
  auto b = decode_workchain_coordinator_state(root).move_as_ok();
  ASSERT_TRUE(b.deposit_sequence.has_value());
  ASSERT_EQ(*b.deposit_sequence, 7u);
  ASSERT_EQ(b.unexpected->get_hash(), buckets->get_hash());
  ASSERT_EQ(next_workchain_deposit_sequence(7).move_as_ok(), 8u);
  ASSERT_TRUE(next_workchain_deposit_sequence(UINT64_MAX).is_error());
  a.unexpected.clear();
  ASSERT_TRUE(encode_workchain_coordinator_state(a).is_error());
  WorkchainCoordinatorState missing{3, {1,0,2,0}, 20};
  ASSERT_TRUE(encode_workchain_coordinator_state(missing).is_error());
  auto old = encode_workchain_coordinator_state({2, {1,0,2,0}, 20}).move_as_ok();
  auto legacy = decode_workchain_coordinator_state(old).move_as_ok();
  ASSERT_TRUE(!legacy.deposit_sequence);
  ASSERT_EQ(legacy.layout_version, 2u);
}

TEST(ConfidentialState, ExistingM3VectorBytesRemainCanonical) {
  using namespace block;
  auto base = std::filesystem::path(__FILE__).parent_path() / "workchain-m3-vectors";
  for (const auto* scenario : {"send", "collect1", "collect3"}) {
    for (const auto* name : {"alice.boc", "bob.boc", "candidate-1.boc"}) {
      std::ifstream file(base / scenario / name, std::ios::binary);
      ASSERT_TRUE(file.good());
      std::string bytes((std::istreambuf_iterator<char>(file)), {});
      auto root = vm::std_boc_deserialize(bytes).move_as_ok();
      td::Ref<vm::Cell> rebuilt;
      if (std::string(name) == "candidate-1.boc") {
        auto input = decode_workchain_transfer_input(root).move_as_ok();
        rebuilt = encode_workchain_transfer_input(input).move_as_ok();
      } else {
        auto a = decode_workchain_confidential_account(root).move_as_ok();
        ASSERT_EQ(a.schema_version, 1u);
        ASSERT_TRUE(a.system_pending.empty());
        rebuilt = encode_workchain_confidential_account(a).move_as_ok();
        for (const auto& r : a.pending) {
          auto leaf = encode_workchain_pending_receipt(r).move_as_ok();
          auto rr = decode_workchain_pending_receipt(leaf).move_as_ok();
          ASSERT_EQ(encode_workchain_pending_receipt(rr).move_as_ok()->get_hash(), leaf->get_hash());
        }
      }
      ASSERT_EQ(rebuilt->get_hash(), root->get_hash());
      // Normalize the BoC container identically; every cell byte and reference
      // is preserved. This does not claim layout 2 equals layout 1.
      ASSERT_EQ(vm::std_boc_serialize(rebuilt, 0).move_as_ok().as_slice(), td::Slice(bytes));
    }
  }
}

TEST(ConfidentialState, M4SerializedFullAccountSize) {
  using namespace block;
  auto a = account();
  a.schema_version = 2;
  // Test-only canonical points, deliberately distinct to avoid understating
  // storage through artificial ciphertext sharing. No validity proof is claimed.
  auto distinct_point = [](unsigned n) {
    unsigned char uniform[64]{};
    uniform[0] = static_cast<unsigned char>(n);
    td::Bits256 point;
    CHECK(crypto_core_ristretto255_from_hash(reinterpret_cast<unsigned char*>(point.as_slice().data()), uniform) == 0);
    return point;
  };
  for (unsigned i = 0; i < 16; ++i) {
    auto r = receipt(i);
    r.source.account = bits(30+i);
    r.source.instance = bits(50+i);
    r.operation_id = bits(70+i);
    r.receipt_id = derive_workchain_receipt_id(r.source.instance, r.operation_id, i).move_as_ok();
    r.ciphertext = {distinct_point(2*i+1), distinct_point(2*i+2)};
    a.pending.push_back(r);
  }
  auto bytes = [](td::Ref<vm::Cell> root) { return vm::std_boc_serialize(root, 0).move_as_ok().size(); };
  auto user_only = encode_workchain_confidential_account(a).move_as_ok();
  for (unsigned i = 1; i <= 4; ++i) {
    auto id = derive_workchain_deposit_id(bits(100+i), i).move_as_ok();
    a.system_pending.push_back({id, bits(100+i), i, 1000000000ULL, a.address.instance,
      a.key_epoch, a.bindings.asset, {distinct_point(33+2*i), distinct_point(34+2*i)}, 0});
  }
  auto full = encode_workchain_confidential_account(a).move_as_ok();
  auto single = encode_workchain_deposit_receipt(a.system_pending[0]).move_as_ok();
  vm::CellBuilder storage;
  storage.store_long(0, 64);
  ASSERT_TRUE(CurrencyCollection(0).store(storage));
  storage.store_long(1,1).store_long(0,1).store_long(0,1);
  ASSERT_TRUE(storage.store_maybe_ref(workchain_confidential_native_code()));
  ASSERT_TRUE(storage.store_maybe_ref(full));
  storage.store_long(0,1);
  td::Ref<vm::Cell> stored = storage.finalize();
  vm::CellStorageStat stat;
  ASSERT_TRUE(stat.compute_used_storage(stored).is_ok());
  vm::CellBuilder native;
  native.store_long(1,1).store_long(4,3).store_long(2,8).store_bits(a.address.account.bits(),256);
  ASSERT_TRUE(store_UInt7(native, stat.cells));
  ASSERT_TRUE(store_UInt7(native, stat.bits));
  native.store_long(0,3).store_long(0,32).store_long(0,1).append_cellslice(vm::load_cell_slice(stored));
  auto native_root = native.finalize();
  auto shard_account = vm::CellBuilder().store_ref(native_root).store_zeroes(320).finalize();
  Account native_readback(2, a.address.account.bits());
  ASSERT_TRUE(native_readback.unpack(vm::load_cell_slice_ref(shard_account), 0, false));
  ASSERT_EQ(native_readback.data->get_hash(), full->get_hash());
  std::cout << "M4_SIZE_BOC_MODE0 deposit=" << bytes(single) << " four_system_increment="
    << bytes(full)-bytes(user_only) << " full_data=" << bytes(full)
    << " native_account=" << bytes(native_root) << " shard_account=" << bytes(shard_account)
    << "; 16 user + 4 occupied system slots; fixed Native wrapper; no per-account proof field; "
    << "shared cells deduplicated; measured fixture, not a frozen maximum\n";
  ASSERT_TRUE(bytes(full) > bytes(user_only));
}

TEST(ConfidentialState, SystemCollectIdentityInputs) {
  auto base = std::filesystem::path(__FILE__).parent_path() / "workchain-m3-vectors/send";
  auto load = [&](const char* name) {
    std::ifstream file(base / name, std::ios::binary);
    CHECK(file.good());
    std::string bytes((std::istreambuf_iterator<char>(file)), {});
    return vm::std_boc_deserialize(bytes).move_as_ok();
  };
  auto a = block::decode_workchain_confidential_account(load("alice.boc")).move_as_ok();
  auto input = block::decode_workchain_transfer_input(load("candidate-1.boc")).move_as_ok();
  auto send = block::derive_workchain_receipt_id(a.address.instance, input.claimed_operation_id, 0).move_as_ok();
  auto first = block::derive_workchain_deposit_id(bits(101), 1).move_as_ok();
  auto second = block::derive_workchain_deposit_id(bits(102), 2).move_as_ok();
  std::ifstream fixture(std::filesystem::path(__FILE__).parent_path() / "workchain-m4-collect-ids.txt");
  ASSERT_TRUE(fixture.good());
  std::string contents((std::istreambuf_iterator<char>(fixture)), {});
  ASSERT_TRUE(contents.find("send=" + td::hex_encode(send.as_slice()) + "\n") != std::string::npos);
  ASSERT_TRUE(contents.find("system1=" + td::hex_encode(first.as_slice()) + "\n") != std::string::npos);
  ASSERT_TRUE(contents.find("system2=" + td::hex_encode(second.as_slice()) + "\n") != std::string::npos);
  std::cout << "M4_COLLECT_ID send=" << td::hex_encode(send.as_slice())
            << " system1=" << td::hex_encode(first.as_slice())
            << " system2=" << td::hex_encode(second.as_slice()) << '\n';
}
