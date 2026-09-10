#include <filesystem>
#include <fstream>
#include <map>

#include "block/workchain-confidential-execution.h"
#include "td/utils/misc.h"
#include "td/utils/tests.h"
#include "test/workchain-proof-test-access.h"
#include "vm/boc.h"

namespace {
using namespace block;
using Text = std::map<std::string, std::string>;
Text read_text(const std::filesystem::path& path) {
  std::ifstream file(path);
  CHECK(file.good());
  Text result;
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#')
      continue;
    auto eq = line.find('=');
    CHECK(eq != std::string::npos);
    CHECK(result.emplace(line.substr(0, eq), line.substr(eq + 1)).second);
  }
  return result;
}
td::Bits256 word(const std::string& hex) {
  auto bytes = td::hex_decode(hex).move_as_ok();
  CHECK(bytes.size() == 32);
  td::Bits256 result;
  result.as_slice().copy_from(bytes);
  return result;
}
td::Ref<vm::Cell> boc(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  CHECK(file.good());
  std::string bytes((std::istreambuf_iterator<char>(file)), {});
  return vm::std_boc_deserialize(bytes).move_as_ok();
}
struct Fixture {
  std::filesystem::path path;
  Text env_text;
  WorkchainTransferEnvironment env;
  WorkchainConfidentialAccount alice, bob;
  explicit Fixture(const std::string& scenario)
      : path(std::filesystem::path(UNO_M3_VECTORS) / scenario), env_text(read_text(path / "environment.txt")) {
    const auto& e = env_text;
    auto u = [&](const char* k) { return std::stoull(e.at(k)); };
    auto u32 = [&](const char* k) {
      auto n = u(k);
      CHECK(n <= UINT32_MAX);
      return static_cast<std::uint32_t>(n);
    };
    auto u16 = [&](const char* k) {
      auto n = u(k);
      CHECK(n <= UINT16_MAX);
      return static_cast<std::uint16_t>(n);
    };
    auto w = [&](const char* k) { return word(e.at(k)); };
    env.limits = {u("max_balance"), u("max_value"), u32("max_collect"), u32("max_context_bytes"),
                  u32("max_proof_bytes")};
    auto domain = td::hex_decode(e.at("domain")).move_as_ok();
    CHECK(domain.size() == 80);
    std::copy(domain.begin(), domain.end(), env.domain.begin());
    env.protocol = {u32("engine_version"),
                    u16("relation_version"),
                    u16("wire_version"),
                    u16("proof_version"),
                    u32("kind"),
                    std::stoi(e.at("global_id")),
                    std::stoi(e.at("workchain_id")),
                    w("genesis_hash"),
                    w("workchain_instance")};
    env.rules = {w("asset"), w("custody"), w("policy")};
    env.profiles = {w("configuration"), w("generator_profile"), w("range_profile")};
    env.fee_profile = w("fee_profile");
    env.fee_effective_height = u32("fee_effective_height");
    env.height = u32("current_height");
    env.execution_fee = u("execution_fee");
    env.pending_capacity = u("pending_capacity");
    env.account_schema = u16("account_schema");
    env.relation_profile = u16("relation_profile");
    env.proof_profile = u16("proof_profile");
    // Authenticate the fixture dictionary against the independently supplied
    // pre-state commitment, then load accounts from that root, not the input.
    auto root = boc(path / "prestate.boc");
    CHECK(td::Bits256(root->get_hash().bits()) == w("prestate_hash"));
    vm::Dictionary accounts(vm::load_cell_slice_ref(root), 256);
    alice = decode_workchain_confidential_account(accounts.lookup_ref(w("alice_account"))).move_as_ok();
    bob = decode_workchain_confidential_account(accounts.lookup_ref(w("bob_account"))).move_as_ok();
  }
  WorkchainTransferInput input(const char* name = "candidate-1.boc") const {
    return decode_workchain_transfer_input(boc(path / name)).move_as_ok();
  }
};
WorkchainHistoricalConfidentialAccount historical(const WorkchainConfidentialAccount& a) {
  return std::optional{a};
}
td::Result<WorkchainConfidentialTransferResult> execute(const Fixture& f, const WorkchainTransferInput& input,
                                                        const WorkchainConfidentialAccount& a,
                                                        const WorkchainConfidentialAccount& b, std::uint64_t& charged) {
  auto meter = WorkchainProofTestAccess::create(100000);
  auto result = execute_workchain_confidential_transfer(f.env, input, historical(a), historical(b), meter);
  charged = meter.consumed();
  return result;
}
void same_receipt(const WorkchainPendingReceipt& a, const WorkchainPendingReceipt& b) {
  ASSERT_TRUE(encode_workchain_pending_receipt(a).move_as_ok()->get_hash() ==
              encode_workchain_pending_receipt(b).move_as_ok()->get_hash());
}
}  // namespace

TEST(ConfidentialExecution, SendFreshProofRetryConsumesNonceNotId) {
  Fixture f("send");
  auto first = f.input(), second = f.input("candidate-2.boc");
  ASSERT_TRUE(first.claimed_operation_id == second.claimed_operation_id);
  ASSERT_TRUE(first.authorization.commitments != second.authorization.commitments);
  auto old_a = encode_workchain_confidential_account(f.alice).move_as_ok()->get_hash();
  auto old_b = encode_workchain_confidential_account(f.bob).move_as_ok()->get_hash();
  std::uint64_t units;
  auto one = execute(f, first, f.alice, f.bob, units);
  if (one.is_error())
    LOG(ERROR) << one.error();
  ASSERT_TRUE(one.is_ok());
  ASSERT_TRUE(units > 0);
  // Both distinct proofs are valid for the SAME old state, independently.
  auto two = execute(f, second, f.alice, f.bob, units);
  ASSERT_TRUE(two.is_ok());
  ASSERT_TRUE(units > 0);
  ASSERT_TRUE(one.ok().source_data->get_hash() == two.ok().source_data->get_hash());
  ASSERT_TRUE(one.ok().destination_data->get_hash() == two.ok().destination_data->get_hash());
  auto a = decode_workchain_confidential_account(one.ok().source_data).move_as_ok();
  auto b = decode_workchain_confidential_account(one.ok().destination_data).move_as_ok();
  ASSERT_EQ(a.auth_nonce, f.alice.auth_nonce + 1);
  ASSERT_EQ(a.available_revision, f.alice.available_revision + 1);
  const auto& send = std::get<WorkchainSendData>(first.data);
  ASSERT_TRUE(a.available.commitment == send.available.commitment);
  ASSERT_TRUE(a.available.handle == send.available.handle);
  ASSERT_EQ(b.pending.size(), f.bob.pending.size() + 1);
  ASSERT_EQ(b.auth_nonce, f.bob.auth_nonce);
  ASSERT_EQ(b.available_revision, f.bob.available_revision);
  auto id = derive_workchain_receipt_id(f.alice.address.instance, one.ok().operation_id, 0).move_as_ok();
  auto created = std::find_if(b.pending.begin(), b.pending.end(), [&](const auto& r) { return r.receipt_id == id; });
  ASSERT_TRUE(created != b.pending.end());
  ASSERT_TRUE(created->ciphertext.commitment == send.transfer.commitment);
  ASSERT_TRUE(created->ciphertext.handle == send.transfer.recipient_handle);
  auto retry = execute(f, second, a, b, units);
  ASSERT_TRUE(retry.is_error());
  ASSERT_EQ(retry.error().code(), -7200);
  ASSERT_EQ(retry.error().message(), "confidential nonce or available revision mismatch");
  ASSERT_EQ(units, 0u);
  ASSERT_TRUE(encode_workchain_confidential_account(f.alice).move_as_ok()->get_hash() == old_a);
  ASSERT_TRUE(encode_workchain_confidential_account(f.bob).move_as_ok()->get_hash() == old_b);
  auto full = f.bob;
  while (full.pending.size() < 16) {
    auto receipt = full.pending.front();
    receipt.output_index = static_cast<std::uint32_t>(full.pending.size() + 1);
    receipt.receipt_id =
        derive_workchain_receipt_id(receipt.source.instance, receipt.operation_id, receipt.output_index).move_as_ok();
    full.pending.push_back(receipt);
  }
  auto capacity = execute(f, second, f.alice, full, units);
  ASSERT_TRUE(capacity.is_error());
  ASSERT_EQ(capacity.error().code(), -7200);
  ASSERT_EQ(units, 0u);
  // Invalid proof produces neither partial source debit nor a target receipt.
  first.authorization.range_proof[0] ^= 1;
  auto bad = execute(f, first, f.alice, f.bob, units);
  ASSERT_TRUE(bad.is_error());
  ASSERT_EQ(bad.error().code(), -7200);
  ASSERT_TRUE(units > 0);
  ASSERT_TRUE(encode_workchain_confidential_account(f.alice).move_as_ok()->get_hash() == old_a);
  ASSERT_TRUE(encode_workchain_confidential_account(f.bob).move_as_ok()->get_hash() == old_b);
}

TEST(ConfidentialExecution, CollectOneAndThreeRetainUnselected) {
  for (const auto* scenario : {"collect1", "collect3"}) {
    Fixture f(scenario);
    auto input = f.input();
    const auto& collect = std::get<WorkchainCollectData>(input.data);
    auto old_hash = encode_workchain_confidential_account(f.bob).move_as_ok()->get_hash();
    std::uint64_t units;
    auto result = execute(f, input, f.bob, f.alice, units);
    if (result.is_error())
      LOG(ERROR) << result.error();
    ASSERT_TRUE(result.is_ok());
    ASSERT_TRUE(units > 0);
    ASSERT_TRUE(result.ok().destination_data.is_null());
    auto next = decode_workchain_confidential_account(result.ok().source_data).move_as_ok();
    ASSERT_EQ(next.auth_nonce, f.bob.auth_nonce + 1);
    ASSERT_EQ(next.available_revision, f.bob.available_revision + 1);
    ASSERT_TRUE(next.available.commitment == collect.available.commitment);
    ASSERT_TRUE(next.available.handle == collect.available.handle);
    ASSERT_EQ(next.pending.size() + collect.selected.size(), f.bob.pending.size());
    for (const auto& original : f.bob.pending) {
      bool selected = std::any_of(collect.selected.begin(), collect.selected.end(),
                                  [&](const auto& s) { return s.receipt_id == original.receipt_id; });
      auto found = std::find_if(next.pending.begin(), next.pending.end(),
                                [&](const auto& p) { return p.receipt_id == original.receipt_id; });
      ASSERT_EQ(found == next.pending.end(), selected);
      if (!selected)
        same_receipt(original, *found);
    }
    ASSERT_TRUE(encode_workchain_confidential_account(f.bob).move_as_ok()->get_hash() == old_hash);
    auto changed = input;
    changed.claimed_operation_id.as_slice()[0] ^= 1;
    ASSERT_EQ(execute(f, changed, f.bob, f.alice, units).error().code(), -7200);
    ASSERT_EQ(units, 0u);
    auto missing = f.bob;
    missing.pending.clear();
    auto absent = execute(f, input, missing, f.alice, units);
    ASSERT_EQ(absent.error().code(), -7200);
    ASSERT_EQ(absent.error().message(), "selected pending receipt does not exist");
    auto wrong_owner = f.bob;
    for (auto& p : wrong_owner.pending)
      p.target_key_epoch++;
    auto denied = execute(f, input, wrong_owner, f.alice, units);
    ASSERT_EQ(denied.error().code(), -7200);
    ASSERT_EQ(denied.error().message(), "pending consumption, ownership or source domain mismatch");
    auto wrong_origin = f.bob;
    for (auto& p : wrong_origin.pending)
      ++p.source_operation_nonce;
    auto unauthenticated = execute(f, input, wrong_origin, f.alice, units);
    ASSERT_EQ(unauthenticated.error().code(), -7200);
    ASSERT_EQ(unauthenticated.error().message(), "pending source identity mismatch");
    auto bad_proof = input;
    bad_proof.authorization.range_proof[0] ^= 1;
    auto rejected = execute(f, bad_proof, f.bob, f.alice, units);
    ASSERT_TRUE(rejected.is_error());
    ASSERT_EQ(rejected.error().code(), -7200);
    ASSERT_TRUE(units > 0);
    ASSERT_TRUE(encode_workchain_confidential_account(f.bob).move_as_ok()->get_hash() == old_hash);
  }
}
