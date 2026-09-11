// TEST PURE-TRANSITION BACKEND. No node gate, block publication or M4 payment claim.
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "block/workchain-account-closure.h"
#include "block/workchain-confidential-execution.h"
#include "block/workchain-confidential-native.h"
#include "block/workchain-registration-settlement.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/vm.h"

#include "workchain-m3-scenario.h"
#include "block/workchain-closure-settlement.h"
#include "block/workchain-account-settlement.h"
#include "workchain-m3-test-funding.h"
#include "workchain-proof-test-access.h"
using namespace block;
using namespace block::m3_test;
namespace {
using Text = std::map<std::string, std::string>;
Text read(const std::filesystem::path& p) {
  std::ifstream f(p);
  CHECK(f.good());
  Text m;
  std::string l;
  while (std::getline(f, l)) {
    if (l.empty() || l[0] == '#')
      continue;
    auto e = l.find('=');
    CHECK(e != std::string::npos);
    CHECK(m.emplace(l.substr(0, e), l.substr(e + 1)).second);
  }
  return m;
}
std::string hex(td::Slice b) {
  return td::hex_encode(b);
}
std::string hex(const td::Bits256& b) {
  return hex(b.as_slice());
}
std::string hex(const std::array<unsigned char, 80>& b) {
  return hex(td::Slice(reinterpret_cast<const char*>(b.data()), b.size()));
}
td::Bits256 word(const std::string& s) {
  auto b = td::hex_decode(s).move_as_ok();
  CHECK(b.size() == 32);
  td::Bits256 r;
  r.as_slice().copy_from(b);
  return r;
}
std::vector<td::Bits256> words(const std::string& s) {
  CHECK(s.size() % 64 == 0);
  std::vector<td::Bits256> v;
  for (size_t i = 0; i < s.size(); i += 64)
    v.push_back(word(s.substr(i, 64)));
  return v;
}
Root boc(const std::filesystem::path& p) {
  return vm::std_boc_deserialize(td::read_file_str(p.string()).move_as_ok()).move_as_ok();
}
Root roundtrip(const Root& r) {
  return vm::std_boc_deserialize(vm::std_boc_serialize(r, 0).move_as_ok()).move_as_ok();
}
std::string quote(const std::string& s) {
  std::string r = "'";
  for (char c : s) {
    if (c == '\'')
      r += "'\\''";
    else
      r += c;
  }
  return r + "'";
}
void be(std::string& s, std::uint64_t n, unsigned width) {
  for (unsigned i = width; i > 0; --i)
    s.push_back(static_cast<char>(n >> (8 * (i - 1))));
}
// Wallet context encoding follows the frozen independent registration/closure
// ABI transcript. No verifier hash/challenge is supplied by this wallet.
std::string prefix(const WorkchainConfidentialAccount& a, const std::array<unsigned char, 80>* domain) {
  std::string s;
  if (domain)
    s.assign(reinterpret_cast<const char*>(domain->data()), 80);
  be(s, static_cast<std::uint32_t>(a.global_id), 4);
  s += a.genesis_hash.as_slice().str();
  be(s, static_cast<std::uint32_t>(a.address.workchain_id), 4);
  for (const auto& v : {a.address.account, a.address.instance, a.bindings.asset, a.bindings.custody, a.bindings.policy})
    s += v.as_slice().str();
  be(s, a.schema_version, 2);
  be(s, a.relation_profile, 2);
  be(s, a.proof_profile, 2);
  be(s, a.key_epoch, 4);
  if (domain) {
    be(s, a.auth_nonce, 8);
    be(s, a.available_revision, 8);
  }
  return hex(td::Slice(s));
}
struct Wallet {
  std::uint64_t secret, value, blind;
};
struct PendingWitness {
  std::uint64_t value, blind;
};
class PureBackend final : public ScenarioBackend {
  ScenarioState state_;
  std::array<WorkchainConfidentialAccount, 2> templates_;
  std::array<Wallet, 2> wallets_{{{101, 0, 0}, {223, 0, 0}}};
  std::map<td::Bits256, PendingWitness> pending_;
  WorkchainTransferEnvironment env_;
  Root native_accounts_;
  td::Bits256 coordinator_id_;
  std::uint64_t registration_lt_ = 1;
  WorkchainResourcePolicy registration_resources_{4,
                                                  {4096, 1048576, 32, 3, 3, 1},
                                                  {4096, 1048576, 2048, 524288, 128},
                                                  {100000, 4096, 1048576, 4096, 1048576, 2},
                                                  {0, 2, 2},
                                                  1};
  WorkchainNativeIngressPolicy registration_ingress_;
  WorkchainExecutionDescriptor registration_descriptor_;
  std::filesystem::path tool_, tmp_;
  unsigned step_ = 0;
  Text wallet(const std::string& mode, Text m) {
    auto stem = tmp_ / std::to_string(++step_);
    auto in = stem.string() + ".request", out = stem.string() + ".result";
    {
      std::ofstream f(in);
      CHECK(f.good());
      for (auto& [k, v] : m)
        f << k << '=' << v << '\n';
    }
    auto cmd = quote(tool_.string()) + " " + quote(mode) + " " + quote(in) + " " + quote(out);
    CHECK(std::system(cmd.c_str()) == 0);
    return read(out);
  }
  WorkchainConfidentialAccount account(unsigned owner) const {
    return decode_workchain_confidential_account(state_.accounts.at(owner)).move_as_ok();
  }
  WorkchainCoordinatorState coordinator() const {
    return decode_workchain_coordinator_state(state_.coordinator).move_as_ok();
  }
  WorkchainPossessionPolicy possession_policy() const {
    const auto& p = env_.protocol;
    return {{p.engine_version, p.relation_version, p.wire_version, p.proof_version,
             p.global_id, p.workchain_id, p.genesis_hash, p.workchain_instance},
            env_.rules, env_.profiles, env_.fee_profile, env_.fee_effective_height};
  }
  td::Result<std::pair<WorkchainHostIdentity, Root>> entry(Root candidate, std::vector<td::Bits256> keys) {
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    WorkchainHostIdentity identity{env_.protocol.global_id, env_.protocol.genesis_hash,
        env_.protocol.workchain_instance, 2, tos::shardIdAll,
        td::Bits256(registration_ingress_.engine_configuration->get_hash().bits()), false,
        0x554e4f32, 17, 2, 4, td::Bits256(native_accounts_->get_hash().bits()),
        1234, 1234, registration_lt_, vm::CellBuilder().finalize()};
    vm::AugmentedDictionary old(vm::load_cell_slice_ref(native_accounts_), 256, block::tlb::aug_ShardAccounts);
    WorkchainAccountDeclarations declarations;
    declarations.writes = keys;
    for (const auto& key : keys) {
      Account account(2, key.bits());
      if (!account.unpack(old.lookup(key), 1234, false)) return alarm("entry old account unavailable");
      declarations.reads.push_back({key, td::Bits256(account.total_state->get_hash().bits())});
    }
    TRY_RESULT(access, encode_workchain_account_declarations(declarations, 3, 3));
    InputPolicyIdentity cut{registration_ingress_.engine_configuration->get_hash(), false, 0x554e4f32, 17, 2, 4};
    auto resolved = ResolvedBatchInputPolicy::from_resolved_fields(registration_resources_, cut);
    if (!std::holds_alternative<ResolvedBatchInputPolicy>(resolved)) return alarm("entry resource policy unavailable");
    const std::vector<Root> inbox;
    BatchInputAdmissionSession session(std::get<ResolvedBatchInputPolicy>(resolved), candidate, access, identity, inbox);
    const auto& admitted = session.evaluate();
    if (const auto* failure = std::get_if<BatchInputAdmissionFailure>(&admitted))
      return td::Status::Error(static_cast<int>(failure->category), td::Slice(failure->reason));
    return std::make_pair(identity, std::get<AdmittedBatchInput>(admitted).root());
  }
  template <size_t N>
  std::array<unsigned char, N> proof(const std::string& mode, unsigned owner, const WorkchainConfidentialAccount& a) {
    Text q{{"secret", std::to_string(wallets_[owner].secret)},
           {"prefix", prefix(a, mode == "close" ? &env_.domain : nullptr)},
           {"commitment", hex(a.available.commitment)},
           {"handle", hex(a.available.handle)}};
    auto context = encode_workchain_replay_context(rebuild_workchain_possession_context(possession_policy(), a),
        mode == "close" ? WorkchainReplayOperation::Closure : WorkchainReplayOperation::Registration).move_as_ok();
    q["context"] = td::hex_encode(context);
    auto r = td::hex_decode(wallet(mode, q).at("proof")).move_as_ok();
    CHECK(r.size() == N);
    std::array<unsigned char, N> out;
    std::copy(r.begin(), r.end(), out.begin());
    return out;
  }

 public:
  PureBackend(std::filesystem::path tool, std::filesystem::path tmp) : tool_(std::move(tool)), tmp_(std::move(tmp)) {
    std::filesystem::create_directories(tmp_);
    auto path = std::filesystem::path(M3_VECTOR_DIR) / "send";
    templates_ = {decode_workchain_confidential_account(boc(path / "alice.boc")).move_as_ok(),
                  decode_workchain_confidential_account(boc(path / "bob.boc")).move_as_ok()};
    // Explicit test identities only. The vector file is never read by a production
    // configuration parser. It supplies no defaults to a node or a deployment.
    auto e = read(path / "environment.txt");
    auto n = [&](const char* k) { return std::stoull(e.at(k)); };
    auto w = [&](const char* k) { return word(e.at(k)); };
    env_.limits = {1000000, 10000, 8, 1024, 4096};
    auto domain = td::hex_decode(e.at("domain")).move_as_ok();
    CHECK(domain.size() == 80);
    std::copy(domain.begin(), domain.end(), env_.domain.begin());
    env_.protocol = {2, 1, 1, 2, 1, std::stoi(e.at("global_id")), 2, w("genesis_hash"), w("workchain_instance")};
    env_.rules = {w("asset"), w("custody"), w("policy")};
    env_.profiles = {w("configuration"), w("generator_profile"), w("range_profile")};
    env_.fee_profile = w("fee_profile");
    env_.fee_effective_height = 1200;
    env_.height = 1234;
    env_.execution_fee = 11;
    env_.pending_capacity = 16;
    env_.account_schema = 1;
    env_.relation_profile = 1;
    env_.proof_profile = 2;
    (void)n;
    for (auto& a : templates_) {
      a.key_epoch = 0;
      a.auth_nonce = 0;
      a.available_revision = 0;
      a.pending.clear();
      a.available = {td::Bits256::zero(), td::Bits256::zero()};
      a.lifecycle = WorkchainAccountActive{};
    }
    state_.coordinator = encode_workchain_coordinator_state({2, {1, 1, 0, 0}, 0}).move_as_ok();
    state_.native_balances = {100000000000ULL, 100000000000ULL};
    vm::init_vm().ensure();
    auto label = vm::CellBuilder().store_bytes("M3 TEST registration coordinator").finalize();
    coordinator_id_ = td::Bits256(label->get_hash().bits());
    registration_ingress_.workchain_id = 2;
    registration_ingress_.engine_key = {WorkchainFormat::Basic, 0x554e4f32};
    registration_ingress_.vm_mode = 17;
    registration_ingress_.descriptor_version = 2;
    registration_ingress_.executor_address = coordinator_id_;
    // TEST registration shell only, not a production M3 business-config codec.
    registration_ingress_.engine_configuration =
        encode_workchain_engine_parameters({400, env_.protocol.workchain_instance, registration_resources_,
                                            vm::CellBuilder().finalize(), templates_[0].funding.paid_deposit})
            .move_as_ok();
    registration_descriptor_.workchain_id = 2;
    registration_descriptor_.active = true;
    registration_descriptor_.vm_version = 0x554e4f32;
    registration_descriptor_.vm_mode = 17;
    registration_descriptor_.version = 2;
    vm::CellBuilder storage;
    storage.store_long(0, 64);
    // Assumed TEST operating budget, separate from later refundable deposits.
    CHECK(CurrencyCollection(1000).store(storage));
    storage.store_long(1, 1).store_long(0, 1).store_long(0, 1);
    CHECK(storage.store_maybe_ref(workchain_confidential_native_code()));
    CHECK(storage.store_maybe_ref(state_.coordinator));
    storage.store_long(0, 1);
    vm::CellBuilder native;
    native.store_long(1, 1).store_long(4, 3).store_long(2, 8).store_bits(coordinator_id_.bits(), 256);
    CHECK(store_UInt7(native, 0));
    CHECK(store_UInt7(native, 0));
    native.store_long(0, 3).store_long(0, 32).store_long(0, 1).append_cellslice(
        vm::load_cell_slice(storage.finalize()));
    vm::CellBuilder shard;
    shard.store_ref(native.finalize()).store_zeroes(256).store_long(0, 64);
    vm::AugmentedDictionary dictionary(256, block::tlb::aug_ShardAccounts);
    CHECK(dictionary.set_builder(coordinator_id_, shard, vm::Dictionary::SetMode::Add));
    native_accounts_ = dictionary.get_wrapped_dict_root();
  }
  const ScenarioState& state() const override {
    return state_;
  }
  Point wallet_secret(unsigned i) const override {
    Point s{};
    auto v = wallets_.at(i).secret;
    for (unsigned j = 0; j < 8; ++j)
      s[j] = static_cast<unsigned char>(v >> (8 * j));
    return s;
  }
  std::uint64_t fee(unsigned kind) const override {
    return kind == 1 ? 11 : 17;
  }
  td::Status register_account(unsigned owner) override {
    auto a = templates_.at(owner);
    // Test-scope authenticated destination table, not a deployment default.
    WorkchainSet refund_workchains;
    td::Ref<WorkchainInfo> basechain{true};
    basechain.write().workchain = 0;
    basechain.write().basic = basechain.write().active = basechain.write().accept_msgs = true;
    basechain.write().min_addr_len = basechain.write().max_addr_len = 256;
    refund_workchains.emplace(0, basechain);
    WorkchainRegistrationPolicy policy{a.global_id,     a.genesis_hash,        env_.protocol.workchain_instance,
                                       a.bindings,      a.schema_version,      a.relation_profile,
                                       a.proof_profile, a.funding.paid_deposit, possession_policy(), refund_workchains};
    TRY_RESULT(incarnation, derive_workchain_registration_operation_id(policy, a));
    a.address.instance = incarnation;
    auto p = proof<64>("register", owner, a);
    WorkchainReplayInput registration_input = WorkchainRegistrationReplayInput{
        incarnation, rebuild_workchain_possession_context(policy.possession, a), p};
    TRY_RESULT(replay_root, encode_workchain_replay_input(registration_input));
    if (a.funding.paid_deposit > state_.native_balances[owner])
      return alarm("registration source lacks deposit");
    TRY_RESULT(encoded, encode_workchain_confidential_account(a));
    vm::AugmentedDictionary prior(vm::load_cell_slice_ref(native_accounts_), 256, block::tlb::aug_ShardAccounts);
    Account old_coordinator(2, coordinator_id_.bits());
    if (!old_coordinator.unpack(prior.lookup(coordinator_id_), 1234, false))
      return alarm("native coordinator unavailable");
    if (old_coordinator.data->get_hash() != state_.coordinator->get_hash())
      return alarm("scenario coordinator snapshots differ");
    if (prior.lookup(a.address.account).not_null())
      return alarm("new account already exists in Native dictionary");
    // This is a TEST final-import boundary. Source emission/queue inclusion is
    // outside this post-admission settlement test, never claimed as live evidence.
    vm::CellBuilder message;
    message.store_long(4, 4)
        .store_long(4, 3)
        .store_long(a.funding.refund_workchain, 8)
        .store_bits(a.funding.refund_account.bits(), 256)
        .store_long(4, 3)
        .store_long(2, 8)
        .store_bits(coordinator_id_.bits(), 256);
    auto amount = vm::CellBuilder().store_long(a.funding.paid_deposit, 64).finalize();
    CurrencyCollection payment_value(vm::load_cell_slice(amount).fetch_int256(64, false));
    if (!payment_value.store(message))
      return alarm("registration message value cannot encode");
    message.store_long(0, 4)
        .store_long(0, 4)
        .store_long(registration_lt_, 64)
        .store_long(1234, 32)
        .store_long(0, 1)
        .store_long(1, 1)
        .store_ref(encoded);
    auto msg = message.finalize();
    block::tlb::MsgEnvelope::Record_std env{0x60, 0x60, td::make_refint(0), msg, {}, {}};
    Root envelope;
    if (!::tlb::pack_cell(envelope, env))
      return alarm("registration envelope cannot encode");
    std::vector<Root> messages{envelope};
    TRY_RESULT(inbox_root, encode_workchain_batch_inbound(messages));
    auto inbox = plan_workchain_native_inbox(inbox_root, 2, {coordinator_id_}, registration_lt_, 1);
    WorkchainHostIdentity identity{env_.protocol.global_id,
                                   env_.protocol.genesis_hash,
                                   env_.protocol.workchain_instance,
                                   2,
                                   tos::shardIdAll,
                                   td::Bits256(registration_ingress_.engine_configuration->get_hash().bits()),
                                   false,
                                   0x554e4f32,
                                   17,
                                   2,
                                   4,
                                   td::Bits256(native_accounts_->get_hash().bits()),
                                   1234,
                                   1234,
                                   registration_lt_,
                                   vm::CellBuilder().finalize()};
    WorkchainAccountDeclarations declarations{
        {{coordinator_id_, td::Bits256(old_coordinator.total_state->get_hash().bits())},
         {a.address.account, std::nullopt}},
        {coordinator_id_, a.address.account}};
    TRY_RESULT(access, encode_workchain_account_declarations(declarations, 2, 2));
    InputPolicyIdentity cut{registration_ingress_.engine_configuration->get_hash(), false, 0x554e4f32, 17, 2, 4};
    auto resolved = ResolvedBatchInputPolicy::from_resolved_fields(registration_resources_, cut);
    if (!std::holds_alternative<ResolvedBatchInputPolicy>(resolved))
      return alarm("test registration resource cut invalid");
    BatchInputAdmissionSession session(std::get<ResolvedBatchInputPolicy>(resolved), replay_root, access, identity,
                                       messages);
    const auto& admitted = session.evaluate();
    if (const auto* failure = std::get_if<BatchInputAdmissionFailure>(&admitted))
      return td::Status::Error(static_cast<int>(failure->category), td::Slice(failure->reason));
    const auto& input = std::get<AdmittedBatchInput>(admitted);
    SerializeConfig cfg;
    cfg.global_version = 16;
    struct Engine final : WorkchainAccountEngine {
      std::function<td::Result<WorkchainAccountEffects>(const Root&, WorkchainAccountReadView&,
                                                       WorkchainProofVerifier&)> execute;
      td::Result<std::uint64_t> proof_work(const Root& candidate, const InputPolicyIdentity&) const override {
        TRY_RESULT(wire, decode_workchain_replay_input(candidate));
        if (!std::holds_alternative<WorkchainRegistrationReplayInput>(wire)) return alarm("expected registration");
        return workchain_registration_operations_v4().total();
      }
      td::Result<WorkchainAccountEffects> execute_accounts(const Root&, WorkchainAccountReadView&) const override {
        return alarm("registration fixture requires admitted verifier");
      }
      td::Result<WorkchainAccountEffects> execute_metered_accounts(const Root& input, WorkchainAccountReadView& view,
                                                                 WorkchainProofVerifier& verifier) const override {
        return execute(input, view, verifier);
      }
    } engine;
    std::shared_ptr<const WorkchainRegistrationPaymentResult> verified_payment;
    unsigned calls = 0;
    engine.execute = [&](const Root& root, WorkchainAccountReadView& view, WorkchainProofVerifier& verifier)
        -> td::Result<WorkchainAccountEffects> {
      ++calls;
      TRY_RESULT(old, view.read(coordinator_id_));
      TRY_RESULT(absent, view.read(a.address.account));
      if (old.is_null() || old->get_hash() != old_coordinator.total_state->get_hash())
        return alarm("registration admitted coordinator differs from fixture snapshot");
      gen::UnoV2HostInput::Record host;
      if (!::tlb::unpack_cell(root, host)) return alarm("admitted registration unavailable");
      TRY_RESULT(payment, replay_workchain_registration_payment(policy, registration_ingress_,
          registration_descriptor_, inbox, td::Bits256(msg->get_hash().bits()), coordinator(),
          old_coordinator.balance, absent, host.candidate, verifier));
      if (verifier.consumed() != 433) return alarm("registration verification was not metered once");
      verified_payment = std::make_shared<WorkchainRegistrationPaymentResult>(std::move(payment));
      WorkchainAccountEffects effects;
      effects.updates = {{a.address.account, verified_payment->registration.account_data},
                        {coordinator_id_, verified_payment->registration.coordinator_data}};
      std::sort(effects.updates.begin(), effects.updates.end(), [](const auto& x, const auto& y) {
        return x.account < y.account;
      });
      effects.registration = verified_payment;
      return effects;
    };
    auto native = NativeCellMaterializer::run(messages, {10000, 1000000, 1});
    if (!std::holds_alternative<MaterializedNativeCells>(native)) return alarm("registration inbox unavailable");
    ActionPhaseConfig prices; prices.global_version = 16;
    TRY_RESULT(settled, execute_and_settle_workchain_accounts(engine, native_accounts_, identity, input,
        std::get<MaterializedNativeCells>(native), env_.rules.custody, coordinator_id_, td::make_refint(0),
        4096, cfg, prices));
    if (calls != 1 || !verified_payment) return alarm("registration engine did not execute exactly once");
    const auto& payment = *verified_payment;
    auto persisted = roundtrip(settled.state.accounts);
    vm::AugmentedDictionary next_dictionary(vm::load_cell_slice_ref(persisted), 256, block::tlb::aug_ShardAccounts);
    Account created(2, a.address.account.bits()), funded(2, coordinator_id_.bits());
    if (!created.unpack(next_dictionary.lookup(a.address.account), 1234, false) ||
        !funded.unpack(next_dictionary.lookup(coordinator_id_), 1234, false))
      return alarm("settled Native accounts cannot reload");
    if (created.status != Account::acc_active || !created.balance.is_zero() ||
        !is_workchain_confidential_native_wrapper(created.code, created.tick, created.tock))
      return alarm("registered Native wrapper invalid");
    if (created.data->get_hash() != payment.registration.account_data->get_hash() ||
        funded.data->get_hash() != payment.registration.coordinator_data->get_hash() ||
        funded.balance != payment.coordinator_flow.new_balance)
      return alarm("settlement differs from verified payment");
    vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(settled.state.account_blocks), 256,
                                   block::tlb::aug_ShardAccountBlocks);
    for (const auto* participant : {&created, &funded}) {
      auto leaf = blocks.lookup(participant->addr);
      gen::AccountBlock::Record ab;
      if (leaf.is_null() || !gen::t_AccountBlock.unpack(leaf.write(), ab) || !leaf->empty())
        return alarm("registration AccountBlock missing");
      vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
      auto transaction = txs.lookup_ref(td::BitArray<64>(participant->last_trans_lt_));
      if (transaction.is_null() || !gen::t_Transaction.validate_ref(4096, transaction) ||
          !block::tlb::t_Transaction.validate_ref(4096, transaction))
        return alarm("registration transaction invalid");
      gen::Transaction::Record tx;
      if (!::tlb::unpack_cell(transaction, tx) || tx.orig_status != (participant == &created ? 3 : 2) ||
          tx.end_status != 2 || tx.outmsg_cnt != 0)
        return alarm("registration transition statuses differ");
      if (participant == &funded) {
        // Read authorization back from the serialized entry, not the wallet's
        // proof buffer. This is settlement readback, not an actor-validation claim.
        gen::TransactionDescr::Record_trans_workchain_entry_v3 entry;
        gen::UnoV2HostInput::Record host;
        gen::UnoV2HostRecord::Record binding;
        if (!::tlb::unpack_cell(tx.description, entry) || !::tlb::unpack_cell(entry.input, host) ||
            !::tlb::unpack_cell(entry.binding, binding) ||
            binding.input_hash != entry.input->get_hash().bits() || !host.inbox->prefetch_ulong(1))
          return alarm("registration entry authorization missing or uncommitted");
        TRY_RESULT(recorded_inbox, plan_workchain_native_inbox(host.inbox->prefetch_ref(), 2,
                                                              {coordinator_id_}, registration_lt_, 1));
        if (recorded_inbox.envelopes.size() != 1) return alarm("registration replay inbox is not singular");
        block::tlb::MsgEnvelope::Record_std recorded_envelope;
        if (!::tlb::unpack_cell(recorded_inbox.envelopes[0], recorded_envelope))
          return alarm("registration replay envelope malformed");
        const td::Bits256 recorded_message(recorded_envelope.msg->get_hash().bits());
        TRY_RESULT(rebuilt, block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return replay_workchain_registration_payment(
            policy, registration_ingress_, registration_descriptor_, recorded_inbox, recorded_message,
            coordinator(), old_coordinator.balance, {}, host.candidate, verification_budget); }));
        if (rebuilt.registration.account_data->get_hash() != created.data->get_hash() ||
            rebuilt.registration.coordinator_data->get_hash() != funded.data->get_hash() ||
            rebuilt.coordinator_flow.new_balance != funded.balance)
          return alarm("registration entry replay differs from Native state");
        TRY_RESULT(wire, decode_workchain_replay_input(host.candidate));
        auto* registered = std::get_if<WorkchainRegistrationReplayInput>(&wire);
        if (!registered) return alarm("registration entry carries another operation");
        registered->claimed_operation_id.as_slice()[0] ^= 1;
        TRY_RESULT(wrong_id, encode_workchain_replay_input(wire));
        auto rejected = block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return replay_workchain_registration_payment(
            policy, registration_ingress_, registration_descriptor_, recorded_inbox, recorded_message,
            coordinator(), old_coordinator.balance, {}, wrong_id, verification_budget); });
        if (rejected.is_ok() || rejected.error().code() != -7200 ||
            rejected.error().message() != "claimed operationID mismatch")
          return alarm("registration payment accepted or misclassified a false operationID");
      }
    }
    if (owner == 1) {
      Account retained(2, templates_[0].address.account.bits());
      if (!retained.unpack(next_dictionary.lookup(templates_[0].address.account), 1234, false) ||
          retained.data->get_hash() != state_.accounts[0]->get_hash())
        return alarm("second registration changed first account");
    }
    TRY_RESULT(created_record, decode_workchain_confidential_account(created.data));
    if (created_record.key_epoch != a.key_epoch || created_record.public_key != a.public_key)
      return alarm("epoch guard: registration changed the authenticated initial key");
    gen::UnoV2HostInput::Record persisted_input;
    gen::UnoV2HostIdentity::Record persisted_identity;
    gen::UnoV2HostDomain::Record persisted_domain;
    if (!resource_policy_detail::unpack_exact(input.root(), persisted_input) ||
        !resource_policy_detail::unpack_exact(persisted_input.identity, persisted_identity) ||
        !resource_policy_detail::unpack_exact(persisted_identity.domain, persisted_domain) ||
        persisted_domain.instance_id != env_.protocol.workchain_instance ||
        created_record.address.instance != incarnation ||
        created_record.address.instance == persisted_domain.instance_id)
      return alarm("test registration collapsed account incarnation and workchain identity");
    auto next = state_;
    next.accounts[owner] = created.data;
    next.coordinator = funded.data;
    // The message represents an already-debited TEST source payment. Final import
    // does not debit again: registration.payer_balance is the message remainder.
    if (payment.registration.payer_balance != 0)
      return alarm("unowned registration payment remainder");
    next.native_balances[owner] -= a.funding.paid_deposit;  // checked source coverage above.
    state_ = std::move(next);
    native_accounts_ = std::move(persisted);
    registration_lt_ = settled.state.end_lt;
    std::cout << "Native registration settled: 2 transactions; account_none->active; readback verified\n";
    return td::Status::OK();
  }
  td::Status seed(unsigned owner, std::uint64_t value) override {
    auto a = account(owner);
    Text q{{"secret", std::to_string(wallets_[owner].secret)},
           {"old_value", std::to_string(value)},
           {"old_blind", "23"},
           {"new_blind", "1"},
           {"aux_blind", "1"},
           {"fee", "0"}};
    auto pts = words(wallet("seed", q).at("available"));
    WorkchainCiphertext available{pts.at(0), pts.at(1)};
    TRY_RESULT(funded, fund_registered_test_account(native_accounts_, a.address.account, available, 1234));
    auto persisted = roundtrip(funded);
    vm::AugmentedDictionary dictionary(vm::load_cell_slice_ref(persisted), 256, block::tlb::aug_ShardAccounts);
    Account readback(2, a.address.account.bits());
    if (!readback.unpack(dictionary.lookup(a.address.account), 1234, false))
      return alarm("funded Native account cannot reload");
    TRY_RESULT(decoded, decode_workchain_confidential_account(readback.data));
    TRY_RESULT(value_readback, decrypt(decoded.available, wallet_secret(owner), 1000000));
    TRY_STATUS(assert_balance(value_readback, value));
    // Repeat funding and missing-account edits must not silently replace state.
    if (fund_registered_test_account(persisted, a.address.account, available, 1234).is_ok() ||
        fund_registered_test_account(persisted, td::Bits256::zero(), available, 1234).is_ok())
      return alarm("test funding accepted a nonempty or absent account");
    native_accounts_ = std::move(persisted);
    state_.accounts[owner] = readback.data;
    std::cout << "TEST funding: Native ShardAccounts readback=" << value_readback
              << "; assumed initial balance, NOT verified M4 Deposit\n";
    wallets_[owner].value = value;
    wallets_[owner].blind = 23;
    return td::Status::OK();
  }
  td::Result<Root> transfer(unsigned owner, unsigned receiver, std::uint64_t value,
                            const std::vector<td::Bits256>& selected) {
    unsigned kind = selected.empty() ? 1 : 2;
    auto a = account(owner), b = account(receiver);
    auto config = env_;
    config.protocol.kind = kind;
    config.execution_fee = fee(kind);
    // Small deterministic TEST openings, fresh per operation. Real wallet entropy
    // for Sigma/range proofs comes from public prove(); these are known witnesses.
    std::uint64_t rho = 149 + step_, r = 179 + step_, t = 163 + step_;
    Text q{{"secret", std::to_string(wallets_[owner].secret)},
           {"receiver_secret", std::to_string(wallets_[receiver].secret)},
           {"old_value", std::to_string(wallets_[owner].value)},
           {"old_blind", std::to_string(wallets_[owner].blind)},
           {"new_blind", std::to_string(rho)},
           {"transfer_blind", std::to_string(r)},
           {"aux_blind", std::to_string(t)},
           {"fee", std::to_string(config.execution_fee)},
           {"kind", std::to_string(kind)},
           {"value", std::to_string(value)},
           {"max_balance", "1000000"},
           {"max_value", "10000"}};
    if (kind == 2) {
      std::string vv, rr, tt;
      for (size_t i = 0; i < selected.size(); ++i) {
        auto witness = pending_.at(selected[i]);
        if (i) {
          vv += ',';
          rr += ',';
          tt += ',';
        }
        vv += std::to_string(witness.value);
        rr += std::to_string(witness.blind);
        tt += std::to_string(83 + i);
      }
      q["values"] = vv;
      q["blinds"] = rr;
      q["auxiliaries"] = tt;
    }
    auto result = wallet("points", q);
    auto pp = words(result.at("points"));
    WorkchainTransferClaims claims{a.address,   a.auth_nonce, a.available_revision,
                                   a.key_epoch, 1300,         config.execution_fee};
    WorkchainTransferData data;
    if (kind == 1)
      data = WorkchainSendData{claims,  b.address, b.key_epoch, {pp.at(4), pp.at(5)}, {pp.at(6), pp.at(7), pp.at(8)},
                               pp.at(9)};
    else {
      WorkchainCollectData c{claims, {pp.at(3), pp.at(4)}, pp.at(5), {}};
      for (size_t i = 0; i < selected.size(); ++i)
        c.selected.push_back({selected[i], pp.at(8 + 3 * i)});
      data = std::move(c);
    }
    gen::UnoV2OperationNetworkV1::Record network{config.protocol.global_id, config.protocol.genesis_hash,
                                                 config.protocol.workchain_instance};
    TRY_RESULT(id, derive_workchain_operation_id(network, a.address, kind, a.auth_nonce));
    WorkchainTransferInput input{id, data, {}};
    auto historical = [](const WorkchainConfidentialAccount& v) -> WorkchainHistoricalConfidentialAccount {
      return std::optional<WorkchainConfidentialAccount>{v};
    };
    TRY_RESULT(statement, prepare_workchain_transfer_statement(config, input, historical(a), historical(b)));
    q["context"] = hex(td::Slice(statement.context));
    q["domain"] = hex(config.domain);
    q["points"] = "";
    q["receipt_ids"] = "";
    for (auto& point : statement.points)
      q["points"] += hex(td::Slice(reinterpret_cast<const char*>(point.data()), 32));
    for (auto& id : statement.receipt_ids)
      q["receipt_ids"] += hex(td::Slice(reinterpret_cast<const char*>(id.data()), 32));
    auto auth = wallet("prove", q);
    input.authorization = {words(auth.at("commitments")), words(auth.at("responses")),
                           td::hex_decode(auth.at("range_proof")).move_as_ok()};
    TRY_RESULT(candidate, encode_workchain_transfer_input(input));
    auto persisted = roundtrip(candidate);
    TRY_RESULT(decoded, decode_workchain_transfer_input(persisted));
    auto meter = WorkchainProofTestAccess::create(100000);
    TRY_RESULT(effects, execute_workchain_confidential_transfer(config, decoded, historical(a), historical(b), meter));
    if (meter.consumed() == 0)
      return alarm("real proof verifier was not charged");
    std::vector<td::Bits256> keys{coordinator_id_, a.address.account};
    if (effects.destination_data.not_null()) keys.push_back(b.address.account);
    TRY_RESULT(admitted_entry, entry(persisted, keys));
    WorkchainAccountEffects native_effects;
    native_effects.updates = {{coordinator_id_, state_.coordinator}, {a.address.account, effects.source_data}};
    if (effects.destination_data.not_null()) native_effects.updates.push_back({b.address.account, effects.destination_data});
    std::sort(native_effects.updates.begin(), native_effects.updates.end(),
              [](const auto& x, const auto& y) { return x.account < y.account; });
    TRY_RESULT(encoded_effects, encode_workchain_account_effects(native_effects, 3, 0, 4096));
    SerializeConfig cfg; cfg.global_version = 16;
    TRY_RESULT(settled, build_workchain_inbound_allocation_overlay(native_accounts_, admitted_entry.first,
        admitted_entry.second, encoded_effects, coordinator_id_, env_.rules.custody, 3, 3, 0, 0, 4096, cfg));
    auto settled_root = roundtrip(settled.state.accounts);
    vm::AugmentedDictionary stored(vm::load_cell_slice_ref(settled_root), 256, block::tlb::aug_ShardAccounts);
    for (const auto& update : native_effects.updates) {
      Account readback(2, update.account.bits());
      if (!readback.unpack(stored.lookup(update.account), 1234, false) ||
          readback.data->get_hash() != update.data->get_hash()) return alarm("Native transfer state readback mismatch");
    }
    auto next = state_;
    next.accounts[owner] = roundtrip(effects.source_data);
    if (effects.destination_data.not_null())
      next.accounts[receiver] = roundtrip(effects.destination_data);
    state_ = std::move(next);
    native_accounts_ = settled_root;
    registration_lt_ = settled.state.end_lt;
    wallets_[owner].value = std::stoull(result.at("new_value"));
    wallets_[owner].blind = rho;
    if (kind == 1) {
      TRY_RESULT(receipt, derive_workchain_receipt_id(a.address.instance, id, 0));
      pending_.emplace(receipt, PendingWitness{value, r});
    } else
      for (auto& receipt : selected)
        pending_.erase(receipt);
    return persisted;
  }
  td::Result<Root> send(unsigned owner, unsigned receiver, std::uint64_t value) override {
    return transfer(owner, receiver, value, {});
  }
  td::Result<Root> collect(unsigned owner, const std::vector<td::Bits256>& selected) override {
    if (selected.empty())
      return alarm("empty COLLECT");
    return transfer(owner, owner, 0, selected);
  }
  td::Result<RefundObserved> close(unsigned owner) override {
    auto a = account(owner);
    auto p = proof<96>("close", owner, a);
    auto policy = possession_policy();
    TRY_RESULT(id, derive_workchain_closure_operation_id(
        {a.global_id, a.genesis_hash, env_.protocol.workchain_instance}, a.address, a.auth_nonce));
    WorkchainReplayInput replay = WorkchainClosureReplayInput{
        id, rebuild_workchain_possession_context(policy, a), p};
    TRY_RESULT(replay_root, encode_workchain_replay_input(replay));
    TRY_RESULT(admitted_entry, entry(roundtrip(replay_root), {a.address.account, coordinator_id_}));
    WorkchainSet workchains;
    td::Ref<WorkchainInfo> basechain{true};
    basechain.write().workchain = 0;
    basechain.write().basic = basechain.write().active = basechain.write().accept_msgs = true;
    basechain.write().min_addr_len = basechain.write().max_addr_len = 256;
    workchains.emplace(0, basechain);
    SerializeConfig cfg; cfg.global_version = 16;
    ActionPhaseConfig prices; prices.global_version = 16; prices.workchains = &workchains;
    prices.fwd_std = prices.fwd_mc = MsgPrices(100, 0, 0, 0, 16384, 0);
    auto before = native_accounts_;
    struct Engine final : WorkchainAccountEngine {
      std::function<td::Result<WorkchainAccountEffects>(const Root&, WorkchainAccountReadView&,
                                                       WorkchainProofVerifier&)> execute;
      td::Result<std::uint64_t> proof_work(const Root& candidate, const InputPolicyIdentity&) const override {
        TRY_RESULT(wire, decode_workchain_replay_input(candidate));
        if (!std::holds_alternative<WorkchainClosureReplayInput>(wire)) return alarm("expected closure input");
        return workchain_closure_operations_v4().total();
      }
      td::Result<WorkchainAccountEffects> execute_accounts(const Root&, WorkchainAccountReadView&) const override {
        return alarm("closure fixture cannot run without admitted verifier");
      }
      td::Result<WorkchainAccountEffects> execute_metered_accounts(const Root& input, WorkchainAccountReadView& view,
                                                                 WorkchainProofVerifier& verifier) const override {
        return execute(input, view, verifier);
      }
    } engine;
    unsigned calls = 0;
    std::uint64_t consumed = 0;
    engine.execute = [&](const Root& input, WorkchainAccountReadView& view, WorkchainProofVerifier& verifier)
        -> td::Result<WorkchainAccountEffects> {
      ++calls;
      auto load = [&](const td::Bits256& key) -> td::Result<Root> {
        TRY_RESULT(root, view.read(key));
        if (root.is_null()) return alarm("closure fixture account missing");
        auto wrapper = vm::CellBuilder().store_ref(root).store_zeroes(320).finalize();
        Account native(2, key.bits());
        if (!native.unpack(vm::load_cell_slice_ref(wrapper), 1234, false)) return alarm("Native read unavailable");
        return native.data;
      };
      TRY_RESULT(account_data, load(a.address.account));
      TRY_RESULT(coordinator_data, load(coordinator_id_));
      TRY_RESULT(account, decode_workchain_confidential_account(account_data));
      TRY_RESULT(system, decode_workchain_coordinator_state(coordinator_data));
      gen::UnoV2HostInput::Record host;
      if (!::tlb::unpack_cell(input, host)) return alarm("admitted closure input unavailable");
      TRY_RESULT(transition, replay_workchain_account_closure(account, system, policy, env_.domain,
                                                             host.candidate, verifier));
      consumed = verifier.consumed();
      WorkchainAccountEffects effects;
      effects.updates = {{a.address.account, transition.account_data}, {coordinator_id_, transition.coordinator_data}};
      std::sort(effects.updates.begin(), effects.updates.end(), [](const auto& x, const auto& y) {
        return x.account < y.account;
      });
      effects.closure = std::make_shared<WorkchainAccountClosureExecution>(WorkchainAccountClosureExecution{
          a.address.account, td::Bits256(account_data->get_hash().bits()),
          td::Bits256(coordinator_data->get_hash().bits()), std::move(transition)});
      return effects;
    };
    gen::UnoV2HostInput::Record host;
    if (!::tlb::unpack_cell(admitted_entry.second, host)) return alarm("closure entry unavailable");
    InputPolicyIdentity cut{registration_ingress_.engine_configuration->get_hash(), false, 0x554e4f32, 17, 2, 4};
    auto resolved = ResolvedBatchInputPolicy::from_resolved_fields(registration_resources_, cut);
    if (!std::holds_alternative<ResolvedBatchInputPolicy>(resolved)) return alarm("closure policy unavailable");
    std::vector<Root> inbox;
    BatchInputAdmissionSession session(std::get<ResolvedBatchInputPolicy>(resolved), host.candidate, host.access,
                                       admitted_entry.first, inbox);
    if (!std::holds_alternative<AdmittedBatchInput>(session.evaluate())) return alarm("closure admission failed");
    auto native = NativeCellMaterializer::run(inbox, {10000, 1000000, 1});
    if (!std::holds_alternative<MaterializedNativeCells>(native)) return alarm("empty Native inbox unavailable");
    TRY_RESULT(settled, execute_and_settle_workchain_accounts(engine, before, admitted_entry.first,
        std::get<AdmittedBatchInput>(session.evaluate()), std::get<MaterializedNativeCells>(native),
        env_.rules.custody, coordinator_id_, td::make_refint(0), 4096, cfg, prices));
    if (consumed != 441 || calls != 1 || settled.exports.size() != 1)
      return alarm("closure verifier or single outbound refund missing");
    auto persisted = roundtrip(settled.state.accounts);
    vm::AugmentedDictionary old(vm::load_cell_slice_ref(persisted), 256, block::tlb::aug_ShardAccounts);
    Account closed(2, a.address.account.bits()), coordinator(2, coordinator_id_.bits());
    if (!closed.unpack(old.lookup(a.address.account), 1234, false) ||
        !coordinator.unpack(old.lookup(coordinator_id_), 1234, false)) return alarm("closure Native readback failed");
    // One-way push only: there is no recipient balance credit in this fixture.
    // Delivery/compensation/claim is not established by an outbound transaction.
    auto next = state_;
    next.accounts[owner] = closed.data;
    next.coordinator = coordinator.data;
    state_ = std::move(next);
    native_accounts_ = persisted;
    registration_lt_ = settled.state.end_lt;
    return RefundObserved{settled.exports[0].trans, settled.exports[0].msg, before, persisted,
                          coordinator_id_, 2, 1234};
  }
};
}  // namespace
#include "workchain-m4-retention-test.h"
int main(int argc, char** argv) {
  if (argc == 4 && std::string(argv[1]) == "--m4-system-collect") {
    auto result = test_m4_system_retention(argv[2], argv[3]);
    if (result.is_error()) std::cerr << result.to_string() << '\n';
    return result.is_ok() ? 0 : 1;
  }
  if (argc != 3) {
    std::cerr << "usage: workchain-m3-scenario WALLET_EXECUTABLE TEMP_DIRECTORY\n";
    return 2;
  }
  PureBackend backend(argv[1], argv[2]);
  auto result = run_m3_scenario(backend);
  if (result.is_error()) {
    std::cerr << result.error().to_string() << '\n';
    return 1;
  }
  std::cout << result.ok() << '\n';
  return 0;
}
