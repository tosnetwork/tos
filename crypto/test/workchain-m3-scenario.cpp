// TEST PURE-TRANSITION BACKEND. No node gate, block publication or M4 payment claim.
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "block/workchain-account-closure.h"
#include "block/workchain-confidential-execution.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "vm/boc.h"

#include "workchain-m3-scenario.h"
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
  // There is no queue in this pure atomic backend. SEND installs the destination
  // pending in the same transition; no in-flight entry is created. A live backend
  // must obtain this view from its actual authenticated obligation state instead.
  std::array<std::map<td::Bits256, Root>, 2> obligations_;
  WorkchainTransferEnvironment env_;
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
  template <size_t N>
  std::array<unsigned char, N> proof(const std::string& mode, unsigned owner, const WorkchainConfidentialAccount& a) {
    Text q{{"secret", std::to_string(wallets_[owner].secret)},
           {"prefix", prefix(a, mode == "close" ? &env_.domain : nullptr)},
           {"commitment", hex(a.available.commitment)},
           {"handle", hex(a.available.handle)}};
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
    WorkchainRegistrationPolicy policy{a.global_id,     a.genesis_hash,        env_.protocol.workchain_instance,
                                       a.bindings,      a.schema_version,      a.relation_profile,
                                       a.proof_profile, a.funding.paid_deposit};
    TRY_RESULT(registration_id, derive_workchain_registration_operation_id(policy, a));
    a.address.instance = registration_id;
    auto p = proof<64>("register", owner, a);
    WorkchainRegistrationSnapshot before{coordinator(), state_.accounts[owner], a.funding.refund_workchain,
                                         a.funding.refund_account, state_.native_balances[owner]};
    TRY_RESULT(encoded, encode_workchain_confidential_account(a));
    TRY_RESULT(result, execute_workchain_registration(policy, before, a.address.account, encoded, p));
    auto next = state_;
    next.accounts[owner] = roundtrip(result.account_data);
    next.coordinator = roundtrip(result.coordinator_data);
    next.native_balances[owner] = result.payer_balance;
    state_ = std::move(next);
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
    a.available = {pts.at(0), pts.at(1)};
    TRY_RESULT(encoded, encode_workchain_confidential_account(a));
    state_.accounts[owner] = roundtrip(encoded);
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
    auto next = state_;
    next.accounts[owner] = roundtrip(effects.source_data);
    if (effects.destination_data.not_null())
      next.accounts[receiver] = roundtrip(effects.destination_data);
    state_ = std::move(next);
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
    TRY_RESULT(result,
               execute_workchain_account_closure(a, coordinator(), obligations_.at(owner).size(), env_.domain, p));
    // Pure backend applies the refund to its Native balance state atomically. A
    // live backend must use the delivered Native transaction instead.
    auto next = state_;
    TRY_RESULT(balance, checked_sum(next.native_balances[owner], result.refund.amount));
    next.accounts[owner] = roundtrip(result.account_data);
    next.coordinator = roundtrip(result.coordinator_data);
    next.native_balances[owner] = balance;
    auto credited = balance - state_.native_balances[owner];  // checked_sum established no wrap and nonnegative delta.
    state_ = std::move(next);
    return RefundObserved{credited, result.refund.workchain, result.refund.account};
  }
};
}  // namespace
int main(int argc, char** argv) {
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
