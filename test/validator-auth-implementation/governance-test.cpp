#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>

#include "validator/auth/governance.h"
#ifdef VALIDATOR_AUTH_NATIVE_GOVERNANCE
#include "validator/auth/native-transaction.h"
#endif
#include "vm/boc.h"

#include "governance-fixture.h"
namespace {
void write(const std::filesystem::path& path, const Bytes& bytes) {
  std::ofstream file(path, std::ios::binary);
  file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  check(file.good(), "fixture-write");
}
using governance_fixture::Fixture;
using governance_fixture::fixture;
using governance_fixture::sign;
Bytes outcome(const VerifiedCertificate& result) {
  Writer w;
  w.bytes(result.certificate_id());
  w.integer(result.weight());
  w.list(result.signers(), 2, 400);
  check(w.ok(), "outcome");
  return w.data;
}
RegistryState at(const RegistryState& state, std::uint32_t coordinate) {
  return value(RegistryState::decode_cell(value(state.encode_cell(), "registry"), coordinate), "checkpoint");
}
RegistryState rotated(const RegistryState& before) {
  const auto& identity = before.identities().begin()->second;
  auto old = value(before.find(identity.active_[4].key_.key_id_), "old");
  auto key = old;
  key.epoch_ = 2;
  key.valid_from_ = 1;
  Update u{2,
           identity.identity_,
           identity.next_nonce_,
           value(object_id("identity", identity), "identity"),
           1,
           identity.active_[4].key_.key_id_,
           value(encode(key), "new"),
           {},
           {}};
  struct Authority final : LifecycleAuthority {
    Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
      return true;
    }
    Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override {
      return true;
    }
    Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override {
      return true;
    }
    Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                              std::uint32_t) const override {
      return Error{"fixture-governance"};
    }
  } authority;
  auto uid = value(object_id("update", u), "uid");
  Authorizations auth;
  auth.owner_.push_back({uid, identity.stake_id_, identity.owner_workchain_, identity.owner_address_, {}});
  auth.possession_.push_back({uid, value(key_reference(key), "ref"), {}});
  auth.administration_.push_back({uid, identity.identity_, {}});
  return value(before.apply_block(1, {{u, auth}}, authority), "rotation-fixture");
}
RegistryState policy_successor(const RegistryState& before) {
  auto root = value(before.encode_cell(), "registry");
  vm::CellSlice s(vm::NoVm{}, root);
  auto policy = value(before.policy_at(0), "policy");
  policy.revision_ = 2;
  policy.previous_ = before.current_policy();
  policy.effective_from_ = 1;
  auto pid = value(object_id("policy", policy), "policy-id");
  vm::CellSlice ps(vm::NoVm{}, s.prefetch_ref(2));
  vm::Dictionary policies(ps, 256);
  check(policies.set_ref(td::ConstBitPtr(pid.data()), 256,
                         value(pack_bytes(value(encode(policy), "policy")), "policy-cell")),
        "policy-put");
  vm::CellBuilder pw;
  check(policies.append_dict_to_bool(pw), "policies");
  Activation a{1, {}, pid, 1, 0, h(91), h(92), h(93)};
  vm::Dictionary acts(32);
  std::array<std::uint8_t, 4> index{0, 0, 0, 1};
  check(acts.set_ref(td::ConstBitPtr(index.data()), 32,
                     value(pack_bytes(value(encode(a), "activation")), "activation-cell")),
        "activation-put");
  vm::CellBuilder aw;
  check(acts.append_dict_to_bool(aw), "activations");
  vm::CellSlice old_control(vm::NoVm{}, s.prefetch_ref(3));
  vm::CellBuilder control;
  control.store_long(0x76616331, 32).store_ref(aw.finalize()).store_ref(old_control.prefetch_ref(1));
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(s.size() - 256));
  check(s.advance(256), "policy-position");
  b.store_bytes(td::Slice(reinterpret_cast<const char*>(pid.data()), pid.size()));
  b.store_ref(s.prefetch_ref(0)).store_ref(s.prefetch_ref(1)).store_ref(pw.finalize()).store_ref(control.finalize());
  return value(RegistryState::decode_cell(b.finalize(), 1), "policy-successor");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 1 || argc == 2, "arguments");
    std::filesystem::path out;
    if (argc == 2) {
      out = argv[1];
      check(std::filesystem::create_directory(out), "fresh-output");
    }
    unsigned count = 0;
    auto run = [&](Fixture f, const char* label, const char* error = "-") {
      auto snapshot = value(RegistrySnapshot::compile(f.committee, f.policy), "snapshot");
      auto before = value(f.current.encode_cell(), "state-before");
      ObjectReader reader({});
#ifdef VALIDATOR_AUTH_NATIVE_GOVERNANCE
      auto native = value(NativeRegistry::bootstrap(before, f.current.coordinate()), "fixture-native-governance");
      if (std::string(label) == "governance-native-resource")
        native = value(NativeRegistryBlock::begin(native, 1, {2, 32}), "fixture-native-budget").state();
      auto checkpoint = value(native.checkpoint(), "fixture-native-checkpoint");
      auto result = verify_current_governance(f.chain, snapshot, native, f.update, f.evidence, f.inclusion, reader);
      check(checkpoint->get_hash() == value(native.checkpoint(), "fixture-after-checkpoint")->get_hash(),
            "native-verification-read-only");
#else
      auto result = verify_current_governance(f.chain, snapshot, f.current, f.update, f.evidence, f.inclusion, reader);
#endif
      if (std::string(error) == "-")
        check(result.ok(), label);
      else if (result.ok() || result.error().code != error) {
        std::cerr << "DETAIL: " << label << " expected=" << error
                  << " actual=" << (result.ok() ? "accepted" : result.error().code) << '\n';
        check(false, label);
      }
      check(before->get_hash() == value(f.current.encode_cell(), "state-after")->get_hash(), "verification-read-only");
      if (!out.empty()) {
        auto path = out / std::to_string(count);
        check(std::filesystem::create_directory(path), "case-dir");
        auto boc = vm::std_boc_serialize(before, 31);
        check(boc.is_ok(), "boc");
        auto data = boc.ok().as_slice();
        write(path / "registry", Bytes(data.begin(), data.end()));
        write(path / "committee", value(encode(f.committee), "committee"));
        write(path / "policy", value(encode(f.policy), "policy"));
        write(path / "update", value(encode(f.update), "update"));
        write(path / "evidence", value(encode(f.evidence), "evidence"));
        Writer chain;
        chain.integer(f.chain.network);
        chain.bytes(f.chain.genesis_root);
        chain.bytes(f.chain.genesis_file);
        chain.bytes(f.chain.chain_domain);
        check(chain.ok(), "chain");
        write(path / "chain", chain.data);
        std::ofstream(path / "case") << f.current.coordinate() << ' ' << f.inclusion << ' ' << label << ' ' << error
                                     << '\n';
        if (result.ok())
          write(path / "verified", outcome(result.value()));
      }
      ++count;
    };
    auto base = fixture();
    run(base, "governance-full-quorum");
    auto f = base;
    sign(f, 2);
    run(f, "governance-exact-quorum");
    f = base;
    sign(f, 1);
    run(f, "governance-below-quorum", "quorum");
    f = base;
    f.update.operation_ = 4;
    f.update.operation_data_.clear();
    f.update.new_policy_ = value(encode(f.policy), "policy");
    sign(f);
    run(f, "governance-policy-intent");
    f = base;
    f.update.identity_ = h(1);
    sign(f);
    run(f, "governance-target-identity", "governance-target");
    f = base;
    f.update.operation_ = 5;
    sign(f);
    run(f, "governance-target-operation", "governance-target");
    f = base;
    f.evidence.owner_.push_back({});
    run(f, "governance-owner-separation", "governance-authorizations");
    f = base;
    f.evidence.possession_.push_back({});
    run(f, "governance-pop-separation", "governance-authorizations");
    f = base;
    f.evidence.administration_.push_back({});
    run(f, "governance-identity-separation", "governance-authorizations");
    f = base;
    f.evidence.governance_.clear();
    run(f, "governance-missing-authority", "governance-authorizations");
    f = base;
    f.inclusion = 1;
    run(f, "governance-state-coordinate", "governance-current-state");
    f = base;
    f.chain.chain_domain = h(99);
    run(f, "governance-chain-domain", "governance-current-state");
    f = base;
    f.current = policy_successor(base.current);
    f.inclusion = 1;
    run(f, "governance-current-policy", "governance-current-policy");
    f = base;
    f.committee.workchain_ = 0;
    sign(f);
    run(f, "governance-masterchain", "governance-committee");
    f = base;
    f.committee.shard_ = 1ULL << 62;
    sign(f);
    run(f, "governance-full-shard", "governance-committee");
    f = base;
    f.inclusion = 128;
    f.current = at(base.current, 128);
    run(f, "governance-inclusive-freshness");
    f = base;
    f.inclusion = 129;
    f.current = at(base.current, 129);
    run(f, "governance-stale", "admin-freshness");
    f = base;
    f.committee.anchor_mc_ = 1;
    sign(f);
    run(f, "governance-future-anchor", "admin-freshness");
    f = base;
    f.evidence.governance_[0].update_id_[0] ^= 1;
    run(f, "governance-update-binding", "governance-binding");
    f = base;
    f.evidence.governance_[0].committee_[0] ^= 1;
    run(f, "governance-roster-binding", "governance-binding");
    f = base;
    f.chain.network += 1;
    run(f, "governance-network", "expected-context");
    f = base;
    f.chain.genesis_root = h(88);
    run(f, "governance-genesis", "expected-context");
    f = base;
    f.update.nonce_ += 1;
    f.evidence.governance_[0].update_id_ = value(object_id("update", f.update), "changed-id");
    run(f, "governance-intent-substitution", "expected-context");
    f = base;
    auto cert = value(decode<Certificate>(f.evidence.governance_[0].certificate_.inline_), "cert");
    cert.records_.back().components_[0].signature_[0] ^= 1;
    f.evidence.governance_[0].certificate_ = value(object_value(4, value(encode(cert), "bad-cert")), "bad-carrier");
    run(f, "governance-surplus-signature", "signature");
    f = base;
    f.current = state(2);
    run(f, "governance-missing-current-identity", "governance-current-identity");
    f = base;
    f.current = at(base.current, 1000);
    f.inclusion = 1000;
    f.committee.anchor_mc_ = 900;
    sign(f);
    run(f, "governance-expired-admin", "snapshot-validity");
    f = base;
    f.current = rotated(base.current);
    f.inclusion = 1;
    run(f, "governance-retired-admin", "governance-current-key");
    run(fixture(400), "governance-full-400");
#ifdef VALIDATOR_AUTH_NATIVE_GOVERNANCE
    f = base;
    f.inclusion = 1;
    run(f, "governance-native-resource", "state-resource");
#endif
    if (!out.empty())
      std::ofstream(out / "complete") << count << '\n';
    std::cout << "PASS: current governance authority " << count << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
