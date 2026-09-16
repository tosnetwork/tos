#include "owner-proof-producer.h"
#if defined(P0_PERSISTENT_REGISTRY) || defined(P0_NATIVE_TRANSACTIONS) || defined(P0_NATIVE_CONFIG_HOST)
#include "validator/auth/native-transaction.h"
#endif
#ifdef P0_NATIVE_CONFIG_HOST
#include "validator/auth/cells.h"
#include "validator/auth/native-config-host.h"
#include "validator/auth/native-evidence.h"
#endif
#include "validator/auth/native-apply.h"

#include "owner-fixture.h"
using namespace p0_owner_fixture;
namespace {
struct History : FinalizedAnchorSource {
  Anchor anchor;
  bool available = true;
  Result<Anchor> finalized_anchor(std::uint32_t at) const override {
    if (!available || at != anchor.seqno_)
      return Error{"finalized-anchor-unavailable"};
    return anchor;
  }
};
using Updates = std::vector<std::pair<Update, Authorizations>>;
struct Case {
  RegistryState parent;
  ChainContext chain;
  Committee committee;
  Policy policy;
  History history;
  Updates updates;
  std::uint32_t inclusion = 100;
};
Bytes sign(std::span<const std::uint8_t> payload) {
  Hash pub{};
  std::array<std::uint8_t, 64> secret{};
  auto seed = h(7);
  check(crypto_sign_seed_keypair(pub.data(), secret.data(), seed.data()) == 0, "sign-key");
  Bytes result(64);
  check(crypto_sign_detached(result.data(), nullptr, payload.data(), payload.size(), secret.data()) == 0, "sign");
  return result;
}
RegistrySnapshot snapshot(const Case& c) {
  return value(RegistrySnapshot::compile(c.committee, c.policy), "governing");
}
IdentityAuth administration(const Case& c, const Update& u, const Key& key) {
  auto s = snapshot(c);
  auto payload = value(encode(u), "payload");
  auto duty = value(
      make_duty(c.chain, s, value(admin_session_id(c.chain, u.identity_), "session"), 5, u.nonce_, payload), "duty");
  auto ref = value(key_reference(key), "keyref");
  Record row{u.identity_, {{ref.suite_, ref.parameters_, ref.epoch_, ref.key_id_, {}}}};
  row.components_[0].signature_ = sign(value(signing_statement(duty, row), "statement"));
  return {value(object_id("update", u), "uid"), u.identity_,
          value(object_value(4, value(encode(Certificate{duty, payload, {row}}), "cert")), "carrier")};
}
Authorizations evidence(const Case& c, const Update& u, const Key& admin, std::optional<OwnerAuth> owner = {}) {
  Authorizations auth;
  if (owner) {
    auth.owner_.push_back(*owner);
    auto key = value(decode<Key>(u.new_key_), "new-key");
    auth.possession_.push_back({value(object_id("update", u), "uid"), value(key_reference(key), "ref"),
                                sign(value(possession_preimage(c.chain, u, key), "pop-message"))});
  }
  auth.administration_.push_back(administration(c, u, admin));
  return auth;
}
std::pair<Update, Authorizations> retire(const Case& c, const RegistryState& current, const Key& admin,
                                         unsigned role = 1) {
  const auto& id = current.identities().begin()->second;
  auto found = std::find_if(id.active_.begin(), id.active_.end(), [&](const auto& ref) { return ref.role_ == role; });
  check(found != id.active_.end(), "retire-fixture");
  Update u{
      3, id.identity_, id.next_nonce_, value(object_id("identity", id), "predecessor"), 0, found->key_.key_id_, {}, {},
      {}};
  return {u, evidence(c, u, admin)};
}
Result<RegistryState> apply(const Case& c) {
  auto s = snapshot(c);
  NativeIdentityContext context{c.chain, s, c.history};
  ObjectReader reader({});
#if defined(P0_PERSISTENT_REGISTRY) || defined(P0_NATIVE_TRANSACTIONS)
  auto parent =
      value(NativeRegistry::bootstrap(value(c.parent.encode_cell(), "persistent-parent"), c.parent.coordinate()),
            "persistent-bootstrap");
#ifdef P0_NATIVE_TRANSACTIONS
  auto begun = NativeRegistryBlock::begin(parent, c.inclusion);
  if (!begun.ok())
    return begun.error();
  auto prefix = std::move(begun.value());
  for (const auto& [update, auth] : c.updates) {
    auto before = value(prefix.state().checkpoint(), "transaction-before")->get_hash();
    auto candidate = prefix.apply_transaction(update, auth, context, reader);
    check(value(prefix.state().checkpoint(), "transaction-after")->get_hash() == before,
          "transaction-immutable-prefix");
    if (!candidate.ok())
      return candidate.error();
    // Discarding a candidate models an uncommitted execution. Retrying from the
    // accepted prefix must produce exactly the same successor, including indexes.
    auto retry = value(prefix.apply_transaction(update, auth, context, reader), "transaction-retry");
    check(value(retry.state().checkpoint(), "retry-state")->get_hash() ==
              value(candidate.value().state().checkpoint(), "candidate-state")->get_hash(),
          "transaction-discard-retry");
    prefix = std::move(candidate.value());
    auto bad = update;
    bad.nonce_ = UINT64_MAX;
    auto stable = value(prefix.state().checkpoint(), "transaction-stable")->get_hash();
    auto rejected = prefix.apply_transaction(bad, auth, context, reader);
    check(!rejected.ok() && rejected.error().code == "nonce", "transaction-rejected-nonce");
    check(value(prefix.state().checkpoint(), "transaction-rejected")->get_hash() == stable,
          "transaction-rejected-prefix");
  }
  if (c.updates.size() == 2) {
    auto remaining = prefix.state().remaining();
    auto initial = StateReadBudget{};
    check(initial.bytes > remaining.bytes, "transaction-budget-fixture");
    StateReadBudget budget{initial.entries - remaining.entries, initial.bytes - remaining.bytes - 1};
    auto limited = value(NativeRegistryBlock::begin(parent, c.inclusion, budget), "transaction-limited-begin");
    limited = value(limited.apply_transaction(c.updates[0].first, c.updates[0].second, context, reader),
                    "transaction-limited-first");
    auto stable = value(limited.state().checkpoint(), "limited-before")->get_hash();
    auto exhausted = limited.apply_transaction(c.updates[1].first, c.updates[1].second, context, reader);
    check(!exhausted.ok() && exhausted.error().code == "state-resource", "transaction-cumulative-budget");
    check(value(limited.state().checkpoint(), "limited-after")->get_hash() == stable, "transaction-resource-rollback");
  }
  Result<NativeRegistry> next = prefix.state();
#else
  auto next = parent.apply_native_block(c.inclusion, c.updates, context, reader);
#endif
  if (!next.ok())
    return next.error();
  return RegistryState::decode_cell(value(next.value().encode_cell(), "persistent-result"), c.inclusion);
#else
  return apply_native_identity_block(c.parent, c.inclusion, c.updates, context, reader);
#endif
}
RegistryState revision(const RegistryState& state, std::uint64_t revision) {
  vm::CellSlice s(vm::NoVm{}, value(state.encode_cell(), "revision-source"));
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(560)).store_long(revision, 64);
  check(s.advance(64), "revision-skip");
  b.append_cellslice(s);
  return value(RegistryState::decode_cell(b.finalize(), state.coordinate()), "revision-fixture");
}
RegistryState coordinate(const RegistryState& state, std::uint32_t at) {
  return value(RegistryState::decode_cell(value(state.encode_cell(), "state-cell"), at), "coordinate-fixture");
}
RegistryState policy_boundary(const RegistryState& state, std::uint32_t at, Policy& successor) {
  auto root = value(state.encode_cell(), "policy-parent");
  vm::CellSlice s(vm::NoVm{}, root);
  successor = value(state.policy_at(state.coordinate()), "parent-policy");
  ++successor.revision_;
  successor.previous_ = state.current_policy();
  successor.effective_from_ = at;
  auto id = value(object_id("policy", successor), "next-policy");
  vm::CellSlice old(vm::NoVm{}, s.prefetch_ref(2));
  vm::Dictionary policies(old, 256);
  check(policies.set_ref(td::ConstBitPtr(id.data()), 256,
                         value(pack_bytes(value(encode(successor), "policy")), "policy-bytes")),
        "add-policy");
  vm::CellBuilder wrapper;
  check(policies.append_dict_to_bool(wrapper), "policy-wrapper");

  // A policy that takes effect is a policy something attested to, so the parent
  // this fixture builds has to carry the attestation as a real one would; a
  // state without it is one no chain could produce.
  Activation attestation;
  attestation.revision_ = 1;
  attestation.next_policy_ = id;
  attestation.effective_from_ = at;
  attestation.checkpoint_seqno_ = at - 1;
  attestation.checkpoint_root_ = h(41);
  attestation.checkpoint_file_ = h(42);
  attestation.checkpoint_state_ = h(43);
  vm::CellSlice control(vm::NoVm{}, s.prefetch_ref(3));
  check(control.fetch_ulong(32) == 0x76616331, "policy-control");
  vm::Dictionary activations(32);
  std::array<std::uint8_t, 4> key{};
  for (unsigned i = 0; i < 4; ++i)
    key[i] = static_cast<std::uint8_t>(at >> (24 - i * 8));
  check(activations.set_ref(td::ConstBitPtr(key.data()), 32,
                            value(pack_bytes(value(encode(attestation), "activation")), "activation-bytes")),
        "add-activation");
  vm::CellBuilder activation_wrapper;
  check(activation_wrapper.store_maybe_ref(activations.get_root_cell()), "activation-wrapper");
  vm::CellBuilder rebuilt_control;
  rebuilt_control.store_long(0x76616331, 32)
      .store_ref(activation_wrapper.finalize())
      .store_ref(control.prefetch_ref(1));

  vm::CellBuilder b;
  b.store_bits(s.prefetch_bits(s.size()))
      .store_ref(s.prefetch_ref(0))
      .store_ref(s.prefetch_ref(1))
      .store_ref(wrapper.finalize())
      .store_ref(rebuilt_control.finalize());
  return value(RegistryState::decode_cell(b.finalize(), state.coordinate()), "future-policy");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 3 || argc == 4, "arguments");
    std::filesystem::path input(argv[2]);
    auto f = fixture(input, 5);
    if (std::string(argv[1]) == "prepare") {
      write(input / "identity", value(encode(f.identity), "identity"));
      write(input / "update", value(encode(f.update), "update"));
      write(input / "body.boc", boc(value(owner_approval_body(f.chain, f.update, f.identity), "body")));
      return 0;
    }
    check(argc == 4 && std::string(argv[1]) == "verify", "mode");
    std::filesystem::path out(argv[3]);
    check(std::filesystem::create_directory(out), "fresh-output");
    auto tx = cell(read(input / "accept.boc"));
    auto state = mcstate(f);
    auto block = block_for(tx, state, f);
    if (f.identity.owner_workchain_ != -1)
      state = mcstate(f, block);
    Anchor anchor{99, hash(block), h(6001), hash(state)};
    block::gen::Transaction::Record transaction;
    check(tlb::unpack_cell(tx, transaction), "transaction");
    auto owner = value(
        make_owner_execution_proof(state, block, anchor, f.chain, f.update, f.identity, transaction.lt, 0), "owner");
    Case base{coordinate(f.registry, 99), f.chain, {}, value(f.registry.policy_at(0), "policy"), {}, {}};
    base.history.anchor = anchor;
    auto& committee = base.committee;
    committee.policy_ = base.parent.current_policy();
    committee.election_ = h(9000);
    committee.workchain_ = -1;
    committee.shard_ = 1ULL << 63;
    committee.catchain_ = 3;
    committee.anchor_mc_ = 99;
    Member member{f.identity.identity_, f.identity.stake_id_, 1, h(9100), {}};
    for (const auto& ref : f.identity.active_)
      member.keys_.push_back(value(f.registry.find(ref.key_.key_id_), "member-key"));
    committee.members_ = {member};
    auto old_admin = member.keys_.at(4);
    auto new_admin = value(decode<Key>(f.update.new_key_), "new-admin");
    base.updates.push_back({f.update, evidence(base, f.update, old_admin, owner)});
    unsigned count = 0;
    auto run = [&](const Case& c, const char* label, const char* error = "-") {
      auto before = value(c.parent.encode_cell(), "immutable-before");
      auto result = apply(c);
      if ((std::string(error) == "-" && !result.ok()) ||
          (std::string(error) != "-" && (result.ok() || result.error().code != error))) {
        std::cerr << "DETAIL " << label << " expected=" << error
                  << " actual=" << (result.ok() ? "accepted" : result.error().code) << '\n';
        check(false, label);
      }
      check(before->get_hash() == value(c.parent.encode_cell(), "immutable-after")->get_hash(),
            "native-apply-atomic-parent");
      auto folder = out / std::to_string(count++);
      check(std::filesystem::create_directory(folder), "case-folder");
      write(folder / "parent", boc(before));
      write(folder / "committee", value(encode(c.committee), "committee"));
      write(folder / "policy", value(encode(c.policy), "policy"));
      write(folder / "anchor", value(encode(c.history.anchor), "anchor"));
      Writer chain;
      chain.integer(c.chain.network);
      chain.bytes(c.chain.genesis_root);
      chain.bytes(c.chain.genesis_file);
      chain.bytes(c.chain.chain_domain);
      write(folder / "chain", chain.data);
      std::ofstream meta(folder / "case");
      meta << c.parent.coordinate() << ' ' << c.inclusion << ' ' << c.history.available << ' ' << c.updates.size()
           << ' ' << label << ' ' << error << '\n';
      for (unsigned i = 0; i < c.updates.size(); ++i) {
        write(folder / ("update" + std::to_string(i)), value(encode(c.updates[i].first), "update"));
        write(folder / ("auth" + std::to_string(i)), value(encode(c.updates[i].second), "evidence"));
      }
      if (result.ok()) {
        auto root = value(result.value().encode_cell(), "result");
        auto restored = value(RegistryState::decode_cell(root, c.inclusion), "result-roundtrip");
        check(value(restored.encode_cell(), "restored")->get_hash() == root->get_hash(), "native-apply-checkpoint");
        write(folder / "result", boc(root));
        return result.value();
      }
      return c.parent;
    };
    auto first = run(base, "native-admin-rotation");
    check(first.identities().begin()->second.active_.back().key_.epoch_ == 2, "native-admin-rotation-effect");
    auto two = base;
    two.updates.push_back(retire(two, first, new_admin));
    auto second = run(two, "native-same-block-current-key");
    check(second.revision() == base.parent.revision() + 1 && second.keys().size() == 6 &&
              second.identities().begin()->second.next_nonce_ == 2,
          "native-batch-one-revision");
    check(second.identities().begin()->second.active_.front().role_ == 2, "native-ordered-retire-effect");
    auto old = two;
    old.updates[1].second = evidence(old, old.updates[1].first, old_admin);
    run(old, "native-old-admin-after-rotation", "identity-key-binding");
    auto bad = two;
    bad.updates[1].first.previous_ = f.update.previous_;
    bad.updates[1].second = evidence(bad, bad.updates[1].first, new_admin);
    run(bad, "native-stale-second-predecessor", "predecessor");
    bad = two;
    bad.updates[1].first.nonce_ = 0;
    bad.updates[1].second = evidence(bad, bad.updates[1].first, new_admin);
    run(bad, "native-stale-second-nonce", "nonce");
    bad = two;
    std::reverse(bad.updates.begin(), bad.updates.end());
    run(bad, "native-reversed-order", "predecessor");
    bad = base;
    bad.updates.push_back(base.updates[0]);
    run(bad, "native-duplicate-operation", "nonce");
    auto later = base;
    later.parent = first;
    later.inclusion = 101;
    later.updates = {retire(later, first, new_admin)};
    auto after = run(later, "native-next-block-new-admin");
    auto checkpoint = coordinate(first, 100);
    later.parent = checkpoint;
    auto replay = run(later, "native-checkpoint-replay");
    check(value(after.encode_cell(), "continuous")->get_hash() == value(replay.encode_cell(), "replay")->get_hash(),
          "native-replay-identical");
    bad = base;
    bad.history.available = false;
    run(bad, "native-missing-finality", "finalized-anchor-unavailable");
    bad = base;
    bad.history.anchor.file_ = h(700);
    run(bad, "native-wrong-finalized-fork", "proof-anchor");
    bad = base;
    bad.updates[0].second.owner_[0].proof_.anchor_.seqno_ = 100;
    run(bad, "native-uncommitted-owner-proof", "owner-finality-coordinate");
    bad = base;
    bad.chain.chain_domain = h(88);
    bad.updates = {retire(bad, bad.parent, old_admin)};
    run(bad, "native-wrong-current-domain", "authority-current-state");
    bad = base;
    bad.chain.genesis_root = {};
    run(bad, "native-missing-genesis", "chain-context");
    bad = base;
    bad.chain.network = 43;
    run(bad, "native-wrong-network", "state-context");
    bad = base;
    bad.committee.workchain_ = 0;
    bad.updates = {retire(bad, bad.parent, old_admin)};
    run(bad, "native-shard-governance", "authority-committee");
    bad = base;
    bad.committee.anchor_mc_ = 101;
    run(bad, "native-future-governance", "admin-freshness");
    auto retire_only = base;
    retire_only.updates = {retire(retire_only, retire_only.parent, old_admin)};
    run(retire_only, "native-retire-without-owner");
    bad = retire_only;
    bad.parent = coordinate(base.parent, 227);
    bad.inclusion = 228;
    run(bad, "native-expired-governance", "admin-freshness");
    bad = retire_only;
    bad.parent = coordinate(base.parent, 226);
    bad.inclusion = 227;
    run(bad, "native-governance-freshness-boundary");
    bad = base;
    bad.updates[0].second.owner_.clear();
    run(bad, "native-owner-required", "authority-shape");
    bad = base;
    bad.updates[0].second.possession_[0].signature_[0] ^= 1;
    run(bad, "native-pop-signature", "possession-signature");
    bad = base;
    bad.updates[0].second.possession_.clear();
    run(bad, "native-pop-required", "authority-shape");
    bad = base;
    bad.updates[0].second.administration_.clear();
    run(bad, "native-admin-required", "authority-shape");
    bad = base;
    auto cert = value(decode<Certificate>(bad.updates[0].second.administration_[0].certificate_.inline_), "cert");
    cert.records_[0].components_[0].signature_[0] ^= 1;
    bad.updates[0].second.administration_[0].certificate_ =
        value(object_value(4, value(encode(cert), "cert")), "carrier");
    run(bad, "native-admin-signature", "identity-signature");
    bad = base;
    bad.updates[0].second.owner_[0].proof_.proof_hash_ = h(887);
    run(bad, "native-owner-proof-authentication", "proof-hash");
    bad = base;
    cert = value(decode<Certificate>(bad.updates[0].second.administration_[0].certificate_.inline_), "cert");
    cert.duty_.genesis_root_ = h(888);
    cert.records_[0].components_[0].signature_ =
        sign(value(signing_statement(cert.duty_, cert.records_[0]), "other-context-statement"));
    bad.updates[0].second.administration_[0].certificate_ =
        value(object_value(4, value(encode(cert), "cert")), "carrier");
    run(bad, "native-claimed-duty-is-not-context", "identity-context");
    bad = base;
    bad.updates[0].second.governance_.push_back({});
    run(bad, "native-governance-is-not-identity", "authority-shape");
    bad = retire_only;
    bad.updates[0].second.owner_.push_back(owner);
    run(bad, "native-unused-owner", "authority-shape");
    bad = base;
    bad.inclusion = 101;
    run(bad, "native-block-gap", "block-gap");
    bad = base;
    bad.updates.clear();
    auto empty = run(bad, "native-empty-block");
    check(empty.revision() == base.parent.revision(), "native-empty-revision");
    bad = retire_only;
    Policy next_policy;
    bad.parent = policy_boundary(bad.parent, 100, next_policy);
    run(bad, "native-policy-before-authorization", "authority-current-policy");
    bad.policy = next_policy;
    bad.committee.policy_ = value(object_id("policy", next_policy), "pid");
    bad.committee.anchor_mc_ = 100;
    bad.updates = {retire(bad, bad.parent, old_admin)};
    run(bad, "native-current-policy-at-boundary");
    bad.updates.clear();
    auto policy_empty = run(bad, "native-empty-policy-boundary");
    check(policy_empty.current_policy() == bad.committee.policy_ && policy_empty.revision() == bad.parent.revision(),
          "native-policy-only-revision");
    // Schedule a role-5 change in a controlled authenticated parent, then prove
    // that due effects precede real current-key certificate admission.
    auto pending_parent = f.identity;
    auto uid = value(object_id("update", f.update), "uid");
    auto aid = value(object_id("authorizations", base.updates[0].second), "aid");
    pending_parent.next_nonce_ = 1;
    pending_parent.previous_ = f.update.previous_;
    pending_parent.pending_.push_back({2, 5, 1, 1, f.update.old_key_, value(object_id("key", new_admin), "kid"), 100,
                                       98, 0, f.update.previous_, uid, aid});
    auto keys = member.keys_;
    keys.push_back(new_admin);
    auto pending =
        value(RegistryState::genesis(f.registry.chain_domain(), base.policy, {pending_parent}, keys), "pending");
    Case due = base;
    due.parent = coordinate(pending, 99);
    due.updates.clear();
    auto due_only = run(due, "native-due-empty-block");
    due.updates = {retire(due, due_only, new_admin)};
    run(due, "native-due-before-new-admin");
    due.updates[0].second = evidence(due, due.updates[0].first, old_admin);
    run(due, "native-due-removes-old-admin", "identity-key-binding");
    auto maximum = base;
    maximum.parent = revision(base.parent, UINT64_MAX);
    run(maximum, "native-revision-overflow", "registry-revision");
    maximum.updates.clear();
    auto max_empty = run(maximum, "native-maximum-empty");
    check(max_empty.revision() == UINT64_MAX, "native-maximum-empty-revision");
    maximum = two;
    maximum.parent = revision(two.parent, UINT64_MAX - 1);
    auto max_final = run(maximum, "native-maximum-two-transactions");
    check(max_final.revision() == UINT64_MAX, "native-maximum-one-increment");
#ifdef P0_NATIVE_CONFIG_HOST
    {
      // The host is the only authority behind the two privileged instructions.
      // What matters is not that a good update applies, but that a refused one
      // leaves the accepted prefix exactly where it was: a reverted transaction
      // that moved the registry would be invisible to every other check.
      auto governing = snapshot(base);
      NativeIdentityContext host_context{base.chain, governing, base.history};
      ObjectReader host_reader({});
      auto persistent =
          value(NativeRegistry::bootstrap(value(base.parent.encode_cell(), "host-parent"), base.parent.coordinate()),
                "host-bootstrap");
      auto prefix = value(NativeRegistryBlock::begin(persistent, base.inclusion), "host-begin");
      // The evidence a registry message carries: the container admission opens,
      // which the contract then hands to the instruction unchanged. The host is
      // built from what was admitted, so it can recognise that reference rather
      // than read the cell a second time under a different assumption.
      auto carried_authorizations = value(encode(base.updates[0].second), "carried-authorizations");
      vm::CellBuilder carried;
      carried.store_long(native_evidence_tag, 32).store_long(1, 16).store_long(0, 1);
      carried.store_ref(value(pack_bytes(carried_authorizations), "carried-packed"))
          .store_ref(vm::CellBuilder().finalize());
      auto evidence_cell = carried.finalize();
      NativeConfigHost host(std::move(prefix), host_context, host_reader, base.inclusion, evidence_cell,
                            base.updates[0].second);

      long long charged = 0;
      auto charge = [&](long long amount) { charged += amount; };

      auto first = host.checkpoint(charge);
      check(first.not_null() && host.checkpoints() == 1, "host-checkpoint");
      check(charged >= 0, "host-checkpoint-charge");

      auto staged_before = value(host.staged().state().checkpoint(), "host-staged-before")->get_hash();

      // A canonical update and its evidence, carried as AuthBytes exactly as the
      // instruction receives them.
      auto update_cell = value(pack_bytes(value(encode(base.updates[0].first), "host-update")), "host-update-cell");

      // Any other cell, including the authorizations the container carries, is
      // not what this transaction was admitted with and must be refused before
      // any registry work.
      const std::vector<td::Ref<vm::Cell>> not_admitted = {
          value(pack_bytes(carried_authorizations), "other-packed"),
          td::Ref<vm::Cell>(vm::CellBuilder().store_long(0, 8).finalize())};
      for (const auto& other : not_admitted) {
        bool refused = false;
        try {
          host.apply(update_cell, other, charge);
        } catch (const vm::VmError&) {
          refused = true;
        }
        check(refused, "host-refuses-evidence-it-did-not-admit");
      }

      auto applied = host.apply(update_cell, evidence_cell, charge);
      check(applied.not_null() && host.updates() == 1, "host-apply");
      auto staged_after = value(host.staged().state().checkpoint(), "host-staged-after")->get_hash();
      check(staged_after != staged_before, "host-apply-advances-prefix");
      // The registry state, which is what the contract installs as
      // configuration parameter 46 and what every reader of that parameter
      // decodes. This once compared against the checkpoint instead, and nothing
      // noticed: the case that pins what parameter 46 holds runs against a
      // stand-in host, so the two descriptions never met.
      auto encoded = value(host.staged().state().encode_cell(), "host-staged-state");
      check(applied->get_hash() == encoded->get_hash(), "host-apply-returns-staged");
      // And the checkpoint the state instruction hands back commits to exactly
      // that cell -- restoring an account binds the two by hash, so a host that
      // returned one of them and staged the other would be refused there.
      auto restored = NativeRegistry::restore(value(host.staged().state().checkpoint(), "host-staged-checkpoint"),
                                              p0_owner_fixture::hash(encoded), host.staged().state().coordinate());
      check(restored.ok(), "host-apply-returns-staged");

      // A refused update must throw and must not move the prefix.
      auto rejected = base.updates[0].first;
      rejected.nonce_ = UINT64_MAX;
      auto rejected_cell = value(pack_bytes(value(encode(rejected), "host-rejected")), "host-rejected-cell");
      bool threw = false;
      try {
        host.apply(rejected_cell, evidence_cell, charge);
      } catch (const vm::VmError&) {
        threw = true;
      }
      check(threw, "host-refusal-throws");
      check(value(host.staged().state().checkpoint(), "host-staged-rejected")->get_hash() == staged_after,
            "host-refusal-does-not-move-prefix");
      check(host.updates() == 1, "host-refusal-not-counted");

      // An operand that is not a canonical AuthBytes cell is refused before any
      // registry work, not decoded into whatever it happens to resemble.
      threw = false;
      try {
        host.apply(vm::CellBuilder().store_long(0, 8).finalize(), evidence_cell, charge);
      } catch (const vm::VmError&) {
        threw = true;
      }
      check(threw, "host-operand-encoding-refused");
      check(value(host.staged().state().checkpoint(), "host-staged-operand")->get_hash() == staged_after,
            "host-operand-does-not-move-prefix");
      ++count;
      std::cout << "CASE_PASS native-config-host\n";
    }
#endif
    std::ofstream(out / "complete") << count << '\n';
    std::cout << "PASS: native authenticated ordered apply " << count << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
