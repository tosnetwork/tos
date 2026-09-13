#include <filesystem>
#include <fstream>
#include <iostream>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "validator/auth/owner-proof.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/MerkleUpdate.h"

#include "native-fixture.h"
using namespace p0_fixture;
namespace {
Bytes read(const std::filesystem::path& p) {
  std::ifstream f(p, std::ios::binary);
  check(f.good(), "input-file");
  return Bytes(std::istreambuf_iterator<char>(f), {});
}
void write(const std::filesystem::path& p, const Bytes& b) {
  std::ofstream f(p, std::ios::binary);
  f.write(reinterpret_cast<const char*>(b.data()), b.size());
  check(f.good(), "output-file");
}
Bytes boc(td::Ref<vm::Cell> c) {
  auto b = vm::std_boc_serialize(c);
  check(b.is_ok(), "fixture-boc");
  auto s = b.ok().as_slice();
  return Bytes(s.ubegin(), s.uend());
}
td::Ref<vm::Cell> cell(const Bytes& b) {
  auto c = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char*>(b.data()), b.size()));
  check(c.is_ok(), "fixture-cell");
  return c.move_as_ok();
}
Hash hash(td::Ref<vm::Cell> c) {
  Hash h{};
  auto own = c->get_hash();
  auto s = own.as_slice();
  std::copy(s.ubegin(), s.uend(), h.begin());
  return h;
}
td::Ref<vm::CellSlice> zero(unsigned bits) {
  vm::CellBuilder b;
  b.store_zeroes(bits);
  return vm::load_cell_slice_ref(b.finalize());
}
struct Fixture {
  RegistryState registry;
  Identity identity;
  Update update;
  ChainContext chain;
};
Fixture fixture(const std::filesystem::path& input) {
  auto raw = read(input / "owner");
  check(raw.size() == 36, "owner-size");
  Reader r(raw);
  std::int32_t wc;
  Hash address;
  r.integer(wc);
  r.hash(address);
  check(r.ok(), "owner-input");
  auto original = state(1);
  auto id = original.identities().begin()->second;
  id.owner_workchain_ = wc;
  id.owner_address_ = address;
  std::vector<Key> keys;
  for (const auto& role : id.active_)
    keys.push_back(value(original.find(role.key_.key_id_), "key"));
  auto policy = value(original.policy_at(0), "policy");
  auto registry = value(RegistryState::genesis(original.chain_domain(), policy, {id}, keys), "owner-registry");
  auto key = keys[0];
  key.epoch_ = 2;
  key.valid_from_ = 100;
  Update update{2,
                id.identity_,
                0,
                value(object_id("identity", id), "predecessor"),
                100,
                id.active_[0].key_.key_id_,
                value(encode(key), "new-key"),
                {},
                {}};
  return {registry, id, update, {42, h(11), h(12), registry.chain_domain()}};
}
td::Ref<vm::Cell> mcstate(const Fixture& f, td::Ref<vm::Cell> shard_block = {}) {
  auto root = masterchain(f.registry, 99);
  block::gen::ShardStateUnsplit::Record s;
  check(tlb::unpack_cell(root, s), "state-unpack");
  s.global_id = f.chain.network;
  block::gen::McStateExtra::Record extra;
  check(tlb::unpack_cell(s.custom->prefetch_ref(), extra), "extra-unpack");
  block::gen::ConfigParams::Record cp;
  check(tlb::csr_unpack(extra.config, cp), "config-unpack");
  vm::Dictionary config(cp.config, 32);
  vm::CellBuilder elector;
  elector.store_bytes(td::Slice(reinterpret_cast<const char*>(h(900).data()), 32));
  check(config.set_ref(td::BitArray<32>{1}, elector.finalize()), "elector-entry");
  cp.config = config.get_root_cell();
  vm::CellBuilder cb;
  check(tlb::pack(cb, cp), "config-pack");
  extra.config = vm::load_cell_slice_ref(cb.finalize());
  if (shard_block.not_null()) {
    vm::CellBuilder desc;
    desc.store_long(0, 1)
        .store_long(0xa, 4)
        .store_long(77, 32)
        .store_long(99, 32)
        .store_long(0, 64)
        .store_long(100000000, 64)
        .store_bytes(shard_block->get_hash().as_slice())
        .store_zeroes(256)
        .store_zeroes(8)
        .store_long(0, 32)
        .store_long(0x8000000000000000ULL, 64)
        .store_long(99, 32)
        .store_long(1780000000, 32)
        .store_long(0, 1);
    vm::CellBuilder fees;
    fees.store_zeroes(10);
    desc.store_ref(fees.finalize());
    vm::Dictionary shards(32);
    check(shards.set_ref(td::BitArray<32>{f.identity.owner_workchain_}, desc.finalize()), "shard-desc");
    vm::CellBuilder sw;
    check(shards.append_dict_to_bool(sw), "shards-wrap");
    extra.shard_hashes = vm::load_cell_slice_ref(sw.finalize());
  }
  td::Ref<vm::Cell> e;
  check(tlb::pack_cell(e, extra), "extra-pack");
  vm::CellBuilder custom;
  custom.store_long(1, 1).store_ref(e);
  s.custom = vm::load_cell_slice_ref(custom.finalize());
  check(tlb::pack_cell(root, s), "state-pack");
  return root;
}
td::Ref<vm::Cell> block_for(td::Ref<vm::Cell> tx, td::Ref<vm::Cell> state, const Fixture& f) {
  block::gen::Transaction::Record tr;
  check(tlb::unpack_cell(tx, tr), "tx-unpack");
  vm::AugmentedDictionary txs(64, block::tlb::aug_AccountTransactions);
  check(txs.set_ref(td::BitArray<64>{static_cast<long long>(tr.lt)}, tx), "tx-dictionary");
  block::gen::AccountBlock::Record account;
  account.account_addr = tr.account_addr;
  account.transactions = vm::load_cell_slice_ref(txs.get_root_cell());
  account.state_update = tr.state_update;
  vm::CellBuilder ab;
  check(tlb::pack(ab, account), "account-block");
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccountBlocks);
  check(accounts.set_builder(tr.account_addr, ab), "account-dictionary");
  vm::CellBuilder wrapped;
  check(accounts.append_dict_to_bool(wrapped), "account-wrapper");
  block::gen::BlockExtra::Record extra;
  extra.in_msg_descr = vm::CellBuilder().store_zeroes(1 + 10).finalize();
  extra.out_msg_descr = vm::CellBuilder().store_zeroes(1 + 5).finalize();
  extra.account_blocks = wrapped.finalize();
  extra.rand_seed.set_zero();
  extra.created_by.set_zero();
  extra.custom = zero(1);
  td::Ref<vm::Cell> extra_cell;
  check(tlb::pack_cell(extra_cell, extra), "block-extra");
  vm::CellBuilder prev;
  prev.store_zeroes(64).store_long(98, 32).store_zeroes(512);
  vm::CellBuilder info;
  bool shard = f.identity.owner_workchain_ != -1;
  info.store_long(0x9bc7a987, 32)
      .store_long(0, 32)
      .store_long(shard ? 128 : 0, 8)
      .store_long(0, 8)
      .store_long(shard ? 77 : 99, 32)
      .store_long(0, 32)
      .store_zeroes(8)
      .store_long(f.identity.owner_workchain_, 32)
      .store_long(0, 64)
      .store_long(tr.now, 32)
      .store_long(tr.lt - 1, 64)
      .store_long(tr.lt + 100, 64)
      .store_zeroes(128);
  if (shard)
    info.store_ref(prev.finalize_copy());
  info.store_ref(prev.finalize());
  vm::CellBuilder flow_values;
  flow_values.store_zeroes(20);
  auto fv = flow_values.finalize();
  vm::CellBuilder flow;
  flow.store_long(0xb8e48dfb, 32).store_ref(fv).store_zeroes(5).store_ref(fv);
  vm::CellUsageTree used;
  auto change = vm::MerkleUpdate::generate(state, state, &used);
  check(change.is_ok(), "state-update");
  vm::CellBuilder b;
  b.store_long(0x11ef55aa, 32)
      .store_long(f.chain.network, 32)
      .store_ref(info.finalize())
      .store_ref(flow.finalize())
      .store_ref(change.ok())
      .store_ref(extra_cell);
  return b.finalize();
}
OwnerAuth claim(const Fixture& f, td::Ref<vm::Cell> state, td::Ref<vm::Cell> block, const Anchor& a, std::uint64_t lt,
                std::uint16_t index = 0) {
  auto sp = vm::MerkleProof::generate(state, [](const auto&) { return false; });
  auto bp = vm::MerkleProof::generate(block, [](const auto&) { return false; });
  check(sp.is_ok() && bp.is_ok(), "fixture-full-proof");
  vm::CellBuilder root;
  root.store_long(owner_proof_tag, 32)
      .store_long(1, 16)
      .store_long(lt, 64)
      .store_long(index, 15)
      .store_ref(sp.ok())
      .store_ref(bp.ok());
  auto bytes = boc(root.finalize());
  auto id = value(object_id("update", f.update), "claim-id");
  return {
      id,
      f.identity.stake_id_,
      f.identity.owner_workchain_,
      f.identity.owner_address_,
      {a, 1, id, value(digest("proof", bytes), "claim-proof-hash"), value(object_value(5, bytes), "claim-carrier")}};
}

}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 3 || argc == 4, "arguments");
    std::string mode = argv[1];
    std::filesystem::path input = argv[2];
    auto f = fixture(input);
    if (mode == "prepare") {
      write(input / "identity", value(encode(f.identity), "identity"));
      write(input / "update", value(encode(f.update), "update"));
      write(input / "body.boc", boc(value(owner_approval_body(f.chain, f.update, f.identity), "body")));
      return 0;
    }
    check(mode == "verify" && argc == 4, "mode");
    std::filesystem::path out = argv[3];
    check(std::filesystem::create_directory(out), "fresh-output");
    auto tx = cell(read(input / "accept.boc"));
    auto state = mcstate(f);
    auto block = block_for(tx, state, f);
    if (f.identity.owner_workchain_ != -1)
      state = mcstate(f, block);
    Anchor a{99, hash(block), h(6001), hash(state)};
    block::gen::Transaction::Record transaction;
    check(tlb::unpack_cell(tx, transaction), "transaction");
    auto auth = value(make_owner_execution_proof(state, block, a, f.chain, f.update, f.identity, transaction.lt, 0),
                      "owner-make");
    ObjectReader reader({});
    auto accepted = value(verify_owner_execution(auth, f.update, f.identity, a, f.chain, reader), "owner-verify");
    check(accepted.transaction_id() == hash(tx), "owner-transaction-hash");
    unsigned count = 0;
    auto record = [&](const OwnerAuth& candidate, const Update& update, const Identity& identity, const Anchor& anchor,
                      const ChainContext& context, const char* error, const char* label, const Hash& result = Hash{}) {
      auto folder = out / std::to_string(count++);
      check(std::filesystem::create_directory(folder), "case-folder");
      write(folder / "auth", value(encode(candidate), "auth"));
      write(folder / "update", value(encode(update), "update"));
      write(folder / "identity", value(encode(identity), "identity"));
      write(folder / "anchor", value(encode(anchor), "anchor"));
      Writer w;
      w.integer(context.network);
      w.bytes(context.genesis_root);
      w.bytes(context.genesis_file);
      w.bytes(context.chain_domain);
      write(folder / "chain", w.data);
      write(folder / "transaction", Bytes(result.begin(), result.end()));
      std::ofstream meta(folder / "case");
      meta << error << ' ' << label << '\n';
    };
    record(auth, f.update, f.identity, a, f.chain, "-", "owner-valid", accepted.transaction_id());
    auto reject = [&](OwnerAuth candidate, Update update, Identity identity, Anchor anchor, ChainContext context,
                      const char* error, const char* label) {
      ObjectReader r({});
      auto result = verify_owner_execution(candidate, update, identity, anchor, context, r);
      if (result.ok() || result.error().code != error) {
        std::cerr << "expected " << error << " got " << (result.ok() ? "success" : result.error().code) << '\n';
        check(false, label);
      }
      record(candidate, update, identity, anchor, context, error, label);
    };
    auto bad = auth;
    bad.update_id_ = h(88);
    reject(bad, f.update, f.identity, a, f.chain, "owner-binding", "owner-wrapper-update");
    bad = auth;
    bad.stake_id_ = h(88);
    reject(bad, f.update, f.identity, a, f.chain, "owner-binding", "owner-wrapper-stake");
    bad = auth;
    bad.owner_address_ = h(88);
    reject(bad, f.update, f.identity, a, f.chain, "owner-binding", "owner-wrapper-address");
    bad = auth;
    bad.owner_workchain_ = 2;
    reject(bad, f.update, f.identity, a, f.chain, "owner-binding", "owner-wrapper-workchain");
    bad = auth;
    bad.proof_.kind_ = 2;
    reject(bad, f.update, f.identity, a, f.chain, "proof-kind", "owner-proof-kind");
    bad = auth;
    bad.proof_.object_id_ = h(88);
    reject(bad, f.update, f.identity, a, f.chain, "proof-object", "owner-proof-object");
    bad = auth;
    bad.proof_.proof_hash_ = h(88);
    reject(bad, f.update, f.identity, a, f.chain, "proof-hash", "owner-proof-hash");
    auto changed = a;
    changed.file_ = h(88);
    reject(auth, f.update, f.identity, changed, f.chain, "proof-anchor", "owner-proof-anchor");
    auto chain_bad = f.chain;
    chain_bad.network = 43;
    reject(auth, f.update, f.identity, a, chain_bad, "state-context", "owner-network");
    chain_bad = f.chain;
    chain_bad.chain_domain = h(88);
    reject(auth, f.update, f.identity, a, chain_bad, "chain-domain", "owner-chain-domain");
    auto changed_update = f.update;
    changed_update.operation_ = 3;
    reject(auth, changed_update, f.identity, a, f.chain, "owner-target", "owner-operation");
    for (const char* name : {"wrong-update", "wrong-stake", "wrong-domain", "wrong-target", "rollback"}) {
      auto t = cell(read(input / (std::string(name) + ".boc")));
      auto s = mcstate(f);
      auto b = block_for(t, s, f);
      if (f.identity.owner_workchain_ != -1)
        s = mcstate(f, b);
      auto anchor = a;
      anchor.root_ = hash(b);
      anchor.state_ = hash(s);
      block::gen::Transaction::Record tr;
      check(tlb::unpack_cell(t, tr), "negative-transaction");
      auto rejected = make_owner_execution_proof(s, b, anchor, f.chain, f.update, f.identity, tr.lt, 0);
      auto expected = std::string(name) == "rollback"       ? "owner-execution"
                      : std::string(name) == "wrong-target" ? "owner-message"
                                                            : "owner-approval";
      check(!rejected.ok() && rejected.error().code == expected, name);
      reject(claim(f, s, b, anchor, tr.lt), f.update, f.identity, anchor, f.chain, expected, name);
    }
    auto with_body = [&](OwnerAuth original, td::Ref<vm::Cell> root) {
      auto bytes = boc(root);
      original.proof_.proof_ = value(object_value(5, bytes), "changed-carrier");
      original.proof_.proof_hash_ = value(digest("proof", bytes), "changed-hash");
      return original;
    };
    auto raw = value(ObjectReader({}).resolve(auth.proof_.proof_, 5), "proof-raw");
    auto carrier = cell(raw);
    vm::CellSlice ps{vm::NoVm{}, carrier};
    auto reheader = [&](std::uint32_t tag, std::uint16_t version, std::uint64_t lt, std::uint16_t index) {
      vm::CellBuilder r;
      r.store_long(tag, 32)
          .store_long(version, 16)
          .store_long(lt, 64)
          .store_long(index, 15)
          .store_ref(ps.prefetch_ref(0))
          .store_ref(ps.prefetch_ref(1));
      return r.finalize();
    };
    reject(with_body(auth, reheader(owner_proof_tag ^ 1, 1, transaction.lt, 0)), f.update, f.identity, a, f.chain,
           "owner-proof-header", "owner-header-tag");
    reject(with_body(auth, reheader(owner_proof_tag, 2, transaction.lt, 0)), f.update, f.identity, a, f.chain,
           "owner-proof-header", "owner-header-version");
    reject(with_body(auth, reheader(owner_proof_tag, 1, transaction.lt - 1, 0)), f.update, f.identity, a, f.chain,
           "owner-transaction", "owner-lt-locator");
    reject(with_body(auth, reheader(owner_proof_tag, 1, transaction.lt, 1)), f.update, f.identity, a, f.chain,
           "owner-message-index", "owner-message-locator");
    reject(claim(f, state, block, a, transaction.lt), f.update, f.identity, a, f.chain, "proof-unrelated-values",
           "owner-unrelated-reveals");
    auto moved = f.identity;
    moved.owner_address_ = h(88);
    bad = auth;
    bad.owner_address_ = moved.owner_address_;
    reject(bad, f.update, moved, a, f.chain, "owner-allocation", "owner-current-allocation");
    moved = f.identity;
    moved.stake_id_ = h(88);
    bad = auth;
    bad.stake_id_ = moved.stake_id_;
    reject(bad, f.update, moved, a, f.chain, "owner-allocation", "owner-current-stake");
    changed = a;
    changed.state_ = h(88);
    bad = auth;
    bad.proof_.anchor_ = changed;
    reject(bad, f.update, f.identity, changed, f.chain, "owner-anchor", "owner-state-substitution");
    changed = a;
    changed.root_ = h(88);
    bad = auth;
    bad.proof_.anchor_ = changed;
    if (f.identity.owner_workchain_ == -1)
      reject(bad, f.update, f.identity, changed, f.chain, "owner-block-anchor", "owner-block-substitution");
    for (const char* label : {"owner-compute-success", "owner-aborted", "owner-destroyed", "owner-action-success",
                              "owner-action-valid", "owner-action-funds", "owner-action-code", "owner-action-count"}) {
      auto t = transaction;
      block::gen::TransactionDescr::Record_trans_ord d;
      check(tlb::unpack_cell(t.description, d), "phase-descriptor");
      block::gen::TrComputePhase::Record_tr_phase_compute_vm compute;
      check(tlb::csr_unpack(d.compute_ph, compute), "phase-compute");
      block::gen::TrActionPhase::Record action;
      check(tlb::unpack_cell(d.action->prefetch_ref(), action), "phase-action");
      std::string name(label);
      if (name == "owner-compute-success")
        compute.success = false;
      if (name == "owner-aborted")
        d.aborted = true;
      if (name == "owner-destroyed")
        d.destroyed = true;
      if (name == "owner-action-success")
        action.success = false;
      if (name == "owner-action-valid")
        action.valid = false;
      if (name == "owner-action-funds")
        action.no_funds = true;
      if (name == "owner-action-code")
        action.result_code = 1;
      if (name == "owner-action-count")
        action.msgs_created = 2;
      vm::CellBuilder cp;
      check(tlb::pack(cp, compute), "compute-pack");
      d.compute_ph = vm::load_cell_slice_ref(cp.finalize());
      td::Ref<vm::Cell> ap;
      check(tlb::pack_cell(ap, action), "action-pack");
      vm::CellBuilder opt;
      opt.store_long(1, 1).store_ref(ap);
      d.action = vm::load_cell_slice_ref(opt.finalize());
      check(tlb::pack_cell(t.description, d), "descriptor-pack");
      vm::CellSlice ts{vm::NoVm{}, tx};
      vm::CellBuilder tb;
      tb.store_bits(ts.fetch_bits(ts.size()))
          .store_ref(ts.prefetch_ref(0))
          .store_ref(ts.prefetch_ref(1))
          .store_ref(t.description);
      td::Ref<vm::Cell> tc = tb.finalize();
      auto s = mcstate(f);
      auto b = block_for(tc, s, f);
      if (f.identity.owner_workchain_ != -1)
        s = mcstate(f, b);
      auto anchor = a;
      anchor.root_ = hash(b);
      anchor.state_ = hash(s);
      reject(claim(f, s, b, anchor, t.lt), f.update, f.identity, anchor, f.chain,
             name == "owner-action-count" ? "owner-message-index" : "owner-execution", label);
    }
    if (f.identity.owner_workchain_ != -1) {
      block::gen::Block::Record alternate;
      check(tlb::unpack_cell(block, alternate), "alternate-block");
      block::gen::BlockExtra::Record extra;
      check(tlb::unpack_cell(alternate.extra, extra), "alternate-extra");
      extra.rand_seed = td::Bits256{td::ConstBitPtr(h(8900).data())};
      check(tlb::pack_cell(alternate.extra, extra), "alternate-extra-pack");
      td::Ref<vm::Cell> other;
      check(tlb::pack_cell(other, alternate), "alternate-block-pack");
      auto other_state = mcstate(f, other);
      auto other_anchor = a;
      other_anchor.state_ = hash(other_state);
      auto other_auth = value(make_owner_execution_proof(other_state, other, other_anchor, f.chain, f.update,
                                                         f.identity, transaction.lt, 0),
                              "alternate-proof");
      auto other_raw = value(ObjectReader({}).resolve(other_auth.proof_.proof_, 5), "alternate-raw");
      vm::CellSlice other_header{vm::NoVm{}, cell(other_raw)};
      vm::CellBuilder mixed;
      mixed.store_bits(ps.prefetch_bits(ps.size()))
          .store_ref(ps.prefetch_ref(0))
          .store_ref(other_header.prefetch_ref(1));
      reject(with_body(auth, mixed.finalize()), f.update, f.identity, a, f.chain, "owner-shard-anchor",
             "owner-shard-substitution");
    }
    std::ofstream complete(out / "complete");
    complete << count << '\n';

    std::cout << "PASS: native owner execution " << count << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
