#include "owner-fixture.h"
using namespace p0_owner_fixture;
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
