#include "validator/auth/native-config-context.h"

#include "owner-fixture.h"
using namespace p0_owner_fixture;
namespace {
td::Ref<vm::Cell> account_cell(Hash address, td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, bool tick) {
  vm::CellBuilder a;
  a.store_long(1, 1)
      .store_long(0x9f, 8)
      .store_long(7, 3)
      .store_bytes(td::Slice(address.data(), 32))
      .store_zeroes(3 + 3 + 3 + 32 + 1)
      .store_long(1, 64)
      .store_long(4, 4)
      .store_long(1000000000, 32)
      .store_long(0, 1)
      .store_long(1, 1)
      .store_long(0, 1)
      .store_long(1, 1)
      .store_long(tick, 1)
      .store_long(1, 1)
      .store_long(1, 1)
      .store_ref(code)
      .store_long(1, 1)
      .store_ref(data)
      .store_long(0, 1);
  return vm::CellBuilder().store_zeroes(256 + 64).store_ref(a.finalize()).finalize();
}
struct ContextFixture {
  td::Ref<vm::Cell> root, code, data, checkpoint;
  Anchor head;
  ChainContext chain;
  Hash address;
};
ContextFixture make(td::Ref<vm::Cell> base, unsigned mode) {
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::gen::ConfigParams::Record params;
  check(tlb::unpack_cell(base, state) && tlb::unpack_cell(state.custom->prefetch_ref(), extra) &&
            tlb::csr_unpack(extra.config, params),
        "fixture-context-state");
  vm::Dictionary config(params.config, 32);
  Hash address = h(900);
  auto parameter_address = mode == 1 ? h(0) : address;
  auto encoded_address = vm::CellBuilder().store_bytes(td::Slice(parameter_address.data(), 32)).finalize();
  check(config.set_ref(td::BitArray<32>{0LL}, encoded_address), "fixture-address");
  params.config = config.get_root_cell();
  if (mode == 2)
    params.config_addr = td::Bits256(td::ConstBitPtr(h(901).data()));
  vm::CellBuilder cp;
  check(tlb::pack(cp, params), "fixture-params");
  extra.config = vm::load_cell_slice_ref(cp.finalize());
  td::Ref<vm::Cell> custom;
  check(tlb::pack_cell(custom, extra), "fixture-extra");
  state.custom = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(custom).finalize());
  auto registry =
      value(NativeRegistry::bootstrap(config.lookup_ref(td::BitArray<32>{46}), state.seq_no), "fixture-registry");
  auto checkpoint = value(registry.checkpoint(), "fixture-checkpoint");
  if (mode == 9) {
    auto old = vm::load_cell_slice(checkpoint);
    vm::CellBuilder b;
    b.store_bits(old.prefetch_bits(old.size()))
        .store_ref(old.prefetch_ref(0))
        .store_ref(vm::CellBuilder().store_long(0, 1).finalize())
        .store_ref(old.prefetch_ref(2))
        .store_ref(old.prefetch_ref(3));
    checkpoint = b.finalize();
  }
  if (mode == 10) {
    auto later = value(NativeRegistry::bootstrap(config.lookup_ref(td::BitArray<32>{46}), 1), "fixture-later-cache");
    checkpoint = value(later.checkpoint(), "fixture-later-checkpoint");
  }
  if (mode == 11) {
    auto other = value(NativeRegistry::bootstrap(value(p0_fixture::state(3).encode_cell(), "fixture-other-root"), 0),
                       "fixture-other-state");
    checkpoint = value(other.checkpoint(), "fixture-other-checkpoint");
  }
  auto code = vm::CellBuilder().store_long(0, 8).finalize();
  auto own_config = params.config;
  if (mode == 7) {
    auto changed = config;
    check(changed.set_ref(td::BitArray<32>{1234}, vm::CellBuilder().finalize()), "fixture-other-config");
    own_config = changed.get_root_cell();
  }
  vm::CellBuilder d;
  d.store_ref(own_config).store_zeroes(32 + 256).store_long(0, 1);
  if (mode != 6)
    d.store_ref(checkpoint);
  if (mode == 8)
    d.store_long(0, 1);
  auto data = d.finalize();
  auto account = account_cell(mode == 4 ? h(901) : address, code, data, mode != 5);
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  if (mode != 3)
    check(accounts.set(td::ConstBitPtr(address.data()), 256, vm::load_cell_slice_ref(account)),
          "fixture-account-entry");
  vm::CellBuilder wrapped;
  check(accounts.append_dict_to_bool(wrapped), "fixture-accounts");
  state.accounts = wrapped.finalize();
  td::Ref<vm::Cell> root;
  check(tlb::pack_cell(root, state), "fixture-state-pack");
  Hash file{};
  auto bytes = boc(root);
  check(crypto_hash_sha256(file.data(), bytes.data(), bytes.size()) == 0, "fixture-file-hash");
  Anchor head{state.seq_no, hash(root), file, hash(root)};
  ChainContext chain{state.global_id, head.root_, head.file_, registry.chain_domain()};
  return {root, code, data, checkpoint, head, chain, address};
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 3, "arguments");
    SET_VERBOSITY_LEVEL(0);
    std::filesystem::path inputs(argv[1]), out(argv[2]);
    check(std::filesystem::create_directory(out), "fresh-output");
    auto base = cell(read(inputs / "0.boc"));
    unsigned count = 0;
    auto run = [&](const ContextFixture& f, unsigned cache_mode, unsigned bind_mode, const char* label,
                   const char* error) {
      auto folder = out / std::to_string(count++);
      check(std::filesystem::create_directory(folder), "case-dir");
      auto cfg = block::Config::extract_from_state(f.root);
      check(cfg.is_ok(), "fixture-cache-config");
      auto registry =
          value(NativeRegistry::bootstrap(cfg.ok()->get_config_param(46), cache_mode == 3 ? 1 : f.head.seqno_),
                "fixture-cache");
      auto other = value(NativeRegistry::bootstrap(value(state(3).encode_cell(), "fixture-other-root"), 0),
                         "fixture-other-cache");
      auto& cached = cache_mode == 2 || cache_mode == 4 ? other : registry;
      auto result = NativeConfigContext::open(f.root, f.head, f.chain, cache_mode ? &cached : nullptr);
      write(folder / "cache", boc(value(cached.checkpoint(), "cache-export")));
      write(folder / "state", boc(f.root));
      write(folder / "head", value(encode(f.head), "head"));
      write(folder / "checkpoint", boc(f.checkpoint));
      write(folder / "other-cache", boc(value(other.checkpoint(), "cache")));
      Writer w;
      w.integer(f.chain.network);
      w.bytes(f.chain.genesis_root);
      w.bytes(f.chain.genesis_file);
      w.bytes(f.chain.chain_domain);
      write(folder / "chain", w.data);
      write(folder / "code", boc(f.code));
      write(folder / "data", boc(f.data));
      write(folder / "address", Bytes(f.address.begin(), f.address.end()));
      std::ofstream(folder / "case") << cache_mode << ' ' << bind_mode << ' ' << label << ' ' << error << '\n';
      std::string actual = result.ok() ? "-" : result.error().code;
      if (result.ok()) {
        auto& context = result.value();
        auto code = bind_mode == 3 ? vm::CellBuilder().store_long(1, 8).finalize() : f.code;
        auto data = bind_mode == 4 ? vm::CellBuilder().store_long(1, 8).finalize() : f.data;
        auto library = bind_mode == 5 ? vm::CellBuilder().store_long(1, 8).finalize() : td::Ref<vm::Cell>{};
        auto bound = context.binds(bind_mode == 1 ? 0 : -1, bind_mode == 2 ? h(901) : f.address, code, data, library);
        if (!bound.ok())
          actual = bound.error().code;
        else {
          check(context.address() == f.address && context.chain().chain_domain == f.chain.chain_domain &&
                    context.head() == f.head,
                label);
          check(hash(value(context.parent().checkpoint(), "context-checkpoint")) == hash(f.checkpoint), label);
          write(folder / "committee", value(encode(context.committee().snapshot().committee()), "committee"));
        }
      }
      if (actual != error) {
        std::cerr << "DETAIL " << label << " expected=" << error << " actual=" << actual << '\n';
        check(false, label);
      }
    };
    auto f = make(base, 0);
    run(f, 0, 0, "config-authenticated-account", "-");
    run(f, 1, 0, "config-validated-cache", "-");
    run(f, 2, 0, "config-cache-substitution", "config-cache-binding");
    for (unsigned mode = 1; mode <= 8; ++mode) {
      const char* labels[]{"",
                           "config-zero-address",
                           "config-extra-address",
                           "config-missing-account",
                           "config-account-address",
                           "config-required-tick",
                           "config-required-checkpoint",
                           "config-owned-dictionary",
                           "config-data-trailing"};
      const char* errors[]{"",
                           "config-address",
                           "config-address-binding",
                           "config-account",
                           "config-account",
                           "config-account",
                           "config-data",
                           "config-dictionary-binding",
                           "config-data"};
      run(make(base, mode), 0, 0, labels[mode], errors[mode]);
    }
    run(make(base, 9), 0, 0, "config-restore-index", "checkpoint-index");
    run(make(base, 9), 1, 0, "config-cache-index", "config-cache-binding");
    run(make(base, 10), 0, 0, "config-restore-coordinate", "checkpoint-coordinate");
    run(make(base, 10), 3, 0, "config-cache-coordinate", "config-cache-binding");
    run(make(base, 11), 0, 0, "config-restore-registry", "checkpoint-registry");
    run(make(base, 11), 4, 0, "config-cache-registry", "config-cache-binding");
    for (unsigned mode = 1; mode <= 5; ++mode) {
      const char* labels[]{"",
                           "config-bind-workchain",
                           "config-bind-address",
                           "config-bind-code",
                           "config-bind-data",
                           "config-bind-library"};
      run(f, 0, mode, labels[mode], "config-transaction-binding");
    }
    std::ofstream(out / "complete") << count << '\n';
    std::cout << "PASS: authenticated native configuration context " << count << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
