#include "validator/auth/native-config-context.h"

#include "native-config-context-fixture.h"
#include "owner-fixture.h"

using namespace owner_fixture;
namespace context_fixture = config_context_fixture;

int main(int argc, char** argv) {
  try {
    check(argc == 3, "arguments");
    SET_VERBOSITY_LEVEL(0);
    std::filesystem::path inputs(argv[1]), out(argv[2]);
    check(std::filesystem::create_directory(out), "fresh-output");
    auto base = cell(read(inputs / "0.boc"));
    unsigned count = 0;
    auto run = [&](const context_fixture::ContextFixture& f, unsigned cache_mode, unsigned bind_mode, const char* label,
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
    auto f = context_fixture::make(base, 0);
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
      run(context_fixture::make(base, mode), 0, 0, labels[mode], errors[mode]);
    }
    run(context_fixture::make(base, 9), 0, 0, "config-restore-index", "checkpoint-index");
    run(context_fixture::make(base, 9), 1, 0, "config-cache-index", "config-cache-binding");
    run(context_fixture::make(base, 10), 0, 0, "config-restore-coordinate", "checkpoint-coordinate");
    run(context_fixture::make(base, 10), 3, 0, "config-cache-coordinate", "config-cache-binding");
    run(context_fixture::make(base, 11), 0, 0, "config-restore-registry", "checkpoint-registry");
    run(context_fixture::make(base, 11), 4, 0, "config-cache-registry", "config-cache-binding");
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
