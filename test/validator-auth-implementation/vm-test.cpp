#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <stdexcept>

#include "validator/auth/cells.h"
#include "vm/authops.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cp0.h"
#include "vm/vm.h"

using namespace tos::auth;
using Cell = td::Ref<vm::Cell>;
std::filesystem::path export_path;
unsigned exported = 0;
void check(bool result, const std::string& label) {
  if (!result)
    throw std::runtime_error(label);
}
td::Slice slice(std::span<const std::uint8_t> bytes) {
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}
Cell packed(const Bytes& bytes) {
  auto result = pack_bytes(bytes);
  check(result.ok(), "fixture-pack");
  return result.value();
}
Cell leaf(std::span<const std::uint8_t> bytes) {
  return vm::CellBuilder().store_long(0, 1).store_long(bytes.size(), 7).store_bytes(slice(bytes)).finalize();
}
Cell root(const Bytes& bytes, Cell tree, unsigned tag = 0x76616231, unsigned version = 1, long long declared = -1,
          bool bad_hash = false) {
  Hash hash;
  check(crypto_hash_sha256(hash.data(), bytes.data(), bytes.size()) == 0, "fixture-hash");
  if (bad_hash)
    hash[0] ^= 1;
  return vm::CellBuilder()
      .store_long(tag, 32)
      .store_long(version, 16)
      .store_long(declared < 0 ? bytes.size() : declared, 32)
      .store_bytes(slice(hash))
      .store_ref(tree)
      .finalize();
}
struct Input {
  Cell message, signature;
  Hash key;
};
struct Run {
  int exit;
  long long gas;
  long long value;
};
Run execute(const Input& in, int version = 16, td::uint64 capabilities = 1024, long long budget = 1000000,
            bool ignore = false, bool child = false, bool forged_c7 = false, unsigned repeats = 1, unsigned fault = 0) {
  auto opcode = vm::CellBuilder().store_long(0xf917, 16).finalize();
  td::Ref<vm::Stack> stack{true};
  for (unsigned i = 0; i < repeats; ++i) {
    if (fault == 5)
      stack.write().push_cellslice(vm::load_cell_slice_ref(in.message));
    else
      stack.write().push_cell(in.message);
    if (fault == 4)
      stack.write().push_smallint(0);
    else
      stack.write().push_cellslice(vm::load_cell_slice_ref(in.signature));
    auto key = td::make_refint(0);
    check(key.write().import_bytes(in.key.data(), in.key.size(), false), "fixture-key");
    if (fault == 1)
      key = td::make_refint(-1);
    if (fault == 2)
      key.write().invalidate();
    if (fault == 3)
      stack.write().push_cell(in.message);
    else if (fault == 2)
      stack.write().push_int_quiet(std::move(key));
    else if (fault != 6)
      stack.write().push_int(std::move(key));
  }
  Cell code = opcode;
  if (child) {
    stack.write().push_smallint(3);
    stack.write().push_cellslice(vm::load_cell_slice_ref(opcode));
    code = vm::CellBuilder().store_long(0xdb4000, 24).store_long(0x30, 8).finalize();  // RUNVM 0; DROP exit
  } else if (repeats > 1) {
    vm::CellBuilder builder;
    for (unsigned i = 1; i < repeats; ++i)
      builder.store_long(0xf917, 16).store_long(0x30, 8);  // DROP boolean
    code = builder.store_long(0xf917, 16).finalize();
  }
  td::Ref<vm::Tuple> c7;
  if (forged_c7)
    c7 = td::make_ref<vm::Tuple>(std::vector<vm::StackEntry>{vm::StackEntry(td::make_refint(1024))});
  vm::VmState state{vm::load_cell_slice_ref(code),
                    version,
                    std::move(stack),
                    vm::GasLimits{budget, budget},
                    0,
                    {},
                    {},
                    {},
                    c7,
                    capabilities};
  state.set_chksig_always_succeed(ignore);
  auto exit = ~state.run();
  long long value = 99;
  if (exit == 0) {
    check(state.get_stack().depth() == 1, "vm-stack-result");
    value = state.get_stack().pop_int_finite()->to_long();
  }
  if (!export_path.empty()) {
    auto dir = export_path / std::to_string(exported++);
    check(std::filesystem::create_directory(dir), "fixture-export-directory");
    auto save = [&](const char* name, Cell cell) {
      auto boc = vm::std_boc_serialize(cell);
      check(boc.is_ok(), "fixture-export-boc");
      std::ofstream file(dir / name, std::ios::binary);
      file.write(boc.ok().as_slice().data(), boc.ok().size());
      check(file.good(), "fixture-export-write");
    };
    save("message.boc", in.message);
    save("signature.boc", in.signature);
    save("code.boc", code);
    std::ofstream key(dir / "key", std::ios::binary);
    key.write(reinterpret_cast<const char*>(in.key.data()), in.key.size());
    check(key.good(), "fixture-export-key");
    std::ofstream meta(dir / "meta");
    meta << version << ' ' << capabilities << ' ' << budget << ' ' << ignore << ' ' << child << ' ' << forged_c7 << ' '
         << repeats << ' ' << exit << ' ' << state.gas_consumed() << ' ' << value << '\n';
    check(meta.good(), "fixture-export-meta");
    std::ofstream fault_file(dir / "fault");
    fault_file << fault << '\n';
    check(fault_file.good(), "fixture-export-fault");
  }
  return {exit, state.gas_consumed(), value};
}
int main(int argc, char** argv) {
  try {
    check(argc >= 1 && argc <= 3, "arguments");
    if (argc >= 2) {
      export_path = argv[1];
      check(std::filesystem::create_directory(export_path), "fresh-vm-fixtures");
    }
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(0);
    check(sodium_init() >= 0, "fixture-sodium");
    std::array<unsigned char, 32> seed{};
    std::array<unsigned char, 64> secret{}, sig{};
    Hash pub;
    check(crypto_sign_seed_keypair(pub.data(), secret.data(), seed.data()) == 0, "fixture-keypair");
    auto input = [&](const Bytes& bytes) {
      check(crypto_sign_detached(sig.data(), nullptr, bytes.data(), bytes.size(), secret.data()) == 0, "fixture-sign");
      return Input{packed(bytes), vm::CellBuilder().store_bytes(slice(sig)).finalize(), pub};
    };
    auto good = input(Bytes(300, 7));
    auto valid = execute(good);
    check(valid.exit == 0 && valid.value == -1, "valid-long-message");
    check(valid.gas >= 50000 + 300, "base-and-byte-gas");
    auto three = execute(input(Bytes(3, 5))), four = execute(input(Bytes(4, 5)));
    check(three.exit == 0 && four.exit == 0 && four.gas == three.gas + 1, "byte-gas");
    check(execute(good, 15).exit == 6, "version-gate");
    check(execute(good, 16, 0).exit == 6, "capability-gate");
    check(execute(good, 16, 0).gas == 60, "disabled-instruction-gas");
    for (int version : {0, 3, 4, 15, 16}) {
      for (long long budget : {0LL, 9LL, 10LL, 59LL, 60LL}) {
        auto result = execute(good, version, 0, budget);
        check(result.exit == (budget == 60 ? 6 : -14), "disabled-gas-boundary");
      }
    }
    check(execute(good, 16, 512).exit == 6, "unrelated-capability");
    check(execute(good, 16, 0, 1000000, false, false, true).exit == 6, "immutable-capability");
    check(execute(good, 16, 1024, 1000000, false, true).value == -1, "child-capability");
    auto at = execute(good, 16, 1024, valid.gas);
    auto below = execute(good, 16, 1024, valid.gas - 1);
    check(at.exit == 0 && at.value == -1 && below.exit == -14, "exact-gas-boundary");
    check(execute(good, 16, 1024, 50000).exit == -14, "base-gas-admission");
    check(execute(good, 16, 1024, 1000000, false, false, false, 2).gas >= 100000 + 600, "every-call-metered");
    for (unsigned fault = 1; fault <= 6; ++fault) {
      auto result = execute(good, 16, 1024, 1000000, false, false, false, 1, fault);
      check(result.exit == (fault <= 2 ? 5 : fault == 6 ? 2 : 7), "operand-" + std::to_string(fault));
    }
    auto bad = good;
    check(crypto_sign_detached(sig.data(), nullptr, Bytes(300, 7).data(), 300, secret.data()) == 0, "fixture-sign");
    sig[0] ^= 1;
    bad.signature = vm::CellBuilder().store_bytes(slice(sig)).finalize();
    auto denied = execute(bad, 16, 1024, 1000000, true);
    check(denied.exit == 0 && denied.value == 0, "invalid-signature-no-bypass");
    bad = good;
    bad.key.fill(0);
    bad.key[0] = 1;
    auto weak = execute(bad);
    check(weak.exit == 0 && weak.value == 0, "key-admission");
    for (auto size : {1U, 119U, 120U, 121U, 480U, 481U, 1920U, 1921U, 65536U}) {
      auto result = execute(input(Bytes(size, 17)));
      check(result.exit == 0 && result.value == -1, "message-boundary-" + std::to_string(size));
    }
    bad = input(Bytes(65537, 17));
    check(execute(bad).exit == 9, "message-upper-bound");
    bad = good;
    const Bytes small(3, 5);
    auto reject_root = [&](Cell message, const char* label) {
      auto changed = good;
      changed.message = message;
      check(execute(changed).exit == 9, label);
    };
    reject_root(root({}, leaf(small), 0x76616231, 1, 0), "message-empty");
    reject_root(root(small, leaf(small), 0x76616230), "root-tag");
    reject_root(root(small, leaf(small), 0x76616231, 2), "root-version");
    reject_root(root(small, leaf(small), 0x76616231, 1, -1, true), "root-hash");
    reject_root(root(small, leaf(Bytes(2, 5))), "leaf-length");
    reject_root(root(small, vm::CellBuilder().store_long(1, 1).store_long(3, 7).store_bytes(slice(small)).finalize()),
                "leaf-kind");
    reject_root(
        root(small,
             vm::CellBuilder().store_long(0, 1).store_long(3, 7).store_bytes(slice(small)).store_long(0, 1).finalize()),
        "leaf-bit-tail");
    reject_root(root(small, vm::CellBuilder()
                                .store_long(0, 1)
                                .store_long(3, 7)
                                .store_bytes(slice(small))
                                .store_ref(leaf(small))
                                .finalize()),
                "leaf-ref-tail");
    Bytes branch(121, 9);
    auto raw = std::span<const std::uint8_t>(branch);
    auto alternative = vm::CellBuilder()
                           .store_long(1, 1)
                           .store_long(2, 3)
                           .store_long(121, 32)
                           .store_ref(leaf(raw.first(119)))
                           .store_ref(leaf(raw.last(2)))
                           .finalize();
    reject_root(root(branch, alternative), "branch-partition");
    auto wrong_length = vm::CellBuilder()
                            .store_long(1, 1)
                            .store_long(2, 3)
                            .store_long(122, 32)
                            .store_ref(leaf(raw.first(120)))
                            .store_ref(leaf(raw.last(1)))
                            .finalize();
    reject_root(root(branch, wrong_length), "branch-length");
    auto wrong_count = vm::CellBuilder()
                           .store_long(1, 1)
                           .store_long(3, 3)
                           .store_long(121, 32)
                           .store_ref(leaf(raw.first(120)))
                           .store_ref(leaf(raw.last(1)))
                           .store_ref(leaf(small))
                           .finalize();
    reject_root(root(branch, wrong_count), "branch-count");
    for (unsigned bits : {511U, 513U}) {
      bad = good;
      vm::CellBuilder builder;
      builder.store_bits(sig.data(), bits == 511 ? 511 : 512);
      if (bits == 513)
        builder.store_long(0, 1);
      bad.signature = builder.finalize();
      check(execute(bad).exit == 9, "signature-bit-boundary");
    }
    bad = good;
    bad.signature = vm::CellBuilder().store_bytes(slice(sig)).store_ref(leaf(small)).finalize();
    check(execute(bad).exit == 9, "signature-reference");
    if (argc == 3) {
      std::filesystem::path vectors = argv[2];
      std::ifstream cases(vectors / "cases");
      check(cases.good(), "crypto-fixture-cases");
      unsigned index = 0;
      int expected_exit, expected_value;
      while (cases >> expected_exit >> expected_value) {
        auto read = [&](const char* suffix) {
          std::ifstream file(vectors / (std::to_string(index) + suffix), std::ios::binary);
          check(file.good(), "crypto-fixture-file");
          return Bytes(std::istreambuf_iterator<char>(file), {});
        };
        auto key = read(".key"), message = read(".message"), signature = read(".signature");
        check(key.size() == 32 && !message.empty() && message.size() <= 65536 && signature.size() <= 120,
              "crypto-fixture-bound");
        Input entry{packed(message), vm::CellBuilder().store_bytes(slice(signature)).finalize(), {}};
        std::copy(key.begin(), key.end(), entry.key.begin());
        auto result = execute(entry);
        check(result.exit == expected_exit && result.value == expected_value, "crypto-vm-" + std::to_string(index));
        ++index;
      }
      check(cases.eof() && index == 98, "crypto-fixture-complete");
    }
    if (!export_path.empty()) {
      std::ofstream marker(export_path / "complete");
      marker << exported << '\n';
      check(marker.good(), "fixture-completion-marker");
    }
    std::cout << "PASS native P0 VM gates, raw C0 signatures, canonical cells and gas boundaries; gas(300)="
              << valid.gas << '\n';
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
