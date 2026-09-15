#pragma once

#include <cstdint>
#include <sodium.h>

#include "block/block-auto.h"
#include "block/mc-config.h"
#include "validator/auth/native-config-context.h"
#include "validator/auth/native-registry.h"
#include "vm/dict.h"

#include "native-fixture.h"
#include "owner-fixture.h"

namespace p0_config_context_fixture {
using namespace tos::auth;
// check(), h() and value() live in p0_fixture; boc() and hash() in the owner
// fixture that builds on it. Naming the wrong namespace for the first three is
// what this header did, and it does not compile.
using namespace p0_fixture;
using p0_owner_fixture::boc;
using p0_owner_fixture::hash;

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

// Adds a real configuration account to an already valid committee fixture
// without changing the shared native fixture used by unrelated tests. The
// Config0 value and the masterchain state's own config_addr are produced from
// the same owned Hash, which avoids the aliasing failure that motivated keeping
// this construction isolated.
ContextFixture make(td::Ref<vm::Cell> base, unsigned mode = 0) {
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::gen::ConfigParams::Record params;
  check(tlb::unpack_cell(base, state) && tlb::unpack_cell(state.custom->prefetch_ref(), extra) &&
            tlb::csr_unpack(extra.config, params),
        "fixture-context-state");
  vm::Dictionary config(params.config, 32);
  Hash address = h(900);
  const Hash parameter_address = mode == 1 ? Hash{} : address;
  auto encoded_address = vm::CellBuilder().store_bytes(td::Slice(parameter_address.data(), 32)).finalize();
  check(config.set_ref(td::BitArray<32>{0LL}, encoded_address), "fixture-address");
  params.config = config.get_root_cell();
  if (mode == 2) {
    const auto other = h(901);
    params.config_addr = td::Bits256(td::ConstBitPtr(other.data()));
  }
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
  const auto bytes = boc(root);
  Hash file{};
  check(crypto_hash_sha256(file.data(), bytes.data(), bytes.size()) == 0, "fixture-file-hash");
  Anchor head{state.seq_no, hash(root), file, hash(root)};
  ChainContext chain{state.global_id, head.root_, head.file_, registry.chain_domain()};
  return {root, code, data, checkpoint, head, chain, address};
}

}  // namespace p0_config_context_fixture
