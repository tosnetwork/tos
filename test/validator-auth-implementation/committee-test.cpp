#include <filesystem>
#include <fstream>
#include <iostream>

#include "block/block-auto.h"
#include "block/mc-config.h"
#include "tos/quorum.h"
#include "validator/auth/native-committee.h"
#include "vm/boc.h"

#include "committee-fixture.h"
using namespace p0_fixture;
namespace {
td::Bits256 bits(const Hash& h) {
  return td::Bits256(h);
}
td::Ref<vm::Cell> descriptor(unsigned i, const RegistryState& registry, unsigned variant = 0) {
  vm::CellBuilder pub;
  auto pk = h(variant == 13 ? 10001 : 10000 + i);
  if (variant == 7) {
    auto bytes = registry.keys().begin()->second.public_key_;
    std::copy(bytes.begin(), bytes.end(), pk.begin());
  }
  pub.store_long(0x8e81278a, 32).store_bytes(td::Slice(reinterpret_cast<const char*>(pk.data()), 32));
  vm::CellBuilder cell;
  cell.store_long(variant == 1 ? 0x73 : 0xb3, 8)
      .append_cellslice(vm::CellSlice(vm::NoVm{}, pub.finalize()))
      .store_long(i * 3, 64)
      .store_bytes(td::Slice(reinterpret_cast<const char*>(h(20000 + i).data()), 32));
  if (variant != 1) {
    vm::CellBuilder binding;
    binding
        .store_bytes(td::Slice(reinterpret_cast<const char*>(h((variant == 2 || variant == 12) ? 1
                                                               : variant == 3                  ? 0
                                                                                               : i)
                                                                 .data()),
                               32))
        .store_bytes(td::Slice(reinterpret_cast<const char*>(h((variant == 4 || variant == 12) ? 1001
                                                               : variant == 5                  ? 0
                                                               : variant == 10                 ? 9999
                                                                                               : 1000 + i)
                                                                 .data()),
                               32));
    if (variant == 6)
      binding.store_long(0, 1);
    if (variant == 9)
      binding.store_ref(vm::CellBuilder().finalize());
    cell.store_ref(binding.finalize());
  }
  return cell.finalize();
}
td::Ref<vm::Cell> election(const RegistryState& registry, unsigned variant = 0, unsigned count = 4) {
  vm::Dictionary list(16);
  std::uint64_t weight = 0;
  for (unsigned i = 1; i <= count; ++i) {
    td::BitArray<16> key(i - 1);
    check(list.set(key.bits(), 16,
                   td::make_ref<vm::CellSlice>(
                       vm::NoVm{},
                       descriptor(i, registry, i == ((variant == 12 || variant == 13) ? 4u : 2u) ? variant : 0))),
          "list-add");
    check(tos::checked_add_validator_weight(weight, i * 3), "fixture-weight");
  }
  vm::CellBuilder root;
  root.store_long(0x12, 8)
      .store_long(0, 32)
      .store_long(variant == 8 ? 0 : 10000, 32)
      .store_long(count, 16)
      .store_long(variant == 11 ? count : std::min(count, 3u), 16)
      .store_long(weight, 64);
  check(list.append_dict_to_bool(root), "election-list");
  return root.finalize();
}
td::Ref<vm::Cell> chain_state(const RegistryState& registry, unsigned variant = 0, bool shuffle = false,
                              unsigned count = 4) {
  auto root = masterchain(registry, registry.coordinate());
  root = replace_config(root, 34, election(registry, variant, count));
  return replace_config(root, 28, catchain_selector(shuffle));
}
}  // namespace
int main(int argc, char** argv) {
  try {
    std::filesystem::path output;
    if (argc == 2) {
      output = argv[1];
      check(std::filesystem::create_directory(output), "fresh-committee-export");
    } else
      check(argc == 1, "committee-arguments");
    unsigned cases = 0;
    auto registry = state(4);
    ChainContext chain{-239, h(6002), h(6003), registry.chain_domain()};
    auto run = [&](td::Ref<vm::Cell> root, tos::ShardIdFull shard, unsigned cc, const char* name, bool accepted,
                   std::optional<Anchor> pinned = {}, std::optional<ChainContext> context = {}) {
      auto a = pinned.value_or(anchor(root, registry.coordinate()));
      auto c = context.value_or(chain);
      auto result = NativeCommittee::derive(root, a, c, shard, cc);
      check(result.ok() == accepted, name);
      if (!output.empty()) {
        auto prefix = output / std::to_string(cases);
        auto write = [&](const std::string& suffix, td::Slice data) {
          std::ofstream f(prefix.string() + suffix, std::ios::binary);
          f.write(data.data(), data.size());
          check(f.good(), "fixture-write");
        };
        auto boc = vm::std_boc_serialize(root, 31);
        check(boc.is_ok(), "fixture-boc");
        write(".boc", boc.ok().as_slice());
        auto raw = value(encode(a), "fixture-anchor");
        write(".anchor", {reinterpret_cast<const char*>(raw.data()), raw.size()});
        Writer w;
        w.integer(c.network);
        w.bytes(c.genesis_root);
        w.bytes(c.genesis_file);
        w.bytes(c.chain_domain);
        write(".chain", {reinterpret_cast<const char*>(w.data.data()), w.data.size()});
        std::ofstream meta(prefix.string() + ".case");
        meta << shard.workchain << ' ' << shard.shard << ' ' << cc << ' ' << accepted << ' ' << name << '\n';
        {
          block::gen::ShardStateUnsplit::Record export_header;
          block::gen::McStateExtra::Record export_extra;
          check(tlb::unpack_cell(root, export_header) &&
                    tlb::unpack_cell(export_header.custom->prefetch_ref(), export_extra),
                "export-header");
          auto cfg = block::Config::unpack_config(export_extra.config);
          check(cfg.is_ok(), "export-config");
          auto eboc = vm::std_boc_serialize(cfg.ok()->get_config_param(35, 34), 31);
          check(eboc.is_ok(), "export-election");
          write(".election", eboc.ok().as_slice());
        }
        if (result.ok()) {
          auto bytes = value(encode(result.value().snapshot().committee()), "fixture-committee");
          write(".committee", {reinterpret_cast<const char*>(bytes.data()), bytes.size()});
          Writer order;
          for (const auto& member : result.value().transport_order()) {
            auto raw = member.auth_binding->identity.as_slice();
            order.bytes(std::span<const std::uint8_t>(raw.ubegin(), raw.size()));
          }
          write(".order", {reinterpret_cast<const char*>(order.data.data()), order.data.size()});
        }
      }
      ++cases;
      return result;
    };
    auto mc = tos::ShardIdFull(-1), shard = tos::ShardIdFull(0);
    auto root = chain_state(registry);
    auto full = value(run(root, mc, 7, "native-full-roster", true), "native-full-roster");
    check(full.snapshot().total_weight() == 18 && full.snapshot().committee().members_.size() == 3,
          "native-full-weight");
    auto partition = value(run(root, shard, 7, "native-shard-roster", true), "native-shard-roster");
    check(partition.snapshot().total_weight() == 2 && partition.snapshot().committee().members_.size() == 2,
          "native-shard-weight");
    for (unsigned cc : {0u, 1u, 8u, 999u}) {
      run(chain_state(registry, 0, true), mc, cc, "native-shuffle", true);
      run(root, tos::ShardIdFull(0, 0x4000000000000000ULL), cc, "native-split-shard", true);
    }
    const char* labels[]{"",
                         "missing-binding",
                         "duplicate-identity",
                         "zero-identity",
                         "duplicate-stake",
                         "zero-stake",
                         "binding-tail",
                         "network-key-reuse",
                         "election-time",
                         "binding-reference",
                         "stake-substitution"};
    for (unsigned v = 1; v <= 10; ++v)
      run(chain_state(registry, v), mc, 7, labels[v], false);
    run(chain_state(registry, 12), mc, 7, "unselected-duplicate-binding", false);
    run(chain_state(registry, 13), mc, 7, "unselected-duplicate-network", false);
    auto mismatch = root;
    auto other_registry = state(3);
    mismatch = replace_config(root, 46, value(other_registry.encode_cell(), "other-registry"));
    run(mismatch, mc, 7, "election-registry-binding", false);
    auto wrong = anchor(root);
    wrong.state_[0] ^= 1;
    run(root, mc, 7, "state-root", false, wrong);
    vm::CellSlice zero_network_source(vm::NoVm{}, root);
    vm::CellBuilder zero_network;
    zero_network.store_bits(zero_network_source.fetch_bits(32));
    zero_network_source.advance(32);
    zero_network.store_long(0, 32).store_bits(zero_network_source.fetch_bits(zero_network_source.size()));
    while (zero_network_source.size_refs())
      zero_network.store_ref(zero_network_source.fetch_ref());
    auto zero_context = chain;
    zero_context.network = 0;
    run(zero_network.finalize(), mc, 7, "native-zero-network", false, {}, zero_context);
    auto alien = chain;
    alien.network += 1;
    run(root, mc, 7, "network", false, {}, alien);
    alien = chain;
    alien.chain_domain[0] ^= 1;
    run(root, mc, 7, "chain-domain", false, {}, alien);
    vm::CellBuilder cap;
    cap.store_long(0xc4, 8).store_long(16, 32).store_long(0, 64);
    run(replace_config(root, 8, cap.finalize()), mc, 7, "native-capability", false);
    vm::CellBuilder version;
    version.store_long(0xc4, 8).store_long(15, 32).store_long(1024, 64);
    run(replace_config(root, 8, version.finalize()), mc, 7, "native-version", false);
    run(root, tos::ShardIdFull(-1, 0x4000000000000000ULL), 7, "masterchain-shard", false);
    vm::CellBuilder count401;
    count401.store_long(401, 16).store_long(100, 16).store_long(1, 16);
    run(replace_config(root, 16, count401.finalize()), mc, 7, "validator-ceiling", false);
    auto too_many = state(401);
    run(chain_state(too_many, 0, false, 401), mc, 7, "elected-ceiling", false);
    vm::Dictionary missing(32);
    td::BitArray<32> other(8);
    missing.set(other.bits(), 32, td::make_ref<vm::CellSlice>(vm::NoVm{}, vm::CellBuilder().finalize()));
    run(replace_config(root, 9, missing.get_root_cell()), mc, 7, "mandatory-config", false);
    vm::CellBuilder selector;
    selector.store_long(0xc2, 8)
        .store_long(2, 8)
        .store_long(100, 32)
        .store_long(100, 32)
        .store_long(1000, 32)
        .store_long(2, 32);
    run(replace_config(root, 28, selector.finalize()), mc, 7, "unsupported-selector", false);
    vm::CellBuilder wide_selector;
    wide_selector.store_long(0xc2, 8)
        .store_long(0, 8)
        .store_long(100, 32)
        .store_long(100, 32)
        .store_long(1000, 32)
        .store_long(65536, 32);
    auto wide = value(run(replace_config(root, 28, wide_selector.finalize()), shard, 7, "wide-selector", true),
                      "wide-selector");
    check(wide.snapshot().committee().members_.size() == 4, "wide-selector-count");
    auto many = state(400);
    auto large = chain_state(many, 0, true, 400);
    run(large, mc, 42, "full-election-400", true);
    run(large, shard, 42, "large-shard", true);
    vm::CellBuilder main400;
    main400.store_long(400, 16).store_long(400, 16).store_long(1, 16);
    auto all400 = replace_config(chain_state(many, 11, true, 400), 16, main400.finalize());
    auto complete400 = value(run(all400, mc, 42, "native-committee-400", true), "native-committee-400");
    check(complete400.snapshot().committee().members_.size() == 400 && complete400.snapshot().total_weight() == 240600,
          "native-400-weight");
    auto ephemeral = replace_config(root, 35, election(registry, 0, 3));
    auto temporary = value(run(ephemeral, mc, 7, "temporary-election", true), "temporary-election");
    check(temporary.snapshot().committee().election_ != full.snapshot().committee().election_, "election-id-binding");
    auto limited = NativeCommittee::derive(root, anchor(root), chain, mc, 7, {1, 268435456});
    check(!limited.ok(), "registry-entry-budget");
    limited = NativeCommittee::derive(root, anchor(root), chain, mc, 7, {1000000, 375});
    check(!limited.ok(), "registry-byte-budget");
    auto duplicate_epoch = value(registry.encode_cell(), "epoch-root");
    vm::CellSlice epoch_root(vm::NoVm{}, duplicate_epoch);
    auto key_wrapper = epoch_root.prefetch_ref(1);
    vm::CellSlice wrapper(vm::NoVm{}, key_wrapper);
    vm::Dictionary keys(wrapper, 256);
    auto key = registry.keys().begin()->second;
    key.valid_until_ += 1;
    auto key_id = value(object_id("key", key), "duplicate-epoch-id");
    check(keys.set_ref(td::ConstBitPtr(key_id.data()), 256,
                       value(pack_bytes(value(encode(key), "duplicate-epoch-key")), "duplicate-epoch-cell")),
          "duplicate-epoch-add");
    vm::CellBuilder kw;
    check(keys.append_dict_to_bool(kw), "epoch-wrapper");
    vm::CellBuilder new_registry;
    new_registry.store_bits(epoch_root.fetch_bits(epoch_root.size()));
    for (unsigned i = 0; i < 4; ++i) {
      auto ref = epoch_root.fetch_ref();
      new_registry.store_ref(i == 1 ? kw.finalize() : ref);
    }
    auto invalid_archive = new_registry.finalize();
    check(!RegistryState::decode_cell(invalid_archive, 0).ok(), "duplicate-key-epoch");
    run(replace_config(root, 46, invalid_archive), mc, 7, "unused-archive-not-read", true);
    if (!output.empty()) {
      for (const auto& [name, cell] : std::vector<std::pair<std::string, td::Ref<vm::Cell>>>{
               {"registry-valid", duplicate_epoch}, {"registry-duplicate", invalid_archive}}) {
        auto boc = vm::std_boc_serialize(cell, 31);
        check(boc.is_ok(), "registry-fixture");
        std::ofstream f(output / (name + ".boc"), std::ios::binary);
        f.write(boc.ok().data(), boc.ok().size());
        check(f.good(), "registry-write");
      }
    }
    auto descriptors = block::Config::unpack_validator_set(election(registry));
    check(descriptors.is_ok(), "native-descriptor-parse");
    check(block::Config::unpack_validator_set(election(registry, 3)).is_error(), "descriptor-zero-identity");
    check(block::Config::unpack_validator_set(election(registry, 5)).is_error(), "descriptor-zero-stake");
    auto exported = descriptors.ok()->export_validator_set();
    check(exported.size() == 4 && exported[1].auth_binding && exported[1].auth_binding->identity == bits(h(2)),
          "export-binding");
    auto first = exported[0], changed = first;
    changed.auth_binding->stake_id = bits(h(9));
    check(first != changed, "descriptor-equality");
    auto pending = pending_state(4);
    auto pending_root = chain_state(pending);
    auto old = NativeCommittee::derive(pending_root, anchor(pending_root, 1), chain, mc, 7);
    check(old.ok(), "pending-before-boundary");
    auto due = value(pending.apply_block(2, {}, AcceptedFixtureRequests{}), "due");
    auto due_root = chain_state(due);
    check(!NativeCommittee::derive(due_root, anchor(due_root, 2), chain, mc, 7).ok(), "missing-slot-no-weight-drop");
    check(
        old.value().snapshot().total_weight() == 18 && old.value().snapshot().committee().members_[0].keys_.size() == 5,
        "old-snapshot-retained");
    if (!output.empty()) {
      std::ofstream done(output / "complete");
      done << cases << '\n';
    }
    std::cout << "PASS: native committee state, selector, bindings and retained snapshots " << cases
              << " exported cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
