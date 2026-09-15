#pragma once
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
namespace p0_owner_fixture {
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
inline Fixture fixture(const std::filesystem::path& input, unsigned role = 1) {
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
  auto key = keys.at(role - 1);
  key.epoch_ = 2;
  key.valid_from_ = 100;
  Update update{2,
                id.identity_,
                0,
                value(object_id("identity", id), "predecessor"),
                100,
                id.active_.at(role - 1).key_.key_id_,
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
  const auto configuration = h(900);
  vm::CellBuilder elector;
  elector.store_bytes(td::Slice(reinterpret_cast<const char*>(configuration.data()), configuration.size()));
  check(config.set_ref(td::BitArray<32>{1}, elector.finalize()), "elector-entry");
  vm::CellBuilder configuration_parameter;
  configuration_parameter.store_bytes(
      td::Slice(reinterpret_cast<const char*>(configuration.data()), configuration.size()));
  // The LL suffix is load-bearing. BitArray has a non-explicit constructor from
  // ConstBitPtr, and a bare 0 is a null pointer constant, so td::BitArray<32>{0}
  // selects that constructor and builds a key out of a null pointer instead of
  // the key zero. Nonzero literals are unaffected, which is why every other key
  // here is written plainly, and the failure it causes is reported against an
  // unrelated check further up.
  check(config.set_ref(td::BitArray<32>{0LL}, configuration_parameter.finalize()), "configuration-entry");
  cp.config_addr = td::Bits256(td::ConstBitPtr(configuration.data()));
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

}  // namespace p0_owner_fixture
