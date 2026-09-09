#include <iostream>
#include "block/workchain-instance-identity.h"
#include "block/workchain-resource-policy.h"
#include "block/workchain-execution-dispatch.h"
#include "block/mc-config.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "vm/boc.h"

namespace {
void require(bool value, int code) {
  if (!value) { std::cerr << "fixture_failure_identity=" << code << '\n'; std::exit(1); }
}
void save(const std::string& path, const td::Ref<vm::Cell>& root) {
  auto data = vm::std_boc_serialize(root); require(data.is_ok(), 1101);
  require(td::write_file(path, data.ok().as_slice()).is_ok(), 1102);
}
}

// Offline proposal generator, not an installation entry. It writes only
// configuration parameter proposals; it never produces a candidate ledger.
int main(int argc, char** argv) {
  require(argc == 5, 1100);  // genesis.boc shard.boc output-prefix workchain
  auto raw = td::read_file(td::CSlice(argv[1])); require(raw.is_ok(), 1103);
  auto decoded = vm::std_boc_deserialize(raw.ok().as_slice()); require(decoded.is_ok(), 1104);
  auto genesis = decoded.move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  require(tlb::unpack_cell(genesis, state), 1105);
  require(state.seq_no == 0 && (state.global_id == -23901 || state.global_id == -23903), 1106);
  td::Bits256 file_hash; td::sha256(raw.ok().as_slice(), file_hash.as_slice());
  tos::BlockIdExt zero{{tos::masterchainId, tos::shardIdAll, 0}, genesis->get_hash().bits(), file_hash};
  auto parsed = block::ConfigInfo::extract_config(genesis, zero, block::Config::needWorkchainInfo);
  require(parsed.is_ok(), 1107);
  auto config = parsed.move_as_ok();
  require(config->get_config_param(84).is_null(), 1108);
  const int wc = std::stoi(argv[4]); require(wc == 2 || wc == 3, 1109);
  auto shard_raw = td::read_file(td::CSlice(argv[2])); require(shard_raw.is_ok(), 1110);
  auto shard = vm::std_boc_deserialize(shard_raw.ok().as_slice()); require(shard.is_ok(), 1111);
  td::Bits256 shard_file; td::sha256(shard_raw.ok().as_slice(), shard_file.as_slice());
  auto format = vm::CellBuilder().store_long(1, 4).store_long(0x434e5431, 32).store_long(0, 64).finalize();
  block::gen::WorkchainDescr::Record_workchain descriptor{
      state.gen_utime, 0, 0, 0, true, true, false, 0,
      shard.ok()->get_hash().bits(), shard_file, 0, vm::load_cell_slice_ref(format)};
  td::Ref<vm::Cell> closed; require(tlb::pack_cell(closed, descriptor), 1112);
  block::gen::WorkchainInstanceRecord::Record first{1, closed->get_hash().bits()};
  auto identity = block::derive_workchain_instance_id(state.global_id, wc, first); require(identity.is_ok(), 1113);
  // These are explicit isolated-test limits and the historical acceptance
  // interval. No current cadence, deployment configuration, or default identity.
  block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}};
  auto shell = block::encode_workchain_engine_parameters(
      {400, identity.ok(), resources, vm::CellBuilder().finalize()});
  require(shell.is_ok(), 1114);
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = wc;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address.set_zero();
  policy.engine_configuration = shell.move_as_ok();
  auto ingress = block::encode_workchain_native_ingress_table({policy}); require(ingress.is_ok(), 1115);
  vm::Dictionary workchains(vm::load_cell_slice(config->get_config_param(12)), 32);
  require(workchains.set(td::BitArray<32>{static_cast<long long>(wc)}, vm::load_cell_slice_ref(closed),
                         vm::Dictionary::SetMode::Add), 1116);
  vm::CellBuilder closed_list; require(workchains.append_dict_to_bool(closed_list), 1117);
  const std::string prefix = argv[3];
  save(prefix + ".12.closed.boc", closed_list.finalize());
  save(prefix + ".84.boc", ingress.move_as_ok());
  descriptor.accept_msgs = true;
  td::Ref<vm::Cell> opened; require(tlb::pack_cell(opened, descriptor), 1118);
  require(workchains.set(td::BitArray<32>{static_cast<long long>(wc)}, vm::load_cell_slice_ref(opened)), 1119);
  vm::CellBuilder open_list; require(workchains.append_dict_to_bool(open_list), 1120);
  save(prefix + ".12.open.boc", open_list.finalize());
  std::cout << "genesis=" << zero.root_hash.to_hex() << "\ninstance=" << identity.ok().to_hex()
            << "\ncreation_descriptor=" << closed->get_hash().to_hex() << '\n';
}
