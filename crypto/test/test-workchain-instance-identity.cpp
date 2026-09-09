#include <iostream>
#include "block/workchain-instance-identity.h"
#include "block/workchain-resource-policy.h"
#include "block/workchain-execution-dispatch.h"

namespace {
void require(bool value, int identity) {
  if (!value) { std::cerr << "failure_identity=" << identity << '\n'; std::exit(1); }
}
td::Bits256 bits(unsigned byte) {
  auto result = td::Bits256::zero(); result.bits().store_uint(byte, 8); return result;
}
td::Ref<vm::Cell> issue(const td::Ref<vm::Cell>& ledger, int wc, const td::Ref<vm::Cell>& descriptor) {
  block::gen::WorkchainInstanceRecord::Record record{1, descriptor->get_hash().bits()};
  auto id = block::derive_workchain_instance_id(bits(7), wc, record); require(id.is_ok(), 800);
  auto next = block::stage_first_workchain_instance(ledger, wc, bits(7), descriptor, id.move_as_ok());
  require(next.is_ok(), 801); return next.move_as_ok().ledger;
}
td::Ref<vm::Cell> configuration_for(std::int32_t workchain, const td::Ref<vm::Cell>& descriptor, const td::Bits256& id) {
  block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}};
  auto payload = vm::CellBuilder().finalize();
  auto shell = block::encode_workchain_engine_parameters({400, bits(7), id, resources, payload});
  require(shell.is_ok(), 830);
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = workchain;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address = bits(1);
  policy.engine_configuration = shell.move_as_ok();
  auto table = block::encode_workchain_native_ingress_table({policy}); require(table.is_ok(), 831);
  vm::Dictionary config(32), workchains(32);
  require(workchains.set(td::BitArray<32>{static_cast<long long>(workchain)}, vm::load_cell_slice_ref(descriptor)), 832);
  vm::CellBuilder list; require(workchains.append_dict_to_bool(list), 833);
  require(config.set_ref(td::BitArray<32>{12}, list.finalize()), 834);
  require(config.set_ref(td::BitArray<32>{84}, table.move_as_ok()), 835);
  return config.get_root_cell();
}
td::Ref<vm::Cell> configuration(const td::Ref<vm::Cell>& descriptor, const td::Bits256& id) {
  return configuration_for(2, descriptor, id);
}
td::Ref<vm::Cell> descriptor_at(unsigned enabled_since) {
  auto root = vm::CellBuilder().store_long(0xa6,8).store_long(enabled_since,32).store_zeroes(24)
      .store_long(1,1).store_long(1,1).store_long(0,1).store_zeroes(13+512)
      .store_long(0,32).store_long(1,4).store_long(0x434e5431,32).store_long(0,64).finalize();
  require(block::gen::t_WorkchainDescr.validate_ref(10000, root), 836);
  return root;
}

}
int main(int argc, char** argv) {
  const int selected = argc == 2 ? std::stoi(argv[1]) : 0;
  auto initial = block::make_initial_workchain_instance_ledger(); require(initial.is_ok(), 802);
  auto empty = initial.move_as_ok();
  auto descriptor = descriptor_at(12);
  auto one = issue(empty, 2, descriptor);
  auto two = issue(one, 9, descriptor);
  auto changed = issue(two, 10, descriptor);
  // No admitted creation event: expected is the complete predecessor root.
  auto modified = block::check_workchain_instance_ledger_delta(two, changed);
  if (selected == 0 || selected == 4) require(modified.is_error() && modified.error().code() == int(block::InstanceIdentityError::UnexpectedLedgerDelta), 804);
  // Key 9 is unrelated to the operation's wc=2. Delete without reading it.
  auto deleted = block::check_workchain_instance_ledger_delta(two, one);
  if (selected == 0 || selected == 5) require(deleted.is_error() && deleted.error().code() == int(block::InstanceIdentityError::UnexpectedLedgerDelta), 805);
  require(block::check_workchain_instance_ledger_delta(two, two).is_ok(), 806);
  auto missing = block::read_workchain_instance_ledger({});
  require(missing.is_error() && missing.error().code() == int(block::InstanceIdentityError::MissingLedger), 803);
  auto frozen = two->get_hash();
  auto failed = block::stage_first_workchain_instance(two, 11, bits(7), descriptor, bits(99));
  require(failed.is_error() && failed.error().code() == int(block::InstanceIdentityError::IdentityMismatch), 807);
  require(two->get_hash() == frozen, 808);
  auto absent = block::read_workchain_instance_record(two, 11);
  require(absent.is_ok() && !absent.move_as_ok(), 809);
  auto prior = block::read_workchain_instance_record(two, 2); require(prior.is_ok(), 810);
  auto record = prior.move_as_ok(); require(bool(record), 811);
  auto before = block::derive_workchain_instance_id(bits(7), 2, *record); require(before.is_ok(), 812);
  auto updated_descriptor = descriptor_at(13);
  require(updated_descriptor->get_hash() != descriptor->get_hash(), 813);
  auto identity = before.move_as_ok();
  auto first = block::reconstruct_workchain_instance_ledger(empty, configuration(descriptor, identity), bits(7), 2);
  require(first.is_ok(), 840);
  auto installed = first.move_as_ok();
  auto installed_record = block::read_workchain_instance_record(installed, 2); require(installed_record.is_ok(), 841);
  auto actual = installed_record.move_as_ok(); require(bool(actual), 842);
  require(actual->instance_seq == 1 && actual->creation_descriptor_hash == descriptor->get_hash().bits(), 843);
  require(block::check_workchain_instance_ledger_delta(installed, one).is_ok(), 844);
  auto update = block::reconstruct_workchain_instance_ledger(installed, configuration(updated_descriptor, identity), bits(7), 2);
  require(update.is_ok(), 814);
  require(update.move_as_ok()->get_hash() == installed->get_hash(), 815);
  auto second = block::stage_first_workchain_instance(installed, 2, bits(7), descriptor, identity);
  require(second.is_error() && second.error().code() == int(block::InstanceIdentityError::SuccessorUnsupported), 846);
  // Removing the record cannot change the authenticated predecessor used by
  // reconstruction. Even though the configuration still contains wc=2, the
  // candidate with an empty ledger must fail the complete-root comparison.
  auto expected = block::reconstruct_workchain_instance_ledger(installed, configuration(descriptor, identity), bits(7), 2);
  require(expected.is_ok(), 847);
  auto reset = block::check_workchain_instance_ledger_delta(expected.move_as_ok(), empty);
  if (selected == 0 || selected == 7) require(reset.is_error() && reset.error().code() == int(block::InstanceIdentityError::UnexpectedLedgerDelta), 848);
  auto successor = block::stage_first_workchain_instance(two, 2, bits(7), updated_descriptor, bits(99));
  require(successor.is_error() && successor.error().code() == int(block::InstanceIdentityError::SuccessorUnsupported), 816);
  // A legitimate first wc=3 installation must survive the same host-wide
  // reconstruction that retains unrelated historical entries.
  block::gen::WorkchainInstanceRecord::Record peer_record{1, descriptor->get_hash().bits()};
  auto peer_id = block::derive_workchain_instance_id(bits(7), 3, peer_record); require(peer_id.is_ok(), 850);
  auto peer_config = configuration_for(3, descriptor, peer_id.move_as_ok());
  auto peer = block::reconstruct_configured_workchain_instances(two, peer_config, bits(7));
  require(peer.is_ok(), 851);
  auto peer_ledger = peer.move_as_ok();
  auto peer_expected = issue(two, 3, descriptor);
  require(peer_ledger->get_hash() == peer_expected->get_hash(), 852);
  auto unchanged_peer = block::reconstruct_configured_workchain_instances(peer_ledger, peer_config, bits(7));
  require(unchanged_peer.is_ok(), 853);
  require(unchanged_peer.move_as_ok()->get_hash() == peer_ledger->get_hash(), 854);
  // A candidate cannot substitute wc=3's commitment, even though wc=2 and
  // every other record remain byte-identical. This is separate from issuance.
  auto peer_header = block::read_workchain_instance_ledger(peer_ledger); require(peer_header.is_ok(), 855);
  auto altered_header = peer_header.move_as_ok();
  vm::Dictionary altered_entries(altered_header.entries, 32);
  vm::CellBuilder altered_value;
  require(tlb::pack(altered_value, block::gen::WorkchainInstanceRecord::Record{1, bits(99)}), 856);
  require(altered_entries.set_builder(td::BitArray<32>{3}, altered_value), 857);
  altered_header.entries = altered_entries.get_root();
  td::Ref<vm::Cell> altered_ledger;
  require(tlb::pack_cell(altered_ledger, altered_header), 858);
  auto altered_peer = block::check_workchain_instance_ledger_delta(peer_ledger, altered_ledger);
  require(altered_peer.is_error() && altered_peer.error().code() == int(block::InstanceIdentityError::UnexpectedLedgerDelta), 859);
  std::cout << "PASS: private ledger primitives; live installation acceptance is separate\n";
}
