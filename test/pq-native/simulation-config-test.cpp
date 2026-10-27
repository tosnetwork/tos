/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstdio>
#include <vector>

#include "block/check-proof.h"
#include "lite-client/proof-verify/material.h"
#include "lite-client/proof-verify/simulation-config.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"

namespace pv = tos::proofverify;
namespace detail = tos::proofverify::detail;

// Preserve existing proof branches and prune one real configuration value.
// The state commitment at level zero stays identical to the authenticated one.
td::Ref<vm::Cell> hide_parameter(td::Ref<vm::Cell> cell, const vm::CellHash& hash, bool& found) {
  if (cell->get_hash(0) == hash) {
    found = true;
    return vm::CellBuilder::do_create_pruned_branch(std::move(cell), 1);
  }
  auto loaded = cell->load_cell();
  if (loaded.is_error() || loaded.ok().data_cell->special_type() != vm::Cell::SpecialType::Ordinary) {
    return cell;
  }
  vm::CellSlice slice{vm::NoVm{}, cell};
  vm::CellBuilder builder;
  builder.store_bits(slice.fetch_bits(slice.size()));
  for (unsigned i = 0; i < slice.size_refs(); ++i) {
    builder.store_ref(hide_parameter(slice.prefetch_ref(i), hash, found));
  }
  return builder.finalize();
}

int main(int argc, char** argv) {
  if (argc != 2) {
    return 2;
  }
  int failures = 0;
  auto check = [&](const char* name, bool ok) {
    std::printf("SIMULATION_CONFIG_CASE %s %s\n", name, ok ? "PASS" : "FAIL");
    failures += !ok;
  };
  auto refused = [](const auto& result, detail::SimulationConfigError code) {
    return result.is_error() && result.error().code() == static_cast<int>(code);
  };
  const std::string directory = argv[1];
  auto request_bytes = pv::read_bounded_file(directory + "/historical-request.json", 1u << 20);
  auto material = pv::read_material(directory + "/historical");
  if (request_bytes.is_error() || material.is_error()) {
    return 2;
  }
  auto request = pv::parse_request(request_bytes.ok());
  if (request.is_error() || !request.ok().target || !material.ok().exec_config || !material.ok().config) {
    return 2;
  }
  const auto target = *request.ok().target;
  auto full = detail::extract_simulation_config(target, material.ok().exec_config->as_slice());
  check("real-full-configuration", full.is_ok() && full.ok()->block_id == target &&
                                       full.ok()->get_global_version() == 18 && full.ok()->utime != 0 &&
                                       full.ok()->lt != 0 && full.ok()->get_prev_blocks_info().is_ok());
  check("real-workchain-execution-context", full.is_ok() && full.ok()->get_workchain_info(0).not_null());
  auto specials = full.is_ok() ? full.ok()->get_special_smartcontracts()
                               : td::Result<std::vector<tos::StdSmcAddress>>{td::Status::Error("no config")};
  check("real-special-account-execution-context",
        specials.is_ok() && request.ok().account &&
            std::find(specials.ok().begin(), specials.ok().end(), request.ok().account->addr) != specials.ok().end());
  auto selected = detail::extract_simulation_config(target, material.ok().config->as_slice());
  check("real-selected-parameter-proof-is-incomplete", refused(selected, detail::SimulationConfigError::Incomplete));
  auto partial_answer =
      tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(material.ok().exec_config->clone(), true);
  if (full.is_error() || partial_answer.is_error()) {
    return 2;
  }
  auto state_proof = vm::std_boc_deserialize(partial_answer.ok()->config_proof_.as_slice());
  auto validator_param = full.ok()->get_config_param(34);
  if (state_proof.is_error() || validator_param.is_null()) {
    return 2;
  }
  auto loaded_proof = state_proof.ok()->load_cell();
  if (loaded_proof.is_error() || loaded_proof.ok().data_cell->size_refs() != 1) {
    return 2;
  }
  auto raw_state = loaded_proof.ok().data_cell->get_ref(0);
  bool found_parameter = false;
  auto hidden_state = hide_parameter(raw_state, validator_param->get_hash(0), found_parameter);
  auto hidden_boc = vm::std_boc_serialize(vm::CellBuilder::create_merkle_proof(hidden_state), 2);
  if (hidden_boc.is_error()) {
    return 2;
  }
  partial_answer.ok()->config_proof_ = hidden_boc.move_as_ok();
  auto authentic_hidden = block::check_extract_state_proof(target, partial_answer.ok()->state_proof_.as_slice(),
                                                           partial_answer.ok()->config_proof_.as_slice());
  auto hidden_bytes = tos::serialize_tl_object(partial_answer.ok(), true);
  check("same-authenticated-state-hidden-parameter",
        found_parameter && raw_state->get_hash(0) == hidden_state->get_hash(0) && authentic_hidden.is_ok() &&
            refused(detail::extract_simulation_config(target, hidden_bytes.as_slice()),
                    detail::SimulationConfigError::Incomplete));
  auto wrong = target;
  ++wrong.id.seqno;
  check("wrong-target", refused(detail::extract_simulation_config(wrong, material.ok().exec_config->as_slice()),
                                detail::SimulationConfigError::Proof));
  auto mislabeled =
      tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(material.ok().exec_config->clone(), true);
  if (mislabeled.is_error()) {
    return 2;
  }
  ++mislabeled.ok()->id_->seqno_;
  auto mislabeled_bytes = tos::serialize_tl_object(mislabeled.ok(), true);
  check("answer-label-must-match-target",
        refused(detail::extract_simulation_config(target, mislabeled_bytes.as_slice()),
                detail::SimulationConfigError::Proof));
  auto other_bytes = pv::read_bounded_file(directory + "/other-block-config.tl", 1u << 20);
  auto mixed = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(material.ok().exec_config->clone(), true);
  if (other_bytes.is_error() || mixed.is_error()) {
    return 2;
  }
  auto other = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(td::BufferSlice(other_bytes.ok()), true);
  if (other.is_error()) {
    return 2;
  }
  mixed.ok()->state_proof_ = other.ok()->state_proof_.clone();
  auto mixed_bytes = tos::serialize_tl_object(mixed.ok(), true);
  check(
      "foreign-block-proof-with-correct-label",
      refused(detail::extract_simulation_config(target, mixed_bytes.as_slice()), detail::SimulationConfigError::Proof));
  std::string corrupt = material.ok().exec_config->as_slice().str();
  corrupt[corrupt.size() / 2] ^= 1;
  check("corrupt-proof",
        refused(detail::extract_simulation_config(target, corrupt), detail::SimulationConfigError::Proof));
  check("empty-reply", refused(detail::extract_simulation_config(target, {}), detail::SimulationConfigError::Resource));
  check("reply-byte-bound",
        refused(detail::extract_simulation_config(target, std::string(detail::kMaxSimulationConfigReplyBytes + 1, 'x')),
                detail::SimulationConfigError::Resource));
  check("null-subtree",
        refused(detail::check_complete_simulation_config({}), detail::SimulationConfigError::Incomplete));
  auto leaf = vm::CellBuilder().store_long(1, 32).finalize();
  auto branch = vm::CellBuilder().store_ref(leaf).store_ref(leaf).finalize();
  auto shared = detail::check_complete_simulation_config(branch);
  check("shared-cells-counted-once", shared.is_ok() && shared.ok() == 2);
  auto pruned = vm::CellBuilder::create_pruned_branch(branch, 1);
  auto hidden = vm::CellBuilder().store_ref(pruned).finalize();
  check("nested-pruned-branch",
        refused(detail::check_complete_simulation_config(hidden), detail::SimulationConfigError::Incomplete));
  check("virtualized-pruned-branch", refused(detail::check_complete_simulation_config(pruned->virtualize(0)),
                                             detail::SimulationConfigError::Incomplete));
  auto proof = vm::CellBuilder::create_merkle_proof(branch);
  check("nested-merkle-proof",
        refused(detail::check_complete_simulation_config(proof), detail::SimulationConfigError::Unsupported));
  // A complete dictionary can prove absence; no selected-parameter proof is used.
  vm::Dictionary dict{32};
  const auto inserted = dict.set_ref(td::BitArray<32>(8), branch);
  auto complete_dict = detail::check_complete_simulation_config(dict.get_root_cell());
  check("complete-dictionary-absence",
        inserted && complete_dict.is_ok() && dict.lookup_ref(td::BitArray<32>(48)).is_null());
  auto partial_dict = vm::MerkleProof::generate_raw(
      dict.get_root_cell(), [&](const auto& cell) { return cell->get_hash() == branch->get_hash(); });
  if (partial_dict.is_error()) {
    return 2;
  }
  check("same-root-missing-configuration-content",
        partial_dict.ok()->get_hash(0) == dict.get_root_cell()->get_hash(0) &&
            refused(detail::check_complete_simulation_config(partial_dict.ok()),
                    detail::SimulationConfigError::Incomplete));
  auto hidden_virtual = partial_dict.ok()->virtualize(0);
  auto representations = vm::CellBuilder().store_ref(hidden_virtual).store_ref(dict.get_root_cell()).finalize();
  check("duplicate-ordinary-partial-representation",
        refused(detail::check_complete_simulation_config(representations), detail::SimulationConfigError::Incomplete));
  auto wrapped_full = vm::CellBuilder().store_ref(dict.get_root_cell()).finalize();
  auto wrapped_partial = vm::CellBuilder().store_ref(hidden_virtual).finalize();
  auto wrapped_representations = vm::CellBuilder().store_ref(wrapped_partial).store_ref(wrapped_full).finalize();
  check("nested-ordinary-partial-representation",
        wrapped_partial->get_hash() == wrapped_full->get_hash() &&
            refused(detail::check_complete_simulation_config(wrapped_representations),
                    detail::SimulationConfigError::Incomplete));
  auto duplicate_leaf = vm::CellBuilder().store_long(1, 32).finalize();
  auto distinct = vm::CellBuilder().store_ref(leaf).store_ref(duplicate_leaf).finalize();
  auto distinct_count = detail::check_complete_simulation_config(distinct);
  check("distinct-loaded-representations-charged", duplicate_leaf.get() != leaf.get() &&
                                                       duplicate_leaf->get_hash() == leaf->get_hash() &&
                                                       distinct_count.is_ok() && distinct_count.ok() == 3);
  auto deep = leaf;
  for (unsigned i = 0; i < detail::kMaxSimulationConfigDepth; ++i) {
    deep = vm::CellBuilder().store_ref(deep).finalize();
  }
  check("depth-at-limit", detail::check_complete_simulation_config(deep).is_ok());
  auto too_deep = vm::CellBuilder().store_ref(deep).finalize();
  check("depth-over-limit",
        refused(detail::check_complete_simulation_config(too_deep), detail::SimulationConfigError::Resource));
  std::vector<td::Ref<vm::Cell>> level;
  for (unsigned i = 0; i < 32768; ++i) {
    level.push_back(vm::CellBuilder().store_long(i, 32).finalize());
  }
  while (level.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < level.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(level[i]).store_ref(level[i + 1]).finalize());
    }
    level = std::move(next);
  }
  auto at_limit = vm::CellBuilder().store_long(1, 1).store_ref(level[0]).finalize();
  auto counted = detail::check_complete_simulation_config(at_limit);
  check("cell-count-at-limit", counted.is_ok() && counted.ok() == detail::kMaxSimulationConfigCells);
  auto over_limit = vm::CellBuilder().store_long(0, 1).store_ref(at_limit).finalize();
  check("cell-count-over-limit",
        refused(detail::check_complete_simulation_config(over_limit), detail::SimulationConfigError::Resource));
  auto bounded_proof_boc = vm::std_boc_serialize(over_limit, 2);
  auto oversized_pair =
      tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(material.ok().exec_config->clone(), true);
  if (bounded_proof_boc.is_error() || oversized_pair.is_error()) {
    return 2;
  }
  oversized_pair.ok()->state_proof_ = bounded_proof_boc.ok().clone();
  oversized_pair.ok()->config_proof_ = bounded_proof_boc.ok().clone();
  auto oversized_pair_bytes = tos::serialize_tl_object(oversized_pair.ok(), true);
  check("combined-proof-cell-budget",
        refused(detail::extract_simulation_config(target, oversized_pair_bytes.as_slice()),
                detail::SimulationConfigError::Resource));
  return failures ? 1 : 0;
}
