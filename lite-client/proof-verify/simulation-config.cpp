/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <unordered_set>
#include <vector>

#include "block/check-proof.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"
#include "vm/cells/DataCell.h"
#include "vm/excno.hpp"

#include "simulation-config.h"

namespace tos::proofverify::detail {
namespace {
td::Status refuse(SimulationConfigError code) {
  return td::Status::Error(static_cast<int>(code), "simulation configuration refused");
}

td::Result<std::size_t> proof_cell_count(td::Slice bytes) {
  vm::BagOfCells::Info header;
  if (bytes.empty() || header.parse_serialized_header(bytes) <= 0 || !header.valid || header.root_count != 1 ||
      header.absent_count != 0 || header.cell_count < 1 || header.total_size != bytes.size()) {
    return refuse(SimulationConfigError::Input);
  }
  if (static_cast<std::size_t>(header.cell_count) > kMaxSimulationConfigProofCells) {
    return refuse(SimulationConfigError::Resource);
  }
  return static_cast<std::size_t>(header.cell_count);
}
}  // namespace

td::Result<std::size_t> check_complete_simulation_config(const td::Ref<vm::Cell>& root) {
  try {
    if (root.is_null()) {
      return refuse(SimulationConfigError::Incomplete);
    }
    if (root->get_depth() > kMaxSimulationConfigDepth) {
      return refuse(SimulationConfigError::Resource);
    }
    std::unordered_set<vm::CellHash> visited;
    std::vector<td::Ref<vm::Cell>> pending{root};
    while (!pending.empty()) {
      auto cell = std::move(pending.back());
      pending.pop_back();
      auto loaded = cell->load_cell();
      if (loaded.is_error()) {
        return refuse(SimulationConfigError::Incomplete);
      }
      const auto& data = loaded.ok().data_cell;
      const auto type = data->special_type();
      if (type == vm::Cell::SpecialType::PrunnedBranch) {
        return refuse(SimulationConfigError::Incomplete);
      }
      if (type != vm::Cell::SpecialType::Ordinary && type != vm::Cell::SpecialType::Library) {
        return refuse(SimulationConfigError::Unsupported);
      }
      if (visited.count(cell->get_hash())) {
        continue;
      }
      if (visited.size() == kMaxSimulationConfigCells) {
        return refuse(SimulationConfigError::Resource);
      }
      visited.insert(cell->get_hash());
      for (unsigned i = 0; i < data->size_refs(); ++i) {
        pending.push_back(data->get_ref(i));
      }
    }
    return visited.size();
  } catch (vm::VmError&) {
    return refuse(SimulationConfigError::Incomplete);
  } catch (vm::VmVirtError&) {
    return refuse(SimulationConfigError::Incomplete);
  }
}

td::Result<std::unique_ptr<block::ConfigInfo>> extract_simulation_config(const tos::BlockIdExt& target,
                                                                         td::Slice raw_reply) {
  try {
    if (raw_reply.empty() || raw_reply.size() > kMaxSimulationConfigReplyBytes) {
      return refuse(SimulationConfigError::Resource);
    }
    auto answer = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(td::BufferSlice(raw_reply), true);
    if (answer.is_error()) {
      return refuse(SimulationConfigError::Input);
    }
    const auto& info = answer.ok();
    if (tos::create_block_id(info->id_) != target) {
      return refuse(SimulationConfigError::Proof);
    }
    TRY_RESULT(block_cells, proof_cell_count(info->state_proof_.as_slice()));
    TRY_RESULT(state_cells, proof_cell_count(info->config_proof_.as_slice()));
    if (state_cells > kMaxSimulationConfigProofCells - block_cells) {
      return refuse(SimulationConfigError::Resource);
    }
    auto state =
        block::check_extract_state_proof(target, info->state_proof_.as_slice(), info->config_proof_.as_slice());
    if (state.is_error()) {
      return refuse(SimulationConfigError::Proof);
    }
    auto base = block::Config::extract_from_state(state.ok(), 0);
    if (base.is_error()) {
      return refuse(SimulationConfigError::Incomplete);
    }
    TRY_RESULT(cells, check_complete_simulation_config(base.ok()->get_root_cell()));
    (void)cells;
    constexpr int mode = block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks |
                         block::ConfigInfo::needWorkchainInfo | block::ConfigInfo::needSpecialSmc;
    auto config = block::ConfigInfo::extract_config(state.move_as_ok(), target, mode);
    if (config.is_error()) {
      return refuse(SimulationConfigError::Incomplete);
    }
    return config.move_as_ok();
  } catch (vm::VmError&) {
    return refuse(SimulationConfigError::Incomplete);
  } catch (vm::VmVirtError&) {
    return refuse(SimulationConfigError::Incomplete);
  }
}

}  // namespace tos::proofverify::detail
