/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <vector>

#include "auto/tl/lite_api.hpp"
#include "block/mc-config.h"
#include "lite-client/proof-verify/material.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
namespace pv = tos::proofverify;
struct Replay : pv::LiteTransport {
  std::vector<td::BufferSlice> answers;
  std::vector<int> expected;
  int config_mode{-1};
  std::optional<tos::BlockIdExt> target;
  size_t index{0};
  td::Result<td::BufferSlice> query(td::BufferSlice bytes) override {
    auto parsed = tos::fetch_tl_object<tos::lite_api::Function>(std::move(bytes), true);
    if (parsed.is_error() || index >= answers.size() || parsed.ok()->get_id() != expected[index])
      return td::Status::Error("unexpected proof acquisition query");
    if (auto *config = dynamic_cast<tos::lite_api::liteServer_getConfigAll *>(parsed.ok().get())) {
      if ((config_mode >= 0 && config->mode_ != config_mode) ||
          (target && tos::create_block_id(config->id_) != *target))
        return td::Status::Error("wrong execution config mode or target");
    }
    if (auto *account = dynamic_cast<tos::lite_api::liteServer_getAccountState *>(parsed.ok().get())) {
      if (target && tos::create_block_id(account->id_) != *target)
        return td::Status::Error("wrong account target");
    }
    return answers[index++].clone();
  }
};
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  const std::string root = argv[1];
  auto text = pv::read_bounded_file(root + "/historical-request.json", 1u << 20);
  auto atext = pv::read_bounded_file(root + "/anchor.json", 1u << 20);
  auto source = pv::read_material(root + "/historical");
  if (text.is_error() || atext.is_error() || source.is_error())
    return 2;
  auto request = pv::parse_request(text.ok());
  auto anchor = pv::parse_anchor(atext.ok());
  if (request.is_error() || anchor.is_error())
    return 2;
  auto m = source.move_as_ok();
  int failures = 0;
  auto check = [&](const char *name, bool ok) {
    std::printf("ACQUISITION_CASE %s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok)
      ++failures;
  };
  const std::vector<int> ids = {
      tos::lite_api::liteServer_getBlockProof::ID, tos::lite_api::liteServer_getConfigParams::ID,
      tos::lite_api::liteServer_getAccountState::ID, tos::lite_api::liteServer_getConfigAll::ID};
  Replay valid;
  valid.expected = ids;
  valid.answers.push_back(m.chain[0].clone());
  valid.answers.push_back(m.config->clone());
  valid.answers.push_back(m.account->clone());
  valid.answers.push_back(m.exec_config->clone());
  auto acquired = pv::fetch_material(valid, anchor.ok(), request.ok(), std::nullopt);
  check("real-query-sequence", acquired.is_ok() && valid.index == 4);
  if (acquired.is_ok())
    check(
        "acquired-real-proof-verifies",
        pv::verify(anchor.ok(), request.ok(), text.ok(), acquired.ok(), std::nullopt, pv::Policy{1791200932}).is_ok());
  Replay oversized;
  oversized.expected = {ids[0]};
  oversized.answers.emplace_back(pv::kMaxFileBytes + 1);
  auto large = pv::fetch_material(oversized, anchor.ok(), request.ok(), std::nullopt);
  check("single-response-limit",
        large.is_error() && large.error().message().str().find("acquisition byte limit") != std::string::npos);
  auto chain = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(m.chain[0].clone(), true);
  if (chain.is_error())
    return 2;
  auto changed = chain.move_as_ok();
  auto *forward = dynamic_cast<tos::lite_api::liteServer_blockLinkForward *>(changed->steps_[0].get());
  if (!forward)
    return 2;
  forward->dest_proof_ = td::BufferSlice(33u << 20);
  Replay cumulative;
  cumulative.expected = {ids[0], ids[1]};
  cumulative.answers.push_back(tos::serialize_tl_object(changed, true));
  cumulative.answers.emplace_back(32u << 20);
  auto sum = pv::fetch_material(cumulative, anchor.ok(), request.ok(), std::nullopt);
  check("cumulative-response-limit",
        sum.is_error() && sum.error().message().str().find("acquisition byte limit") != std::string::npos &&
            cumulative.index == 2);

  auto live = request.ok();
  live.mode = pv::Mode::Live;
  live.max_age_seconds = 300;
  live.config_params.clear();
  live.get_methods.clear();
  live.account->workchain = 0;
  pv::LiveState prior{anchor.ok(), std::nullopt, std::nullopt};
  auto simulation_replay = [&]() {
    Replay replay;
    replay.expected = {ids[0], ids[2], ids[3]};
    replay.target = live.target;
    replay.config_mode = block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks |
                         block::ConfigInfo::needWorkchainInfo | block::ConfigInfo::needSpecialSmc;
    // Query-planning replies are deliberately unverified here. The C ABI test
    // separately authenticates real basechain material through the simulator.
    replay.answers.push_back(m.chain[0].clone());
    replay.answers.push_back(m.account->clone());
    replay.answers.push_back(m.exec_config->clone());
    return replay;
  };
  auto planned = simulation_replay();
  auto simulation = pv::fetch_material(planned, anchor.ok(), live, prior, pv::FetchPurpose::SelfPaySimulation);
  check("simulation-full-config-without-getter", simulation.is_ok() && planned.index == 3 &&
                                                     simulation.ok().exec_config && simulation.ok().account &&
                                                     !simulation.ok().config && !simulation.ok().libraries);
  Replay ordinary;
  ordinary.expected = {ids[0], ids[2]};
  ordinary.answers.push_back(m.chain[0].clone());
  ordinary.answers.push_back(m.account->clone());
  auto read = pv::fetch_material(ordinary, anchor.ok(), live, prior);
  check("ordinary-account-does-not-fetch-execution-config",
        read.is_ok() && ordinary.index == 2 && !read.ok().exec_config);
  for (int variant = 0; variant < 5; ++variant) {
    auto bad = live;
    auto state = prior;
    std::optional<pv::LiveState> maybe_state = state;
    if (variant == 0)
      bad.mode = pv::Mode::Historical;
    if (variant == 1)
      bad.account.reset();
    if (variant == 2)
      bad.config_params.push_back(19);
    if (variant == 3)
      bad.get_methods = request.ok().get_methods;
    if (variant == 4)
      maybe_state.reset();
    auto refused = simulation_replay();
    auto result = pv::fetch_material(refused, anchor.ok(), bad, maybe_state, pv::FetchPurpose::SelfPaySimulation);
    check(("simulation-restriction-" + std::to_string(variant)).c_str(), result.is_error() && refused.index == 0);
  }
  auto fragmented_request = live;
  auto position = anchor.ok().id;
  fragmented_request.target = position;
  fragmented_request.target->id.seqno += static_cast<tos::BlockSeqno>(pv::kMaxChainResponses + 1);
  auto fragment = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(m.chain[0].clone(), true);
  if (fragment.is_error())
    return 2;
  auto piece = fragment.move_as_ok();
  piece->complete_ = false;
  piece->steps_.clear();
  Replay fragmented;
  for (size_t i = 0; i <= pv::kMaxChainResponses; ++i) {
    piece->from_ = tos::create_tl_lite_block_id(position);
    ++position.id.seqno;
    piece->to_ = tos::create_tl_lite_block_id(position);
    fragmented.expected.push_back(ids[0]);
    fragmented.answers.push_back(tos::serialize_tl_object(piece, true));
  }
  auto too_many =
      pv::fetch_material(fragmented, anchor.ok(), fragmented_request, prior, pv::FetchPurpose::SelfPaySimulation);
  check("simulation-fragment-count-bound",
        too_many.is_error() && fragmented.index == pv::kMaxChainResponses &&
            too_many.error().message().str().find("too many responses") != std::string::npos);
  return failures ? 1 : 0;
}
