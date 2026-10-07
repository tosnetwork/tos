/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <vector>
#include "lite-client/proof-verify/material.h"
#include "auto/tl/lite_api.hpp"
#include "tos/lite-tl.hpp"
#include "tl-utils/lite-utils.hpp"
namespace pv = tos::proofverify;
struct Replay : pv::LiteTransport {
  std::vector<td::BufferSlice> answers;
  std::vector<int> expected;
  size_t index{0};
  td::Result<td::BufferSlice> query(td::BufferSlice bytes) override {
    auto parsed = tos::fetch_tl_object<tos::lite_api::Function>(std::move(bytes), true);
    if (parsed.is_error() || index >= answers.size() || parsed.ok()->get_id() != expected[index]) return td::Status::Error("unexpected proof acquisition query");
    return answers[index++].clone();
  }
};
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const std::string root = argv[1];
  auto text = pv::read_bounded_file(root + "/historical-request.json", 1u << 20);
  auto atext = pv::read_bounded_file(root + "/anchor.json", 1u << 20);
  auto source = pv::read_material(root + "/historical");
  if (text.is_error() || atext.is_error() || source.is_error()) return 2;
  auto request = pv::parse_request(text.ok()); auto anchor = pv::parse_anchor(atext.ok());
  if (request.is_error() || anchor.is_error()) return 2;
  auto m = source.move_as_ok();
  int failures = 0;
  auto check = [&](const char *name, bool ok) { std::printf("ACQUISITION_CASE %s %s\n", name, ok ? "PASS" : "FAIL"); if (!ok) ++failures; };
  const std::vector<int> ids = {tos::lite_api::liteServer_getBlockProof::ID, tos::lite_api::liteServer_getConfigParams::ID,
      tos::lite_api::liteServer_getAccountState::ID, tos::lite_api::liteServer_getConfigAll::ID};
  Replay valid; valid.expected = ids;
  valid.answers.push_back(m.chain[0].clone()); valid.answers.push_back(m.config->clone());
  valid.answers.push_back(m.account->clone()); valid.answers.push_back(m.exec_config->clone());
  auto acquired = pv::fetch_material(valid, anchor.ok(), request.ok(), std::nullopt);
  check("real-query-sequence", acquired.is_ok() && valid.index == 4);
  if (acquired.is_ok()) check("acquired-real-proof-verifies", pv::verify(anchor.ok(), request.ok(), text.ok(), acquired.ok(), std::nullopt, pv::Policy{1791200932}).is_ok());
  Replay oversized; oversized.expected = {ids[0]}; oversized.answers.emplace_back(pv::kMaxFileBytes + 1);
  auto large = pv::fetch_material(oversized, anchor.ok(), request.ok(), std::nullopt);
  check("single-response-limit", large.is_error() && large.error().message().str().find("acquisition byte limit") != std::string::npos);
  auto chain = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(m.chain[0].clone(), true);
  if (chain.is_error()) return 2;
  auto changed = chain.move_as_ok();
  auto *forward = dynamic_cast<tos::lite_api::liteServer_blockLinkForward *>(changed->steps_[0].get());
  if (!forward) return 2;
  forward->dest_proof_ = td::BufferSlice(33u << 20);
  Replay cumulative; cumulative.expected = {ids[0], ids[1]};
  cumulative.answers.push_back(tos::serialize_tl_object(changed, true)); cumulative.answers.emplace_back(32u << 20);
  auto sum = pv::fetch_material(cumulative, anchor.ok(), request.ok(), std::nullopt);
  check("cumulative-response-limit", sum.is_error() && sum.error().message().str().find("acquisition byte limit") != std::string::npos && cumulative.index == 2);
  return failures ? 1 : 0;
}
