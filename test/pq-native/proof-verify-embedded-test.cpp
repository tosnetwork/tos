/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>
#include "lite-client/proof-verify/embedded.h"
#include "lite-client/proof-verify/material.h"
#include "lite-client/proof-verify/proof-verify.h"
namespace pv = tos::proofverify;
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const std::string root = argv[1];
  auto anchor = pv::read_bounded_file(root + "/anchor.json", 1u << 20);
  auto request = pv::read_bounded_file(root + "/historical-request.json", 1u << 20);
  auto material = pv::read_material(root + "/historical");
  if (anchor.is_error() || request.is_error() || material.is_error()) return 2;
  auto m = material.move_as_ok();
  std::vector<tos_proof_material> parts;
  auto append = [&](uint32_t kind, const td::BufferSlice &b) {
    parts.push_back({kind, reinterpret_cast<const uint8_t *>(b.as_slice().data()), b.size()});
  };
  if (m.masterchain_info) append(1, *m.masterchain_info);
  for (const auto &b : m.chain) append(2, b);
  for (const auto &b : m.descent) append(3, b);
  if (m.config) append(4, *m.config);
  if (m.account) append(5, *m.account);
  if (m.exec_config) append(6, *m.exec_config);
  if (m.libraries) append(7, *m.libraries);
  std::vector<char> output(1u << 20, 'x'), state(4096, 'x');
  size_t n = 99, s = 99;
  int failures = 0;
  auto check = [&](const char *name, bool ok) {
    std::printf("EMBEDDED_PROOF_CASE %s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
  };
  auto call = [&](const std::vector<tos_proof_material> &p, size_t capacity, int64_t now) {
    std::fill(output.begin(), output.end(), 'x'); std::fill(state.begin(), state.end(), 'x'); n = s = 99;
    return tos_proof_verify_embedded(anchor.ok().data(), anchor.ok().size(), request.ok().data(), request.ok().size(),
        nullptr, 0, now, p.data(), p.size(), output.data(), capacity, &n, state.data(), state.size(), &s);
  };
  auto cleared = [&]() { return n == 0 && s == 0 && std::all_of(output.begin(), output.end(), [](char c){return c == 0;}) &&
                                      std::all_of(state.begin(), state.end(), [](char c){return c == 0;}); };
  const auto good = call(parts, output.size(), 1791200932);
  check("real-historical-verified", good == 0 && n > 0 && s == 0);
  auto a = pv::parse_anchor(anchor.ok()); auto r = pv::parse_request(request.ok());
  if (a.is_error() || r.is_error()) return 2;
  auto direct = pv::verify(a.ok(), r.ok(), request.ok(), m, std::nullopt, pv::Policy{1791200932});
  check("identical-core-result", direct.is_ok() && std::string(output.data(), n) == pv::render_verified(direct.ok()));
  check("missing-material-refused", call({}, output.size(), 1791200932) == -2 && cleared());
  auto duplicate = parts;
  for (const auto &p : parts) if (p.kind == 4) { duplicate.push_back(p); break; }
  check("duplicate-singleton-refused", call(duplicate, output.size(), 1791200932) == -1 && cleared());
  auto malformed = parts;
  const uint8_t invalid[] = {0, 0, 0, 0};
  for (auto &p : malformed) if (p.kind == 2) { p.data = invalid; p.size = sizeof(invalid); break; }
  check("malformed-chain-refused", call(malformed, output.size(), 1791200932) == -2 && cleared());
  check("invalid-clock-refused", call(parts, output.size(), 0) == -1 && cleared());
  const auto small = call(parts, 1, 1791200932);
  check("capacity-failure-empty", small == -3 && n == 0 && s == 0 && output[0] == 0);
  auto live_request = pv::read_bounded_file(root + "/live-request.json", 1u << 20);
  auto live_state = pv::read_bounded_file(root + "/live-state.json", 1u << 20);
  auto live_material = pv::read_material(root + "/live");
  if (live_request.is_error() || live_state.is_error() || live_material.is_error()) return 2;
  auto lm = live_material.move_as_ok(); parts.clear();
  if (lm.masterchain_info) append(1, *lm.masterchain_info);
  for (const auto &b : lm.chain) append(2, b);
  for (const auto &b : lm.descent) append(3, b);
  if (lm.config) append(4, *lm.config);
  if (lm.account) append(5, *lm.account);
  if (lm.exec_config) append(6, *lm.exec_config);
  if (lm.libraries) append(7, *lm.libraries);
  auto live_call = [&](const std::string &prior, int64_t now, size_t state_cap) {
    std::fill(output.begin(), output.end(), 'x'); std::fill(state.begin(), state.end(), 'x'); n = s = 99;
    return tos_proof_verify_embedded(anchor.ok().data(), anchor.ok().size(), live_request.ok().data(), live_request.ok().size(),
        prior.data(), prior.size(), now, parts.data(), parts.size(), output.data(), output.size(), &n, state.data(), state_cap, &s);
  };
  check("live-verified-with-state", live_call(live_state.ok(), 1791200932, state.size()) == 0 && n > 0 && s > 0);
  auto parsed_next = pv::parse_state(td::Slice(state.data(), s));
  check("live-next-head-bound", parsed_next.is_ok() && parsed_next.ok().head && parsed_next.ok().head->id.seqno() == 636922);
  auto prior = pv::parse_state(live_state.ok());
  if (prior.is_error()) return 2;
  auto rollback_state = prior.move_as_ok();
  rollback_state.head->id.id.seqno = 636923;
  check("live-rollback-clears-result", live_call(pv::render_state(rollback_state), 1791200932, state.size()) == -2 && cleared());
  check("live-expiry-clears-result", live_call(live_state.ok(), 1791201231, state.size()) == -2 && cleared());
  check("live-state-capacity-failure", live_call(live_state.ok(), 1791200932, 1) == -3 && n == 0 && s == 0 && output[0] == 0 && state[0] == 0);
  return failures ? 1 : 0;
}
