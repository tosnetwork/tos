/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "acquisition.h"
#include "material.h"
namespace {
class CallbackTransport final : public tos::proofverify::LiteTransport {
 public:
  CallbackTransport(tos_proof_query_callback query, void *context) : query_(query), context_(context) {}
  td::Result<td::BufferSlice> query(td::BufferSlice request) override {
    const auto capacity = tos::proofverify::kMaxFileBytes - bytes_;
    if (!capacity) return td::Status::Error("proof acquisition byte limit");
    td::BufferSlice response(capacity);
    size_t used = 0;
    const auto raw = request.as_slice();
    const int status = query_(context_, reinterpret_cast<const uint8_t *>(raw.data()), raw.size(),
        reinterpret_cast<uint8_t *>(response.as_slice().data()), capacity, &used);
    if (status != 0 || !used || used > capacity) return td::Status::Error("proof transport refused");
    bytes_ += used;
    return td::BufferSlice(response.as_slice().substr(0, used));
  }
 private:
  tos_proof_query_callback query_;
  void *context_;
  size_t bytes_{0};
};
}
extern "C" int tos_proof_acquire(const char *anchor, size_t anchor_size, const char *request, size_t request_size,
    const char *state, size_t state_size, tos_proof_query_callback query, void *query_context,
    tos_proof_emit_callback emit, void *emit_context) {
  namespace pv = tos::proofverify;
  if (!anchor || !anchor_size || anchor_size > (1u << 20) || !request || !request_size || request_size > (1u << 20) ||
      state_size > (1u << 20) || (state_size && !state) || !query || !emit) return -1;
  try {
    auto a = pv::parse_anchor(td::Slice(anchor, anchor_size)); auto r = pv::parse_request(td::Slice(request, request_size));
    if (a.is_error() || r.is_error()) return -1;
    std::optional<pv::LiveState> prior;
    if (state_size) { auto s = pv::parse_state(td::Slice(state, state_size)); if (s.is_error()) return -1; prior = s.move_as_ok(); }
    if ((r.ok().mode == pv::Mode::Live && !prior) || (r.ok().mode == pv::Mode::Historical && prior) ||
        (prior && (prior->anchor.id != a.ok().id || prior->anchor.kind != a.ok().kind))) return -1;
    CallbackTransport transport(query, query_context);
    auto fetched = pv::fetch_material(transport, a.ok(), r.ok(), prior);
    if (fetched.is_error()) return -2;
    const auto &m = fetched.ok();
    auto send = [&](uint32_t kind, const td::BufferSlice &value) {
      const auto bytes = value.as_slice(); return emit(emit_context, kind, reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()) == 0;
    };
    if (m.masterchain_info && !send(1, *m.masterchain_info)) return -3;
    for (const auto &part : m.chain) if (!send(2, part)) return -3;
    for (const auto &part : m.descent) if (!send(3, part)) return -3;
    if (m.config && !send(4, *m.config)) return -3;
    if (m.account && !send(5, *m.account)) return -3;
    if (m.exec_config && !send(6, *m.exec_config)) return -3;
    if (m.libraries && !send(7, *m.libraries)) return -3;
    return 0;
  } catch (...) { return -4; }
}
