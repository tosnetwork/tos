/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Transport-neutral proof query planning; verification remains a separate required step.
#include "material.h"
#include "auto/tl/lite_api.hpp"
#include "block/mc-config.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
namespace tos::proofverify {
namespace {
template <class T>
td::Result<td::BufferSlice> ask(LiteTransport& transport, tos::tl_object_ptr<T> query) {
  return transport.query(tos::serialize_tl_object(query, true));
}

}
td::Result<Material> fetch_material(LiteTransport& transport, const Anchor& anchor, const Request& request,
                                    const std::optional<LiveState>& state) {
  // Transport responses are untrusted and must be bounded before accumulating a chain.
  class BoundedTransport final : public LiteTransport {
   public:
    explicit BoundedTransport(LiteTransport &inner) : inner_(inner) {}
    td::Result<td::BufferSlice> query(td::BufferSlice query) override {
      if (++queries_ > kMaxChainResponses + kMaxDescentLinks + 5) return td::Status::Error("proof acquisition query limit");
      TRY_RESULT(answer, inner_.query(std::move(query)));
      if (answer.empty() || answer.size() > kMaxFileBytes - bytes_) return td::Status::Error("proof acquisition byte limit");
      bytes_ += answer.size(); return answer;
    }
   private:
    LiteTransport &inner_;
    std::size_t queries_{0}, bytes_{0};
  } bounded(transport);
  Material material;
  tos::BlockIdExt target;
  if (request.target) {
    target = *request.target;
  } else {
    if (request.mode != Mode::Live) {
      return td::Status::Error("target block is not specified");
    }
    TRY_RESULT(raw, ask(bounded, tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>()));
    auto info = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(raw.clone(), true);
    if (info.is_error()) {
      return td::Status::Error("latest block answer is malformed");
    }
    target = tos::create_block_id(info.ok()->last_);
    material.masterchain_info = std::move(raw);
  }
  const auto start = chain_start(anchor, target, request, state);
  auto current = start;
  while (current != target) {
    if (material.chain.size() >= kMaxChainResponses) {
      return td::Status::Error("proof chain needs too many responses");
    }
    TRY_RESULT(raw,
               ask(bounded, tos::create_tl_object<tos::lite_api::liteServer_getBlockProof>(
                                  1, tos::create_tl_lite_block_id(current), tos::create_tl_lite_block_id(target))));
    auto chain = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(raw.clone(), true);
    if (chain.is_error()) {
      return td::Status::Error("proof chain answer is malformed");
    }
    auto reached = tos::create_block_id(chain.ok()->to_);
    const bool complete = chain.ok()->complete_;
    material.chain.push_back(std::move(raw));
    if (complete) {
      break;
    }
    if (reached.seqno() <= current.seqno()) {
      return td::Status::Error("proof chain answer makes no progress");
    }
    current = reached;
  }
  if (request.mode == Mode::Live && state && state->head && target.seqno() > state->head->id.seqno()) {
    TRY_RESULT(raw, ask(bounded,
                        tos::create_tl_object<tos::lite_api::liteServer_getBlockProof>(
                            1, tos::create_tl_lite_block_id(target), tos::create_tl_lite_block_id(state->head->id))));
    material.descent.push_back(std::move(raw));
  }
  if (!request.config_params.empty()) {
    TRY_RESULT(raw,
               ask(bounded, tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(
                                  0, tos::create_tl_lite_block_id(target),
                                  std::vector<td::int32>(request.config_params.begin(), request.config_params.end()))));
    material.config = std::move(raw);
  }
  if (request.account) {
    TRY_RESULT(raw, ask(bounded, tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                                       tos::create_tl_lite_block_id(target),
                                       tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                                           request.account->workchain, request.account->addr))));
    auto answer = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(raw.clone(), true);
    material.account = std::move(raw);
    if (!request.get_methods.empty()) {
      const int mode = block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks;
      TRY_RESULT(config, ask(bounded, tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                                            mode, tos::create_tl_lite_block_id(target))));
      material.exec_config = std::move(config);
      if (answer.is_ok() && !answer.ok()->state_.empty()) {
        TRY_RESULT(libraries, required_libraries(answer.ok()->state_.as_slice()));
        if (!libraries.empty()) {
          if (libraries.size() > 16) {
            return td::Status::Error("account references more libraries than one proof can carry");
          }
          TRY_RESULT(raw_libraries,
                     ask(bounded, tos::create_tl_object<tos::lite_api::liteServer_getLibrariesWithProof>(
                                        tos::create_tl_lite_block_id(target), 0,
                                        std::vector<td::Bits256>(libraries.begin(), libraries.end()))));
          material.libraries = std::move(raw_libraries);
        }
      }
    }
  }
  return material;
}

}
