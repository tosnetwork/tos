/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "auto/tl/lite_api.hpp"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/check-proof.h"
#include "block/mc-config.h"
#include "lite-client/lite-client-common.h"
#include "tl/tl_object_parse.h"
#include "tos/quorum.h"
#include "validator/interfaces/shard.h"
#include "vm/cells/MerkleProof.h"

#include "control-getter-executor.h"
#include "json-rpc-server-internal.h"

namespace tos {
namespace {

using explorer::block_json;
using explorer::Failure;
std::unique_ptr<control_getter::Executor>& workers() {
  static auto instance = [] {
    auto created = control_getter::Executor::create(0, explorer::WorkPermit::limit());
    return created.is_ok() ? created.move_as_ok() : std::unique_ptr<control_getter::Executor>{};
  }();
  return instance;
}
td::Result<std::string> config_json(td::BufferSlice reply, BlockIdExt id, int param, bool with_proof) {
  if (reply.size() > explorer::kAccountProofBytes)
    return explorer::error(Failure::ResourceLimit);
  TRY_RESULT(object, fetch_tl_object<lite_api::liteServer_configInfo>(std::move(reply), true));
  if (!object->id_ || create_block_id(object->id_) != id)
    return explorer::error(Failure::EvidenceInvalid);
  auto state = block::check_extract_state_proof(id, object->state_proof_.as_slice(), object->config_proof_.as_slice());
  if (state.is_error())
    return explorer::error(Failure::EvidenceInvalid);
  block::gen::ShardStateUnsplit::Record observation;
  if (!tlb::unpack_cell(state.ok(), observation))
    return explorer::error(Failure::EvidenceInvalid);
  const auto chain_time = observation.gen_utime;
  // A selective config proof intentionally prunes unrelated state-extra fields.
  // Use the same minimal extraction as the existing raw configuration handler.
  auto config = block::Config::extract_from_state(state.move_as_ok(), 0);
  if (config.is_error())
    return explorer::error(Failure::EvidenceInvalid);
  auto& cfg = *config.ok();
  auto cell = cfg.get_config_param(param);
  const bool typed = param == 8 || param == 43 || param == 48;
  if (cell.is_null() && !typed)
    return explorer::error(Failure::ConfigParamAbsent);
  // Dependency Config 8 is requested in the same proof and decoded exactly.
  auto version_cell = cfg.get_config_param(8);
  if (version_cell.is_null())
    return explorer::error(Failure::StateInvalid);
  TRY_RESULT(global, explorer::decode_config(8, version_cell, 0, chain_time));
  auto version = vm::load_cell_slice(version_cell);
  version.fetch_ulong(8);
  auto vm_version = static_cast<td::uint32>(version.fetch_ulong(32));
  std::string b64;
  if (cell.not_null()) {
    TRY_RESULT(boc, vm::std_boc_serialize(cell));
    b64 = td::base64_encode(boc.as_slice());
  }
  td::StringBuilder out;
  out << "{\"@type\":\"configInfo\",\"config\":{\"@type\":\"tvm.cell\",\"bytes\":";
  if (cell.is_null())
    out << "null";
  else
    out << "\"" << b64 << "\"";
  out << "}" << render_config_validator_set_json(param, cell) << ",\"block_id\":" << block_json(id);
  if (typed) {
    TRY_RESULT(value, explorer::decode_config(param, cell, vm_version, chain_time));
    out << ",\"decoded\":{\"schema_version\":1,\"param\":" << param << ",\"presence\":\""
        << (cell.is_null() ? "absent" : "present") << "\",\"observation\":{\"block_id\":" << block_json(id)
        << ",\"global_id\":" << cfg.get_global_blockchain_id() << ",\"chain_time\":" << chain_time
        << ",\"vm_version\":" << vm_version << "},\"value\":" << value << "}";
  }
  if (with_proof)
    out << ",\"state_proof\":\"" << td::base64_encode(object->state_proof_.as_slice()) << "\",\"config_proof\":\""
        << td::base64_encode(object->config_proof_.as_slice()) << "\"";
  out << "}";
  if (out.as_cslice().size() > explorer::kAccountJsonBytes - 512)
    return explorer::error(Failure::ResourceLimit);
  return out.as_cslice().str();
}

td::Result<std::string> account_json(td::BufferSlice reply, BlockIdExt id, block::StdAddress address, bool wallet,
                                     bool with_proof, bool experimental, bool& needs_seqno) {
  if (reply.size() > explorer::kAccountProofBytes)
    return explorer::error(Failure::ResourceLimit);
  TRY_RESULT(object, fetch_tl_object<lite_api::liteServer_accountState>(reply.clone(), true));
  if (!object->id_ || !object->shardblk_ || create_block_id(object->id_) != id)
    return explorer::error(Failure::EvidenceInvalid);
  // Inspect size before the legacy parser serializes full code and data.
  if (object->state_.size() > explorer::kInspectionBytes)
    return explorer::error(Failure::ResourceLimit);
  auto parsed_result = ParsedAccountState::parse(object, address);
  if (parsed_result.is_error())
    return explorer::error(Failure::EvidenceInvalid);
  auto parsed = parsed_result.move_as_ok();
  TRY_STATUS(explorer::inspect_cells(parsed.code_cell, parsed.data_cell));
  TRY_RESULT(roots, vm::std_boc_deserialize_multi(object->proof_.as_slice()));
  if (roots.size() != 2)
    return explorer::error(Failure::EvidenceInvalid);
  TRY_RESULT(header, vm::MerkleProof::virtualize(roots[0]));
  block::gen::Block::Record block;
  if (!tlb::unpack_cell(header, block))
    return explorer::error(Failure::EvidenceInvalid);
  TRY_RESULT(view, explorer::decode_public_state(parsed.code_cell, parsed.data_cell, block.global_id));
  bool active = parsed.state_str == "active" && parsed.code_cell.not_null();
  const bool recognized = !view.family.empty();
  auto legacy_type = parsed.code_cell.not_null() ? detect_wallet_type(parsed.code_cell->get_hash()) : std::string{};
  needs_seqno = wallet && !recognized && !legacy_type.empty();
  const auto model = recognized ? view.account_model : detect_account_model(parsed, legacy_type);
  const auto authorization = recognized ? view.authorization_version : detect_authorization_version(legacy_type);
  td::StringBuilder pq;
  pq << "{\"schema_version\":1,\"recognition\":\""
     << (!active      ? "no_active_code"
         : recognized ? "recognized"
                      : "unknown_code")
     << "\",\"code_hash\":";
  if (active)
    pq << "\"" << td::base64_encode(parsed.code_cell->get_hash().as_slice()) << "\"";
  else
    pq << "null";
  pq << ",\"code_family\":";
  if (recognized)
    pq << "\"" << view.family << "\"";
  else
    pq << "null";
  pq << ",\"release_status\":\"" << (recognized ? "review_candidate" : "not_asserted") << "\",\"registry_revision\":\""
     << explorer::registry_revision() << "\",\"observed_masterchain_block\":" << block_json(id)
     << ",\"observed_shard_block\":" << block_json(create_block_id(object->shardblk_))
     << ",\"state_verified\":true,\"state_schema\":";
  if (recognized)
    pq << "\"" << view.family << "\"";
  else
    pq << "null";
  pq << ",\"public_state\":" << (recognized ? view.json : "null");
  if (with_proof)
    pq << ",\"proof\":{\"format\":\"liteServer.accountState.tl\",\"bytes\":\"" << td::base64_encode(reply.as_slice())
       << "\"}";
  pq << "}";
  td::StringBuilder out;
  if (wallet) {
    auto body = build_wallet_json(
        recognized ? !view.wallet_type.empty() : !legacy_type.empty(), parsed.balance, parsed.state_str,
        recognized ? view.wallet_type : legacy_type, view.seqno ? static_cast<td::int64>(*view.seqno) : -1,
        parsed.last_trans_lt, parsed.last_trans_hash_b64, block_json(id),
        block_json(create_block_id(object->shardblk_)), view.wallet_id ? static_cast<td::int64>(*view.wallet_id) : -1);
    // The existing serializer supplies the legacy envelope; append the opt-in object.
    body.pop_back();
    out << body;
  } else {
    auto body = build_account_capability_json(explorer::raw_address(address.workchain, address.addr), parsed, model,
                                              authorization, false, experimental);
    body.pop_back();
    out << body;
  }
  out << ",\"pq_authorization\":" << pq.as_cslice() << "}";
  if (out.as_cslice().size() > explorer::kAccountJsonBytes - 512)
    return explorer::error(Failure::ResourceLimit);
  return out.as_cslice().str();
}
}  // namespace

JsonRpcServer::HttpReturn JsonRpcServer::make_explorer_error(const td::Status& status, std::string id,
                                                             const std::string& cors) {
  const auto& kind = explorer::error_kind(status);
  return make_json_rpc_error(kind, kind.reason, std::move(id), cors);
}

class JsonRpcServer::ExplorerQuery final : public td::actor::Actor {
 public:
  ExplorerQuery(td::actor::ActorId<JsonRpcServer> server,
                td::actor::ActorId<validator::ValidatorManagerInterface> manager, std::string method,
                explorer::Selector selector, int param, block::StdAddress address, bool with_proof, bool experimental,
                std::string id, std::string cors, double timeout, std::shared_ptr<explorer::WorkPermit> permit,
                std::shared_ptr<http::BodyBudget::Reservation> response_reservation, td::Promise<HttpReturn> promise)
      : server_(server)
      , manager_(manager)
      , method_(std::move(method))
      , selector_(std::move(selector))
      , param_(param)
      , address_(address)
      , with_proof_(with_proof)
      , experimental_(experimental)
      , id_(std::move(id))
      , cors_(std::move(cors))
      , deadline_(td::Timestamp::in(timeout))
      , permit_(std::move(permit))
      , response_reservation_(std::move(response_reservation))
      , promise_(std::move(promise)) {
  }
  void resolved(td::Result<td::BufferSlice> result) {
    if (expired())
      return;
    if (result.is_error()) {
      fail(explorer::upstream_error(result.error()));
      return;
    }
    td::Result<BlockIdExt> id = explorer::error(Failure::EvidenceInvalid);
    if (selector_.seqno) {
      auto object = fetch_tl_object<lite_api::liteServer_blockHeader>(result.move_as_ok(), true);
      if (object.is_ok() && object.ok()->id_)
        id = create_block_id(object.ok()->id_);
    } else {
      auto object = fetch_tl_object<lite_api::liteServer_masterchainInfo>(result.move_as_ok(), true);
      if (object.is_ok() && object.ok()->last_)
        id = create_block_id(object.ok()->last_);
    }
    if (id.is_error()) {
      fail(id.move_as_error());
      return;
    }
    target_ = id.move_as_ok();
    if (target_.seqno() == 0) {
      fail(explorer::error(Failure::BlockUnavailable));
      return;
    }
    auto status = selector_.check(target_);
    if (status.is_error()) {
      fail(std::move(status));
      return;
    }
    fetch();
  }
  void anchored(td::Result<td::Ref<validator::MasterchainState>> state) {
    if (expired())
      return;
    if (state.is_error() || state.ok().is_null()) {
      fail(explorer::error(Failure::BlockUnavailable));
      return;
    }
    auto height = static_cast<BlockSeqno>(*selector_.seqno);
    // These full IDs come from locally validated masterchain history, never from
    // an unauthenticated lookupBlock response or the signature carrier itself.
    if (!state.ok()->get_old_mc_block_id(height, target_) || !state.ok()->get_old_mc_block_id(height - 1, anchor_)) {
      fail(explorer::error(Failure::BlockUnavailable));
      return;
    }
    auto status = selector_.check(target_);
    if (status.is_error()) {
      fail(std::move(status));
      return;
    }
    fetch();
  }
  void evidence(td::Result<td::BufferSlice> result) {
    if (expired())
      return;
    if (result.is_error()) {
      fail(explorer::upstream_error(result.error()));
      return;
    }
    const auto limit =
        method_ == "getMasterchainBlockSignatures" ? explorer::kProofBytes : explorer::kAccountProofBytes;
    if (result.ok().size() > limit) {
      fail(explorer::error(Failure::ResourceLimit));
      return;
    }
    output_ = std::make_shared<Output>();
    auto bytes = std::make_shared<td::BufferSlice>(result.move_as_ok());
    auto output = output_;
    auto status = explorer::dispatch_work(
        *admission_, permit_,
        [bytes, output, method = method_, target = target_, anchor = anchor_, param = param_, address = address_,
         proof = with_proof_, experimental = experimental_, token = cancellation_.get_cancellation_token()]() mutable {
          td::Result<std::string> result = explorer::error(Failure::EvidenceInvalid);
          try {
            if (token)
              return explorer::error(Failure::UpstreamUnavailable);
            if (method == "getMasterchainBlockSignatures")
              result = explorer::inspect_finality_reply(std::move(*bytes), anchor, target, proof, token);
            else if (method == "getConfigParam")
              result = config_json(std::move(*bytes), target, param, proof);
            else
              result = account_json(std::move(*bytes), target, address, method == "getWalletInformation", proof,
                                    experimental, output->needs_seqno);
          } catch (vm::VmError&) {
            return explorer::error(Failure::EvidenceInvalid);
          } catch (vm::VmVirtError&) {
            return explorer::error(Failure::EvidenceInvalid);
          } catch (const std::exception&) {
            return explorer::error(Failure::BackendFailure);
          }
          if (result.is_error())
            return result.move_as_error();
          output->json = result.move_as_ok();
          return td::Status::OK();
        },
        [output](td::Status status) {
          output->status = std::move(status);
          output->done.store(true, std::memory_order_release);
        });
    if (status.is_error())
      fail(explorer::error(Failure::BackendFailure));
  }

  void legacy_seqno(td::Result<td::BufferSlice> reply) {
    if (expired())
      return;
    td::int64 seqno = -1;
    if (reply.is_ok() && reply.ok().size() <= 16384) {
      auto object = fetch_tl_object<lite_api::liteServer_runMethodResult>(reply.move_as_ok(), true);
      if (object.is_ok() && (!object.ok()->id_ || create_block_id(object.ok()->id_) != target_)) {
        fail(explorer::error(Failure::EvidenceInvalid));
        return;
      }
      if (object.is_ok() && object.ok()->exit_code_ == 0) {
        auto stack = parse_get_method_result_stack(object.ok()->result_.as_slice());
        if (stack.is_ok() && stack.ok()->depth() > 0 && stack.ok()->at(0).is_int()) {
          auto value = stack.ok()->at(0).as_int();
          if (value->fits_bits(32, false))
            seqno = value->to_long();
        }
      }
    }
    finish_seqno(seqno);
  }

 private:
  struct Output {
    std::atomic<bool> done{false};
    td::Status status;
    std::string json;
    bool needs_seqno{false};
  };
  void start_up() override {
    if (!workers()) {
      fail(explorer::error(Failure::BackendFailure));
      return;
    }
    auto reserved = workers()->admit();
    if (reserved.is_error()) {
      promise_.set_value(
          make_json_rpc_error(json_rpc::kRateLimited, "Server busy: verified-view capacity exhausted", id_, cors_));
      stop();
      return;
    }
    admission_ = reserved.move_as_ok();
    alarm_timestamp() = td::Timestamp::in(0.01);
    if (method_ == "getMasterchainBlockSignatures") {
      td::actor::send_closure(
          manager_, &validator::ValidatorManagerInterface::get_top_masterchain_state,
          td::PromiseCreator::lambda([self = actor_id(this)](td::Result<td::Ref<validator::MasterchainState>> result) {
            td::actor::send_closure(self, &ExplorerQuery::anchored, std::move(result));
          }));
      return;
    }
    td::BufferSlice inner;
    if (selector_.seqno)
      inner = serialize_tl_object(
          create_tl_object<lite_api::liteServer_lookupBlock>(
              1, create_tl_object<lite_api::tosNode_blockId>(-1, static_cast<td::int64>(shardIdAll), *selector_.seqno),
              0, 0),
          true);
    else
      inner = serialize_tl_object(create_tl_object<lite_api::liteServer_getMasterchainInfo>(), true);
    td::actor::send_closure(server_, &JsonRpcServer::send_liteserver_query,
                            serialize_tl_object(create_tl_object<lite_api::liteServer_query>(std::move(inner)), true),
                            td::PromiseCreator::lambda([self = actor_id(this)](td::Result<td::BufferSlice> result) {
                              td::actor::send_closure(self, &ExplorerQuery::resolved, std::move(result));
                            }));
  }
  void fetch_legacy_seqno() {
    seqno_pending_ = true;
    vm::CellBuilder builder;
    vm::Stack stack;
    if (!stack.serialize(builder)) {
      finish_seqno(-1);
      return;
    }
    auto boc = vm::std_boc_serialize(builder.finalize());
    if (boc.is_error()) {
      finish_seqno(-1);
      return;
    }
    const auto method = (td::crc16(td::Slice("seqno")) & 0xffff) | 0x10000;
    auto query =
        serialize_tl_object(create_tl_object<lite_api::liteServer_runSmcMethod>(
                                0x04, create_tl_lite_block_id(target_),
                                create_tl_object<lite_api::liteServer_accountId>(address_.workchain, address_.addr),
                                method, boc.move_as_ok()),
                            true);
    td::actor::send_closure(server_, &JsonRpcServer::send_liteserver_query,
                            serialize_tl_object(create_tl_object<lite_api::liteServer_query>(std::move(query)), true),
                            td::PromiseCreator::lambda([self = actor_id(this)](td::Result<td::BufferSlice> result) {
                              td::actor::send_closure(self, &ExplorerQuery::legacy_seqno, std::move(result));
                            }));
    alarm_timestamp() = td::Timestamp::in(0.01);
  }
  void respond() {
    response_reservation_.reset();
    response_reservation_ = reserve_explorer_response(output_->json.size() + 512u);
    if (!response_reservation_) {
      promise_.set_value(
          make_json_rpc_error(json_rpc::kRateLimited, "Server busy: verified-view capacity exhausted", id_, cors_));
      stop();
      return;
    }
    auto response = make_json_ok(std::move(output_->json), id_, cors_);
    response.second = json_rpc::retain_lifetime(std::move(response.second), std::move(response_reservation_));
    promise_.set_value(std::move(response));
    stop();
  }
  void finish_seqno(td::int64 seqno) {
    if (seqno >= 0) {
      const std::string needle = "\"seqno\":null";
      auto position = output_->json.find(needle);
      if (position != std::string::npos)
        output_->json.replace(position, needle.size(), "\"seqno\":" + std::to_string(seqno));
    }
    respond();
  }
  void fetch() {
    if (expired())
      return;
    td::BufferSlice inner;
    if (method_ == "getMasterchainBlockSignatures")
      inner = serialize_tl_object(create_tl_object<lite_api::liteServer_getBlockProof>(
                                      0x1001, create_tl_lite_block_id(anchor_), create_tl_lite_block_id(target_)),
                                  true);
    else if (method_ == "getConfigParam") {
      std::vector<td::int32> params{param_};
      if (param_ != 8)
        params.push_back(8);
      inner = serialize_tl_object(create_tl_object<lite_api::liteServer_getConfigParams>(
                                      0x10000, create_tl_lite_block_id(target_), std::move(params)),
                                  true);
    } else
      inner =
          serialize_tl_object(create_tl_object<lite_api::liteServer_getAccountState>(
                                  create_tl_lite_block_id(target_),
                                  create_tl_object<lite_api::liteServer_accountId>(address_.workchain, address_.addr)),
                              true);
    td::actor::send_closure(server_, &JsonRpcServer::send_liteserver_query,
                            serialize_tl_object(create_tl_object<lite_api::liteServer_query>(std::move(inner)), true),
                            td::PromiseCreator::lambda([self = actor_id(this)](td::Result<td::BufferSlice> result) {
                              td::actor::send_closure(self, &ExplorerQuery::evidence, std::move(result));
                            }));
  }
  bool expired() {
    if (!deadline_.is_in_past())
      return false;
    fail(explorer::error(Failure::UpstreamUnavailable));
    return true;
  }
  void alarm() override {
    if (expired())
      return;
    if (!seqno_pending_ && output_ && output_->done.load(std::memory_order_acquire)) {
      if (output_->status.is_error()) {
        fail(std::move(output_->status));
        return;
      }
      if (output_->needs_seqno) {
        output_->needs_seqno = false;
        fetch_legacy_seqno();
        return;
      }
      respond();
      return;
    }
    alarm_timestamp() = td::Timestamp::in(0.01);
  }
  void fail(td::Status status) {
    cancellation_.cancel();
    if (admission_)
      admission_->cancel();
    promise_.set_value(make_explorer_error(status, id_, cors_));
    stop();
  }
  td::actor::ActorId<JsonRpcServer> server_;
  td::actor::ActorId<validator::ValidatorManagerInterface> manager_;
  std::string method_;
  explorer::Selector selector_;
  int param_;
  block::StdAddress address_;
  bool with_proof_, experimental_;
  std::string id_, cors_;
  BlockIdExt target_, anchor_;
  td::Timestamp deadline_;
  td::CancellationTokenSource cancellation_;
  std::shared_ptr<explorer::WorkPermit> permit_;
  std::unique_ptr<control_getter::Executor::Admission> admission_;
  std::shared_ptr<Output> output_;
  bool seqno_pending_{false};
  std::shared_ptr<http::BodyBudget::Reservation> response_reservation_;
  td::Promise<HttpReturn> promise_;
};

void JsonRpcServer::handle_explorer(std::string method, td::JsonObject& params, std::string id,
                                    td::Promise<HttpReturn> promise) {
  const bool signatures = method == "getMasterchainBlockSignatures";
  auto selector = explorer::parse_selector(params, signatures);
  auto proof = params.get_optional_bool_field("with_proof", false);
  if (selector.is_error() || proof.is_error()) {
    promise.set_value(make_explorer_error(explorer::error(Failure::InvalidArgument), id, opts_.cors_origin));
    return;
  }
  int param = 0;
  bool experimental = false;
  block::StdAddress address;
  if (signatures) {
    if (*selector.ok().seqno == 0) {
      promise.set_value(make_explorer_error(explorer::error(Failure::UnsignedBlock), id, opts_.cors_origin));
      return;
    }
  } else if (method == "getConfigParam") {
    auto decoded = params.get_optional_bool_field("include_decoded", false);
    auto value = params.get_required_int_field(params.has_field("param") ? td::Slice("param") : td::Slice("config_id"));
    if (decoded.is_error() || !decoded.ok() || value.is_error()) {
      promise.set_value(make_explorer_error(explorer::error(Failure::InvalidArgument), id, opts_.cors_origin));
      return;
    }
    param = value.ok();
  } else {
    auto pq = params.get_optional_bool_field("include_pq", false);
    auto ext = params.get_optional_bool_field("include_experimental", false);
    auto addr = parse_address_param(params);
    if (pq.is_error() || !pq.ok() || ext.is_error() || addr.is_error()) {
      promise.set_value(make_explorer_error(explorer::error(Failure::InvalidArgument), id, opts_.cors_origin));
      return;
    }
    address = addr.move_as_ok();
    experimental = ext.ok();
    auto text = params.get_required_string_field("address");
    if (text.is_error() || text.ok() != explorer::raw_address(address.workchain, address.addr)) {
      promise.set_value(make_explorer_error(explorer::error(Failure::InvalidArgument), id, opts_.cors_origin));
      return;
    }
  }
  auto response_reservation =
      reserve_explorer_response(signatures ? explorer::kSignatureJsonBytes : explorer::kAccountJsonBytes);
  if (!response_reservation) {
    promise.set_value(make_json_rpc_error(json_rpc::kRateLimited, "Server busy: verified-view capacity exhausted", id,
                                          opts_.cors_origin));
    return;
  }
  auto permit = explorer::WorkPermit::acquire();
  if (!permit) {
    promise.set_value(make_json_rpc_error(json_rpc::kRateLimited, "Server busy: verified-view capacity exhausted", id,
                                          opts_.cors_origin));
    return;
  }
  // New inspection methods always have a finite absolute deadline, even when
  // legacy RPC subquery timeouts are disabled by operator configuration.
  auto timeout = opts_.request_timeout > 0 ? std::min(opts_.request_timeout, 30.0) : 30.0;
  td::actor::create_actor<ExplorerQuery>("explorer-query", actor_id(this), validator_manager_, std::move(method),
                                         selector.move_as_ok(), param, address, proof.ok(), experimental, std::move(id),
                                         opts_.cors_origin, timeout, std::move(permit), std::move(response_reservation),
                                         std::move(promise))
      .release();
}
}  // namespace tos
