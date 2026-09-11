/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "json-rpc-server-internal.h"
#include "json-rpc-handler-guard.h"

#include "auto/tl/lite_api.hpp"
#include "tl/tl_object_parse.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/check-proof.h"
#include "block/mc-config.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "td/utils/crypto.h"

namespace tos {

using tos::validator_engine::guard_handler;

void JsonRpcServer::handle_getMasterchainInfo(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [cors = opts_.cors_origin, req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id, cors));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse masterchainInfo: " << mc_r.error(), req_id, cors));
          return;
        }
        auto mc = mc_r.move_as_ok();
        auto result = PSTRING()
            << "{\"@type\":\"blocks.masterchainInfo\""
            << ",\"last\":" << format_block_id_json(*mc->last_)
            << ",\"state_root_hash\":\"" << td::base64_encode(mc->state_root_hash_.as_slice()) << "\""
            << ",\"init\":" << format_zero_state_json(*mc->init_)
            << "}";
        promise.set_value(make_json_ok(result, req_id, cors));
      });
}

// ─── lookupBlock ─────────────────────────────────────────────────────

void JsonRpcServer::handle_lookupBlock(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  if (wc_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'workchain'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();

  auto shard_r = params.get_required_string_field("shard");
  if (shard_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'shard'", req_id));
    return;
  }
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);

  // Determine lookup mode: seqno (1), lt (2), or utime (4)
  td::int32 mode = 0;
  td::int32 seqno = 0;
  td::int64 lt = 0;
  td::int32 utime = 0;

  auto seqno_r = params.get_optional_int_field("seqno");
  if (seqno_r.is_ok() && seqno_r.ok() > 0) {
    mode = 1;
    seqno = static_cast<td::int32>(seqno_r.ok());
  }
  if (mode == 0) {
    auto lt_r = params.get_optional_string_field("lt");
    if (lt_r.is_ok() && !lt_r.ok().empty()) {
      mode = 2;
      lt = std::strtoll(lt_r.ok().c_str(), nullptr, 10);
    }
  }
  if (mode == 0) {
    auto unixtime_r = params.get_optional_int_field("unixtime");
    if (unixtime_r.is_ok() && unixtime_r.ok() > 0) {
      mode = 4;
      utime = static_cast<td::int32>(unixtime_r.ok());
    }
  }
  if (mode == 0) {
    // Default to seqno lookup if none specified
    auto seqno2_r = params.get_optional_int_field("seqno");
    if (seqno2_r.is_ok()) {
      mode = 1;
      seqno = static_cast<td::int32>(seqno2_r.ok());
    } else {
      promise.set_value(make_json_error(-32602,
          "Must provide 'seqno', 'lt', or 'utime'", req_id));
      return;
    }
  }

  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
      workchain, shard, seqno);
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          mode, std::move(block_id), lt, utime),
      true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [cors = opts_.cors_origin, req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id, cors));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id, cors));
          return;
        }
        auto lb = lb_r.move_as_ok();
        promise.set_value(make_json_ok(format_block_id_json(*lb->id_), req_id, cors));
      });
}

// ─── getConsensusBlock ────────────────────────────────────────────────

void JsonRpcServer::handle_getConsensusBlock(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  td::actor::send_closure(
      validator_manager_, &validator::ValidatorManagerInterface::get_last_liteserver_state_block,
      td::PromiseCreator::lambda(
          [self_id = actor_id(this), cors = opts_.cors_origin, req_id = std::move(req_id),
           promise = std::move(promise)](
              td::Result<std::pair<td::Ref<validator::MasterchainState>, BlockIdExt>> R) mutable {
        // This continuation is fulfilled inside the validator manager, on
        // its thread and outside this actor's lock, so it must not touch
        // this server's members or call its helpers -- hence the actor id
        // and the copied origin rather than `this`, and the hop back below
        // for anything that reads or writes state.
        guard_handler("getConsensusBlock continuation", [&] {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getConsensusBlock: " << R.error(), req_id, cors));
            return;
          }
          auto [state, block_id] = R.move_as_ok();
          td::uint32 last_block_utime = state.not_null() ? state->get_unix_time() : 0;
          td::actor::send_closure(self_id, &JsonRpcServer::finish_getConsensusBlock, block_id.seqno(),
                                  last_block_utime, state.not_null(), std::move(req_id), std::move(promise));
        });
      }));
}

void JsonRpcServer::finish_getConsensusBlock(td::uint32 seqno, td::uint32 last_block_utime, bool have_state,
                                             std::string req_id, td::Promise<HttpReturn> promise) {
  if (consensus_block_seqno_ != seqno) {
    consensus_block_seqno_ = seqno;
    consensus_block_timestamp_ = static_cast<td::int64>(td::Clocks::system());
  } else if (consensus_block_timestamp_ == 0) {
    consensus_block_timestamp_ = static_cast<td::int64>(td::Clocks::system());
  }

  td::StringBuilder sb;
  sb << "{\"@type\":\"ext.blocks.consensusBlock\""
     << ",\"consensus_block\":" << consensus_block_seqno_
     << ",\"timestamp\":" << consensus_block_timestamp_;
  if (have_state) {
    sb << ",\"last_block_utime\":" << last_block_utime;
  }
  sb << "}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}

// ─── getNodeConsensusStatus (read-only admin) ────────────────────────
//
// Reports this node's internal masterchain consensus view: the applied top block, the
// consensus (liteserver-served) block and the applied-minus-consensus gap, the last key
// block, the current masterchain validator set (catchain seqno, set hash, total weight,
// count), and whether this node's CURRENT local keys are in that set. The whole snapshot is
// produced by a single manager method in one actor turn, so the applied and served points
// cannot be read at different instants (the gap is a true non-negative value), and the
// membership reflects live keys rather than a startup copy. The reply is built in the
// continuation via the static make_json_ok overload, touching no server members.
namespace {
// Emit a masterchain block id as a JSON object field. Hashes are base64, matching the
// getMasterchainInfo / getBlockHeader shape.
void emit_block_id(td::StringBuilder &sb, const char *field, const BlockIdExt &id) {
  sb << "\"" << field << "\":{\"workchain\":" << id.id.workchain << ",\"shard\":" << (td::int64)id.id.shard
     << ",\"seqno\":" << id.id.seqno << ",\"root_hash\":\"" << td::base64_encode(id.root_hash.as_slice())
     << "\",\"file_hash\":\"" << td::base64_encode(id.file_hash.as_slice()) << "\"}";
}
}  // namespace

void JsonRpcServer::handle_getNodeConsensusStatus(td::JsonObject &params, std::string req_id,
                                                  td::Promise<HttpReturn> promise) {
  auto cors = opts_.cors_origin;
  td::actor::send_closure(
      validator_manager_, &validator::ValidatorManagerInterface::get_node_consensus_status,
      td::PromiseCreator::lambda(
          [cors, req_id = std::move(req_id), promise = std::move(promise)](
              td::Result<validator::NodeConsensusStatus> R) mutable {
        guard_handler("getNodeConsensusStatus", [&] {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603, PSTRING() << "getNodeConsensusStatus: " << R.error(), req_id,
                                              cors));
            return;
          }
          auto s = R.move_as_ok();
          td::StringBuilder sb;
          sb << "{\"@type\":\"ext.node.consensusStatus\"";
          sb << ",\"unix_time\":" << s.unix_time;
          sb << ",";
          emit_block_id(sb, "applied_masterchain_block", s.applied_block_id);
          sb << ",\"consensus_block_seqno\":";
          if (s.have_served) {
            sb << s.served_block_id.seqno();
            // Same-turn snapshot, so this is always >= 0 (served never leads applied).
            sb << ",\"applied_minus_consensus\":"
               << ((td::int64)s.applied_block_id.seqno() - (td::int64)s.served_block_id.seqno());
          } else {
            sb << "null";
          }
          sb << ",";
          emit_block_id(sb, "last_key_block", s.last_key_block_id);
          sb << ",\"masterchain_cc_seqno\":" << s.masterchain_cc_seqno;
          if (s.have_validator_set) {
            sb << ",\"validator_set\":{\"catchain_seqno\":" << s.validator_set_catchain_seqno
               << ",\"set_hash\":" << s.validator_set_hash << ",\"total_weight\":" << s.validator_set_total_weight
               << ",\"count\":" << s.validator_set_count << ",\"is_validator\":";
            if (s.has_local_validator_keys) {
              sb << (s.is_validator ? "true" : "false");
            } else {
              sb << "null";  // this node holds no validator keys -> membership is unknown
            }
            sb << "}";
          } else {
            sb << ",\"validator_set\":null";
          }
          sb << "}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
        });
      }));
}

// ─── shards ──────────────────────────────────────────────────────────

void JsonRpcServer::handle_shards(td::JsonObject &params, std::string req_id,
                                  td::Promise<HttpReturn> promise) {
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;

  auto self_id = actor_id(this);

  // Use the shared-Slot pattern from runGetMethod so step-1 outer callbacks
  // can settle the HTTP promise
  // on lookupBlock / getMasterchainInfo errors instead of hanging.
  struct Slot {
    td::Promise<HttpReturn> promise;
    std::string req_id;
    std::string cors;
    bool settled{false};
    void settle_error(int code, const std::string& msg) {
      if (settled) return;
      settled = true;
      promise.set_value(make_json_error(code, msg, req_id, cors));
    }
  };
  auto slot = std::make_shared<Slot>();
  slot->promise = std::move(promise);
  slot->req_id = std::move(req_id);
  slot->cors = opts_.cors_origin;

  // Step 2 lambda: given a resolved block ID, fetch shard hashes
  auto do_get_shards = [cors = opts_.cors_origin, self_id, slot](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> resolved_block_id) mutable {
        // Fetch a block header proof that includes BlockExtra and
        // ShardHashes (mode = 16 | 32 = 48). This avoids total-state download
        // limits and the broken getAllShardsInfo path while staying within the
        // standard liteserver RPC surface.
        auto header_inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getBlockHeader>(
                std::move(resolved_block_id), 48),
            true);
        auto header_query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(header_inner)), true);

        td::actor::send_closure(
            self_id, &JsonRpcServer::send_liteserver_query, std::move(header_query),
            td::PromiseCreator::lambda(
                [cors, slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603, PSTRING() << "getBlockHeader: " << R.error());
            return;
          }
          auto hdr_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (hdr_r.is_error()) {
            slot->settle_error(-32603, PSTRING() << "parse blockHeader: " << hdr_r.error());
            return;
          }
          auto hdr = hdr_r.move_as_ok();

          auto proof_root_r = vm::std_boc_deserialize(hdr->header_proof_.as_slice());
          if (proof_root_r.is_error()) {
            slot->settle_error(-32603, PSTRING() << "deserialize header_proof: " << proof_root_r.error());
            return;
          }
          auto virt_r = vm::MerkleProof::virtualize(proof_root_r.move_as_ok());
          if (virt_r.is_error()) {
            slot->settle_error(-32603, PSTRING() << "virtualize header_proof: " << virt_r.error());
            return;
          }
          auto block_root = virt_r.move_as_ok();
          auto blk_id = tos::create_block_id(hdr->id_);
          auto check_r = block::check_block_header_proof(block_root, blk_id);
          if (check_r.is_error()) {
            slot->settle_error(-32603, PSTRING() << "header proof error: " << check_r);
            return;
          }

          block::gen::Block::Record blk;
          block::gen::BlockExtra::Record extra;
          block::gen::McBlockExtra::Record mc_extra;
          if (!tlb::unpack_cell(block_root, blk) || !tlb::unpack_cell(blk.extra, extra) ||
              !extra.custom->have_refs() ||
              !tlb::unpack_cell(extra.custom->prefetch_ref(), mc_extra)) {
            slot->settle_error(-32603, "failed to extract shard hashes from block header proof");
            return;
          }

          block::ShardConfig sc;
          if (!mc_extra.shard_hashes->have_refs() ||
              !sc.unpack(mc_extra.shard_hashes->prefetch_ref())) {
            slot->settle_error(-32603, "failed to parse shard configuration");
            return;
          }

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.shards\",\"shards\":[";
          bool first = true;
          sc.process_shard_hashes([&](block::McShardHash& sh) -> int {
            if (!first) sb << ",";
            first = false;
            auto& blk = sh.blk_;
            sb << "{\"@type\":\"tos.blockIdExt\""
               << ",\"workchain\":" << blk.id.workchain
               << ",\"shard\":\"" << blk.id.shard << "\""
               << ",\"seqno\":" << blk.id.seqno
               << ",\"root_hash\":\"" << td::base64_encode(blk.root_hash.as_slice()) << "\""
               << ",\"file_hash\":\"" << td::base64_encode(blk.file_hash.as_slice()) << "\""
               << "}";
            return 0;
          });
          sb << "]}";
          if (!slot->settled) {
            slot->settled = true;
            slot->promise.set_value(make_json_ok(sb.as_cslice().str(), slot->req_id, cors));
          }
        }));
  };  // end of do_get_shards

  // Step 1: resolve block
  if (has_seqno) {
    td::int32 seqno = static_cast<td::int32>(seqno_r.ok());
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_get_shards = std::move(do_get_shards), slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603, PSTRING() << "lookupBlock: " << R.error());
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) {
            slot->settle_error(-32603, PSTRING() << "parse lookupBlock: " << lb_r.error());
            return;
          }
          do_get_shards(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    // No seqno provided — query latest masterchain block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_get_shards = std::move(do_get_shards), slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603, PSTRING() << "getMasterchainInfo: " << R.error());
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            slot->settle_error(-32603, PSTRING() << "parse getMasterchainInfo: " << mc_r.error());
            return;
          }
          do_get_shards(std::move(mc_r.move_as_ok()->last_));
        });
  }
}

// ─── getBlockHeader ──────────────────────────────────────────────────

void JsonRpcServer::handle_getBlockHeader(td::JsonObject &params, std::string req_id,
                                          td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  auto shard_r = params.get_required_string_field("shard");
  auto seqno_r = params.get_required_int_field("seqno");
  if (wc_r.is_error() || shard_r.is_error() || seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        "Missing 'workchain', 'shard', or 'seqno'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);
  td::int32 seqno = seqno_r.ok();

  // Step 1: lookupBlock to resolve full block ID
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(workchain, shard, seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [cors = opts_.cors_origin, req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id, cors));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id, cors));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto resolved_id = std::move(lb->id_);
        auto resolved_id_json = format_block_id_json(*resolved_id);

        // Step 2: getBlockHeader
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getBlockHeader>(
                std::move(resolved_id), 0),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, req_id = std::move(req_id), id_json = std::move(resolved_id_json),
                 promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getBlockHeader: " << R.error(), req_id, cors));
            return;
          }
          auto hdr_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (hdr_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse blockHeader: " << hdr_r.error(), req_id, cors));
            return;
          }
          auto hdr = hdr_r.move_as_ok();

          // Parse header proof to extract block info fields
          auto proof_root_r = vm::std_boc_deserialize(hdr->header_proof_.as_slice());
          if (proof_root_r.is_error()) {
            // Return just the block ID and raw proof if parsing fails
            auto result = PSTRING()
                << "{\"@type\":\"blocks.header\",\"id\":" << id_json
                << ",\"header_proof\":\"" << td::base64_encode(hdr->header_proof_.as_slice()) << "\"}";
            promise.set_value(make_json_ok(result, req_id, cors));
            return;
          }

          auto virt_r = vm::MerkleProof::virtualize(proof_root_r.move_as_ok());
          if (virt_r.is_error()) {
            auto result = PSTRING()
                << "{\"@type\":\"blocks.header\",\"id\":" << id_json
                << ",\"header_proof\":\"" << td::base64_encode(hdr->header_proof_.as_slice()) << "\"}";
            promise.set_value(make_json_ok(result, req_id, cors));
            return;
          }
          auto virt_root = virt_r.move_as_ok();

          // Parse Block structure from virtual root
          block::gen::Block::Record blk;
          block::gen::BlockInfo::Record info;
          bool parsed = tlb::unpack_cell(virt_root, blk) &&
                        tlb::unpack_cell(blk.info, info);

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.header\",\"id\":" << id_json;
          if (parsed) {
            sb << ",\"global_id\":" << blk.global_id
               << ",\"version\":" << info.version
               << ",\"after_merge\":" << (info.after_merge ? "true" : "false")
               << ",\"before_split\":" << (info.before_split ? "true" : "false")
               << ",\"after_split\":" << (info.after_split ? "true" : "false")
               << ",\"want_merge\":" << (info.want_merge ? "true" : "false")
               << ",\"want_split\":" << (info.want_split ? "true" : "false")
               << ",\"validator_list_hash_short\":" << info.gen_validator_list_hash_short
               << ",\"catchain_seqno\":" << info.gen_catchain_seqno
               << ",\"min_ref_mc_seqno\":" << info.min_ref_mc_seqno
               << ",\"is_key_block\":" << (info.key_block ? "true" : "false")
               << ",\"prev_key_block_seqno\":" << info.prev_key_block_seqno
               << ",\"start_lt\":\"" << info.start_lt << "\""
               << ",\"end_lt\":\"" << info.end_lt << "\""
               << ",\"gen_utime\":" << info.gen_utime;
          }
          sb << "}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
        }));
      });
}

// ─── getMasterchainBlockSignatures ──────────────────────────────────────

// Helper: serialize a lookupBlock query for a masterchain block by seqno.
static td::BufferSlice masterchain_lookup_query(td::int32 seqno) {
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
      -1, static_cast<td::int64>(-1LL << 63), seqno);
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(1, std::move(block_id), 0, 0), true);
  return tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);
}

void JsonRpcServer::handle_getMasterchainBlockSignatures(td::JsonObject &params, std::string req_id,
                                                         td::Promise<HttpReturn> promise) {
  auto seqno_r = params.get_required_int_field("seqno");
  if (seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'seqno'", req_id));
    return;
  }
  td::int32 seqno = seqno_r.ok();
  if (seqno < 1) {
    // Block #0 is the genesis block; it is not signed by a validator set.
    promise.set_value(
        make_json_error(-32602, "seqno must be >= 1 (block #0 has no signatures)", req_id));
    return;
  }

  auto self_id = actor_id(this);
  auto cors = opts_.cors_origin;

  // The signatures that finalized block N are carried by the forward proof link
  // from N-1 to N (the link "arrives at" N). So resolve N and N-1, then ask for
  // getBlockProof(known = N-1, target = N) and read the forward link into N.
  // This mirrors toslib's GetMasterchainBlockSignatures. The previous version
  // walked the proof forward FROM N (mode 0, no target), whose forward links
  // sign *later* blocks, so it answered with the wrong block's signatures; it
  // also only handled the ordinary signature set, missing the simplex sets this
  // network actually produces.

  // Step 1: resolve block N (full id).
  send_liteserver_query(masterchain_lookup_query(seqno),
      [self_id, cors, req_id = std::move(req_id), seqno, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603, PSTRING() << "lookupBlock: " << R.error(), req_id, cors));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603, PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id, cors));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto id_json = format_block_id_json(*lb->id_);
        auto n_id = std::move(lb->id_);  // full id of N, used as the proof target

        // Step 2: resolve block N-1 (the known block of the proof).
        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            masterchain_lookup_query(seqno - 1),
            td::PromiseCreator::lambda(
                [self_id, cors, req_id = std::move(req_id), seqno, id_json = std::move(id_json),
                 n_id = std::move(n_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603, PSTRING() << "lookupBlock(prev): " << R.error(), req_id, cors));
            return;
          }
          auto pb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (pb_r.is_error()) {
            promise.set_value(make_json_error(-32603, PSTRING() << "parse lookupBlock(prev): " << pb_r.error(), req_id, cors));
            return;
          }
          auto pb = pb_r.move_as_ok();

          // Step 3: getBlockProof(known = N-1, target = N). Mode 0x1001 requests
          // the proof between the two given blocks (same mode toslib uses).
          auto inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getBlockProof>(
                  0x1001, std::move(pb->id_), std::move(n_id)),
              true);
          auto query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(query),
              td::PromiseCreator::lambda(
                  [cors, req_id = std::move(req_id), id_json = std::move(id_json), seqno,
                   promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603, PSTRING() << "getBlockProof: " << R.error(), req_id, cors));
              return;
            }
            auto proof_r = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(R.move_as_ok(), true);
            if (proof_r.is_error()) {
              promise.set_value(make_json_error(-32603, PSTRING() << "parse blockProof: " << proof_r.error(), req_id, cors));
              return;
            }
            auto proof = proof_r.move_as_ok();

            // Take the forward link that arrives at N; its signature set signs N.
            tos::lite_api::liteServer_SignatureSet* sig_set = nullptr;
            for (auto& step : proof->steps_) {
              if (step->get_id() != tos::lite_api::liteServer_blockLinkForward::ID) {
                continue;
              }
              auto* fwd = static_cast<tos::lite_api::liteServer_blockLinkForward*>(step.get());
              if (!fwd->to_ || fwd->to_->seqno_ != seqno || !fwd->signatures_) {
                continue;
              }
              sig_set = fwd->signatures_.get();
              break;
            }

            auto emit_sig_array = [](td::StringBuilder& out, const auto& sig_vec) {
              bool first_sig = true;
              for (auto& sig : sig_vec) {
                if (!first_sig) {
                  out << ",";
                }
                first_sig = false;
                out << "{\"@type\":\"blocks.signature\",\"node_id_short\":\""
                    << td::base64_encode(sig->node_id_short_.as_slice())
                    << "\",\"signature\":\"" << td::base64_encode(sig->signature_.as_slice()) << "\"}";
              }
            };

            td::StringBuilder sb;
            if (sig_set && sig_set->get_id() == tos::lite_api::liteServer_signatureSet_simplex::ID) {
              // Simplex signatures are made over a message built from the
              // session id, slot and candidate data (a finalize vote), not the
              // block's root/file hash. Those fields must be returned or the
              // signatures cannot be verified, so a distinct @type carries them
              // (candidate_ is already the serialized consensus data). This
              // mirrors toslib's blocks.blockSignatures.simplex.
              auto* s = static_cast<tos::lite_api::liteServer_signatureSet_simplex*>(sig_set);
              sb << "{\"@type\":\"blocks.blockSignatures.simplex\",\"id\":" << id_json
                 << ",\"session_id\":\"" << td::base64_encode(s->session_id_.as_slice()) << "\""
                 << ",\"slot\":" << s->slot_
                 << ",\"candidate\":\"" << td::base64_encode(s->candidate_.as_slice()) << "\""
                 << ",\"signatures\":[";
              emit_sig_array(sb, s->signatures_);
              sb << "]}";
            } else {
              sb << "{\"@type\":\"blocks.blockSignatures\",\"id\":" << id_json << ",\"signatures\":[";
              if (sig_set && sig_set->get_id() == tos::lite_api::liteServer_signatureSet_ordinary::ID) {
                emit_sig_array(sb, static_cast<tos::lite_api::liteServer_signatureSet_ordinary*>(sig_set)->signatures_);
              }
              sb << "]}";
            }
            promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
          }));
        }));
      });
}

// ─── getShardBlockProof ─────────────────────────────────────────────────

void JsonRpcServer::handle_getShardBlockProof(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  auto shard_r = params.get_required_string_field("shard");
  auto seqno_r = params.get_required_int_field("seqno");
  if (wc_r.is_error() || shard_r.is_error() || seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        "Missing 'workchain', 'shard', or 'seqno'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);
  td::int32 seqno = seqno_r.ok();

  // Step 1: lookupBlock to resolve the full block ID
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(workchain, shard, seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [cors = opts_.cors_origin, req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id, cors));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id, cors));
          return;
        }
        auto lb = lb_r.move_as_ok();

        // Step 2: getShardBlockProof
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getShardBlockProof>(
                std::move(lb->id_)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getShardBlockProof: " << R.error(), req_id, cors));
            return;
          }
          auto sbp_r = tos::fetch_tl_object<tos::lite_api::liteServer_shardBlockProof>(
              R.move_as_ok(), true);
          if (sbp_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse shardBlockProof: " << sbp_r.error(), req_id, cors));
            return;
          }
          auto sbp = sbp_r.move_as_ok();

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.shardBlockProof\""
             << ",\"masterchain_id\":" << format_block_id_json(*sbp->masterchain_id_)
             << ",\"links\":[";
          bool first = true;
          for (auto& link : sbp->links_) {
            if (!first) sb << ",";
            first = false;
            sb << "{\"id\":" << format_block_id_json(*link->id_)
               << ",\"proof\":\"" << td::base64_encode(link->proof_.as_slice()) << "\""
               << "}";
          }
          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
        }));
      });
}

// ─── getOutMsgQueueSize ──────────────────────────────────────────────────
// Queries liteServer.getOutMsgQueueSizes (mode=0, no shard filter) and returns
// the per-shard queue sizes. The liteserver primitive is available in TOS.

void JsonRpcServer::handle_getOutMsgQueueSize(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  // mode=0 means no workchain/shard filter
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getOutMsgQueueSizes>(0, 0, 0), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [cors = opts_.cors_origin, req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getOutMsgQueueSizes: " << R.error(), req_id, cors));
          return;
        }
        auto qs_r = tos::fetch_tl_object<tos::lite_api::liteServer_outMsgQueueSizes>(
            R.move_as_ok(), true);
        if (qs_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse outMsgQueueSizes: " << qs_r.error(), req_id, cors));
          return;
        }
        auto qs = qs_r.move_as_ok();

        td::StringBuilder sb;
        sb << "{\"@type\":\"blocks.outMsgQueueSizes\""
           << ",\"shards\":[";
        for (size_t i = 0; i < qs->shards_.size(); i++) {
          if (i > 0) sb << ",";
          auto& shard = qs->shards_[i];
          sb << "{\"@type\":\"blocks.outMsgQueueSize\""
             << ",\"id\":" << format_block_id_json(*shard->id_)
             << ",\"size\":" << shard->size_
             << "}";
        }
        sb << "]"
           << ",\"ext_msg_queue_size_limit\":" << qs->ext_msg_queue_size_limit_
           << "}";
        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
      });
}

}  // namespace tos
