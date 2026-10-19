/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <atomic>
#include <memory>
#include <optional>

#include "block/block.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Time.h"

#include "control-getter-executor.h"
#include "json-rpc-contract.h"

namespace tos::explorer {
enum class Failure {
  InvalidArgument = 18001,
  UnsignedBlock,
  BlockIdMismatch,
  BlockUnavailable,
  EvidenceInvalid,
  UnsupportedCarrier,
  StateInvalid,
  ResourceLimit,
  UpstreamUnavailable,
  BackendFailure,
  ConfigParamAbsent
};
td::Status error(Failure failure);
const json_rpc::ErrorKind& error_kind(const td::Status& status);
bool retryable(const td::Status& status);
td::Status upstream_error(const td::Status& status);
struct Selector {
  std::optional<td::int32> seqno;
  std::optional<BlockIdExt> block_id;
  td::Status check(const BlockIdExt& resolved) const;
};
td::Result<Selector> parse_selector(const td::JsonObject& params, bool required = false);
td::Result<td::Bits256> parse_hash(td::Slice encoded);
std::string raw_address(td::int32 workchain, const td::Bits256& hash);
std::string block_json(const BlockIdExt& id);
inline constexpr std::size_t kProofBytes = 8u << 20;
inline constexpr std::size_t kAccountProofBytes = 4u << 20;
inline constexpr std::size_t kInspectionBytes = 256u << 10;
inline constexpr std::size_t kSignatureJsonBytes = 16u << 20;
inline constexpr std::size_t kAccountJsonBytes = 8u << 20;
inline constexpr std::size_t kMaxLinks = 64;
// This admission gate is shared by every listener in the process. Its token must
// remain owned by actual work after a request timeout. There is no waiting queue.
class WorkPermit {
 public:
  static std::shared_ptr<WorkPermit> acquire();
  static unsigned limit();
  ~WorkPermit();

 private:
  WorkPermit() = default;
  static std::atomic<unsigned> active_;
};
td::Result<std::string> inspect_finality_reply(td::BufferSlice reply, BlockIdExt trusted_anchor, BlockIdExt target,
                                               bool with_proof, td::CancellationToken cancellation = {});
td::Status dispatch_work(control_getter::Executor::Admission& admission, std::shared_ptr<WorkPermit> permit,
                         control_getter::Executor::Work work, control_getter::Executor::Completion completion);
td::Status inspect_cells(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data);
struct PublicState {
  std::string family, json, account_model, authorization_version, wallet_type;
  std::optional<td::uint32> seqno, wallet_id;
};
td::Result<PublicState> decode_public_state(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data,
                                            std::optional<td::int32> observation_global_id = {});
struct RegistryEntry {
  std::string family;
  td::Ref<vm::Cell> code;
};
const std::vector<RegistryEntry>& registry();
const char* registry_revision();
td::Bits256 registry_network_tag();
td::Result<std::string> decode_config(int param, td::Ref<vm::Cell> cell, td::uint32 version, td::uint32 chain_time);
}  // namespace tos::explorer
