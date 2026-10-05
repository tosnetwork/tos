/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Authenticated proof verification from a locally provisioned anchor.
//
// Every result this module returns is derived from one masterchain block whose
// identity was authenticated by a continuous chain of post-quantum finality
// proofs starting at the configured anchor. Endpoint-supplied bytes are only
// ever proof material: nothing an endpoint sends can select the anchor, skip a
// check or supply a verdict. Any failure refuses the whole request; there is no
// partial result.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "block/block.h"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "tos/tos-types.h"
#include "vm/stack.hpp"

namespace tos::proofverify {

inline constexpr const char* kInterface = "tos-proof-verify/1";
inline constexpr const char* kStateInterface = "tos-proof-verify-state/1";

// Hard limits on every endpoint-controlled quantity.
inline constexpr std::size_t kMaxFileBytes = 64u << 20;
inline constexpr std::size_t kMaxChainResponses = 1024;
inline constexpr std::size_t kMaxChainLinks = 16384;
inline constexpr std::size_t kMaxDescentLinks = 16;
inline constexpr std::size_t kMaxConfigParams = 64;
inline constexpr std::size_t kMaxGetMethods = 16;
inline constexpr std::size_t kMaxGetMethodArgs = 64;
inline constexpr std::size_t kMaxLibraries = 64;
inline constexpr std::size_t kMaxStackDepth = 16;
inline constexpr std::int64_t kGetMethodGasLimit = 1000000;
inline constexpr std::int64_t kMaxAgeLimitSeconds = 7 * 24 * 3600;
inline constexpr std::int64_t kMaxFutureSkewSeconds = 60;

enum class AnchorKind { Zerostate, KeyBlock };

struct Anchor {
  AnchorKind kind{AnchorKind::Zerostate};
  tos::BlockIdExt id;
};

enum class Mode { Live, Historical };

struct GetMethodRequest {
  std::string method;
  td::int32 method_id{0};
  std::vector<vm::StackEntry> args;
  std::string args_json;  // canonical rendering of the parsed arguments
};

struct Request {
  Mode mode{Mode::Historical};
  std::optional<tos::BlockIdExt> target;
  std::int64_t max_age_seconds{0};
  std::vector<int> config_params;
  std::optional<block::StdAddress> account;
  std::vector<GetMethodRequest> get_methods;
};

// Raw endpoint answers, exactly as received (TL-serialized lite API objects).
struct Material {
  std::optional<td::BufferSlice> masterchain_info;
  std::vector<td::BufferSlice> chain;
  std::vector<td::BufferSlice> descent;
  std::optional<td::BufferSlice> config;
  std::optional<td::BufferSlice> account;
  std::optional<td::BufferSlice> exec_config;
  std::optional<td::BufferSlice> libraries;
};

// A locally committed record of what this verifier has already authenticated
// in live mode. It is written only after a complete successful verification.
struct VerifiedBlock {
  tos::BlockIdExt id;
  td::uint32 gen_utime{0};
};

struct LiveState {
  Anchor anchor;
  std::optional<VerifiedBlock> head;
  std::optional<VerifiedBlock> key_block;
};

struct Policy {
  std::int64_t now{0};  // local wall-clock time, never taken from an endpoint
};

struct ProvenParam {
  int index{0};
  td::Bits256 cell_hash;
  std::string boc;  // raw bytes
};

struct ProvenAccount {
  block::StdAddress address;
  tos::BlockIdExt shard_block;
  bool exists{false};
  td::Bits256 state_hash;
  std::string state_boc;
  std::string balance;  // decimal nanotons
  td::Bits256 code_hash;
  td::Bits256 data_hash;
  bool active{false};
  tos::LogicalTime last_trans_lt{0};
  td::Bits256 last_trans_hash;
  td::uint32 gen_utime{0};
  tos::LogicalTime gen_lt{0};
};

struct ExecutionContext {
  td::uint32 unixtime{0};
  tos::LogicalTime block_lt{0};
  td::Bits256 rand_seed;
  td::Bits256 config_root_hash;
  int global_version{0};
  std::vector<td::Bits256> libraries;
};

struct GetMethodResult {
  std::string method;
  td::int32 method_id{0};
  std::string args_json;
  int exit_code{0};
  std::int64_t gas_used{0};
  std::string stack_json;
  std::string stack_boc;
};

struct Verified {
  Mode mode{Mode::Historical};
  Anchor anchor;
  tos::BlockIdExt start;
  tos::BlockIdExt target;
  td::uint32 target_gen_utime{0};
  bool target_is_key_block{false};
  std::size_t links{0};
  std::vector<tos::BlockIdExt> key_blocks;  // authenticated key blocks on the path, in order
  std::optional<tos::BlockIdExt> descends_from;
  std::int64_t now{0};
  std::int64_t max_age_seconds{0};
  std::string request_sha256;
  std::vector<ProvenParam> params;
  std::optional<ProvenAccount> account;
  std::optional<ExecutionContext> context;
  std::vector<GetMethodResult> get_methods;
  // The live record to commit after the result is accepted.
  std::optional<LiveState> next_state;
};

td::Result<Anchor> parse_anchor(td::Slice json);
td::Result<Request> parse_request(td::Slice json);
td::Result<LiveState> parse_state(td::Slice json);
std::string render_state(const LiveState& state);

// Computes an anchor from a locally stored zerostate file.
td::Result<Anchor> anchor_from_zerostate(td::Slice zerostate_boc);
std::string render_anchor(const Anchor& anchor);

// The full verification. `state` is the persisted live record (live mode only);
// `request_bytes` is hashed into the result so it is bound to the request.
td::Result<Verified> verify(const Anchor& anchor, const Request& request, td::Slice request_bytes,
                            const Material& material, const std::optional<LiveState>& state, const Policy& policy);

std::string render_verified(const Verified& verified);
std::string render_refusal(td::Slice reason);

std::string block_id_json(const tos::BlockIdExt& id);

// The first masterchain block the proof chain starts from: the anchor, or in
// live mode the newest key block this verifier already authenticated from it.
tos::BlockIdExt chain_start(const Anchor& anchor, std::optional<tos::BlockIdExt> target, const Request& request,
                            const std::optional<LiveState>& state);

// Library hashes referenced by the account's code and data that must be
// supplied with proof before any get-method can run.
td::Result<std::vector<td::Bits256>> required_libraries(td::Slice account_state_boc);

}  // namespace tos::proofverify
