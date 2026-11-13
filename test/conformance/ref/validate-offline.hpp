// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Offline run of the node's block-candidate validation (ValidateQuery, validator/impl/validate-query.cpp,
// entered through run_validate_query of validator/fabric.h) on one candidate, with every input it asks the
// validator manager for served from memory by a test-only manager. Shared by the validate harness and the
// context exporter (migrate/validate-export.cpp).
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "tos/tos-types.h"
#include "vm/cells.h"

namespace conformance::validate {

// One input ValidateQuery may ask for: the state of a block, served by the manager's state requests
// (wait_block_state, wait_block_state_short, wait_block_message_queue_short, get_out_msg_queue_size).
struct ServedState {
  tos::BlockIdExt block;
  td::Ref<vm::Cell> root;
};

struct Request {
  tos::BlockIdExt candidate;  // BlockCandidate::id
  td::BufferSlice data;       // the block BOC, as received
  td::BufferSlice collated_data;
  td::Bits256 created_by;              // BlockCandidate::producer (Ed25519 public key)
  std::vector<tos::BlockIdExt> prev;   // ValidateParams::prev
  tos::BlockIdExt min_masterchain;     // ValidateParams::min_masterchain_block_id
  tos::BlockIdExt top_masterchain;     // answer of get_top_masterchain_state_block
  tos::BlockIdExt validator_set_from;  // masterchain state the validator set is computed from, as the manager does
  bool skip_shard_signatures = false;  // ValidateParams::is_fake: shard top signatures are not checked
  std::vector<ServedState> states;
};

enum class Verdict { accepted, rejected, error };

struct Outcome {
  Verdict verdict = Verdict::error;
  std::string message;  // reject reason or error text; empty when accepted
  int error_code = 0;
  double ok_from_utime = 0;  // CandidateAccept::ok_from_utime
  // Manager requests ValidateQuery made, in order: the state of each block it asked for, and every
  // request this manager does not serve (they fail, so a missing input is never answered silently).
  std::vector<tos::BlockIdExt> states_requested;
  std::vector<std::string> unserved;
};

// Runs ValidateQuery on a single-threaded actor scheduler and returns when it reports. An error is a
// problem of the request itself (unknown validator set state, duplicate states), not a verdict.
td::Result<Outcome> run(Request request);

// Stable class of a reject or error message (fixed table, "unclassified" for anything else).
const char *classify(const Outcome &outcome);

// Every class classify can return.
const std::vector<std::string> &reason_classes();

}  // namespace conformance::validate
