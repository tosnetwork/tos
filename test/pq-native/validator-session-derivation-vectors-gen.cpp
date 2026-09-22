/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "block/block-auto.h"
#include "block/validator-session-id.h"
#include "block/validator-session-members.h"
#include "td/utils/misc.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "validator/consensus/db-path.h"
#include "validator/consensus/session-compat.h"
#include "validator/impl/shard.hpp"
#include "vm/boc.h"
#include "vm/cells.h"

namespace {

td::Bits256 fill(unsigned char value) {
  td::Bits256 result;
  std::memset(result.data(), value, 32);
  return result;
}

td::Ref<vm::Cell> simplex_cell(td::uint32 slots) {
  vm::CellBuilder builder;
  if (!builder.store_long_bool(0x22, 8) || !builder.store_long_bool(0, 5) || !builder.store_long_bool(2, 2) ||
      !builder.store_long_bool(0, 1) || !builder.store_long_bool(slots, 32) || !builder.store_long_bool(0, 1)) {
    std::abort();
  }
  return builder.finalize();
}

struct Vector {
  td::int32 global_id{-239};
  td::Bits256 options_hash;
  td::Ref<vm::Cell> config_cell;
  td::BufferSlice config_boc;
  tos::ShardIdFull shard{tos::masterchainId, tos::shardIdAll};
  td::uint32 vertical_seqno{7};
  tos::BlockSeqno key_seqno{91};
  tos::CatchainSeqno catchain_seqno{17};
  tos::ValidatorDescr validator;
  td::Bits256 session_config_hash;
  tos::ValidatorSessionId session_id;
};

block::ValidatorSessionIdentityInput identity_input(const Vector& vector) {
  return {
      .global_id = vector.global_id,
      .validator_options_hash = vector.options_hash,
      .simplex_config_cell_hash = td::Bits256{vector.config_cell->get_hash().bits()},
      .shard = vector.shard,
      .catchain_seqno = vector.catchain_seqno,
      .validators = {vector.validator},
      .vertical_seqno = vector.vertical_seqno,
      .last_key_block_seqno = vector.key_seqno,
      .new_catchain_ids = true,
  };
}

Vector make_vector() {
  tos::ValidatorSessionConfig config;
  tos::validator::consensus::ValidatorSessionOptions options{config};
  auto cell = simplex_cell(4);
  auto boc = vm::std_boc_serialize(cell, 0);
  if (boc.is_error()) {
    std::abort();
  }
  Vector vector{
      .options_hash = options.get_hash(),
      .config_cell = cell,
      .config_boc = boc.move_as_ok(),
      .validator = tos::ValidatorDescr{tos::ValidatorId{fill(0xa1)}, 1, tos::ConsensusKeyId{fill(0xb2)},
                                       std::string(1312, '\x5c'), 23, fill(0xc3)},
      .session_config_hash = {},
      .session_id = {},
  };
  auto identity = block::derive_validator_session_identity(identity_input(vector));
  vector.session_config_hash = identity.session_config_hash;
  vector.session_id = identity.session_id;
  return vector;
}

std::string render(const Vector& vector) {
  std::ostringstream out;
  out << "global_id\tparam29_hash\tselected_param30_cell_boc\tselected_param30_cell_hash\tworkchain\tshard\t"
         "vertical_seqno\tlast_key_block_seqno\tcatchain_seqno\tvalidator_id\tkey_id\tadnl\tweight\t"
         "session_config_hash\tvalidator_session_id\n";
  out << vector.global_id << '\t' << vector.options_hash.to_hex() << '\t'
      << td::hex_encode(vector.config_boc.as_slice()) << '\t' << vector.config_cell->get_hash().to_hex() << '\t'
      << vector.shard.workchain << '\t' << vector.shard.shard << '\t' << vector.vertical_seqno << '\t'
      << vector.key_seqno << '\t' << vector.catchain_seqno << '\t' << vector.validator.validator_id.value.to_hex()
      << '\t' << vector.validator.key_id.value.to_hex() << '\t' << vector.validator.addr.to_hex() << '\t'
      << vector.validator.weight << '\t' << vector.session_config_hash.to_hex() << '\t' << vector.session_id.to_hex()
      << '\n';
  return out.str();
}

int check_manager_assembly_inputs(const Vector& vector) {
  const auto expected = block::derive_validator_session_identity(identity_input(vector));
  if (expected.session_config_hash.to_hex() != "9596398C00EBC759D5BC0E25A98D4359EE1062A42D9B40CBDABA1A03B28B0883" ||
      expected.session_id.to_hex() != "F365B81E5D8FB9705FAA85C60665C9B75F8CF82AAF575E149C3EAC4E50B02276") {
    std::fprintf(stderr, "MANAGER_SESSION_ASSEMBLY_FROZEN_VECTOR_MISMATCH\n");
    return 1;
  }

  auto changes_session = [&](block::ValidatorSessionIdentityInput changed, const char* field) {
    if (block::derive_validator_session_identity(changed).session_id == expected.session_id) {
      std::fprintf(stderr, "MANAGER_SESSION_ASSEMBLY_INPUT_NOT_BOUND field=%s\n", field);
      return false;
    }
    return true;
  };
  auto input = identity_input(vector);
  auto changed = input;
  changed.global_id++;
  if (!changes_session(std::move(changed), "global_id"))
    return 1;
  changed = input;
  changed.validator_options_hash.data()[0] ^= 1;
  if (!changes_session(std::move(changed), "validator_options_hash"))
    return 1;
  changed = input;
  changed.simplex_config_cell_hash.data()[0] ^= 1;
  if (!changes_session(std::move(changed), "simplex_config_cell_hash"))
    return 1;
  changed = input;
  changed.shard = tos::ShardIdFull{0, tos::shardIdAll};
  if (!changes_session(std::move(changed), "shard"))
    return 1;
  changed = input;
  changed.catchain_seqno++;
  if (!changes_session(std::move(changed), "catchain_seqno"))
    return 1;
  changed = input;
  changed.validators[0].validator_id.value.data()[0] ^= 1;
  if (!changes_session(std::move(changed), "validators"))
    return 1;
  changed = input;
  changed.vertical_seqno++;
  if (!changes_session(std::move(changed), "vertical_seqno"))
    return 1;
  changed = input;
  changed.last_key_block_seqno++;
  if (!changes_session(std::move(changed), "last_key_block_seqno"))
    return 1;
  changed = input;
  changed.new_catchain_ids = false;
  if (!changes_session(std::move(changed), "new_catchain_ids"))
    return 1;
  return 0;
}

int check_real_state_global_id() {
  std::ifstream input(SHARD_STATE_BOC_FILE, std::ios::binary);
  std::ostringstream bytes;
  bytes << input.rdbuf();
  if (!input) {
    std::fprintf(stderr, "SHARD_STATE_GLOBAL_ID_FIXTURE_READ_FAILURE file=%s\n", SHARD_STATE_BOC_FILE);
    return 1;
  }
  td::BufferSlice data{bytes.str()};
  auto root_r = vm::std_boc_deserialize(data.as_slice());
  if (root_r.is_error()) {
    std::fprintf(stderr, "SHARD_STATE_GLOBAL_ID_BOC_PARSE_FAILURE error=%s\n", root_r.error().message().str().c_str());
    return 1;
  }
  auto root = root_r.move_as_ok();
  block::gen::ShardStateUnsplit::Record header;
  if (!block::gen::unpack_cell(root, header)) {
    std::fprintf(stderr, "SHARD_STATE_GLOBAL_ID_HEADER_PARSE_FAILURE\n");
    return 1;
  }
  block::ShardId parsed_shard{header.shard_id};
  tos::RootHash root_hash{root->get_hash().bits()};
  tos::FileHash file_hash;
  file_hash.set_zero();
  tos::BlockIdExt block_id{tos::BlockId{tos::ShardIdFull(parsed_shard), header.seq_no}, root_hash, file_hash};
  auto state_r = tos::validator::ShardStateQ::fetch(block_id, data.clone());
  if (state_r.is_error()) {
    std::fprintf(stderr, "SHARD_STATE_GLOBAL_ID_FETCH_FAILURE error=%s\n", state_r.error().message().str().c_str());
    return 1;
  }
  // Frozen independently of the session vector: this tracked state BOC is
  // from network -17, while the session vector deliberately uses -239.
  constexpr td::int32 expected_global_id = -17;
  if (header.global_id != expected_global_id || state_r.ok()->get_global_id() != expected_global_id) {
    std::fprintf(stderr, "SHARD_STATE_GLOBAL_ID_MISMATCH header=%d accessor=%d expected=%d\n", header.global_id,
                 state_r.ok()->get_global_id(), expected_global_id);
    return 1;
  }
  return 0;
}

int check(const char* path, td::Slice only) {
  if (!only.empty() && only != "param30" && only != "global-id" && only != "local-override" &&
      only != "governing-snapshot" && only != "session-path" && only != "constructor-selection" &&
      only != "manager-assembly" && only != "state-global-id") {
    std::fprintf(stderr, "UNKNOWN_SESSION_DERIVATION_CHECK name=%s\n", only.str().c_str());
    return 2;
  }
  auto vector = make_vector();
  if (only == "manager-assembly") {
    return check_manager_assembly_inputs(vector);
  }
  if (only == "state-global-id") {
    return check_real_state_global_id();
  }
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  if (!input || contents.str() != render(vector)) {
    std::fprintf(stderr, "SESSION_DERIVATION_VECTOR_MISMATCH file=%s\n", path);
    return 1;
  }

  if (only.empty() && check_manager_assembly_inputs(vector) != 0) {
    return 1;
  }
  if (only.empty() && check_real_state_global_id() != 0) {
    return 1;
  }

  auto other_cell = simplex_cell(5);
  auto identity_b = block::derive_validator_session_identity(
      vector.global_id, vector.options_hash, td::Bits256{other_cell->get_hash().bits()}, vector.shard,
      vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true);
  auto hash_b = identity_b.session_config_hash;
  auto session_b = identity_b.session_id;
  if ((only.empty() || only == "param30") && (hash_b == vector.session_config_hash || session_b == vector.session_id)) {
    std::fprintf(stderr, "PARAM30_CHANGE_DID_NOT_CHANGE_SESSION\n");
    return 1;
  }

  auto other_global_identity = block::derive_validator_session_identity(
      vector.global_id + 1, vector.options_hash, td::Bits256{vector.config_cell->get_hash().bits()}, vector.shard,
      vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true);
  auto other_global = other_global_identity.session_config_hash;
  auto other_global_session = other_global_identity.session_id;
  if ((only.empty() || only == "global-id") &&
      (other_global == vector.session_config_hash || other_global_session == vector.session_id)) {
    std::fprintf(stderr, "GLOBAL_ID_CHANGE_DID_NOT_CHANGE_SESSION\n");
    return 1;
  }

  tos::SelectedNewConsensusConfig selected{.config = {},
                                           .cell_hash = td::Bits256{vector.config_cell->get_hash().bits()}};
  auto before_override =
      block::validator_session_config_hash(vector.global_id, vector.options_hash, selected.cell_hash);
  selected.config.noncritical_params.target_rate = std::chrono::milliseconds(9999);
  auto after_override = block::validator_session_config_hash(vector.global_id, vector.options_hash, selected.cell_hash);
  if ((only.empty() || only == "local-override") && before_override != after_override) {
    std::fprintf(stderr, "LOCAL_NONCRITICAL_OVERRIDE_CHANGED_SESSION\n");
    return 1;
  }

  // K is governed by the snapshot before it, while K+1 is governed by K's state.
  // Verification binds this expected id in the following unit; this test pins
  // the governing-snapshot boundary without pulling that verifier work forward.
  const auto k_under_a =
      block::derive_validator_session_identity(
          vector.global_id, vector.options_hash, td::Bits256{vector.config_cell->get_hash().bits()}, vector.shard,
          vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true)
          .session_id;
  const auto after_k_under_b =
      block::derive_validator_session_identity(
          vector.global_id, vector.options_hash, td::Bits256{other_cell->get_hash().bits()}, vector.shard,
          vector.catchain_seqno, {vector.validator}, vector.vertical_seqno, vector.key_seqno, true)
          .session_id;
  if ((only.empty() || only == "governing-snapshot") &&
      (k_under_a != vector.session_id || k_under_a == session_b || after_k_under_b != session_b)) {
    std::fprintf(stderr, "GOVERNING_SNAPSHOT_BOUNDARY_FAILED\n");
    return 1;
  }

  auto path_a = tos::validator::consensus::consensus_db_dir_name(vector.shard, vector.catchain_seqno, vector.session_id,
                                                                 td::Slice{});
  auto path_b =
      tos::validator::consensus::consensus_db_dir_name(vector.shard, vector.catchain_seqno, session_b, td::Slice{});
  if ((only.empty() || only == "session-path") && path_a == path_b) {
    std::fprintf(stderr, "PARAM30_CHANGE_REUSED_SESSION_PATH\n");
    return 1;
  }

  if (only.empty() || only == "constructor-selection") {
    auto legacy = block::derive_validator_session_identity(vector.global_id, vector.options_hash, selected.cell_hash,
                                                           vector.shard, vector.catchain_seqno, {vector.validator}, 0,
                                                           vector.key_seqno, false);
    auto expected_legacy = tos::create_hash_tl_object<tos::tos_api::validator_group>(
        vector.shard.workchain, vector.shard.shard, vector.catchain_seqno, legacy.session_config_hash,
        block::validator_session_members({vector.validator}));
    auto extended = block::derive_validator_session_identity(vector.global_id, vector.options_hash, selected.cell_hash,
                                                             vector.shard, vector.catchain_seqno, {vector.validator},
                                                             vector.vertical_seqno, vector.key_seqno, false);
    auto expected_extended = tos::create_hash_tl_object<tos::tos_api::validator_groupEx>(
        vector.shard.workchain, vector.shard.shard, vector.vertical_seqno, vector.catchain_seqno,
        extended.session_config_hash, block::validator_session_members({vector.validator}));
    if (legacy.session_id != expected_legacy || extended.session_id != expected_extended ||
        vector.session_id == legacy.session_id || vector.session_id == extended.session_id) {
      std::fprintf(stderr, "SESSION_CONSTRUCTOR_SELECTION_CHANGED\n");
      return 1;
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 1) {
    std::fputs(render(make_vector()).c_str(), stdout);
    return 0;
  }
  if (argc == 2) {
    return check(argv[1], {});
  }
  if (argc == 3) {
    return check(argv[1], td::Slice{argv[2], std::strlen(argv[2])});
  }
  std::fprintf(stderr, "usage: %s [vector-file [check-name]]\n", argv[0]);
  return 2;
}
