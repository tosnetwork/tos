/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Produce a validator's vote exactly as a node produces one.
//
// Everything a node does to vote is here and nowhere else: load the custodied consensus
// seed, build the bytes the contract will rebuild, sign them under that vote's own
// authority domain, and put the signature on the wire. The node calls the same four
// functions; this reaches them from a command line so the result can be handed to the
// real contract and required to be counted.
//
// It holds no controller root and cannot be asked to sign arbitrary bytes: the fields of
// a vote go in, one vote comes out. The same is true of the third thing a consensus key
// signs, a stake authorisation, which is produced here by the same route the node's own
// creator takes -- the frozen preimage, the election context -- and for the same reason:
// so that a first stake, made before the node is in any set, can be required to be
// exactly what the node would have signed.
//
// A stake authorisation consults no validator set. A node signs its first one before it
// is a member of any, so a lookup that required membership would be a circle nothing
// could enter.
#include <iostream>
#include <string>

#include "block/pq-vote.h"
#include "common/bitstring.h"
#include "pq/consensus-key-file.h"
#include "pq/pq-elector.h"
#include "pq/pq-stake-authorization.h"
#include "td/utils/base64.h"
#include "td/utils/misc.h"
#include "vm/boc.h"

namespace {

td::Bits256 bits256_from_hex(const std::string& text) {
  td::Bits256 out;
  if (text.size() != 64 || out.from_hex(td::Slice(text)) <= 0) {
    throw std::runtime_error("expected 32 bytes of hex");
  }
  return out;
}

[[noreturn]] void usage() {
  throw std::runtime_error(
      "usage:\n"
      "  tos-pq-vote config SEEDFILE GLOBAL_ID SET_ID_HEX VALIDATOR_ID_HEX IDX PROPOSAL_HEX\n"
      "  tos-pq-vote complaint SEEDFILE GLOBAL_ID SET_ID_HEX VALIDATOR_ID_HEX IDX ELECTION_ID "
      "COMPLAINT_HEX\n"
      "  tos-pq-vote stake SEEDFILE GLOBAL_ID VALIDATOR_ID_HEX ELECTION_ID MAX_FACTOR ADNL_HEX "
      "OWNER_HEX\n"
      "\n"
      "A vote prints a base64 message body. A stake prints the 2420 signature bytes in hex:\n"
      "the body that carries them is built by the pool or controller that relays the stake.");
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      usage();
    }
    const std::string kind(argv[1]);
    const bool complaint = kind == "complaint";
    const bool stake = kind == "stake";
    if (!complaint && !stake && kind != "config") {
      usage();
    }
    if (argc != (complaint || stake ? 9 : 8)) {
      usage();
    }

    auto loaded = tos::pq::load_consensus_key(argv[2]);
    if (std::holds_alternative<tos::pq::ConsensusKeyFileError>(loaded)) {
      throw std::runtime_error(tos::pq::describe(std::get<tos::pq::ConsensusKeyFileError>(loaded)));
    }
    const auto& store = std::get<tos::pq::ValidatorPQKeyStore>(loaded);

    if (stake) {
      // The identity is the configured controller account and the key is whatever the
      // seed derives, exactly as the node resolves them for its own stake: nothing here
      // asks which set the validator is in, because the answer is meant to be none yet.
      const auto global_id = static_cast<td::int32>(std::stol(argv[3]));
      const auto validator_id = bits256_from_hex(argv[4]);
      const auto election = static_cast<td::uint32>(std::stoul(argv[5]));
      const auto max_factor = static_cast<td::uint32>(std::stoul(argv[6]));
      const auto adnl = bits256_from_hex(argv[7]);
      const auto owner = bits256_from_hex(argv[8]);
      // The one routine that assembles and signs a stake, shared with the node's control
      // query so the tool a review can run and the producer it stands in for cannot drift.
      // It derives the key identity from the seed store, rejects a zero address or owner and
      // a factor below one, and signs under the election domain.
      auto authorization =
          tos::pq::sign_stake_authorization(store, global_id, election, max_factor, validator_id, adnl, owner);
      if (!authorization.has_value()) {
        throw std::runtime_error("the consensus key could not sign this stake, or its arguments were out of range");
      }
      std::cout << td::buffer_to_hex(td::Slice(authorization->signature.signature)) << '\n';
      return 0;
    }

    const auto global_id = static_cast<td::int32>(std::stol(argv[3]));
    const auto set_id = bits256_from_hex(argv[4]);
    const auto validator_id = bits256_from_hex(argv[5]);
    const auto idx = static_cast<td::uint16>(std::stoul(argv[6]));

    // The bytes the contract rebuilds. A field out of place here is a vote nobody can
    // verify, which is why these come from the one place every producer shares.
    std::string preimage;
    td::Result<td::Ref<vm::Cell>> body = td::Status::Error("unset");
    if (complaint) {
      const auto election_id = static_cast<td::uint32>(std::stoul(argv[7]));
      const auto complaint_hash = bits256_from_hex(argv[8]);
      preimage = tos::pq::complaint_vote_preimage(global_id, set_id, validator_id, idx, election_id, complaint_hash);
      auto signature = store.sign_election(preimage);
      if (!signature.has_value()) {
        throw std::runtime_error("the consensus key could not sign this complaint vote");
      }
      body = block::pq::complaint_vote_body(1, idx, election_id, complaint_hash, signature->signature);
    } else {
      const auto proposal_hash = bits256_from_hex(argv[7]);
      preimage = tos::pq::config_vote_preimage(global_id, set_id, validator_id, idx, proposal_hash);
      auto signature = store.sign_config_vote(preimage);
      if (!signature.has_value()) {
        throw std::runtime_error("the consensus key could not sign this configuration vote");
      }
      body = block::pq::config_vote_body(1, idx, proposal_hash, signature->signature);
    }
    if (body.is_error()) {
      throw std::runtime_error(body.move_as_error().to_string());
    }

    auto serialized = vm::std_boc_serialize(body.move_as_ok());
    if (serialized.is_error()) {
      throw std::runtime_error(serialized.move_as_error().to_string());
    }
    std::cout << td::base64_encode(serialized.move_as_ok().as_slice()) << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
