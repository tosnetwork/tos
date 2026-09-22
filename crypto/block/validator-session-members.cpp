/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <cstring>
#include <keys/keys.hpp>
#include <set>

#include "block/validator-session-members.h"
#include "block/validator-set.h"
#include "pq/pq-consensus.h"

namespace block {

std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> validator_session_members(
    const std::vector<tos::ValidatorDescr>& nodes) {
  std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> members;
  members.reserve(nodes.size());
  for (const auto& n : nodes) {
    if (n.is_pq()) {
      members.push_back(tos::create_tl_object<tos::tos_api::validator_groupMemberPQ>(n.validator_id.value,
                                                                                     n.key_id.value, n.addr, n.weight));
    } else {
      auto pub_key = tos::PublicKey{tos::pubkeys::Ed25519{n.classical_key()}};
      members.push_back(tos::create_tl_object<tos::tos_api::validator_groupMember>(
          pub_key.compute_short_id().bits256_value(), n.addr, n.weight));
    }
  }
  return members;
}

td::Status validate_pq_consensus_descriptor(const tos::ValidatorDescr& descr) {
  if (!descr.is_pq()) {
    return td::Status::Error("validator descriptor is classical; the post-quantum consensus path does not accept it");
  }
  const auto algorithm_id = static_cast<tos::pq::PQAlgorithmId>(descr.algorithm_id);
  if (!tos::pq::is_admitted(algorithm_id)) {
    return td::Status::Error(PSTRING() << "validator descriptor names an unadmitted consensus algorithm "
                                       << descr.algorithm_id);
  }
  if (descr.pq_public_key.size() != tos::pq::mldsa44_public_key_bytes) {
    return td::Status::Error(PSTRING() << "validator descriptor's consensus public key is "
                                       << descr.pq_public_key.size() << " bytes, expected "
                                       << tos::pq::mldsa44_public_key_bytes);
  }
  auto derived = tos::pq::derive_key_id(algorithm_id, descr.pq_public_key);
  if (!derived || std::memcmp(derived->data(), descr.key_id.value.data(), 32) != 0) {
    return td::Status::Error("validator descriptor's consensus key id does not derive from its public key");
  }
  // A post-quantum descriptor must state where it is reachable. It can never fall back to
  // deriving a transport identity from its consensus key, which is the whole point of
  // keeping the two apart, so an absent address leaves it unroutable.
  if (descr.addr.is_zero()) {
    return td::Status::Error("validator descriptor carries no transport address");
  }
  return td::Status::OK();
}

td::Bits256 validator_adnl_identity(const tos::ValidatorDescr& descr) {
  if (!descr.addr.is_zero()) {
    return descr.addr;
  }
  // Only a classical descriptor can leave it implicit; a post-quantum one is refused at
  // decode without an explicit address.
  return tos::PublicKey{tos::pubkeys::Ed25519{descr.classical_key()}}.compute_short_id().bits256_value();
}

td::Status validate_simplex_pq_validator_set(const ValidatorSet& set) {
  auto nodes = set.export_vector();
  if (nodes.empty()) {
    return td::Status::Error("validator set is empty");
  }
  // Identity and consensus-key uniqueness are deliberately not re-checked here. A decoded
  // set is refused outright if it repeats either, and ValidatorSet's own constructor holds
  // the same line for sets built directly by tests and tooling, so a set that exists at all
  // cannot repeat them. Restating the rule here would be a guard no input can reach.
  //
  // The transport identity is different, and it is checked. Decoding refuses a repeated
  // one, but the constructor does not, so a set built directly -- by a test fixture or by
  // tooling -- can carry two members at one address and reach this function. That set is
  // not merely malformed: the overlay indexes peers by transport identity, so the second
  // member silently replaces the first, and a message authenticated on that transport is
  // then attributed to a different validator from the one whose consensus key signed it.
  // It is refused here rather than asserted in the constructor so that the manager meets a
  // structured refusal instead of an abort.
  std::set<td::Bits256> transport_ids;
  for (const auto& descr : nodes) {
    if (auto usable = validate_pq_consensus_descriptor(descr); usable.is_error()) {
      return td::Status::Error(PSTRING() << "validator " << descr.validator_id.value.to_hex() << ": "
                                         << usable.message());
    }
    if (!transport_ids.insert(validator_adnl_identity(descr)).second) {
      return td::Status::Error(PSTRING() << "validator " << descr.validator_id.value.to_hex()
                                         << ": repeats a transport identity another member already claims");
    }
  }
  return td::Status::OK();
}

td::Status authorise_collate_request(const ValidatorSet& validator_set, const tos::ValidatorId& creator,
                                     const td::Bits256& src) {
  const auto* descr = validator_set.get_validator(creator);
  if (descr == nullptr) {
    return td::Status::Error("collate query: creator is not in the validator set");
  }
  if (src != validator_adnl_identity(*descr)) {
    return td::Status::Error("collate query: authenticated ADNL identity does not belong to the named creator");
  }
  return td::Status::OK();
}

}  // namespace block
