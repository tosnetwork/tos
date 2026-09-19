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
#pragma once

#include <vector>

#include "auto/tl/tos_api.h"
#include "tos/tos-types.h"

namespace block {

// The members a consensus session commits to.
//
// A post-quantum member carries both of its identities: the stable one saying which
// validator this is, and the one naming the consensus key it currently holds. That is
// what makes a key rotation start a different session while leaving the validator the
// same member of the set. A classical member still commits to the identity derived
// from its key.
//
// The two forms are separate constructors of one boxed type, so their encodings carry
// distinct ids and a classical member can never be read as a post-quantum one.
//
// Boxing the member list changes session identifiers for classical sets as well, since
// every member now carries a constructor id. That is an intentional pre-mainnet break,
// not something to paper over: session identifiers are per-round and never enter a
// block, so nothing persisted moves, but two nodes must agree on this encoding to join
// the same session. There is deliberately no legacy session form and no selection
// between one and the other.
std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> validator_session_members(
    const std::vector<tos::ValidatorDescr>& nodes);

// The ADNL identity a validator is reachable at, as the set records it.
//
// A classical descriptor may leave it implicit, in which case it is the one derived
// from its key. A post-quantum descriptor always carries it explicitly, because a
// consensus key is never a transport identity. Answering this in one place keeps the
// rule from being restated at each call site and drifting.
td::Bits256 validator_adnl_identity(const tos::ValidatorDescr& descr);

class ValidatorSet;

// Whether a collate request may be served.
//
// Two separate facts have to line up: the creator a request names must be a member of
// the set, and the transport identity the request actually arrived on must be the one
// that member is reachable at. Checking only that both are validators lets one member
// have blocks collated and stored under another's identity, so the decision is made
// here, once, rather than restated at the call site.
td::Status authorise_collate_request(const ValidatorSet& validator_set, const tos::ValidatorId& creator,
                                     const td::Bits256& src);

}  // namespace block
