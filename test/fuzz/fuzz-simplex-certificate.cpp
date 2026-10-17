/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Simplex consensus messages as a peer validator delivers them: signed votes, quorum
// certificates and candidate broadcasts, through the production parsers and their
// ML-DSA-44 verification (Signed<Vote>::deserialize, Certificate<Vote>::from_tl after the
// same TL fetch the pool does, Candidate::deserialize).
//
// Input layout: a kind byte (vote, certificate, candidate; see simplex-fixture.h), a byte
// naming the validator a vote or candidate comes from, then the message bytes.
//
// An accepted certificate must name each signer once, only signers in the set, and carry
// at least the quorum weight; serialized again it must parse to the same certificate. An
// accepted vote, serialized again, must be accepted from the same validator.
//
// Run:
//   build-fuzz/fuzz/fuzz-simplex-certificate -max_total_time=300 -max_len=65536 fuzz-work/fuzz-simplex-certificate test/fuzz/corpus/fuzz-simplex-certificate

#include <set>

#include "tl-utils/tl-utils.hpp"
#include "validator/consensus/simplex/certificate.h"
#include "validator/consensus/simplex/votes.h"

#include "fuzz-common.h"
#include "simplex-fixture.h"

namespace {

namespace c = tos::validator::consensus;
namespace sx = tos::validator::consensus::simplex;

const tos::fuzz::SimplexFixture *fixture = nullptr;

void check_certificate(const td::Ref<sx::Certificate<sx::Vote>> &cert, const c::Bus &bus) {
  std::set<std::size_t> signers;
  tos::ValidatorWeight weight = 0;
  for (const auto &item : cert->signatures) {
    auto index = item.validator.value();
    TOS_FUZZ_INVARIANT(index < bus.validator_set.size());
    TOS_FUZZ_INVARIANT(signers.insert(index).second);
    TOS_FUZZ_INVARIANT(tos::checked_add_validator_weight(weight, bus.validator_set[index].weight));
  }
  TOS_FUZZ_INVARIANT(weight >= tos::quorum_threshold(bus.total_weight));

  auto r_wire = tos::fetch_tl_object<sx::tl::certificate>(cert->serialize(), true);
  TOS_FUZZ_INVARIANT(r_wire.is_ok());
  auto r_again = sx::Certificate<sx::Vote>::from_tl(std::move(*r_wire.move_as_ok()), bus);
  TOS_FUZZ_INVARIANT(r_again.is_ok());
  TOS_FUZZ_INVARIANT(r_again.ok()->serialize().as_slice() == cert->serialize().as_slice());
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  static const tos::fuzz::SimplexFixture instance;
  if (!instance.ok) {
    tos::fuzz::invariant_failed("the consensus fixture keys could not be derived");
  }
  fixture = &instance;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  const auto &bus = fixture->bus;
  tos::fuzz::Reader in(data, size);
  auto kind = static_cast<tos::fuzz::SimplexInput>(in.u8() % 3);
  auto source = c::PeerValidatorId{static_cast<std::size_t>(in.u8() % tos::fuzz::SimplexFixture::kValidators)};
  auto message = in.rest();

  switch (kind) {
    case tos::fuzz::SimplexInput::vote: {
      auto r_vote = sx::Signed<sx::Vote>::deserialize(message, source, bus);
      if (r_vote.is_ok()) {
        auto again = sx::Signed<sx::Vote>::deserialize(r_vote.ok().serialize(), source, bus);
        TOS_FUZZ_INVARIANT(again.is_ok());
        TOS_FUZZ_INVARIANT(again.ok().serialize().as_slice() == r_vote.ok().serialize().as_slice());
      }
      break;
    }
    case tos::fuzz::SimplexInput::certificate: {
      auto r_tl = tos::fetch_tl_object<sx::tl::certificate>(message, true);
      if (r_tl.is_error()) {
        break;
      }
      auto r_cert = sx::Certificate<sx::Vote>::from_tl(std::move(*r_tl.move_as_ok()), bus);
      if (r_cert.is_ok()) {
        check_certificate(r_cert.ok(), bus);
      }
      break;
    }
    case tos::fuzz::SimplexInput::candidate: {
      auto r_candidate = c::Candidate::deserialize(message, bus, source);
      if (r_candidate.is_ok()) {
        TOS_FUZZ_INVARIANT(r_candidate.ok()->leader == source);
      }
      break;
    }
  }
  return 0;
}
