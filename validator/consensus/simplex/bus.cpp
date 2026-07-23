/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "bus.h"

namespace tos::validator::consensus::simplex {

namespace {

std::string certificate_to_string(const CertificateRef<Vote> &cert) {
  std::string ids;
  for (const auto &signature : cert->signatures) {
    if (!ids.empty()) {
      ids += ",";
    }
    ids += std::to_string(signature.validator.value());
  }

  return PSTRING() << "Certificate{vote=" << cert->vote << ", signatures=[" << ids << "]}";
}

}  // namespace

std::string BroadcastVote::contents_to_string() const {
  return PSTRING() << "{vote=" << vote << "}";
}

std::string NotarizationObserved::contents_to_string() const {
  return PSTRING() << "{id=" << id << "}";
}

std::string FinalizationObserved::contents_to_string() const {
  return PSTRING() << "{id=" << id << "}";
}

std::string LeaderWindowObserved::contents_to_string() const {
  return PSTRING() << "{start_slot=" << start_slot << ", base=" << base << "}";
}

std::string WaitForParent::contents_to_string() const {
  return PSTRING() << "{id=" << candidate->id << ", parent=" << candidate->parent_id << "}";
}

std::string ResolveCandidate::contents_to_string() const {
  return PSTRING() << "{id=" << id << "}";
}

std::string StoreCandidate::contents_to_string() const {
  return PSTRING() << "{id=" << candidate->id << "}";
}

std::string ResolveState::contents_to_string() const {
  return PSTRING() << "{id=" << id << "}";
}

std::string ResolveState::response_to_string(const ReturnType &result) {
  return PSTRING() << "ResolvedState{state=" << *result.state << ", gen_utime_exact="
                   << (result.gen_utime_exact ? (PSTRING() << *result.gen_utime_exact) : "nullopt") << "}";
}

std::string SaveCertificate::contents_to_string() const {
  return PSTRING() << "{cert=" << certificate_to_string(cert) << "}";
}

std::string QueryValidatorGroupInfo::contents_to_string() const {
  return "{}";
}

}  // namespace tos::validator::consensus::simplex
