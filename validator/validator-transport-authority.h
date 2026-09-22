/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <map>
#include <set>
#include <vector>

#include "adnl/adnl-node-id.hpp"
#include "block/validator-session-members.h"

namespace tos::validator {

using ValidatorAdnlRefCounts = std::map<adnl::AdnlNodeIdShort, std::size_t>;

struct FastSyncValidatorTransportAuthority {
  std::vector<PublicKeyHash> roots;
  std::vector<adnl::AdnlNodeIdShort> validator_adnl_ids;
};

// Overlay membership is an Ed25519 transport authority. A post-quantum
// consensus key, stable validator identity, and historical permanent key are
// deliberately outside this namespace.
inline PublicKeyHash validator_transport_root(const ValidatorDescr &descr) {
  return PublicKeyHash{block::validator_adnl_identity(descr)};
}

inline bool add_validator_adnl_reference(ValidatorAdnlRefCounts &ids, adnl::AdnlNodeIdShort id) {
  return ++ids[id] == 1;
}

inline bool del_validator_adnl_reference(ValidatorAdnlRefCounts &ids, adnl::AdnlNodeIdShort id) {
  auto it = ids.find(id);
  if (it == ids.end()) {
    return false;
  }
  if (--it->second == 0) {
    ids.erase(it);
    return true;
  }
  return false;
}

inline std::vector<PublicKeyHash> canonical_validator_transport_roots(std::vector<PublicKeyHash> roots) {
  std::sort(roots.begin(), roots.end());
  roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
  return roots;
}

// Fast-sync overlays authorize certificates and direct validator membership from
// the same descriptor field. Keeping this extraction in one production helper is
// what makes a wrong namespace (validator_id, consensus key, or permanent key)
// observable as a behavioral failure rather than two internally consistent lists.
inline FastSyncValidatorTransportAuthority fast_sync_validator_transport_authority(
    const std::vector<ValidatorDescr> &validators) {
  FastSyncValidatorTransportAuthority result;
  result.roots.reserve(validators.size());
  result.validator_adnl_ids.reserve(validators.size());
  for (const auto &validator : validators) {
    auto root = validator_transport_root(validator);
    result.roots.push_back(root);
    result.validator_adnl_ids.emplace_back(root);
  }
  result.roots = canonical_validator_transport_roots(std::move(result.roots));
  std::sort(result.validator_adnl_ids.begin(), result.validator_adnl_ids.end());
  result.validator_adnl_ids.erase(std::unique(result.validator_adnl_ids.begin(), result.validator_adnl_ids.end()),
                                  result.validator_adnl_ids.end());
  return result;
}

inline PublicKeyHash select_validator_transport_signer(const std::vector<PublicKeyHash> &roots,
                                                       const ValidatorAdnlRefCounts &local_ids) {
  for (const auto &root : roots) {
    if (local_ids.contains(adnl::AdnlNodeIdShort{root})) {
      return root;
    }
  }
  // An observer without one of the authorized ADNL private keys remains an
  // operational full node, but cannot issue a membership certificate.
  return PublicKeyHash::zero();
}

inline std::set<adnl::AdnlNodeIdShort> validator_adnl_id_set(const ValidatorAdnlRefCounts &ids) {
  std::set<adnl::AdnlNodeIdShort> result;
  for (const auto &[id, _] : ids) {
    result.insert(id);
  }
  return result;
}

}  // namespace tos::validator
