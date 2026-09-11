// Test-constructed policy only; not a production business-config codec.
#pragma once
#include "block/workchain-registration-proof.h"
namespace block::test {
inline WorkchainPossessionPolicy possession_policy(const WorkchainConfidentialAccount& a) {
  td::Bits256 configured;
  std::fill(configured.as_slice().begin(), configured.as_slice().end(), 7);
  return {{2, 1, 1, 2, a.global_id, a.address.workchain_id, a.genesis_hash, configured},
          {a.bindings.asset, a.bindings.custody, a.bindings.policy},
          {configured, configured, configured}, configured, 1200};
}
}
