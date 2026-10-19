/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include "adnl/adnl-node-id.hpp"
#include "keys/keys.hpp"
#include "td/utils/Status.h"

namespace tos::validator::fullnode {

// A full-node slave signs in to its masters with the full node's ADNL key, so
// that a master, which serves configured slave identities only, recognises it.
// There is no anonymous fallback: a slave that cannot sign in with that key
// would be refused by every master, so it refuses to start instead.

// The full-node ADNL id a slave signs in with must be configured.
inline td::Status check_full_node_slave_id(const adnl::AdnlNodeIdShort &full_node_id) {
  if (full_node_id.is_zero()) {
    return td::Status::Error(
        "full-node slave mode needs a full-node ADNL id: a slave signs in to its masters with that id's key, and "
        "masters refuse connections that do not sign in");
  }
  return td::Status::OK();
}

// Accept the key exported from the keyring only if it is the private key of
// the configured full-node ADNL id.
inline td::Result<PrivateKey> full_node_slave_sign_in_key(const adnl::AdnlNodeIdShort &full_node_id,
                                                          td::Result<PrivateKey> exported) {
  TRY_STATUS(check_full_node_slave_id(full_node_id));
  if (exported.is_error()) {
    return exported.move_as_error_prefix(PSLICE() << "cannot load the key of full-node ADNL id "
                                                  << full_node_id.bits256_value().to_hex()
                                                  << " that this slave signs in to its masters with: ");
  }
  auto key = exported.move_as_ok();
  if (key.empty()) {
    return td::Status::Error(PSLICE() << "the keyring returned no key for full-node ADNL id "
                                      << full_node_id.bits256_value().to_hex());
  }
  auto loaded_id = adnl::AdnlNodeIdShort{key.compute_short_id()};
  if (loaded_id != full_node_id) {
    return td::Status::Error(PSLICE() << "the key loaded for full-node ADNL id "
                                      << full_node_id.bits256_value().to_hex() << " belongs to "
                                      << loaded_id.bits256_value().to_hex());
  }
  return std::move(key);
}

}  // namespace tos::validator::fullnode
