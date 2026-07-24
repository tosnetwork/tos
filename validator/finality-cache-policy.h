/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

namespace tos::validator {

// A final signature set may replace an approve set. Equal-strength duplicates
// and final-to-approve downgrades keep the already validated cached value.
constexpr bool should_replace_pending_finality(bool has_cached, bool cached_is_final, bool incoming_is_final) {
  return !has_cached || (!cached_is_final && incoming_is_final);
}

}  // namespace tos::validator
