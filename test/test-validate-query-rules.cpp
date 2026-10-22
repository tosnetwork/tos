/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// State-free block rules enforced by ValidateQuery.

#include "td/utils/tests.h"
#include "validator/impl/validate-query.hpp"

namespace {

namespace rules = tos::validator::validate_rules;

constexpr tos::LogicalTime kBlockStartLt = 7000000;

TEST(ValidateQueryRules, NewAndDeferredMessagesEnqueueAtEmittedLt) {
  for (int tag : {rules::out_msg_tag_new, rules::out_msg_tag_deferred_tr}) {
    // The collator enqueues these at their emitted_lt.
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt + 5, kBlockStartLt + 5, kBlockStartLt).is_ok());
    // A later enqueued_lt would move the message behind messages emitted after it.
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt + 5, kBlockStartLt + 6, kBlockStartLt).is_error());
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt + 5, kBlockStartLt + 900, kBlockStartLt).is_error());
    // An earlier enqueued_lt is refused as before.
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt + 5, kBlockStartLt + 4, kBlockStartLt).is_error());
  }
}

TEST(ValidateQueryRules, TransitMessagesEnqueueAtBlockStartLt) {
  for (int tag : {rules::out_msg_tag_tr, rules::out_msg_tag_tr_req}) {
    // Transit messages were emitted in an earlier block and enter this queue at its start_lt.
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt - 3000, kBlockStartLt, kBlockStartLt).is_ok());
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt - 3000, kBlockStartLt + 1, kBlockStartLt).is_error());
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt - 3000, kBlockStartLt + 500, kBlockStartLt).is_error());
    // emitted_lt above enqueued_lt stays an error even when enqueued_lt equals start_lt.
    ASSERT_TRUE(rules::check_enqueued_lt(tag, kBlockStartLt + 1, kBlockStartLt, kBlockStartLt).is_error());
  }
}

}  // namespace
