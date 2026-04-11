/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "crypto/common/refcnt.hpp"

namespace tos::validator::consensus {

class Misbehavior : public td::CntObject {
 public:
  virtual ~Misbehavior() = default;
};

using MisbehaviorRef = td::Ref<Misbehavior>;

}  // namespace tos::validator::consensus
