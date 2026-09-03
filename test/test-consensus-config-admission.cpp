/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "tos/tos-types.h"

#include "td/utils/optional.h"

#include <cstdio>

using tos::consensus_group_admissible;
using tos::NewConsensusConfig;

static int failures = 0;

#define EXPECT(cond)                                                          \
  do {                                                                        \
    if (!(cond)) {                                                            \
      std::fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #cond);  \
      ++failures;                                                             \
    }                                                                         \
  } while (0)

int main() {
  // A missing consensus config is never admissible: the node must not run a
  // group (and must not fall back to a different consensus implementation).
  td::optional<NewConsensusConfig> missing;
  EXPECT(!consensus_group_admissible(missing));

  // Every version this build understands is admissible.
  for (td::uint32 v = 0; v <= NewConsensusConfig::MAX_SUPPORTED_PROTOCOL_VERSION; ++v) {
    NewConsensusConfig cfg;
    cfg.protocol_version = v;
    EXPECT(cfg.protocol_version_supported());
    EXPECT(consensus_group_admissible(td::optional<NewConsensusConfig>{cfg}));
  }

  // A version newer than this build supports is present but NOT admissible:
  // this is the load-bearing case -- it must fail closed rather than reach the
  // bridge's version check (which aborts) or run an unknown protocol.
  for (td::uint32 delta = 1; delta <= 4; ++delta) {
    NewConsensusConfig cfg;
    cfg.protocol_version = NewConsensusConfig::MAX_SUPPORTED_PROTOCOL_VERSION + delta;
    EXPECT(!cfg.protocol_version_supported());
    EXPECT(!consensus_group_admissible(td::optional<NewConsensusConfig>{cfg}));
  }

  if (failures != 0) {
    std::fprintf(stderr, "consensus-config-admission: %d checks failed\n", failures);
    return 1;
  }
  return 0;
}
