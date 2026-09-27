/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The C++ half of the authorisation-preimage lock. The Rust half reads the same file, and
// the contracts are written against it, so a field order that drifts on any one side
// produces signatures the other two cannot verify.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "crypto/pq/pq-elector.h"
#include "td/utils/misc.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

std::vector<std::string> split(const std::string& line, char sep) {
  std::vector<std::string> out;
  std::istringstream row(line);
  for (std::string field; std::getline(row, field, sep);) {
    out.push_back(field);
  }
  return out;
}

}  // namespace

int main() {
  std::map<std::string, std::string> expected;
  std::map<std::string, std::size_t> lengths;
  {
    std::ifstream file(AUTHORISATION_PREIMAGE_VECTORS_FILE);
    assert(file);
    for (std::string line; std::getline(file, line);) {
      if (line.empty() || line[0] == '#') {
        continue;
      }
      auto fields = split(line, '\t');
      assert(fields.size() == 3);
      lengths[fields[0]] = std::stoul(fields[1]);
      expected[fields[0]] = fields[2];
    }
  }

  auto check = [&](const char* name, const std::string& bytes) {
    auto it = expected.find(name);
    assert(it != expected.end() && "the shared file is missing a case this side produces");
    assert(lengths[name] == bytes.size());
    if (td::hex_encode(td::Slice(bytes)) != it->second) {
      std::printf("FAIL %s\n  want %s\n  got  %s\n", name, it->second.c_str(),
                  td::hex_encode(td::Slice(bytes)).c_str());
      assert(false);
    }
    expected.erase(it);
  };

  check("stake",
        tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa1), fill(0xd7), 1, fill(0xb2), fill(0xc3)));
  check("config-vote", tos::pq::config_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, fill(0xe5)));
  check("complaint-vote", tos::pq::complaint_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, 1789434000u, fill(0xf6)));
  check("stake-other-key",
        tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa1), fill(0xd7), 1, fill(0xb3), fill(0xc3)));
  check("stake-other-validator",
        tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa2), fill(0xd7), 1, fill(0xb2), fill(0xc3)));
  check("stake-other-algorithm",
        tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa1), fill(0xd7), 2, fill(0xb2), fill(0xc3)));
  check("stake-other-owner",
        tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa1), fill(0xd8), 1, fill(0xb2), fill(0xc3)));
  check("stake-other-network",
        tos::pq::stake_preimage(-1, 1789434000u, 0x10000u, fill(0xa1), fill(0xd7), 1, fill(0xb2), fill(0xc3)));
  check("config-vote-other-set", tos::pq::config_vote_preimage(-239, fill(0xd5), fill(0xa1), 7, fill(0xe5)));
  check("config-vote-other-index", tos::pq::config_vote_preimage(-239, fill(0xd4), fill(0xa1), 8, fill(0xe5)));
  check("complaint-vote-other-election",
        tos::pq::complaint_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, 1789434001u, fill(0xf6)));

  // A case in the file that nothing here produces would be a layout no implementation is
  // held to, which is the same as not having frozen it.
  assert(expected.empty() && "the shared file carries a case this side does not build");

  // The three domains must not collide, and neither must two requests that differ in one
  // field: a preimage that dropped a field would make these equal.
  const auto a = tos::pq::stake_preimage(-239, 1, 0x10000u, fill(0xa1), fill(0xd7), 1, fill(0xb2), fill(0xc3));
  const auto b = tos::pq::stake_preimage(-239, 1, 0x10000u, fill(0xa1), fill(0xd7), 1, fill(0xb3), fill(0xc3));
  assert(a != b);
  const auto vote = tos::pq::config_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, fill(0xe5));
  const auto complaint = tos::pq::complaint_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, 1, fill(0xe5));
  assert(vote != complaint);
  assert(vote.substr(0, 4) != complaint.substr(0, 4));

  std::printf("AUTHORISATION_PREIMAGE_VECTORS_OK stake=%zu config-vote=%zu complaint-vote=%zu bytes\n", a.size(),
              vote.size(), complaint.size());
  return 0;
}
