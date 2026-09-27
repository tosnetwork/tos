/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The C++ half of the controller-authorisation lock. The Rust half reads the same file
// and the controller contract is written against it, so a field order that drifts on any
// one side produces authorisations the other two cannot verify.
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

#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-controller.h"
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
    std::ifstream file(CONTROLLER_AUTH_VECTORS_FILE);
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

  auto take = [&](const char* name) {
    auto it = expected.find(name);
    assert(it != expected.end() && "the shared file is missing a case this side needs");
    auto hex = it->second;
    auto length = lengths[name];
    expected.erase(it);
    auto bytes = td::hex_decode(td::Slice(hex));
    assert(bytes.is_ok());
    assert(bytes.ok().size() == length);
    return bytes.move_as_ok();
  };

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

  const auto base = tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434000u, 1, fill(0xb2));
  assert(base.size() == 93 && "the frozen controller authorisation is 93 bytes");
  check("controller-auth", base);
  check("controller-auth-other-network",
        tos::pq::controller_auth_preimage(-1, fill(0xa1), 7, 3, 1789434000u, 1, fill(0xb2)));
  check("controller-auth-other-controller",
        tos::pq::controller_auth_preimage(-239, fill(0xa2), 7, 3, 1789434000u, 1, fill(0xb2)));
  check("controller-auth-other-epoch",
        tos::pq::controller_auth_preimage(-239, fill(0xa1), 8, 3, 1789434000u, 1, fill(0xb2)));
  check("controller-auth-other-nonce",
        tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 4, 1789434000u, 1, fill(0xb2)));
  check("controller-auth-other-expiry",
        tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434001u, 1, fill(0xb2)));
  check("controller-auth-other-kind",
        tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434000u, 2, fill(0xb2)));
  check("controller-auth-other-payload",
        tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434000u, 1, fill(0xb3)));

  const std::string context(tos::pq::controller_auth_context);
  check("context", context);

  // One real signature, so a consumer is held to verifying rather than only to rebuilding.
  const auto public_key = take("root-public-key");
  const auto signature = take("root-signature");
  assert(public_key.size() == 1312);
  assert(signature.size() == tos::pq::mldsa44_signature_bytes);
  assert(tos::pq::verify_mldsa44(base, context, signature, public_key) == tos::pq::VerifyResult::valid &&
         "the pinned signature does not verify over the pinned preimage and context");

  // The same signature under a neighbouring authority's context must not verify: the
  // domain is what stops one authority's signature being replayed as another's.
  assert(tos::pq::verify_mldsa44(base, "TOS-VALIDATOR-ELECTION-v1", signature, public_key) !=
             tos::pq::VerifyResult::valid &&
         "a controller authorisation verifies under the election context");
  // And neither must it verify over a preimage that differs in one field.
  assert(tos::pq::verify_mldsa44(tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 4, 1789434000u, 1, fill(0xb2)),
                                 context, signature, public_key) != tos::pq::VerifyResult::valid &&
         "a controller authorisation verifies with the nonce changed");

  // A case in the file that nothing here builds would be a layout no implementation is
  // held to, which is the same as not having frozen it.
  assert(expected.empty() && "the shared file carries a case this side does not build");

  // This authority's tags must not collide with any already frozen, and they are one byte
  // apart from the complaint tags, which is exactly the kind of thing eyes miss.
  const std::uint32_t frozen[] = {tos::pq::elector_pq_stake_op,     tos::pq::elector_pq_stake_sign_tag,
                                  tos::pq::config_pq_vote_op,       tos::pq::config_pq_vote_sign_tag,
                                  tos::pq::elector_pq_complaint_op, tos::pq::elector_pq_complaint_sign_tag};
  for (auto tag : frozen) {
    assert(tag != tos::pq::controller_auth_op);
    assert(tag != tos::pq::controller_auth_sign_tag);
  }
  assert(tos::pq::controller_auth_op != tos::pq::controller_auth_sign_tag);

  std::printf("CONTROLLER_AUTH_VECTORS_OK preimage=%zu bytes context=%zu bytes\n", base.size(), context.size());
  return 0;
}
