/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/

// =============================================================================
// Slice 1 Stage 4 deterministic BoC / Envelope fuzz smoke.
//
// This fixture gives CI a stable BoC-side fuzz signal without depending on a
// coverage-guided libFuzzer runtime. The corpus is deterministic, small, and
// focused on the Slice 1 envelope shape (`opcode:uint32 query_id:uint64 ...`)
// from `doc/tos-message-policy.md` v6 §3.1. The Tol-side sibling lives in
// `tol-tester/tests/slice-1-envelope-fuzz-smoke.tol` and exercises
// Envelope/OP_ERROR struct round-trips directly.
//
// The existing coverage-guided `test-boc-libfuzzer` target remains useful for
// manual campaigns; this fixture is the required CI smoke because it runs
// through the normal `test-emulator` target and has no fuzzer-driver exit-path
// dependency.
// =============================================================================

#include "crypto/vm/boc.h"
#include "td/utils/Slice.h"
#include "td/utils/tests.h"
#include "vm/cells.h"

#include <cstddef>
#include <string>
#include <utility>

namespace {

constexpr td::uint32 kFuzzEnvelopeBaseOpcode = 0x10040000;

td::uint64 splitmix64(td::uint64& state) {
  state += 0x9e3779b97f4a7c15ULL;
  td::uint64 z = state;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

std::string deterministic_bytes(td::uint64 seed, std::size_t len) {
  std::string out;
  out.reserve(len);
  td::uint64 state = seed;
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(static_cast<char>(splitmix64(state) >> 56));
  }
  return out;
}

td::Ref<vm::Cell> build_envelope_body(td::uint32 opcode, td::uint64 query_id, td::uint32 payload) {
  vm::CellBuilder cb;
  cb.store_long(opcode, 32);
  cb.store_long(static_cast<long long>(query_id), 64);
  cb.store_long(payload, 32);
  return cb.finalize();
}

std::string serialize_cell(td::Ref<vm::Cell> cell) {
  auto serialized = vm::std_boc_serialize(std::move(cell), /*mode=*/0);
  CHECK(serialized.is_ok());
  return serialized.move_as_ok().as_slice().str();
}

std::string mutate_valid_boc(td::Slice valid_boc, td::uint64 seed) {
  std::string mutated = valid_boc.str();
  CHECK(!mutated.empty());

  auto next = seed;
  const auto byte = static_cast<char>(splitmix64(next) >> 56);
  const auto pos = static_cast<std::size_t>(splitmix64(next) % mutated.size());

  switch (seed % 5) {
    case 0:
      mutated[pos] = static_cast<char>(mutated[pos] ^ byte ^ 0x5a);
      break;
    case 1:
      mutated.resize(pos);
      break;
    case 2:
      mutated.insert(mutated.begin() + static_cast<std::ptrdiff_t>(pos), byte);
      break;
    case 3:
      mutated.erase(mutated.begin() + static_cast<std::ptrdiff_t>(pos));
      break;
    default:
      mutated.append(deterministic_bytes(seed ^ 0xa5a5a5a5ULL, 1 + (seed % 7)));
      break;
  }
  return mutated;
}

void deserialize_without_throw(td::Slice bytes) {
  try {
    auto root = vm::std_boc_deserialize(bytes);
    if (root.is_ok()) {
      CHECK(root.move_as_ok().not_null());
    }
  } catch (...) {
    CHECK(false);
  }
}

}  // namespace

TEST(Slice1BocEnvelopeFuzzFixture, DeterministicMalformedBocSmoke) {
  const auto valid = serialize_cell(build_envelope_body(kFuzzEnvelopeBaseOpcode, 0x100000001ULL, 0x42));

  for (td::uint64 seed = 0; seed < 128; ++seed) {
    auto random = deterministic_bytes(seed + 1, static_cast<std::size_t>(seed % 96));
    if (random.size() >= 4 && seed % 4 == 0) {
      random[0] = static_cast<char>(0xb5);
      random[1] = static_cast<char>(0xee);
      random[2] = static_cast<char>(0x9c);
      random[3] = static_cast<char>(0x72);
    }

    deserialize_without_throw(td::Slice(random));
    deserialize_without_throw(td::Slice(mutate_valid_boc(td::Slice(valid), seed)));
  }
}

TEST(Slice1BocEnvelopeFuzzFixture, ValidEnvelopeBocRoundtripPreservesHash) {
  for (td::uint64 seed = 0; seed < 64; ++seed) {
    const auto original =
        build_envelope_body(kFuzzEnvelopeBaseOpcode + static_cast<td::uint32>(seed), 0x100000000ULL + seed * 17,
                            static_cast<td::uint32>(seed * 65537 + 11));
    const auto original_hash = original->get_hash();
    const auto serialized = serialize_cell(original);

    auto parsed = vm::std_boc_deserialize(td::Slice(serialized));
    CHECK(parsed.is_ok());
    CHECK(parsed.ok()->get_hash() == original_hash);
  }
}
