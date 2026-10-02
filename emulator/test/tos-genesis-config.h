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

// Fee-profile fixtures measure contracts on the C++ TVM under the shared
// emulator config, raised to the TOS genesis global version.

#pragma once

#include <memory>
#include <string>

#include "block/mc-config.h"
#include "crypto/vm/boc.h"
#include "emulator/emulator-extern.h"
#include "td/utils/base64.h"
#include "td/utils/tests.h"

// Base64 config dictionary defined in emulator-tests.cpp in this binary.
extern const char *config_boc;

namespace fee_fixture {

// TOS genesis runs global version 14 (crypto/smartcont/gen-zerostate.fif);
// the fee instructions the wallet uses need at least 6.
constexpr td::uint32 kTosGlobalVersion = 14;

// The shared fixture config, with ConfigParam 8 raised to the TOS genesis
// version. Price tables, capabilities and every other parameter are kept.
inline std::string tos_versioned_config_boc() {
  auto decoded = td::base64_decode(td::Slice(config_boc));
  CHECK(decoded.is_ok());
  auto root = vm::std_boc_deserialize(decoded.move_as_ok());
  CHECK(root.is_ok());
  vm::Dictionary params{root.move_as_ok(), 32};
  td::BitArray<32> key;
  key.store_ulong(8);
  auto current = params.lookup_ref(key);
  CHECK(current.not_null());
  auto cs = vm::load_cell_slice(current);
  CHECK(cs.fetch_ulong(8) == 0xc4);
  cs.skip_first(32);
  const auto capabilities = cs.fetch_ulong(64);
  vm::CellBuilder cb;
  cb.store_long(0xc4, 8).store_long(kTosGlobalVersion, 32).store_long(static_cast<long long>(capabilities), 64);
  CHECK(params.set_ref(key, cb.finalize()));
  auto boc = vm::std_boc_serialize(params.get_root_cell());
  CHECK(boc.is_ok());
  return td::base64_encode(boc.move_as_ok());
}

inline std::shared_ptr<const block::Config> config() {
  static std::shared_ptr<const block::Config> cfg = [] {
    const auto boc = tos_versioned_config_boc();
    auto raw = static_cast<block::Config *>(emulator_config_create(boc.c_str()));
    CHECK(raw != nullptr);
    CHECK(raw->get_global_version() == static_cast<int>(kTosGlobalVersion));
    return std::shared_ptr<const block::Config>(raw);
  }();
  return cfg;
}

}  // namespace fee_fixture
