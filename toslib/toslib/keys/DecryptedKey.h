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

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once
#include <string>
#include <vector>

#include "td/utils/SharedSlice.h"
#include "td/utils/tl_helpers.h"
#include "toslib/keys/Mnemonic.h"

namespace toslib {

struct RawDecryptedKey {
  std::vector<td::SecureString> mnemonic_words;
  td::SecureString private_key;

  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(mnemonic_words, storer);
    store(private_key, storer);
  }

  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    parse(mnemonic_words, parser);
    parse(private_key, parser);
  }
};

struct EncryptedKey;
struct DecryptedKey {
  DecryptedKey() = delete;
  explicit DecryptedKey(const Mnemonic &mnemonic);
  DecryptedKey(std::vector<td::SecureString> mnemonic_words, td::Ed25519::PrivateKey key);
  DecryptedKey(RawDecryptedKey key);

  std::vector<td::SecureString> mnemonic_words;
  td::Ed25519::PrivateKey private_key;

  EncryptedKey encrypt(td::Slice local_password, td::Slice secret = {}) const;
};

}  // namespace toslib
