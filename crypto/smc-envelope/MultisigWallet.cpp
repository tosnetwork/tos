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

    Copyright 2019-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "td/utils/misc.h"
#include "vm/dict.h"

#include "MultisigWallet.h"
#include "SmartContractCode.h"

// Codex audit (round 13, finding #4): the public methods of MultisigWallet
// (processed, get_query_state, get_public_keys, check_query_signatures,
// get_n_k, get_unsigned_messaged) return plain values and ignore
// `Answer.success`, then unchecked `pop_smallint_range / pop_int /
// pop_cell / fetch_*` calls can throw VmError on a malformed get-method
// result or malformed account state. Hardening these to return
// `td::Result<...>` is a public API change — every caller (toslib,
// validator-engine wallet helpers, etc.) needs to thread Result through.
// Out of scope for this audit pass; the SDK helper crash is bounded to
// the embedding caller (validator daemon does not call these), and a
// proper Result<T> migration is tracked as a follow-up. Inline TODO
// comments marker for future review.

namespace tos {

MultisigWallet::QueryBuilder::QueryBuilder(td::uint32 wallet_id, td::int64 query_id, td::Ref<vm::Cell> msg, int mode) {
  msg_ = vm::CellBuilder()
             .store_long(wallet_id, 32)
             .store_long(query_id, 64)
             .store_long(mode, 8)
             .store_ref(std::move(msg))
             .finalize();
}
void MultisigWallet::QueryBuilder::sign(td::int32 id, td::Ed25519::PrivateKey& pk) {
  CHECK(id < td::narrow_cast<td::int32>(mask_.size()));
  auto signature = pk.sign(msg_->get_hash().as_slice()).move_as_ok();
  mask_.set(id);
  vm::CellBuilder cb;
  cb.store_bytes(signature.as_slice());
  cb.store_long(id, 8);
  cb.ensure_throw(cb.store_maybe_ref(std::move(dict_)));
  dict_ = cb.finalize();
}

td::Ref<vm::Cell> MultisigWallet::QueryBuilder::create_inner() const {
  vm::CellBuilder cb;
  cb.ensure_throw(cb.store_maybe_ref(dict_));
  return cb.append_cellslice(vm::load_cell_slice(msg_)).finalize();
}

td::Ref<vm::Cell> MultisigWallet::QueryBuilder::create(td::int32 id, td::Ed25519::PrivateKey& pk) const {
  auto cell = create_inner();
  vm::CellBuilder cb;
  cb.store_long(id, 8);
  cb.append_cellslice(vm::load_cell_slice(cell));
  cell = cb.finalize();

  auto signature = pk.sign(cell->get_hash().as_slice()).move_as_ok();
  vm::CellBuilder cb2;
  cb2.store_bytes(signature.as_slice());
  cb2.append_cellslice(vm::load_cell_slice(cell));
  return cb2.finalize();
}

td::Ref<MultisigWallet> MultisigWallet::create(td::Ref<vm::Cell> data) {
  return td::Ref<MultisigWallet>(
      true, State{tos::SmartContractCode::get_code(tos::SmartContractCode::Multisig), std::move(data)});
}

int MultisigWallet::processed(td::uint64 query_id) const try {
  // Codex SDK-FFI audit (S2.2): defensive layer. The full Result<T>
  // migration (R13.4) is still deferred — public signature remains plain
  // value — but stack pops can throw on a malformed get-method result
  // from a hostile contract / lite-server. Catch at the boundary and
  // return -1 ("unknown") rather than aborting the embedding host.
  auto res = run_get_method("processed?", {td::make_refint(query_id)});
  if (!res.success) return -1;
  return res.stack.write().pop_smallint_range(1, -1);
} catch (...) {
  return -1;
}

MultisigWallet::QueryState MultisigWallet::get_query_state(td::uint64 query_id) const try {
  // Codex SDK-FFI audit (S2.2): defensive layer; on any failure return a
  // QueryState::Unknown sentinel rather than aborting the host.
  auto ans = run_get_method("get_query_state", {td::make_refint(query_id)});
  QueryState res;
  if (!ans.success) {
    res.state = QueryState::Unknown;
    return res;
  }

  auto mask = ans.stack.write().pop_int();
  auto state = ans.stack.write().pop_smallint_range(1, -1);

  if (state == 1) {
    res.state = QueryState::Unknown;
  } else if (state == 0) {
    res.state = QueryState::NotReady;
    for (size_t i = 0; i < res.mask.size(); i++) {
      if (mask->get_bit(static_cast<int>(i))) {
        res.mask.set(i);
      }
    }
  } else {
    res.state = QueryState::Sent;
  }
  return res;
} catch (...) {
  QueryState res;
  res.state = QueryState::Unknown;
  return res;
}

std::vector<td::SecureString> MultisigWallet::get_public_keys() const try {
  // Codex SDK-FFI audit (S2.2): defensive layer; empty vector on failure.
  auto ans = run_get_method("get_public_keys");
  if (!ans.success) return {};
  auto dict_root = ans.stack.write().pop_cell();
  vm::Dictionary dict(std::move(dict_root), 8);
  std::vector<td::SecureString> res;
  dict.check_for_each([&](auto cs, auto x, auto y) {
    td::SecureString key(32);
    cs->prefetch_bytes(key.as_mutable_slice().ubegin(), td::narrow_cast<int>(key.size()));
    res.push_back(std::move(key));
    return true;
  });
  return res;
} catch (...) {
  return {};
}

td::Ref<vm::Cell> MultisigWallet::create_init_data(td::uint32 wallet_id, std::vector<td::SecureString> public_keys,
                                                   int k) const try {
  // Codex SDK-FFI audit (S2.2): defensive layer. Replace the previous
  // CHECK(res.code == 0) abort with a null-cell return on get-method
  // failure or pop exception.
  vm::Dictionary pk(8);
  for (size_t i = 0; i < public_keys.size(); i++) {
    auto key = pk.integer_key(td::make_refint(i), 8, false);
    pk.set_builder(key.bits(), 8, vm::CellBuilder().store_bytes(public_keys[i].as_slice()).store_long(0, 8));
  }
  auto res = run_get_method("create_init_state", {td::make_refint(wallet_id), td::make_refint(public_keys.size()),
                                                  td::make_refint(k), pk.get_root_cell()});
  if (!res.success || res.code != 0) {
    return {};
  }
  return res.stack.write().pop_cell();
} catch (...) {
  return {};
}

td::Ref<vm::Cell> MultisigWallet::create_init_data_fast(td::uint32 wallet_id, std::vector<td::SecureString> public_keys,
                                                        int k) {
  vm::Dictionary pk(8);
  for (size_t i = 0; i < public_keys.size(); i++) {
    auto key = pk.integer_key(td::make_refint(i), 8, false);
    pk.set_builder(key.bits(), 8, vm::CellBuilder().store_bytes(public_keys[i].as_slice()).store_long(0, 8));
  }

  vm::CellBuilder cb;
  cb.store_long(wallet_id, 32);
  cb.store_long(public_keys.size(), 8).store_long(k, 8).store_long(0, 64);
  cb.ensure_throw(cb.store_maybe_ref(pk.get_root_cell()));
  cb.ensure_throw(cb.store_maybe_ref({}));
  return cb.finalize();
}

td::Ref<vm::Cell> MultisigWallet::merge_queries(td::Ref<vm::Cell> a, td::Ref<vm::Cell> b) const try {
  // Codex SDK-FFI audit (S3.2): defensive layer (S2.2 pattern). Hostile
  // contract / lite-server result no longer aborts the embedding host.
  auto res = run_get_method("merge_queries", {a, b});
  if (!res.success) return {};
  return res.stack.write().pop_cell();
} catch (...) {
  return {};
}

MultisigWallet::Mask MultisigWallet::to_mask(td::RefInt256 mask) const {
  Mask res_mask;
  for (size_t i = 0; i < res_mask.size(); i++) {
    if (mask->get_bit(static_cast<int>(i))) {
      res_mask.set(i);
    }
  }
  return res_mask;
}

std::pair<int, MultisigWallet::Mask> MultisigWallet::check_query_signatures(td::Ref<vm::Cell> a) const try {
  // Codex SDK-FFI audit (S3.2): defensive layer; (-1, empty mask) on failure.
  auto ans = run_get_method("check_query_signatures", {a});
  if (!ans.success) return std::make_pair(-1, Mask{});

  auto mask = ans.stack.write().pop_int();
  auto cnt = ans.stack.write().pop_smallint_range(128);
  return std::make_pair(cnt, to_mask(mask));
} catch (...) {
  return std::make_pair(-1, Mask{});
}

std::pair<int, int> MultisigWallet::get_n_k() const try {
  // Codex SDK-FFI audit (S3.2): defensive layer; (0, 0) on failure.
  auto ans = run_get_method("get_n_k");
  if (!ans.success) return std::make_pair(0, 0);
  auto k = ans.stack.write().pop_smallint_range(128);
  auto n = ans.stack.write().pop_smallint_range(128);
  return std::make_pair(n, k);
} catch (...) {
  return std::make_pair(0, 0);
}

std::vector<MultisigWallet::Message> MultisigWallet::get_unsigned_messaged(int id) const try {
  // Codex SDK-FFI audit (S3.2): defensive layer; empty vector on any
  // get-method failure or stack/dict exception.
  SmartContract::Answer ans;
  if (id == -1) {
    ans = run_get_method("get_messages_unsigned");
  } else {
    ans = run_get_method("get_messages_unsigned_by_id", {td::make_refint(id)});
  }
  if (!ans.success) return {};
  auto n_k = get_n_k();

  auto cell = ans.stack.write().pop_maybe_cell();
  vm::Dictionary dict(std::move(cell), 64);
  std::vector<Message> res;
  dict.check_for_each([&](auto cs, auto ptr, auto ptr_bits) {
    cs.write().skip_first(8 + 8);
    Message message;
    td::BigInt256 query_id;
    query_id.import_bits(ptr, ptr_bits, false);
    message.query_id = static_cast<td::uint64>(query_id.to_long());
    message.signed_by = to_mask(cs.write().fetch_int256(n_k.first, false));
    message.message = cs.write().fetch_ref();
    res.push_back(std::move(message));
    return true;
  });
  return res;
} catch (...) {
  return {};
}
}  // namespace tos
