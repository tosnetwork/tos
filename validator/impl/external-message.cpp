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

#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "crypto/smc-envelope/SmartContractCode.h"
#include "crypto/openssl/rand.hpp"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "vm/boc.h"

#include "collator-impl.h"
#include "external-message.hpp"

namespace tos {

namespace validator {
using td::Ref;

td::Result<std::unique_ptr<ExtMessageQ::ExecutionConfig>> ExtMessageQ::ExecutionConfig::create(
    const block::ConfigInfo& config, tos::WorkchainId wc, UnixTime utime, bool with_vm_log) {
  auto exec_config = std::make_unique<ExecutionConfig>();
  auto fetch_res = block::FetchConfigParams::fetch_config_params(
      config, &exec_config->old_mparams, &exec_config->storage_prices, &exec_config->storage_phase_cfg,
      &exec_config->rand_seed, &exec_config->compute_phase_cfg, &exec_config->action_phase_cfg,
      &exec_config->serialize_config, &exec_config->masterchain_create_fee, &exec_config->basechain_create_fee, wc,
      utime);
  if (fetch_res.is_error()) {
    auto error = fetch_res.move_as_error();
    LOG(DEBUG) << "Cannot fetch config params: " << error.message();
    return error.move_as_error_prefix("External message was not accepted: cannot fetch config params: ");
  }
  exec_config->compute_phase_cfg.libraries = std::make_unique<vm::Dictionary>(config.get_libraries_root(), 256);
  exec_config->compute_phase_cfg.with_vm_log = with_vm_log;
  exec_config->compute_phase_cfg.stop_on_accept_message = true;
  return std::move(exec_config);
}

td::Status ExtMessageQ::run_message_on_account(tos::WorkchainId wc, block::Account* acc, UnixTime utime, LogicalTime lt,
                                               td::Ref<vm::Cell> msg_root, const block::ConfigInfo& config) {
  TRY_RESULT(exec_config, ExecutionConfig::create(config, wc, utime, /* with_vm_log = */ true));
  return run_message_on_account(wc, acc, utime, lt, std::move(msg_root), *exec_config);
}

td::Status ExtMessageQ::run_message_on_account(tos::WorkchainId wc, block::Account* acc, UnixTime utime, LogicalTime lt,
                                               td::Ref<vm::Cell> msg_root, ExecutionConfig& exec_config) {
  auto res = Collator::impl_create_ordinary_transaction(msg_root, acc, utime, lt, &exec_config.storage_phase_cfg,
                                                        &exec_config.compute_phase_cfg, &exec_config.action_phase_cfg,
                                                        &exec_config.serialize_config, true, lt);
  if (res.is_error()) {
    auto error = res.move_as_error();
    LOG(DEBUG) << "Cannot run message on account: " << error.message();
    return error.move_as_error_prefix("External message was not accepted: cannot run message on account: ");
  }
  std::unique_ptr<block::transaction::Transaction> trans = res.move_as_ok();

  auto trans_root = trans->commit(*acc);
  if (trans_root.is_null()) {
    LOG(DEBUG) << "Cannot commit new transaction for smart contract";
    return td::Status::Error("External message was not accepted: cannot commit new transaction for smart contract");
  }
  return td::Status::OK();
}

namespace {
class WalletMessageProcessorImpl : public WalletMessageProcessor {
  td::Result<std::pair<td::uint32, UnixTime>> parse_message(td::Ref<vm::Cell> msg_root) const override {
    if (msg_root.is_null()) {
      return td::Status::Error("msg is null");
    }
    vm::CellSlice cs{vm::NoVmOrd{}, msg_root};
    block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
    block::gen::EitherStateInit::Record init;
    if (!tlb::unpack(cs, info) || !tlb::unpack(cs, init) || cs.size() < 1) {
      return td::Status::Error("cannot unpack external message");
    }
    vm::CellSlice body;
    if (cs.fetch_ulong(1) == 0) {
      body = cs;
    } else {
      td::Ref<vm::Cell> ref = cs.prefetch_ref();
      if (ref.is_null()) {
        return td::Status::Error("cannot unpack external message");
      }
      body = vm::CellSlice{vm::NoVmOrd{}, std::move(ref)};
    }
    return parse_message_body(std::move(body));
  }

  virtual td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const = 0;

  td::Result<td::uint32> get_wallet_seqno(td::Ref<vm::Cell> data_root) const override {
    if (data_root.is_null()) {
      return td::Status::Error("data is null");
    }
    vm::CellSlice cs{vm::NoVmOrd{}, data_root};
    if (cs.size() < 32) {
      return td::Status::Error("invalid data");
    }
    return (td::uint32)cs.prefetch_ulong(32);
  }

  td::Result<td::Ref<vm::Cell>> set_wallet_seqno(td::Ref<vm::Cell> data_root, td::uint32 new_seqno) const override {
    if (data_root.is_null()) {
      return td::Status::Error("data is null");
    }
    vm::CellSlice cs{vm::NoVmOrd{}, data_root};
    if (cs.size() < 32) {
      return td::Status::Error("invalid data");
    }
    cs.skip_first(32);
    vm::CellBuilder cb;
    cb.store_long(new_seqno, 32);
    cb.append_cellslice(cs);
    return cb.finalize_novm();
  }
};

class WalletV1 : public WalletMessageProcessorImpl {
 public:
  std::string name() const override {
    return "wallet-v1";
  }

  td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const override {
    // signature, msg_seqno
    if (body.size() < 512 + 32) {
      return td::Status::Error("invalid message body");
    }
    body.skip_first(512);
    auto msg_seqno = (td::uint32)body.fetch_ulong(32);
    return std::make_pair(msg_seqno, std::numeric_limits<UnixTime>::max());
  }
};

class WalletV2 : public WalletMessageProcessorImpl {
 public:
  std::string name() const override {
    return "wallet-v2";
  }

  td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const override {
    // signature, msg_seqno, valid_until
    if (body.size() < 512 + 32 + 32) {
      return td::Status::Error("invalid message body");
    }
    body.skip_first(512);
    auto msg_seqno = (td::uint32)body.fetch_ulong(32);
    auto valid_until = (UnixTime)body.fetch_ulong(32);
    return std::make_pair(msg_seqno, valid_until);
  }
};

class WalletV3 : public WalletMessageProcessorImpl {
 public:
  std::string name() const override {
    return "wallet-v3";
  }

  td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const override {
    // signature, subwallet_id, valid_until, msg_seqno
    if (body.size() < 512 + 32 + 32 + 32) {
      return td::Status::Error("invalid message body");
    }
    body.skip_first(512 + 32);
    auto valid_until = (UnixTime)body.fetch_ulong(32);
    auto msg_seqno = (td::uint32)body.fetch_ulong(32);
    return std::make_pair(msg_seqno, valid_until);
  }
};

class WalletV4 : public WalletMessageProcessorImpl {
 public:
  std::string name() const override {
    return "wallet-v4";
  }

  td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const override {
    // signature, subwallet_id, valid_until, msg_seqno
    if (body.size() < 512 + 32 + 32 + 32) {
      return td::Status::Error("invalid message body");
    }
    body.skip_first(512 + 32);
    auto valid_until = (UnixTime)body.fetch_ulong(32);
    auto msg_seqno = (td::uint32)body.fetch_ulong(32);
    return std::make_pair(msg_seqno, valid_until);
  }
};

class WalletV5 : public WalletMessageProcessorImpl {
 public:
  std::string name() const override {
    return "wallet-v5";
  }

  td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const override {
    // tag, subwallet_id, valid_until, msg_seqno
    if (body.size() < 32 + 32 + 32 + 32) {
      return td::Status::Error("invalid message body");
    }
    body.skip_first(32 + 32);
    auto valid_until = (UnixTime)body.fetch_ulong(32);
    auto msg_seqno = (td::uint32)body.fetch_ulong(32);
    return std::make_pair(msg_seqno, valid_until);
  }

  td::Result<td::uint32> get_wallet_seqno(td::Ref<vm::Cell> data_root) const override {
    if (data_root.is_null()) {
      return td::Status::Error("data is null");
    }
    vm::CellSlice cs{vm::NoVmOrd{}, data_root};
    if (cs.size() < 33) {
      return td::Status::Error("invalid data");
    }
    cs.skip_first(1);
    return (td::uint32)cs.prefetch_ulong(32);
  }

  td::Result<td::Ref<vm::Cell>> set_wallet_seqno(td::Ref<vm::Cell> data_root, td::uint32 new_seqno) const override {
    if (data_root.is_null()) {
      return td::Status::Error("data is null");
    }
    vm::CellSlice cs{vm::NoVmOrd{}, data_root};
    if (cs.size() < 33) {
      return td::Status::Error("invalid data");
    }
    bool flag = cs.fetch_long(1);
    cs.skip_first(32);
    vm::CellBuilder cb;
    cb.store_long(flag, 1);
    cb.store_long(new_seqno, 32);
    cb.append_cellslice(cs);
    return cb.finalize_novm();
  }
};

// The wallets shipped with this chain prefix every signed body with the
// network's global_id (int32), so their valid_until/seqno sit 32 bits later
// than in the layouts above.

class NetworkBoundWalletV3 : public WalletV3 {
 public:
  std::string name() const override {
    return "wallet-v3-network-bound";
  }

  td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const override {
    // signature, global_id, subwallet_id, valid_until, msg_seqno
    if (body.size() < 512 + 32 + 32 + 32 + 32) {
      return td::Status::Error("invalid message body");
    }
    body.skip_first(512 + 32 + 32);
    auto valid_until = (UnixTime)body.fetch_ulong(32);
    auto msg_seqno = (td::uint32)body.fetch_ulong(32);
    return std::make_pair(msg_seqno, valid_until);
  }
};

class NetworkBoundWalletV4 : public NetworkBoundWalletV3 {
 public:
  std::string name() const override {
    return "wallet-v4-network-bound";
  }
};

class NetworkBoundWalletV5 : public WalletV5 {
 public:
  std::string name() const override {
    return "wallet-v5-network-bound";
  }

  td::Result<std::pair<td::uint32, UnixTime>> parse_message_body(vm::CellSlice body) const override {
    // tag, global_id, wallet_id, valid_until, msg_seqno
    if (body.size() < 32 + 32 + 32 + 32 + 32) {
      return td::Status::Error("invalid message body");
    }
    body.skip_first(32 + 32 + 32);
    auto valid_until = (UnixTime)body.fetch_ulong(32);
    auto msg_seqno = (td::uint32)body.fetch_ulong(32);
    return std::make_pair(msg_seqno, valid_until);
  }
};

}  // namespace

const WalletMessageProcessor* WalletMessageProcessor::get(td::Bits256 code_hash) {
  static auto wallets = []() -> std::map<td::Bits256, std::shared_ptr<WalletMessageProcessor>> {
    std::map<td::Bits256, std::shared_ptr<WalletMessageProcessor>> wallets;
    auto register_code = [&](td::Bits256 code_hash, std::shared_ptr<WalletMessageProcessor> wallet) {
      wallets[code_hash] = wallet;
      // Make library cell
      vm::CellBuilder cb;
      cb.store_long((int)vm::Cell::SpecialType::Library, 8);
      cb.store_bytes(code_hash.as_slice());
      td::Bits256 library_code_hash = cb.finalize_novm(true)->get_hash().bits();
      wallets[library_code_hash] = wallet;
    };
    // Foreign wallet code this chain did not build: the hash is the only
    // description we have of it, so it stays a literal.
    auto add_wallet = [&](td::Slice s, std::shared_ptr<WalletMessageProcessor> wallet) {
      td::Bits256 code_hash;
      CHECK(code_hash.from_hex(s) == 256);
      register_code(code_hash, wallet);
    };
    // Wallet code this build compiles from crypto/smartcont. Deriving the key
    // from that code instead of repeating its hash here means a contract
    // change cannot leave the table pointing at bytecode that no longer
    // exists: there is no second copy of the value to forget to update.
    auto add_compiled_wallet = [&](SmartContractCode::Type type,
                                   std::shared_ptr<WalletMessageProcessor> wallet) {
      auto code = SmartContractCode::get_code(type);
      CHECK(code.not_null());
      register_code(code->get_hash().bits(), wallet);
    };

    add_wallet("A0CFC2C48AEE16A271F2CFC0B7382D81756CECB1017D077FAAAB3BB602F6868C", std::make_shared<WalletV1>());
    add_wallet("D4902FCC9FAD74698FA8E353220A68DA0DCF72E32BCB2EB9EE04217C17D3062C", std::make_shared<WalletV1>());
    add_wallet("587CC789EFF1C84F46EC3797E45FC809A14FF5AE24F1E0C7A6A99CC9DC9061FF", std::make_shared<WalletV1>());

    add_wallet("5C9A5E68C108E18721A07C42F9956BFB39AD77EC6D624B60C576EC88EEE65329", std::make_shared<WalletV2>());
    add_wallet("FE9530D3243853083EF2EF0B4C2908C0ABF6FA1C31EA243AACAA5BF8C7D753F1", std::make_shared<WalletV2>());

    add_wallet("B61041A58A7980B946E8FB9E198E3C904D24799FFA36574EA4251C41A566F581", std::make_shared<WalletV3>());
    add_wallet("84DAFA449F98A6987789BA232358072BC0F76DC4524002A5D0918B9A75D2D599", std::make_shared<WalletV3>());

    add_wallet("64DD54805522C5BE8A9DB59CEA0105CCF0D08786CA79BEB8CB79E880A8D7322D", std::make_shared<WalletV4>());
    add_wallet("FEB5FF6820E2FF0D9483E7E0D62C817D846789FB4AE580C878866D959DABD5C0", std::make_shared<WalletV4>());

    add_wallet("20834B7B72B112147E1B2FB457B84E74D1A30F04F737D4F62A668E9552D2B72F", std::make_shared<WalletV5>());

    // Wallets compiled from this repository's sources: their signed bodies
    // carry the network's global_id before subwallet_id/valid_until/seqno.
    add_compiled_wallet(SmartContractCode::WalletV3, std::make_shared<NetworkBoundWalletV3>());
    add_compiled_wallet(SmartContractCode::WalletV4, std::make_shared<NetworkBoundWalletV4>());
    add_compiled_wallet(SmartContractCode::WalletV5, std::make_shared<NetworkBoundWalletV5>());

    return wallets;
  }();
  auto it = wallets.find(code_hash);
  return it == wallets.end() ? nullptr : it->second.get();
}

}  // namespace validator
}  // namespace tos
