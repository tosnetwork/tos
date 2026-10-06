/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Authorise one validator-controller action with the offline root key.
//
// This is the command an operator runs, and the only way a controller action is
// authorised outside a test. It lives here rather than in the node for the reason the offline-root split
// created and the custody ruling settled: the root owns the stake, the validator identity and the
// power to replace the consensus key, so a validator host that could run this would be a
// host whose compromise costs the authority rather than the key.
//
// It builds exactly the bytes the contract rebuilds from its own address -- the same
// `controller_auth_preimage` the contract, the vectors and the tests share -- signs them
// under the controller domain, and puts the result on the wire as a `PQca` body. It
// decides nothing: the fields of one authorisation go in, one body comes out.
//
// Generating a root seed is `tos-pq-key keygen`. A second way to write a key file would
// be a second set of durability rules, and the one that got them wrong would be the one
// holding the root.
#include <array>
#include <cstring>
#include <iostream>
#include <string>

#include "common/bitstring.h"
#include "pq/controller-root-file.h"
#include "pq/pq-bytes.h"
#include "pq/pq-controller.h"
#include "td/utils/base64.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cellslice.h"

namespace {

td::Bits256 bits256_from_hex(const std::string& text) {
  td::Bits256 out;
  if (text.size() != 64 || out.from_hex(td::Slice(text)) <= 0) {
    throw std::runtime_error("expected 32 bytes of hex");
  }
  return out;
}

tos::pq::ValidatorControllerRootKeyStore open_key(const char* path) {
  auto loaded = tos::pq::load_controller_root_key(path);
  if (std::holds_alternative<tos::pq::ControllerRootFileError>(loaded)) {
    throw std::runtime_error(std::string(path) + " " +
                             tos::pq::describe(std::get<tos::pq::ControllerRootFileError>(loaded)));
  }
  return std::move(std::get<tos::pq::ValidatorControllerRootKeyStore>(loaded));
}

td::Ref<vm::Cell> stored(td::Slice bytes) {
  auto packed = tos::pq::pack_pq_bytes(bytes, tos::pq::pq_bytes_hard_max);
  if (packed.is_error()) {
    throw std::runtime_error(packed.move_as_error().to_string());
  }
  return packed.move_as_ok();
}

td::Ref<vm::Cell> cell_from_base64(const std::string& text) {
  auto raw = td::base64_decode(text);
  if (raw.is_error()) {
    throw std::runtime_error("the message is not base64");
  }
  const auto bytes = raw.move_as_ok();
  auto cell = vm::std_boc_deserialize(td::Slice(bytes));
  if (cell.is_error()) {
    throw std::runtime_error(cell.move_as_error().to_string());
  }
  return cell.move_as_ok();
}

std::string boc_base64(td::Ref<vm::Cell> cell) {
  auto serialized = vm::std_boc_serialize(std::move(cell));
  if (serialized.is_error()) {
    throw std::runtime_error(serialized.move_as_error().to_string());
  }
  return td::base64_encode(serialized.move_as_ok().as_slice());
}

// The state init the controller is deployed with, and the one the elector rebuilds from a
// birth witness: no split depth, not special, code, data, no libraries.
td::Ref<vm::Cell> controller_state_init(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data) {
  vm::CellBuilder state;
  state.store_long(0x06, 5);
  state.store_ref(std::move(code));
  state.store_ref(std::move(data));
  return state.finalize();
}

// Lower case, as `tos-pq-consensus-key` and `tos-pq-key` print identities, so an operator
// can compare them as strings.
std::string lower_hex(td::Slice bytes) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (const unsigned char c : bytes) {
    out.push_back(digits[c >> 4]);
    out.push_back(digits[c & 15]);
  }
  return out;
}

// The root public key an initial data cell carries, from either thing an operator has: the
// 2624-digit public key `tos-pq-key keygen` and `tos-pq-key public` print, or the root seed
// file itself. Anything of exactly that length that is all hexadecimal is read as the
// key; everything else is a path.
std::string root_public_key(const std::string& argument) {
  constexpr std::size_t digits = 2 * tos::pq::mldsa44_public_key_bytes;
  if (argument.size() == digits) {
    auto decoded = td::hex_decode(td::Slice(argument));
    if (decoded.is_ok()) {
      auto bytes = decoded.move_as_ok();
      if (!tos::pq::valid_public_key(tos::pq::PQAlgorithmId::mldsa44, bytes)) {
        throw std::runtime_error("the root public key is not an ML-DSA-44 public key");
      }
      return bytes;
    }
  }
  auto root = open_key(argument.c_str());
  return root.root_key().public_key;
}

std::uint64_t to_u64(const char* text) {
  return static_cast<std::uint64_t>(std::stoull(text));
}

// One authorisation, on the wire the contract reads it from.
//
// The cosignature belongs to the two kinds that install a key and to no other: it is the
// incoming key proving its private half exists over the very commitment the root signed.
// The contract refuses a request that carries one for any other kind, and refuses one of
// those two that does not.
std::string authorisation_boc(const tos::pq::ValidatorControllerRootKeyStore& root, std::int32_t global_id,
                              const td::Bits256& controller_id, std::uint64_t epoch, std::uint64_t nonce,
                              std::uint32_t valid_until, std::uint8_t kind, td::Ref<vm::Cell> payload,
                              const tos::pq::ValidatorControllerRootKeyStore* cosigner) {
  const auto preimage = tos::pq::controller_auth_preimage(global_id, controller_id, epoch, nonce, valid_until, kind,
                                                          td::Bits256{payload->get_hash(0).bits()});

  auto signature = root.sign_controller_authorization(preimage);
  if (!signature.has_value()) {
    throw std::runtime_error("the root key could not sign this authorisation");
  }

  vm::CellBuilder body;
  body.store_long(tos::pq::controller_auth_op, 32);
  body.store_long(1, 64);  // query_id, echoed by nothing: the controller answers no one
  body.store_long(static_cast<std::uint32_t>(global_id), 32);
  body.store_long(epoch, 64);
  body.store_long(nonce, 64);
  body.store_long(valid_until, 32);
  body.store_long(kind, 8);
  body.store_ref(std::move(payload));
  body.store_ref(stored(td::Slice(signature->signature)));
  if (cosigner != nullptr) {
    auto proof = cosigner->sign_controller_authorization(preimage);
    if (!proof.has_value()) {
      throw std::runtime_error("the incoming key could not prove it exists");
    }
    body.store_long(1, 1);
    body.store_ref(stored(td::Slice(proof->signature)));
  } else {
    body.store_long(0, 1);
  }

  auto serialized = vm::std_boc_serialize(body.finalize());
  if (serialized.is_error()) {
    throw std::runtime_error(serialized.move_as_error().to_string());
  }
  return td::base64_encode(serialized.move_as_ok().as_slice());
}

[[noreturn]] void usage() {
  throw std::runtime_error(
      "usage:\n"
      "  tos-pq-controller show ROOTSEED\n"
      "  tos-pq-controller init-data ROOT_PUBLIC_HEX|ROOTSEED CONSENSUS_KEY_ID_HEX\n"
      "  tos-pq-controller state-init CODE_BOC_B64 INITIAL_DATA_BOC_B64\n"
      "  tos-pq-controller witness CODE_BOC_B64 INITIAL_DATA_BOC_B64\n"
      "  tos-pq-controller send ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL MODE MESSAGE_BOC_B64\n"
      "  tos-pq-controller bind ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL CONSENSUS_SEED\n"
      "  tos-pq-controller rotate-root ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL NEXT_ROOT_SEED\n"
      "  tos-pq-controller fund-operations ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL PAYLOAD_BOC_B64\n"
      "  tos-pq-controller withdraw-operations ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH NONCE VALID_UNTIL "
      "PAYLOAD_BOC_B64\n"
      "\n"
      "A root seed is created with `tos-pq-key keygen`. The authorising commands print a\n"
      "base64 PQca body, to be sent to the controller as an internal message.\n"
      "\n"
      "Deploying a controller (the consensus key is bound at birth, so its seed never\n"
      "leaves the validator host):\n"
      "  1. init-data takes the root public key (or the root seed) and the consensus\n"
      "     key_id `tos-pq-consensus-key show` prints, and prints the initial data BOC.\n"
      "  2. state-init takes the compiled controller code and that data, and prints the\n"
      "     StateInit BOC; its address and code hash go to stderr. The code hash must be\n"
      "     admitted in ConfigParam 47. The code BOC is built from the release source:\n"
      "       func -W controller.boc -AP -o controller.fif \\\n"
      "         crypto/smartcont/stdlib.fc crypto/smartcont/validator-controller-v1.fc\n"
      "       FIFTPATH=crypto/fift/lib fift controller.fif\n"
      "       base64 -w0 controller.boc\n"
      "  3. Send it from an operator wallet as a non-bouncing internal message with an\n"
      "     empty body, for example:\n"
      "       tosctl wallet send --from WALLET --to -1:ADDRESS --amount TOS \\\n"
      "         --state-init-boc STATE_INIT_BOC_B64\n"
      "     and keep the deployment transaction for `tosctl config bind import-birth`.\n"
      "  4. witness takes the same code and data and prints the birth witness a first\n"
      "     stake carries.");
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 3) {
      usage();
    }
    const std::string command(argv[1]);

    // A controller's initial data, exactly as `ctl::load_data` reads it: authority epoch 0,
    // root nonce 0, the consensus algorithm and key identity it is born bound to, and the
    // root public key as canonical PQ bytes. Nothing optional follows: relay, operating
    // and retry state are absent until the contract first stores them.
    if (command == "init-data") {
      if (argc != 4) {
        usage();
      }
      const auto public_key = root_public_key(argv[2]);
      const auto root_id = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, public_key);
      if (!root_id.has_value()) {
        throw std::runtime_error("no key identity can be derived from the root public key");
      }
      const auto consensus = bits256_from_hex(argv[3]);
      if (consensus.is_zero()) {
        throw std::runtime_error("the consensus key_id is zero; no key derives it");
      }
      // A root that is also the consensus key would put the authority on the validator
      // host, which is the one thing the controller exists to prevent.
      if (std::memcmp(root_id->data(), consensus.data(), root_id->size()) == 0) {
        throw std::runtime_error("the consensus key_id is the root key's own; they must be two keys");
      }

      vm::CellBuilder data;
      data.store_long(0, 64);  // authority epoch
      data.store_long(0, 64);  // root nonce
      data.store_long(static_cast<int>(tos::pq::PQAlgorithmId::mldsa44), 16);
      data.store_bits(consensus.bits(), 256);
      data.store_ref(stored(td::Slice(public_key)));
      std::cout << boc_base64(data.finalize()) << '\n';
      std::cerr << "root_key_id " << lower_hex(td::Slice(root_id->data(), root_id->size())) << '\n'
                << "consensus_key_id " << lower_hex(consensus.as_slice()) << '\n';
      return 0;
    }

    // What an operator's wallet sends to bring the controller into existence. The address
    // it lands at is the one every later step names, so it is printed with it.
    if (command == "state-init") {
      if (argc != 4) {
        usage();
      }
      auto code = cell_from_base64(argv[2]);
      auto state = controller_state_init(code, cell_from_base64(argv[3]));
      std::cout << boc_base64(state) << '\n';
      std::cerr << "address -1:" << lower_hex(state->get_hash(0).as_slice()) << '\n'
                << "code_hash " << lower_hex(code->get_hash(0).as_slice()) << '\n';
      return 0;
    }

    // The one command that needs no key: what an account was deployed as.
    //
    // A first stake carries this, and the elector rebuilds the sender's address from it.
    // The four numbers are a record of the deployment, not a reading of the account:
    // binding a consensus key changes the controller's data, and every validator binds
    // one before it first stakes, so an account's live data has already moved on by then.
    // An operator keeps the code and the initial data they deployed with; this turns them
    // into the witness and prints the address they must match.
    if (command == "witness") {
      if (argc != 4) {
        usage();
      }
      auto code = cell_from_base64(argv[2]);
      auto data = cell_from_base64(argv[3]);

      vm::CellBuilder witness;
      witness.store_bits(code->get_hash(0).bits(), 256);
      witness.store_long(code->get_depth(0), 16);
      witness.store_bits(data->get_hash(0).bits(), 256);
      witness.store_long(data->get_depth(0), 16);

      // The state init the elector rebuilds, so an operator can check the address before
      // they find out from a refusal.
      const auto address = controller_state_init(code, data)->get_hash(0);

      std::cout << boc_base64(witness.finalize()) << '\n';
      std::cerr << "address -1:" << td::buffer_to_hex(address.as_slice()) << '\n';
      return 0;
    }

    auto root = open_key(argv[2]);

    if (command == "show") {
      if (argc != 3) {
        usage();
      }
      // What an operator puts into a controller's initial data, and what they check a
      // deployed controller against.
      const auto& key_id = root.root_key().key_id;
      std::cout << "algorithm_id " << static_cast<int>(root.root_key().algorithm_id) << '\n'
                << "key_id "
                << td::buffer_to_hex(td::Slice(reinterpret_cast<const char*>(key_id.data()), key_id.size())) << '\n'
                << "public_key " << td::base64_encode(td::Slice(root.root_key().public_key)) << '\n';
      return 0;
    }

    const bool send = command == "send";
    const bool bind = command == "bind";
    const bool rotate = command == "rotate-root";
    const bool fund = command == "fund-operations";
    const bool withdraw = command == "withdraw-operations";
    if (!send && !bind && !rotate && !fund && !withdraw) {
      usage();
    }
    if (argc != (send ? 10 : 9)) {
      usage();
    }

    const auto global_id = static_cast<std::int32_t>(std::stol(argv[3]));
    const auto controller_id = bits256_from_hex(argv[4]);
    const auto epoch = to_u64(argv[5]);
    const auto nonce = to_u64(argv[6]);
    const auto valid_until = static_cast<std::uint32_t>(to_u64(argv[7]));

    if (fund || withdraw) {
      // Deposits bind the funding wallet, amount, independent allowance, cap,
      // floor and expiry. Withdrawals bind the wallet and exact amount.
      // Neither operation supplies a default amount or submits a transfer.
      std::cout << authorisation_boc(root, global_id, controller_id, epoch, nonce, valid_until, fund ? 4 : 5,
                                     cell_from_base64(argv[8]), nullptr)
                << '\n';
      return 0;
    }

    if (send) {
      const auto mode = static_cast<std::uint8_t>(std::stoul(argv[8]));
      vm::CellBuilder payload;
      payload.store_long(mode, 8);
      payload.store_ref(cell_from_base64(argv[9]));
      std::cout << authorisation_boc(root, global_id, controller_id, epoch, nonce, valid_until, 1, payload.finalize(),
                                     nullptr)
                << '\n';
      return 0;
    }

    // The key being installed signs the same authorisation, which is the proof the
    // contract requires. Its seed is in this offline domain for the length of the
    // ceremony and is provisioned to the validator host afterwards.
    auto incoming = open_key(argv[8]);
    vm::CellBuilder payload;
    if (bind) {
      payload.store_long(static_cast<int>(incoming.root_key().algorithm_id), 16);
    }
    payload.store_ref(stored(td::Slice(incoming.root_key().public_key)));
    std::cout << authorisation_boc(root, global_id, controller_id, epoch, nonce, valid_until, bind ? 3 : 2,
                                   payload.finalize(), &incoming)
              << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
