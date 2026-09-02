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
#include <bitset>
#include <cctype>
#include <cstdlib>
#include <set>
#include <tuple>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "common/bigint.hpp"
#include "fift/Fift.h"
#include "fift/utils.h"
#include "fift/words.h"
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/HighloadWallet.h"
#include "smc-envelope/HighloadWalletV2.h"
#include "smc-envelope/ManualDns.h"
#include "smc-envelope/MultisigWallet.h"
#include "smc-envelope/PaymentChannel.h"
#include "smc-envelope/SmartContract.h"
#include "smc-envelope/SmartContractCode.h"
#include "smc-envelope/WalletV3.h"
#include "smc-envelope/WalletV4.h"
#include "td/utils/PathView.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Random.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/Timer.h"
#include "td/utils/Variant.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/dict.h"

#include "Ed25519.h"

std::string current_dir() {
  return td::PathView(td::realpath(__FILE__).move_as_ok()).parent_dir().str();
}

std::string load_source(std::string name) {
  if (name.rfind("smartcont/auto/", 0) == 0) {
    return td::read_file_str(std::string{TOS_CRYPTO_BUILD_DIR} + "/" + name).move_as_ok();
  }
  return td::read_file_str(current_dir() + "../../crypto/" + name).move_as_ok();
}

namespace {

// The canonical mainnet template refuses every other timestamp. Keep the C++
// byte-regression fixture aligned with 2026-09-15 10:00:00 JST.
constexpr td::uint32 kDeterministicZerostateNow = 1789434000;
constexpr td::Slice kMainWalletPkHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr td::Slice kConfigMasterPkHex = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
constexpr td::Slice kGenesisValidatorPkHex[] = {
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
};
constexpr td::uint32 kFixedFiftNow = 1700000000;
constexpr td::uint32 kValidatorElectTime = 1234567890;
constexpr td::uint32 kValidatorMaxFactor = 2u << 16;
constexpr td::uint32 kConfigVoteSeqno = 25;
constexpr td::uint32 kRelativeExpireAt = 10;
constexpr td::uint16 kValidatorIndex = 9;
constexpr td::uint32 kProposalHash = 0x10203040;
constexpr td::uint32 kComplaintHash = 0x20304050;
constexpr td::uint32 kElectId = 0x89ABCDEF;
constexpr td::Slice kValidatorPrivKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr td::Slice kScriptWalletAddrHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
constexpr td::Slice kScriptConfigAddrHex = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef";
constexpr td::Slice kScriptAdnlAddrHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";

class FixedOsTime : public fift::OsTime {
 public:
  explicit FixedOsTime(td::uint32 now) : now_(now) {
  }

  td::uint32 now() override {
    return now_;
  }

 private:
  td::uint32 now_;
};

std::string shell_quote(td::Slice value) {
  std::string result = "'";
  for (auto c : value) {
    if (c == '\'') {
      result += "'\\''";
    } else {
      result += c;
    }
  }
  result += "'";
  return result;
}

bool is_word_char(char c) {
  auto uc = static_cast<unsigned char>(c);
  return std::isalnum(uc) != 0 || c == '_';
}

std::string replace_word_token(std::string input, td::Slice from, td::Slice to) {
  std::size_t pos = 0;
  while ((pos = input.find(from.str(), pos)) != std::string::npos) {
    auto left_ok = pos == 0 || !is_word_char(input[pos - 1]);
    auto right_pos = pos + from.size();
    auto right_ok = right_pos >= input.size() || !is_word_char(input[right_pos]);
    if (left_ok && right_ok) {
      input.replace(pos, from.size(), to.str());
      pos += to.size();
    } else {
      pos += from.size();
    }
  }
  return input;
}

std::string create_state_binary() {
  std::vector<std::string> candidates;
  if (const char* env_path = std::getenv("TOS_CREATE_STATE_BINARY")) {
    candidates.emplace_back(env_path);
  }
  candidates.emplace_back("crypto/create-state");        // CTest from build/
  candidates.emplace_back("build/crypto/create-state");  // direct run from repo root
  candidates.emplace_back("../crypto/create-state");     // direct run from build/test/

  for (const auto& candidate : candidates) {
    auto real = td::realpath(candidate);
    if (real.is_error()) {
      continue;
    }
    auto path = real.move_as_ok();
    auto info = td::stat(path);
    if (info.is_ok() && info.ok().is_reg_) {
      return path;
    }
  }
  LOG(FATAL) << "Unable to locate crypto/create-state; set TOS_CREATE_STATE_BINARY";
  return {};
}

std::string fift_lib_dir() {
  return current_dir() + "../../crypto/fift/lib/";
}

std::string smartcont_dir() {
  return current_dir() + "../../crypto/smartcont/";
}

std::string generated_smartcont_dir() {
  return std::string{TOS_CRYPTO_BUILD_DIR} + "/smartcont/";
}

std::string hex_bytes(td::Slice hex) {
  return td::hex_decode(hex).move_as_ok();
}

void append_u16_be(std::string& out, td::uint16 value) {
  out.push_back(static_cast<char>((value >> 8) & 0xff));
  out.push_back(static_cast<char>(value & 0xff));
}

void append_u32_be(std::string& out, td::uint32 value) {
  out.push_back(static_cast<char>((value >> 24) & 0xff));
  out.push_back(static_cast<char>((value >> 16) & 0xff));
  out.push_back(static_cast<char>((value >> 8) & 0xff));
  out.push_back(static_cast<char>(value & 0xff));
}

std::string make_masterchain_address_file(td::Slice addr_hex) {
  std::string result = hex_bytes(addr_hex);
  append_u32_be(result, static_cast<td::uint32>(-1));
  return result;
}

void write_masterchain_address_file(fift::SourceLookup& source_lookup, td::Slice name, td::Slice addr_hex) {
  source_lookup.write_file(name.str(), make_masterchain_address_file(addr_hex)).ensure();
}

td::uint32 normalize_vote_expire(td::uint32 raw_expire, td::uint32 now) {
  if (raw_expire < (1u << 30)) {
    auto sum = static_cast<td::uint64>(now) + raw_expire + 1000;
    raw_expire = static_cast<td::uint32>(((sum + 1999) / 2000) * 2000);
  }
  return raw_expire;
}

std::string make_validator_pubkey_b64(const td::Ed25519::PublicKey& public_key) {
  std::string raw;
  append_u32_be(raw, 0xC6B41348);
  raw += public_key.as_octet_string().as_slice().str();
  return td::base64_encode(raw);
}

std::string sign_b64(const td::Ed25519::PrivateKey& private_key, td::Slice data) {
  return td::base64_encode(private_key.sign(data).move_as_ok().as_slice());
}

// Field-level check that a base64 signature actually verifies against the
// to-sign payload. Catches sign-side bugs (wrong-length output, key mismatch,
// data corruption) that root-hash regression cannot detect on its own — a
// broken `sign_b64` would produce a different-but-internally-consistent BOC
// whose root hash would just become the new golden.
void check_signature_b64(const td::Ed25519::PublicKey& public_key, td::Slice data, td::Slice signature_b64) {
  auto sig = td::base64_decode(signature_b64).move_as_ok();
  CHECK(sig.size() == 64);
  CHECK(public_key.verify_signature(data, sig).is_ok());
}

std::string build_validator_elect_request(td::uint32 elect_time, td::uint32 max_factor, td::Slice src_addr,
                                          td::Slice adnl_addr) {
  std::string out = "\x65\x4c\x50\x74";
  append_u32_be(out, elect_time);
  append_u32_be(out, max_factor);
  out += src_addr.str();
  out += adnl_addr.str();
  return out;
}

std::string build_config_vote_ext_request(td::uint32 seqno, td::uint32 expire_at, td::uint16 validator_idx,
                                          td::uint32 proposal_hash) {
  std::string out = "\x56\x6f\x74\x65";
  append_u32_be(out, seqno);
  append_u32_be(out, expire_at);
  append_u16_be(out, validator_idx);
  out.resize(out.size() + 28, '\0');
  append_u32_be(out, proposal_hash);
  return out;
}

std::string build_config_vote_int_request(td::uint16 validator_idx, td::uint32 proposal_hash) {
  std::string out = "\x56\x6f\x74\x45";
  append_u16_be(out, validator_idx);
  out.resize(out.size() + 28, '\0');
  append_u32_be(out, proposal_hash);
  return out;
}

std::string build_complaint_vote_request(td::uint16 validator_idx, td::uint32 elect_id, td::uint32 complaint_hash) {
  std::string out = "\x56\x74\x43\x50";
  append_u16_be(out, validator_idx);
  append_u32_be(out, elect_id);
  out.resize(out.size() + 28, '\0');
  append_u32_be(out, complaint_hash);
  return out;
}

std::string cell_boc(td::Ref<vm::Cell> cell) {
  return vm::std_boc_serialize(std::move(cell), 2).move_as_ok().as_slice().str();
}

std::string cell_root_hash_hex(td::Slice boc) {
  return td::buffer_to_hex(vm::std_boc_deserialize(boc).move_as_ok()->get_hash().as_slice());
}

void write_deterministic_zerostate_keys(const std::string& dir) {
  td::write_file(dir + TD_DIR_SLASH + "main-wallet.pk", td::hex_decode(kMainWalletPkHex).move_as_ok()).ensure();
  td::write_file(dir + TD_DIR_SLASH + "config-master.pk", td::hex_decode(kConfigMasterPkHex).move_as_ok()).ensure();
  std::string validator_public_keys;
  for (auto private_key_hex : kGenesisValidatorPkHex) {
    auto private_key = td::Ed25519::PrivateKey(td::SecureString(td::hex_decode(private_key_hex).move_as_ok()));
    validator_public_keys += private_key.get_public_key().move_as_ok().as_octet_string().as_slice().str();
  }
  td::write_file(dir + TD_DIR_SLASH + "validator-keys.pub", validator_public_keys).ensure();
}

void append_state_hash_summary(std::string& summary, const std::string& dir, const std::string& state_name,
                               bool optional = false) {
  auto boc_r = td::read_file(dir + TD_DIR_SLASH + state_name + ".boc");
  if (optional && boc_r.is_error()) {
    // Some legacy optional state files are absent in the native-only zerostate.
    return;
  }
  auto boc = boc_r.move_as_ok();
  auto file_hash = td::read_file(dir + TD_DIR_SLASH + state_name + ".fhash").move_as_ok();
  auto root_hash = td::read_file(dir + TD_DIR_SLASH + state_name + ".rhash").move_as_ok();

  CHECK(td::sha256(boc.as_slice()) == file_hash.as_slice().str());
  CHECK(vm::std_boc_deserialize(boc.as_slice()).move_as_ok()->get_hash().as_slice() == root_hash.as_slice());

  summary += PSTRING() << state_name << ".boc_size=" << boc.as_slice().size() << "\n";
  summary += PSTRING() << state_name << ".file_hash=" << td::buffer_to_hex(file_hash.as_slice()) << "\n";
  summary += PSTRING() << state_name << ".root_hash=" << td::buffer_to_hex(root_hash.as_slice()) << "\n";
}

void append_optional_hex_summary(std::string& summary, const std::string& dir, const std::string& file_name) {
  auto file = td::read_file(dir + TD_DIR_SLASH + file_name);
  if (file.is_ok()) {
    summary += PSTRING() << file_name << "=" << td::buffer_to_hex(file.ok().as_slice()) << "\n";
  }
}

std::string run_zerostate_regression(td::Slice script_name) {
  auto temp_dir = td::mkdtemp("/tmp", "tos-zerostate").move_as_ok();
  SCOPE_EXIT {
    td::rmrf(temp_dir).ignore();
  };

  write_deterministic_zerostate_keys(temp_dir);

  auto patched_script = replace_word_token(load_source(PSTRING() << "smartcont/" << script_name), "now",
                                           td::Slice(td::to_string(kDeterministicZerostateNow)));
  auto script_path = temp_dir + TD_DIR_SLASH + script_name.str();
  td::write_file(script_path, patched_script).ensure();

  auto stdout_path = temp_dir + TD_DIR_SLASH + "stdout.txt";
  auto stderr_path = temp_dir + TD_DIR_SLASH + "stderr.txt";
  auto include_path = PSTRING() << fift_lib_dir() << ":" << generated_smartcont_dir() << ":" << smartcont_dir();
  // SOURCE_DATE_EPOCH pins the `now`/gen_utime stamped inside mkemptyShardState
  // (Workchain.fif) — which the script-only `now` text-replacement can't reach —
  // so the generated zerostate is byte-deterministic. Match kDeterministicZerostateNow.
  auto command = PSTRING() << "cd " << shell_quote(temp_dir) << " && SOURCE_DATE_EPOCH=" << kDeterministicZerostateNow
                           << " " << shell_quote(create_state_binary()) << " -I " << shell_quote(include_path) << " "
                           << shell_quote(script_path) << " > " << shell_quote(stdout_path) << " 2> "
                           << shell_quote(stderr_path);

  auto rc = std::system(command.c_str());
  if (rc != 0) {
    auto stderr = td::read_file_str(stderr_path);
    if (stderr.is_ok()) {
      LOG(ERROR) << stderr.move_as_ok();
    }
    LOG(ERROR) << "create-state command failed: " << command;
  }
  CHECK(rc == 0);

  std::string summary = PSTRING() << "script=" << script_name << "\n";
  append_state_hash_summary(summary, temp_dir, "basestate0");
  append_state_hash_summary(summary, temp_dir, "zerostate");
  append_optional_hex_summary(summary, temp_dir, "main-wallet.addr");
  append_optional_hex_summary(summary, temp_dir, "config-master.addr");
  append_optional_hex_summary(summary, temp_dir, "elector.addr");
  append_optional_hex_summary(summary, temp_dir, "testgiver.addr");
  return summary;
}

std::string run_validator_fift_script_regression() {
  auto private_key = td::Ed25519::PrivateKey(td::SecureString(hex_bytes(kValidatorPrivKeyHex)));
  auto public_key = private_key.get_public_key().move_as_ok();
  auto pubkey_b64 = make_validator_pubkey_b64(public_key);
  auto wallet_arg = std::string("@wallet.addr");
  auto adnl_hex = kScriptAdnlAddrHex.str();
  auto elect_time = td::to_string(kValidatorElectTime);
  auto request_expected = build_validator_elect_request(kValidatorElectTime, kValidatorMaxFactor,
                                                        hex_bytes(kScriptWalletAddrHex), hex_bytes(kScriptAdnlAddrHex));

  auto request_lookup = fift::create_mem_source_lookup(load_source("smartcont/validator-elect-req.fif")).move_as_ok();
  request_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  write_masterchain_address_file(request_lookup, "wallet.addr", kScriptWalletAddrHex);
  auto request_run =
      fift::mem_run_fift(std::move(request_lookup), {"aba", wallet_arg, elect_time, "2", adnl_hex}).move_as_ok();
  auto request = request_run.source_lookup.read_file("validator-to-sign.bin").move_as_ok().data;
  CHECK(request == request_expected);
  auto signature_b64 = sign_b64(private_key, request);
  check_signature_b64(public_key, request, signature_b64);

  auto signed_lookup = fift::create_mem_source_lookup(load_source("smartcont/validator-elect-signed.fif")).move_as_ok();
  signed_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  write_masterchain_address_file(signed_lookup, "wallet.addr", kScriptWalletAddrHex);
  auto signed_run = fift::mem_run_fift(std::move(signed_lookup),
                                       {"aba", wallet_arg, elect_time, "2", adnl_hex, pubkey_b64, signature_b64})
                        .move_as_ok();
  auto signed_boc = signed_run.source_lookup.read_file("validator-query.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(signed_boc).move_as_ok().not_null());

  auto single_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/single-nominator-pool/validator-elect-signed.fif"))
          .move_as_ok();
  single_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  write_masterchain_address_file(single_lookup, "wallet.addr", kScriptWalletAddrHex);
  auto single_run = fift::mem_run_fift(std::move(single_lookup), {"aba", wallet_arg, elect_time, "2", adnl_hex,
                                                                  pubkey_b64, signature_b64, "single-query.boc", "7"})
                        .move_as_ok();
  auto single_boc = single_run.source_lookup.read_file("single-query.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(single_boc).move_as_ok().not_null());

  auto controller_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/liquid-staking/controller-elect-signed.fif")).move_as_ok();
  controller_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  write_masterchain_address_file(controller_lookup, "wallet.addr", kScriptWalletAddrHex);
  auto controller_run =
      fift::mem_run_fift(std::move(controller_lookup), {"aba", wallet_arg, elect_time, "2", adnl_hex, pubkey_b64,
                                                        signature_b64, "controller-query.boc", "7"})
          .move_as_ok();
  auto controller_boc = controller_run.source_lookup.read_file("controller-query.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(controller_boc).move_as_ok().not_null());

  std::string summary;
  summary += PSTRING() << "validator_to_sign=" << td::buffer_to_hex(request) << "\n";
  summary += PSTRING() << "validator_query_root_hash=" << cell_root_hash_hex(signed_boc) << "\n";
  summary += PSTRING() << "single_nominator_query_root_hash=" << cell_root_hash_hex(single_boc) << "\n";
  summary += PSTRING() << "controller_query_root_hash=" << cell_root_hash_hex(controller_boc) << "\n";
  return summary;
}

std::string run_governance_vote_fift_script_regression() {
  auto private_key = td::Ed25519::PrivateKey(td::SecureString(hex_bytes(kValidatorPrivKeyHex)));
  auto public_key = private_key.get_public_key().move_as_ok();
  auto pubkey_b64 = make_validator_pubkey_b64(public_key);
  auto config_arg = std::string("@config.addr");
  auto expire_at = normalize_vote_expire(kRelativeExpireAt, kFixedFiftNow);
  auto proposal_hash_arg = "0x10203040";
  auto complaint_hash_arg = "0x20304050";
  auto elect_id_arg = "0x89ABCDEF";

  auto config_req_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/config-proposal-vote-req.fif")).move_as_ok();
  config_req_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  auto config_req_run = fift::mem_run_fift(std::move(config_req_lookup),
                                           {"aba", td::to_string(kConfigVoteSeqno), td::to_string(kRelativeExpireAt),
                                            td::to_string(kValidatorIndex), proposal_hash_arg})
                            .move_as_ok();
  auto config_req = config_req_run.source_lookup.read_file("validator-to-sign.req").move_as_ok().data;
  CHECK(config_req == build_config_vote_ext_request(kConfigVoteSeqno, expire_at, kValidatorIndex, kProposalHash));
  auto config_signature_b64 = sign_b64(private_key, config_req);
  check_signature_b64(public_key, config_req, config_signature_b64);

  auto config_int_req_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/config-proposal-vote-req.fif")).move_as_ok();
  config_int_req_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  auto config_int_req_run = fift::mem_run_fift(std::move(config_int_req_lookup),
                                               {"aba", "-i", td::to_string(kValidatorIndex), proposal_hash_arg})
                                .move_as_ok();
  auto config_int_req = config_int_req_run.source_lookup.read_file("validator-to-sign.req").move_as_ok().data;
  CHECK(config_int_req == build_config_vote_int_request(kValidatorIndex, kProposalHash));
  auto config_int_signature_b64 = sign_b64(private_key, config_int_req);
  check_signature_b64(public_key, config_int_req, config_int_signature_b64);

  auto config_signed_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/config-proposal-vote-signed.fif")).move_as_ok();
  config_signed_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  write_masterchain_address_file(config_signed_lookup, "config.addr", kScriptConfigAddrHex);
  auto config_signed_run =
      fift::mem_run_fift(std::move(config_signed_lookup),
                         {"aba", config_arg, td::to_string(kConfigVoteSeqno), td::to_string(kRelativeExpireAt),
                          td::to_string(kValidatorIndex), proposal_hash_arg, pubkey_b64, config_signature_b64})
          .move_as_ok();
  auto config_signed_boc = config_signed_run.source_lookup.read_file("vote-query.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(config_signed_boc).move_as_ok().not_null());

  auto config_internal_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/config-proposal-vote-signed.fif")).move_as_ok();
  config_internal_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  write_masterchain_address_file(config_internal_lookup, "config.addr", kScriptConfigAddrHex);
  auto config_internal_run =
      fift::mem_run_fift(std::move(config_internal_lookup), {"aba", "-i", td::to_string(kValidatorIndex),
                                                             proposal_hash_arg, pubkey_b64, config_int_signature_b64})
          .move_as_ok();
  auto config_internal_boc = config_internal_run.source_lookup.read_file("vote-msg-body.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(config_internal_boc).move_as_ok().not_null());

  auto complaint_req_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/complaint-vote-req.fif")).move_as_ok();
  complaint_req_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  auto complaint_req_run = fift::mem_run_fift(std::move(complaint_req_lookup),
                                              {"aba", td::to_string(kValidatorIndex), elect_id_arg, complaint_hash_arg})
                               .move_as_ok();
  auto complaint_req = complaint_req_run.source_lookup.read_file("validator-to-sign.req").move_as_ok().data;
  CHECK(complaint_req == build_complaint_vote_request(kValidatorIndex, kElectId, kComplaintHash));
  auto complaint_signature_b64 = sign_b64(private_key, complaint_req);
  check_signature_b64(public_key, complaint_req, complaint_signature_b64);

  auto complaint_signed_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/complaint-vote-signed.fif")).move_as_ok();
  complaint_signed_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  auto complaint_signed_run =
      fift::mem_run_fift(std::move(complaint_signed_lookup), {"aba", td::to_string(kValidatorIndex), elect_id_arg,
                                                              complaint_hash_arg, pubkey_b64, complaint_signature_b64})
          .move_as_ok();
  auto complaint_signed_boc = complaint_signed_run.source_lookup.read_file("vote-query.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(complaint_signed_boc).move_as_ok().not_null());

  std::string summary;
  summary += PSTRING() << "config_vote_req=" << td::buffer_to_hex(config_req) << "\n";
  summary += PSTRING() << "config_vote_int_req=" << td::buffer_to_hex(config_int_req) << "\n";
  summary += PSTRING() << "config_vote_ext_root_hash=" << cell_root_hash_hex(config_signed_boc) << "\n";
  summary += PSTRING() << "config_vote_int_root_hash=" << cell_root_hash_hex(config_internal_boc) << "\n";
  summary += PSTRING() << "complaint_vote_req=" << td::buffer_to_hex(complaint_req) << "\n";
  summary += PSTRING() << "complaint_vote_root_hash=" << cell_root_hash_hex(complaint_signed_boc) << "\n";
  return summary;
}

std::string run_governance_proposal_fift_script_regression() {
  auto param_value_boc = cell_boc(vm::CellBuilder().store_long(0xCAFE, 16).finalize());
  auto complaint_boc = cell_boc(vm::CellBuilder().store_long(0xBC, 8).store_long(0x1234, 16).finalize());

  auto config_proposal_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/create-config-proposal.fif")).move_as_ok();
  config_proposal_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  config_proposal_lookup.write_file("proposal-value.boc", param_value_boc).ensure();
  auto config_proposal_run =
      fift::mem_run_fift(std::move(config_proposal_lookup), {"aba", "17", "proposal-value.boc", "cfg-proposal.boc"})
          .move_as_ok();
  auto config_proposal_boc = config_proposal_run.source_lookup.read_file("cfg-proposal.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(config_proposal_boc).move_as_ok().not_null());

  auto config_upgrade_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/create-config-upgrade-proposal.fif")).move_as_ok();
  config_upgrade_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  config_upgrade_lookup.write_file("/auto/config-code.fif", load_source("smartcont/auto/config-code.fif")).ensure();
  auto config_upgrade_run =
      fift::mem_run_fift(std::move(config_upgrade_lookup), {"aba", "cfg-upgrade.boc"}).move_as_ok();
  auto config_upgrade_boc = config_upgrade_run.source_lookup.read_file("cfg-upgrade.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(config_upgrade_boc).move_as_ok().not_null());

  auto elector_upgrade_lookup =
      fift::create_mem_source_lookup(load_source("smartcont/create-elector-upgrade-proposal.fif")).move_as_ok();
  elector_upgrade_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  elector_upgrade_lookup.write_file("/auto/elector-code.fif", load_source("smartcont/auto/elector-code.fif")).ensure();
  auto elector_upgrade_run =
      fift::mem_run_fift(std::move(elector_upgrade_lookup), {"aba", "elector-upgrade.boc"}).move_as_ok();
  auto elector_upgrade_boc = elector_upgrade_run.source_lookup.read_file("elector-upgrade.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(elector_upgrade_boc).move_as_ok().not_null());

  auto complaint_lookup = fift::create_mem_source_lookup(load_source("smartcont/envelope-complaint.fif")).move_as_ok();
  complaint_lookup.set_os_time(std::make_unique<FixedOsTime>(kFixedFiftNow));
  complaint_lookup.write_file("complaint.boc", complaint_boc).ensure();
  auto complaint_run =
      fift::mem_run_fift(std::move(complaint_lookup), {"aba", "123", "complaint.boc", "complaint-envelope.boc"})
          .move_as_ok();
  auto complaint_envelope_boc = complaint_run.source_lookup.read_file("complaint-envelope.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(complaint_envelope_boc).move_as_ok().not_null());

  std::string summary;
  summary += PSTRING() << "config_proposal_root_hash=" << cell_root_hash_hex(config_proposal_boc) << "\n";
  summary += PSTRING() << "config_upgrade_root_hash=" << cell_root_hash_hex(config_upgrade_boc) << "\n";
  summary += PSTRING() << "elector_upgrade_root_hash=" << cell_root_hash_hex(elector_upgrade_boc) << "\n";
  summary += PSTRING() << "complaint_envelope_root_hash=" << cell_root_hash_hex(complaint_envelope_boc) << "\n";
  return summary;
}

}  // namespace

td::Ref<vm::Cell> get_wallet_v3_source() {
  std::string code = R"ABCD(
SETCP0 DUP IFNOTRET // return if recv_internal
   DUP 85143 INT EQUAL OVER 78748 INT EQUAL OR IFJMP:<{ // "seqno" and "get_public_key" get-methods
     1 INT AND c4 PUSHCTR CTOS 32 LDU 32 LDU NIP 256 PLDU CONDSEL  // cnt or pubk
   }>
   INC 32 THROWIF	// fail unless recv_external
   9 PUSHPOW2 LDSLICEX DUP 32 LDU 32 LDU 32 LDU 	//  signature in_msg subwallet_id valid_until msg_seqno cs
   NOW s1 s3 XCHG LEQ 35 THROWIF	//  signature in_msg subwallet_id cs msg_seqno
   c4 PUSH CTOS 32 LDU 32 LDU 256 LDU ENDS	//  signature in_msg subwallet_id cs msg_seqno stored_seqno stored_subwallet public_key
   s3 s2 XCPU EQUAL 33 THROWIFNOT	//  signature in_msg subwallet_id cs public_key stored_seqno stored_subwallet
   s4 s4 XCPU EQUAL 34 THROWIFNOT	//  signature in_msg stored_subwallet cs public_key stored_seqno
   s0 s4 XCHG HASHSU	//  signature stored_seqno stored_subwallet cs public_key msg_hash
   s0 s5 s5 XC2PU	//  public_key stored_seqno stored_subwallet cs msg_hash signature public_key
   CHKSIGNU 35 THROWIFNOT	//  public_key stored_seqno stored_subwallet cs
   ACCEPT
   WHILE:<{
     DUP SREFS	//  public_key stored_seqno stored_subwallet cs _51
   }>DO<{	//  public_key stored_seqno stored_subwallet cs
     8 LDU LDREF s0 s2 XCHG	//  public_key stored_seqno stored_subwallet cs _56 mode
     SENDRAWMSG
   }>	//  public_key stored_seqno stored_subwallet cs
   ENDS SWAP INC	//  public_key stored_subwallet seqno'
   NEWC 32 STU 32 STU 256 STU ENDC c4 POP
)ABCD";
  return fift::compile_asm(code).move_as_ok();
}

TEST(Toslib, WalletV3) {
  // Note: get_wallet_v3_source() is a legacy hand-written ASM without global_id check.
  // The compiled bytecode now includes global_id verification, so hash comparison is skipped.

  auto fift_output = fift::mem_run_fift(load_source("smartcont/new-wallet-v3.fif"), {"aba", "0", "239"}).move_as_ok();
  auto new_wallet_pk = fift_output.source_lookup.read_file("new-wallet.pk").move_as_ok().data;
  auto new_wallet_query = fift_output.source_lookup.read_file("new-wallet-query.boc").move_as_ok().data;
  auto new_wallet_addr = fift_output.source_lookup.read_file("new-wallet.addr").move_as_ok().data;

  td::Ed25519::PrivateKey priv_key{td::SecureString{new_wallet_pk}};
  auto pub_key = priv_key.get_public_key().move_as_ok();
  tos::WalletV3::InitData init_data;
  init_data.public_key = pub_key.as_octet_string();
  init_data.wallet_id = 239;
  auto wallet = tos::WalletV3::create(init_data, -1);
  wallet.write().set_global_id(1);  // TOS mainnet global_id
  ASSERT_EQ(239u, wallet->get_wallet_id().ok());
  ASSERT_EQ(0u, wallet->get_seqno().ok());

  auto address = wallet->get_address();
  CHECK(address.addr.as_slice() == td::Slice(new_wallet_addr).substr(0, 32));

  auto init_message = wallet->get_init_message(priv_key).move_as_ok();
  td::Ref<vm::Cell> ext_init_message = tos::GenericAccount::create_ext_message(
      address, tos::GenericAccount::get_init_state(wallet->get_state()), init_message);
  LOG(ERROR) << "-------";
  vm::load_cell_slice(ext_init_message).print_rec(std::cerr);
  LOG(ERROR) << "-------";
  vm::load_cell_slice(vm::std_boc_deserialize(new_wallet_query).move_as_ok()).print_rec(std::cerr);
  CHECK(vm::std_boc_deserialize(new_wallet_query).move_as_ok()->get_hash() == ext_init_message->get_hash());

  CHECK(wallet.write().send_external_message(init_message).success);

  fift_output.source_lookup.write_file("/main.fif", load_source("smartcont/wallet-v3.fif")).ensure();
  fift_output.source_lookup.write_file("/wallet-v3-code.fif", load_source("smartcont/wallet-v3-code.fif")).ensure();
  fift_output.source_lookup.write_file("/auto/wallet3-code.fif", load_source("smartcont/auto/wallet3-code.fif"))
      .ensure();
  class ZeroOsTime : public fift::OsTime {
   public:
    td::uint32 now() override {
      return 0;
    }
  };
  fift_output.source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
  auto dest = block::StdAddress::parse("Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX").move_as_ok();
  fift_output = fift::mem_run_fift(std::move(fift_output.source_lookup),
                                   {"aba", "new-wallet", "-C", "TESTv3",
                                    "Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX", "239", "1", "321"})
                    .move_as_ok();
  auto wallet_query = fift_output.source_lookup.read_file("wallet-query.boc").move_as_ok().data;

  tos::WalletV3::Gift gift;
  gift.destination = dest;
  gift.message = "TESTv3";
  gift.gramms = 321000000000ll;

  ASSERT_EQ(239u, wallet->get_wallet_id().ok());
  ASSERT_EQ(1u, wallet->get_seqno().ok());
  CHECK(priv_key.get_public_key().ok().as_octet_string() == wallet->get_public_key().ok().as_octet_string());
  CHECK(priv_key.get_public_key().ok().as_octet_string() ==
        tos::GenericAccount::get_public_key(*wallet).ok().as_octet_string());

  auto gift_message = tos::GenericAccount::create_ext_message(
      address, {}, wallet->make_a_gift_message(priv_key, 60, {gift}).move_as_ok());
  LOG(ERROR) << "-------";
  vm::load_cell_slice(gift_message).print_rec(std::cerr);
  LOG(ERROR) << "-------";
  vm::load_cell_slice(vm::std_boc_deserialize(wallet_query).move_as_ok()).print_rec(std::cerr);
  CHECK(vm::std_boc_deserialize(wallet_query).move_as_ok()->get_hash() == gift_message->get_hash());
}

TEST(Toslib, HighloadWallet) {
  auto source_lookup = fift::create_mem_source_lookup(load_source("smartcont/new-highload-wallet.fif")).move_as_ok();
  source_lookup.write_file("/auto/highload-wallet-code.fif", load_source("smartcont/auto/highload-wallet-code.fif"))
      .ensure();
  auto fift_output = fift::mem_run_fift(std::move(source_lookup), {"aba", "0", "239"}).move_as_ok();

  LOG(ERROR) << fift_output.output;
  auto new_wallet_pk = fift_output.source_lookup.read_file("new-wallet.pk").move_as_ok().data;
  auto new_wallet_query = fift_output.source_lookup.read_file("new-wallet239-query.boc").move_as_ok().data;
  auto new_wallet_addr = fift_output.source_lookup.read_file("new-wallet239.addr").move_as_ok().data;

  td::Ed25519::PrivateKey priv_key{td::SecureString{new_wallet_pk}};
  auto pub_key = priv_key.get_public_key().move_as_ok();
  tos::HighloadWallet::InitData init_data(pub_key.as_octet_string(), 239);

  auto wallet = tos::HighloadWallet::create(init_data, -1);
  wallet.write().set_global_id(1);
  auto address = wallet->get_address();
  CHECK(address.addr.as_slice() == td::Slice(new_wallet_addr).substr(0, 32));
  ASSERT_EQ(239u, wallet->get_wallet_id().ok());
  ASSERT_EQ(0u, wallet->get_seqno().ok());
  CHECK(pub_key.as_octet_string() == wallet->get_public_key().ok().as_octet_string());
  CHECK(pub_key.as_octet_string() == tos::GenericAccount::get_public_key(*wallet).ok().as_octet_string());

  CHECK(address.addr.as_slice() == td::Slice(new_wallet_addr).substr(0, 32));

  auto init_message = wallet->get_init_message(priv_key).move_as_ok();
  td::Ref<vm::Cell> res = tos::GenericAccount::create_ext_message(
      address, tos::GenericAccount::get_init_state(wallet->get_state()), init_message);

  LOG(ERROR) << "---smc-envelope----";
  vm::load_cell_slice(res).print_rec(std::cerr);
  LOG(ERROR) << "---fift scripts----";
  vm::load_cell_slice(vm::std_boc_deserialize(new_wallet_query).move_as_ok()).print_rec(std::cerr);
  CHECK(vm::std_boc_deserialize(new_wallet_query).move_as_ok()->get_hash() == res->get_hash());

  fift_output.source_lookup.write_file("/main.fif", load_source("smartcont/highload-wallet.fif")).ensure();
  std::string order;
  std::vector<tos::HighloadWallet::Gift> gifts;
  auto add_order = [&](td::Slice dest_str, td::int64 gramms) {
    auto g = td::to_string(gramms);
    if (g.size() < 10) {
      g = std::string(10 - g.size(), '0') + g;
    }
    order += PSTRING() << "SEND " << dest_str << " " << g.substr(0, g.size() - 9) << "." << g.substr(g.size() - 9)
                       << "\n";

    tos::HighloadWallet::Gift gift;
    gift.destination = block::StdAddress::parse(dest_str).move_as_ok();
    gift.gramms = gramms;
    gifts.push_back(gift);
  };
  std::string dest_str = "Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX";
  add_order(dest_str, 0);
  add_order(dest_str, 321000000000ll);
  add_order(dest_str, 321ll);
  fift_output.source_lookup.write_file("/order", order).ensure();
  class ZeroOsTime : public fift::OsTime {
   public:
    td::uint32 now() override {
      return 0;
    }
  };
  init_data.seqno = 123;
  wallet = tos::HighloadWallet::create(init_data, -1);
  wallet.write().set_global_id(1);
  fift_output.source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
  fift_output = fift::mem_run_fift(std::move(fift_output.source_lookup), {"aba", "new-wallet", "239", "123", "order"})
                    .move_as_ok();
  auto wallet_query = fift_output.source_lookup.read_file("wallet-query.boc").move_as_ok().data;
  auto gift_message = tos::GenericAccount::create_ext_message(
      address, {}, wallet->make_a_gift_message(priv_key, 60, gifts).move_as_ok());
  LOG(ERROR) << "---smc-envelope----";
  vm::load_cell_slice(gift_message).print_rec(std::cerr);
  LOG(ERROR) << "---fift scripts----";
  vm::load_cell_slice(vm::std_boc_deserialize(wallet_query).move_as_ok()).print_rec(std::cerr);
  CHECK(vm::std_boc_deserialize(wallet_query).move_as_ok()->get_hash() == gift_message->get_hash());
}

TEST(Toslib, HighloadWalletV2) {
  auto source_lookup = fift::create_mem_source_lookup(load_source("smartcont/new-highload-wallet-v2.fif")).move_as_ok();
  source_lookup
      .write_file("/auto/highload-wallet-v2-code.fif", load_source("smartcont/auto/highload-wallet-v2-code.fif"))
      .ensure();
  class ZeroOsTime : public fift::OsTime {
   public:
    td::uint32 now() override {
      return 0;
    }
  };
  source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
  auto fift_output = fift::mem_run_fift(std::move(source_lookup), {"aba", "0", "239"}).move_as_ok();

  LOG(ERROR) << fift_output.output;
  auto new_wallet_pk = fift_output.source_lookup.read_file("new-wallet.pk").move_as_ok().data;
  auto new_wallet_query = fift_output.source_lookup.read_file("new-wallet239-query.boc").move_as_ok().data;
  auto new_wallet_addr = fift_output.source_lookup.read_file("new-wallet239.addr").move_as_ok().data;

  td::Ed25519::PrivateKey priv_key{td::SecureString{new_wallet_pk}};
  auto pub_key = priv_key.get_public_key().move_as_ok();
  tos::HighloadWalletV2::InitData init_data(pub_key.as_octet_string(), 239);

  auto wallet = tos::HighloadWalletV2::create(init_data, -1);
  wallet.write().set_global_id(1);
  auto address = wallet->get_address();

  ASSERT_EQ(239u, wallet->get_wallet_id().ok());
  wallet->get_seqno().ensure_error();
  CHECK(pub_key.as_octet_string() == wallet->get_public_key().ok().as_octet_string());
  CHECK(pub_key.as_octet_string() == tos::GenericAccount::get_public_key(*wallet).ok().as_octet_string());

  CHECK(address.addr.as_slice() == td::Slice(new_wallet_addr).substr(0, 32));

  auto init_message = wallet->get_init_message(priv_key, 65535).move_as_ok();
  td::Ref<vm::Cell> res = tos::GenericAccount::create_ext_message(
      address, tos::GenericAccount::get_init_state(wallet->get_state()), init_message);

  LOG(ERROR) << "---smc-envelope----";
  vm::load_cell_slice(res).print_rec(std::cerr);
  LOG(ERROR) << "---fift scripts----";
  vm::load_cell_slice(vm::std_boc_deserialize(new_wallet_query).move_as_ok()).print_rec(std::cerr);
  CHECK(vm::std_boc_deserialize(new_wallet_query).move_as_ok()->get_hash() == res->get_hash());

  fift_output.source_lookup.write_file("/main.fif", load_source("smartcont/highload-wallet-v2.fif")).ensure();
  std::string order;
  std::vector<tos::HighloadWalletV2::Gift> gifts;
  auto add_order = [&](td::Slice dest_str, td::int64 gramms) {
    auto g = td::to_string(gramms);
    if (g.size() < 10) {
      g = std::string(10 - g.size(), '0') + g;
    }
    order += PSTRING() << "SEND " << dest_str << " " << g.substr(0, g.size() - 9) << "." << g.substr(g.size() - 9)
                       << "\n";

    tos::HighloadWalletV2::Gift gift;
    gift.destination = block::StdAddress::parse(dest_str).move_as_ok();
    gift.gramms = gramms;
    gifts.push_back(gift);
  };
  std::string dest_str = "Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX";
  add_order(dest_str, 0);
  add_order(dest_str, 321000000000ll);
  add_order(dest_str, 321ll);
  fift_output.source_lookup.write_file("/order", order).ensure();
  fift_output.source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
  fift_output =
      fift::mem_run_fift(std::move(fift_output.source_lookup), {"aba", "new-wallet", "239", "order"}).move_as_ok();
  auto wallet_query = fift_output.source_lookup.read_file("wallet-query.boc").move_as_ok().data;
  auto gift_message = tos::GenericAccount::create_ext_message(
      address, {}, wallet->make_a_gift_message(priv_key, 60, gifts).move_as_ok());
  LOG(ERROR) << "---smc-envelope----";
  vm::load_cell_slice(gift_message).print_rec(std::cerr);
  LOG(ERROR) << "---fift scripts----";
  vm::load_cell_slice(vm::std_boc_deserialize(wallet_query).move_as_ok()).print_rec(std::cerr);
  CHECK(vm::std_boc_deserialize(wallet_query).move_as_ok()->get_hash() == gift_message->get_hash());
}

namespace {

struct UnpackedWalletExtMessage {
  tos::SmartContract::State state_init;
  td::Ref<vm::Cell> body;
};

// Unpacks an inbound external message produced by the wallet Fift scripts:
// the optional StateInit (code + data) and the signed body.
UnpackedWalletExtMessage unpack_wallet_ext_message(td::Slice serialized_boc) {
  auto msg = vm::std_boc_deserialize(serialized_boc).move_as_ok();
  CHECK(block::gen::t_Message_Any.validate_ref(msg));
  block::gen::Message::Record message;
  CHECK(tlb::type_unpack_cell(msg, block::gen::t_Message_Any, message));

  UnpackedWalletExtMessage res;
  vm::CellSlice init_cs = *message.init;
  if (init_cs.fetch_ulong(1) == 1) {  // Maybe: StateInit present
    vm::CellSlice state_init_cs;
    if (init_cs.fetch_ulong(1) == 1) {  // Either: right, in a reference
      state_init_cs = vm::load_cell_slice(init_cs.fetch_ref());
    } else {
      state_init_cs = init_cs;
    }
    block::gen::StateInit::Record state_init;
    CHECK(tlb::unpack(state_init_cs, state_init));
    if (state_init.code->prefetch_ulong(1) == 1) {
      res.state_init.code = state_init.code->prefetch_ref();
    }
    if (state_init.data->prefetch_ulong(1) == 1) {
      res.state_init.data = state_init.data->prefetch_ref();
    }
  }
  vm::CellSlice body_cs = *message.body;
  if (body_cs.fetch_ulong(1) == 1) {  // Either: right, in a reference
    res.body = body_cs.fetch_ref();
  } else {
    vm::CellBuilder cb;
    cb.append_cellslice(body_cs);
    res.body = cb.finalize();
  }
  return res;
}

std::string gen_test_pubkey_str(const td::Ed25519::PrivateKey& priv_key) {
  auto pub_key = priv_key.get_public_key().move_as_ok().as_octet_string();
  return block::PublicKey::from_bytes(pub_key.as_slice()).move_as_ok().serialize();
}

}  // namespace

TEST(Toslib, RestrictedWalletFiftDeploy) {
  // The deploy queries of restricted wallets v1/v2 must carry the network
  // global_id: the contracts check it before the seqno==0 branch, so a legacy
  // body without it is rejected with exit code 36.
  auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto pub_key_str = gen_test_pubkey_str(priv_key);

  struct Case {
    const char* script;
    std::string code_include;
    const char* code_source;
    std::vector<std::string> args;
  };
  std::vector<Case> cases = {
      {"smartcont/new-restricted-wallet.fif",
       "/auto/restricted-wallet-code.fif",
       "smartcont/auto/restricted-wallet-code.fif",
       {"aba", pub_key_str}},
      {"smartcont/new-restricted-wallet2.fif",
       "/auto/restricted-wallet2-code.fif",
       "smartcont/auto/restricted-wallet2-code.fif",
       {"aba", pub_key_str, "1000"}},
  };
  for (auto& c : cases) {
    auto source_lookup = fift::create_mem_source_lookup(load_source(c.script)).move_as_ok();
    source_lookup.write_file(c.code_include, load_source(c.code_source)).ensure();
    auto fift_output = fift::mem_run_fift(std::move(source_lookup), c.args).move_as_ok();
    auto query = fift_output.source_lookup.read_file("rwallet-query.boc").move_as_ok().data;

    auto unpacked = unpack_wallet_ext_message(query);
    CHECK(unpacked.state_init.code.not_null());
    CHECK(unpacked.state_init.data.not_null());
    auto initial_state = unpacked.state_init;

    tos::SmartContract smc(std::move(unpacked.state_init));
    auto answer = smc.send_external_message(unpacked.body, tos::SmartContract::Args().set_now(1));
    LOG_IF(ERROR, !answer.success) << c.script << ": deploy failed with exit code " << answer.code;
    CHECK(answer.accepted);
    CHECK(answer.success);

    // A legacy deploy body without the leading global_id must keep failing.
    vm::CellBuilder legacy;
    legacy.store_zeroes(512);   // placeholder signature
    legacy.store_long(0, 32);   // seqno
    legacy.store_long(-1, 32);  // valid_until
    tos::SmartContract fresh_smc(std::move(initial_state));
    auto legacy_answer = fresh_smc.send_external_message(legacy.finalize(), tos::SmartContract::Args().set_now(1));
    CHECK(!legacy_answer.success);
    ASSERT_EQ(36, legacy_answer.code);
  }
}

TEST(Toslib, RestrictedWallet3FiftDeploy) {
  // The signed init body of restricted wallet v3 must start with the network
  // global_id, followed by subwallet id, expiration, seqno, start time and the
  // restriction dictionary, matching the compiled contract layout.
  auto init_priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto main_priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto main_pub_key_str = gen_test_pubkey_str(main_priv_key);

  auto source_lookup = fift::create_mem_source_lookup(load_source("smartcont/new-restricted-wallet3.fif")).move_as_ok();
  source_lookup
      .write_file("/auto/restricted-wallet3-code.fif", load_source("smartcont/auto/restricted-wallet3-code.fif"))
      .ensure();
  source_lookup.write_file("main.pk", init_priv_key.as_octet_string().as_slice()).ensure();
  auto fift_output =
      fift::mem_run_fift(std::move(source_lookup), {"aba", "main", main_pub_key_str, "1000"}).move_as_ok();
  auto query = fift_output.source_lookup.read_file("new-rwallet.boc").move_as_ok().data;

  auto unpacked = unpack_wallet_ext_message(query);
  CHECK(unpacked.state_init.code.not_null());
  CHECK(unpacked.state_init.data.not_null());

  tos::SmartContract smc(std::move(unpacked.state_init));
  auto answer = smc.send_external_message(unpacked.body, tos::SmartContract::Args().set_now(1));
  LOG_IF(ERROR, !answer.success) << "restricted wallet v3 deploy failed with exit code " << answer.code;
  CHECK(answer.accepted);
  CHECK(answer.success);
}

TEST(Toslib, HighloadWalletV2OneFiftScript) {
  // A single query built by the one-shot highload v2 script must carry the
  // network global_id and execute against the compiled contract.
  auto source_lookup = fift::create_mem_source_lookup(load_source("smartcont/new-highload-wallet-v2.fif")).move_as_ok();
  source_lookup
      .write_file("/auto/highload-wallet-v2-code.fif", load_source("smartcont/auto/highload-wallet-v2-code.fif"))
      .ensure();
  class ZeroOsTime : public fift::OsTime {
   public:
    td::uint32 now() override {
      return 0;
    }
  };
  source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
  auto fift_output = fift::mem_run_fift(std::move(source_lookup), {"aba", "0", "239"}).move_as_ok();
  auto init_query = fift_output.source_lookup.read_file("new-wallet239-query.boc").move_as_ok().data;
  auto wallet_state = unpack_wallet_ext_message(init_query).state_init;
  CHECK(wallet_state.code.not_null());
  CHECK(wallet_state.data.not_null());

  fift_output.source_lookup.write_file("/main.fif", load_source("smartcont/highload-wallet-v2-one.fif")).ensure();
  fift_output.source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
  fift_output =
      fift::mem_run_fift(std::move(fift_output.source_lookup),
                         {"aba", "new-wallet", "Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX", "239", "321"})
          .move_as_ok();
  auto transfer_query = fift_output.source_lookup.read_file("wallet-query.boc").move_as_ok().data;
  auto transfer = unpack_wallet_ext_message(transfer_query);
  CHECK(transfer.state_init.code.is_null());

  tos::SmartContract smc(std::move(wallet_state));
  auto answer = smc.send_external_message(transfer.body, tos::SmartContract::Args().set_now(0));
  LOG_IF(ERROR, !answer.success) << "highload v2 one-shot query failed with exit code " << answer.code;
  CHECK(answer.accepted);
  CHECK(answer.success);
  ASSERT_EQ(1u, tos::SmartContract::Answer::output_actions_count(answer.actions));
}

TEST(Toslib, SimpleWalletFiftScripts) {
  // The v1/v2 deploy scripts must ship the compiled wallet code (which checks
  // the signed global_id), and the matching transfer scripts must produce
  // bodies that execute against that code.
  class ZeroOsTime : public fift::OsTime {
   public:
    td::uint32 now() override {
      return 0;
    }
  };
  struct Case {
    const char* new_script;
    std::string code_include;
    const char* code_source;
    const char* transfer_script;
  };
  std::vector<Case> cases = {
      {"smartcont/new-wallet.fif", "/auto/simple-wallet-code.fif", "smartcont/auto/simple-wallet-code.fif",
       "smartcont/wallet.fif"},
      {"smartcont/new-wallet-v2.fif", "/auto/wallet-code.fif", "smartcont/auto/wallet-code.fif",
       "smartcont/wallet-v2.fif"},
  };
  for (auto& c : cases) {
    auto source_lookup = fift::create_mem_source_lookup(load_source(c.new_script)).move_as_ok();
    source_lookup.write_file(c.code_include, load_source(c.code_source)).ensure();
    source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
    auto fift_output = fift::mem_run_fift(std::move(source_lookup), {"aba", "0", "w1"}).move_as_ok();
    auto init_query = fift_output.source_lookup.read_file("w1-query.boc").move_as_ok().data;

    auto unpacked = unpack_wallet_ext_message(init_query);
    CHECK(unpacked.state_init.code.not_null());
    CHECK(unpacked.state_init.data.not_null());
    tos::SmartContract smc(std::move(unpacked.state_init));
    auto answer = smc.send_external_message(unpacked.body, tos::SmartContract::Args().set_now(0));
    LOG_IF(ERROR, !answer.success) << c.new_script << ": deploy failed with exit code " << answer.code;
    CHECK(answer.accepted);
    CHECK(answer.success);

    fift_output.source_lookup.write_file("/main.fif", load_source(c.transfer_script)).ensure();
    fift_output.source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
    fift_output = fift::mem_run_fift(std::move(fift_output.source_lookup),
                                     {"aba", "w1", "Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX", "1", "321"})
                      .move_as_ok();
    auto transfer_query = fift_output.source_lookup.read_file("wallet-query.boc").move_as_ok().data;
    auto transfer = unpack_wallet_ext_message(transfer_query);
    auto transfer_answer = smc.send_external_message(transfer.body, tos::SmartContract::Args().set_now(0));
    LOG_IF(ERROR, !transfer_answer.success)
        << c.transfer_script << ": transfer failed with exit code " << transfer_answer.code;
    CHECK(transfer_answer.accepted);
    CHECK(transfer_answer.success);
    ASSERT_EQ(1u, tos::SmartContract::Answer::output_actions_count(transfer_answer.actions));
  }
}

TEST(Toslib, AutoDnsFiftScript) {
  const td::Slice auto_dns_addr = "Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX";
  auto fift_output = fift::mem_run_fift(load_source("smartcont/auto-dns.fif"),
                                        {"aba", auto_dns_addr.str(), "prolong", "alpha.beta", "60"})
                         .move_as_ok();

  auto boc = fift_output.source_lookup.read_file("dns-msg-body.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(boc).move_as_ok().not_null());
}

TEST(Toslib, ManualDnsFiftScript) {
  auto source_lookup = fift::create_mem_source_lookup(load_source("smartcont/manual-dns-manage.fif")).move_as_ok();
  auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  std::string addr_file(36, '\0');

  source_lookup.write_file("dns-wallet.pk", priv_key.as_octet_string().as_slice()).ensure();
  source_lookup.write_file("dns-wallet-dns1.addr", td::Slice(addr_file)).ensure();

  auto fift_output =
      fift::mem_run_fift(std::move(source_lookup), {"aba", "dns-wallet", "1", "add", "alpha.beta", "cat", "1", "text",
                                                    "hello", "delete", "beta.alpha", "cat", "7"})
          .move_as_ok();

  auto boc = fift_output.source_lookup.read_file("dns-query.boc").move_as_ok().data;
  CHECK(vm::std_boc_deserialize(boc).move_as_ok().not_null());
}

TEST(Toslib, ValidatorFiftScriptRegression) {
  REGRESSION_VERIFY(run_validator_fift_script_regression());
}

TEST(Toslib, GovernanceVoteFiftScriptRegression) {
  REGRESSION_VERIFY(run_governance_vote_fift_script_regression());
}

TEST(Toslib, GovernanceProposalFiftScriptRegression) {
  REGRESSION_VERIFY(run_governance_proposal_fift_script_regression());
}

TEST(Toslib, GenZerostateFiftRegression) {
  // Canonical mainnet template — native (wc=0) only (see F1, gen-zerostate.fif).
  REGRESSION_VERIFY(run_zerostate_regression("gen-zerostate.fif"));
}

TEST(Toslib, RestrictedWallet) {
  //auto source_lookup = fift::create_mem_source_lookup(load_source("smartcont/new-restricted-wallet2.fif")).move_as_ok();
  //source_lookup
  //.write_file("/auto/restricted-wallet2-code.fif", load_source("smartcont/auto/restricted-wallet2-code.fif"))
  //.ensure();
  //class ZeroOsTime : public fift::OsTime {
  //public:
  //td::uint32 now() override {
  //return 0;
  //}
  //};
  //source_lookup.set_os_time(std::make_unique<ZeroOsTime>());
  //auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  //auto pub_key = priv_key.get_public_key().move_as_ok();
  //auto pub_key_serialized = block::PublicKey::from_bytes(pub_key.as_octet_string()).move_as_ok().serialize(true);

  //std::vector<std::string> args = {"path", pub_key_serialized, std::string("100")};
  //auto fift_output = fift::mem_run_fift(std::move(source_lookup), args).move_as_ok();

  //tos::RestrictedWallet::InitData init_data;
  //td::uint64 x = 100 * 1000000000ull;
  //init_data.key = &pub_key;
  //init_data.start_at = 0;
  //init_data.limits = {{-32768, x}, {92, x * 3 / 4}, {183, x * 1 / 2}, {366, x * 1 / 4}, {548, 0}};
  //auto wallet = tos::RestrictedWallet::create(init_data, -1);

  //ASSERT_EQ(0u, wallet->get_seqno().move_as_ok());
  //CHECK(pub_key.as_octet_string() == wallet->get_public_key().move_as_ok().as_octet_string());
  ////LOG(ERROR) << wallet->get_balance(x, 60 * 60 * 24 * 400).move_as_ok();

  //auto new_wallet_query = fift_output.source_lookup.read_file("rwallet-query.boc").move_as_ok().data;
  //auto new_wallet_addr = fift_output.source_lookup.read_file("rwallet.addr").move_as_ok().data;

  //auto address = wallet->get_address(-1);
  ////CHECK(address.addr.as_slice() == td::Slice(new_wallet_addr).substr(0, 32));
  //address.bounceable = false;
  //auto res = tos::GenericAccount::create_ext_message(address, wallet->get_init_state(),
  //wallet->get_init_message(priv_key).move_as_ok());
  //LOG(ERROR) << "-------";
  //vm::load_cell_slice(res).print_rec(std::cerr);
  //LOG(ERROR) << "-------";
  //vm::load_cell_slice(vm::std_boc_deserialize(new_wallet_query).move_as_ok()).print_rec(std::cerr);
  //CHECK(vm::std_boc_deserialize(new_wallet_query).move_as_ok()->get_hash() == res->get_hash());

  //auto dest = block::StdAddress::parse("Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX").move_as_ok();
  //fift_output.source_lookup.write_file("/main.fif", load_source("smartcont/wallet-v2.fif")).ensure();
  //fift_output.source_lookup.write_file("rwallet.pk", priv_key.as_octet_string().as_slice()).ensure();
  //fift_output = fift::mem_run_fift(
  //std::move(fift_output.source_lookup),
  //{"aba", "rwallet", "-C", "TESTv2", "Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX", "0", "321"})
  //.move_as_ok();
  //auto wallet_query = fift_output.source_lookup.read_file("wallet-query.boc").move_as_ok().data;
  //tos::TestWallet::Gift gift;
  //gift.destination = dest;
  //gift.message = "TESTv2";
  //gift.gramms = 321000000000ll;
  ////CHECK(priv_key.get_public_key().ok().as_octet_string() == wallet->get_public_key().ok().as_octet_string());
  //auto gift_message = tos::GenericAccount::create_ext_message(
  //address, {}, wallet->make_a_gift_message(priv_key, 60, {gift}).move_as_ok());
  //LOG(ERROR) << "-------";
  //vm::load_cell_slice(gift_message).print_rec(std::cerr);
  //LOG(ERROR) << "-------";
  //vm::load_cell_slice(vm::std_boc_deserialize(wallet_query).move_as_ok()).print_rec(std::cerr);
  //CHECK(vm::std_boc_deserialize(wallet_query).move_as_ok()->get_hash() == gift_message->get_hash());
}
TEST(Toslib, RestrictedWallet3) {
  auto init_priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto init_pub_key = init_priv_key.get_public_key().move_as_ok();
  auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto pub_key = priv_key.get_public_key().move_as_ok();

  tos::RestrictedWallet::InitData init_data;
  init_data.init_key = init_pub_key.as_octet_string();
  init_data.main_key = pub_key.as_octet_string();
  init_data.wallet_id = 123;
  auto wallet = tos::RestrictedWallet::create(init_data, -1);
  wallet.write().set_global_id(1);

  auto address = wallet->get_address();

  td::uint64 x = 100 * 1000000000ull;
  tos::RestrictedWallet::Config config;
  config.start_at = 1;
  config.limits = {{-32768, x}, {92, x * 3 / 4}, {183, x * 1 / 2}, {366, x * 1 / 4}, {548, 0}};
  CHECK(wallet.write().send_external_message(wallet->get_init_message(init_priv_key, 10, config).move_as_ok()).success);
  CHECK(wallet->get_seqno().move_as_ok() == 1);

  tos::WalletInterface::Gift gift;
  gift.destination = address;
  gift.message = "hello";
  CHECK(wallet.write().send_external_message(wallet->make_a_gift_message(priv_key, 10, {gift}).move_as_ok()).success);
  CHECK(wallet->get_seqno().move_as_ok() == 2);
}

template <class T>
void check_wallet_seqno(td::Ref<T> wallet, td::uint32 seqno) {
  ASSERT_EQ(seqno, wallet->get_seqno().ok());
}
void check_wallet_seqno(td::Ref<tos::HighloadWalletV2> wallet, td::uint32 seqno) {
}
void check_wallet_seqno(td::Ref<tos::WalletInterface> wallet, td::uint32 seqno) {
}
template <class T>
void check_wallet_state(td::Ref<T> wallet, td::uint32 seqno, td::uint32 wallet_id, td::Slice public_key) {
  ASSERT_EQ(wallet_id, wallet->get_wallet_id().ok());
  ASSERT_EQ(public_key, wallet->get_public_key().ok().as_octet_string().as_slice());
  check_wallet_seqno(wallet, seqno);
}

struct CreatedWallet {
  td::optional<td::Ed25519::PrivateKey> priv_key;
  block::StdAddress address;
  td::Ref<tos::WalletInterface> wallet;
};

template <class T>
class InitWallet {
 public:
  CreatedWallet operator()(int revision) const {
    tos::WalletInterface::DefaultInitData init_data;
    auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
    auto pub_key = priv_key.get_public_key().move_as_ok();

    init_data.seqno = 0;
    init_data.wallet_id = 123;
    init_data.public_key = pub_key.as_octet_string();

    auto wallet = T::create(init_data, revision);
    wallet.write().set_global_id(1);
    auto address = wallet->get_address();
    check_wallet_state(wallet, 0, 123, init_data.public_key);
    CHECK(wallet.write().send_external_message(wallet->get_init_message(priv_key).move_as_ok()).success);

    CreatedWallet res;
    res.wallet = std::move(wallet);
    res.address = std::move(address);
    res.priv_key = std::move(priv_key);
    return res;
  }
};

template <>
CreatedWallet InitWallet<tos::RestrictedWallet>::operator()(int revision) const {
  auto init_priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto init_pub_key = init_priv_key.get_public_key().move_as_ok();
  auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto pub_key = priv_key.get_public_key().move_as_ok();

  tos::RestrictedWallet::InitData init_data;
  init_data.init_key = init_pub_key.as_octet_string();
  init_data.main_key = pub_key.as_octet_string();
  init_data.wallet_id = 123;
  auto wallet = tos::RestrictedWallet::create(init_data, revision);
  wallet.write().set_global_id(1);
  check_wallet_state(wallet, 0, 123, init_data.init_key);

  auto address = wallet->get_address();

  td::uint64 x = 100 * 1000000000ull;
  tos::RestrictedWallet::Config config;
  config.start_at = 1;
  config.limits = {{-32768, x}, {92, x * 3 / 4}, {183, x * 1 / 2}, {366, x * 1 / 4}, {548, 0}};
  CHECK(wallet.write().send_external_message(wallet->get_init_message(init_priv_key, 10, config).move_as_ok()).success);
  CHECK(wallet->get_seqno().move_as_ok() == 1);

  CreatedWallet res;
  res.wallet = std::move(wallet);
  res.address = std::move(address);
  res.priv_key = std::move(priv_key);
  return res;
}

template <class T>
void do_test_wallet(int revision) {
  auto res = InitWallet<T>()(revision);
  auto priv_key = res.priv_key.unwrap();
  auto address = std::move(res.address);
  auto iwallet = std::move(res.wallet);
  auto public_key = priv_key.get_public_key().move_as_ok().as_octet_string();

  check_wallet_state(iwallet, 1, 123, public_key);

  // lets send a lot of messages
  std::vector<tos::WalletInterface::Gift> gifts;
  for (size_t i = 0; i < iwallet->get_max_gifts_size(); i++) {
    tos::WalletInterface::Gift gift;
    gift.gramms = 1;
    gift.destination = address;
    gift.message = std::string(iwallet->get_max_message_size(), 'z');
    gifts.push_back(gift);
  }

  td::uint32 valid_until = 10000;
  auto send_gifts = iwallet->make_a_gift_message(priv_key, valid_until, gifts).move_as_ok();

  {
    auto cwallet = iwallet;
    CHECK(!cwallet.write()
               .send_external_message(send_gifts, tos::SmartContract::Args().set_now(valid_until + 1))
               .success);
  }
  //TODO: make wallet work (or not) with now == valid_until
  auto ans = iwallet.write().send_external_message(send_gifts, tos::SmartContract::Args().set_now(valid_until - 1));
  CHECK(ans.success);
  const size_t out_actions = static_cast<size_t>(ans.output_actions_count(ans.actions));
  CHECK(gifts.size() <= out_actions);
  check_wallet_state(iwallet, 2, 123, public_key);
}

template <class T>
void do_test_wallet() {
  for (auto revision : T::get_revisions()) {
    do_test_wallet<T>(revision);
  }
}

TEST(Toslib, Wallet) {
  do_test_wallet<tos::WalletV3>();
  do_test_wallet<tos::WalletV4>();
  do_test_wallet<tos::HighloadWallet>();
  do_test_wallet<tos::HighloadWalletV2>();
  do_test_wallet<tos::RestrictedWallet>();
}

TEST(Smartcont, GenericAccountCheckedExternalMessage) {
  auto code = vm::CellBuilder().store_long(0x11, 8).finalize();
  auto data = vm::CellBuilder().store_long(0x22, 8).finalize();
  auto body = vm::CellBuilder().store_long(0x33, 8).finalize();
  block::StdAddress address{0, td::Bits256::zero(), true};

  auto full_state_r = tos::GenericAccount::get_init_state_checked(code, data);
  ASSERT_TRUE(full_state_r.is_ok());
  ASSERT_EQ(full_state_r.ok()->get_hash(), tos::GenericAccount::get_init_state(code, data)->get_hash());

  auto code_only_state_r = tos::GenericAccount::get_init_state_checked(code, {});
  ASSERT_TRUE(code_only_state_r.is_ok());
  auto code_only_raw_state = tos::GenericAccount::get_init_state(code, {});
  ASSERT_TRUE(code_only_raw_state.not_null());
  ASSERT_EQ(code_only_raw_state->get_hash(), code_only_state_r.ok()->get_hash());
  block::gen::StateInit::Record code_only_state;
  ASSERT_TRUE(tlb::unpack_cell(code_only_state_r.move_as_ok(), code_only_state));
  ASSERT_TRUE(code_only_state.code.not_null());
  ASSERT_TRUE(code_only_state.data.not_null());
  ASSERT_EQ(code_only_state.code->prefetch_ulong(1), 1u);
  ASSERT_EQ(code_only_state.data->prefetch_ulong(1), 0u);
  ASSERT_EQ(code_only_state.code->prefetch_ref()->get_hash(), code->get_hash());
  ASSERT_TRUE(code_only_state.data->prefetch_ref().is_null());

  auto data_only_state_r = tos::GenericAccount::get_init_state_checked({}, data);
  ASSERT_TRUE(data_only_state_r.is_ok());
  auto data_only_raw_state = tos::GenericAccount::get_init_state({}, data);
  ASSERT_TRUE(data_only_raw_state.not_null());
  ASSERT_EQ(data_only_raw_state->get_hash(), data_only_state_r.ok()->get_hash());
  block::gen::StateInit::Record data_only_state;
  ASSERT_TRUE(tlb::unpack_cell(data_only_state_r.move_as_ok(), data_only_state));
  ASSERT_TRUE(data_only_state.code.not_null());
  ASSERT_TRUE(data_only_state.data.not_null());
  ASSERT_EQ(data_only_state.code->prefetch_ulong(1), 0u);
  ASSERT_EQ(data_only_state.data->prefetch_ulong(1), 1u);
  ASSERT_TRUE(data_only_state.code->prefetch_ref().is_null());
  ASSERT_EQ(data_only_state.data->prefetch_ref()->get_hash(), data->get_hash());

  auto code_only_message = tos::GenericAccount::create_ext_message_checked(address, code, {}, body);
  ASSERT_TRUE(code_only_message.is_ok());
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(code_only_message.ok()));

  auto data_only_message = tos::GenericAccount::create_ext_message_checked(address, {}, data, body);
  ASSERT_TRUE(data_only_message.is_ok());
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(data_only_message.ok()));

  auto raw_code_only_message = tos::GenericAccount::create_ext_message(address, code_only_raw_state, body);
  ASSERT_TRUE(raw_code_only_message.not_null());
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(raw_code_only_message));

  auto raw_data_only_message = tos::GenericAccount::create_ext_message(address, data_only_raw_state, body);
  ASSERT_TRUE(raw_data_only_message.not_null());
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(raw_data_only_message));
}

TEST(Smartcont, GenericAccountCheckedExternalMessageCatchesCellBuilderFailure) {
  td::Ref<vm::Cell> max_depth_code = vm::CellBuilder().finalize();
  for (int depth = 0; depth < vm::Cell::max_depth; ++depth) {
    max_depth_code = vm::CellBuilder().store_ref(std::move(max_depth_code)).finalize();
  }
  ASSERT_EQ(max_depth_code->get_depth(), vm::Cell::max_depth);

  auto body = vm::CellBuilder().finalize();
  block::StdAddress address{0, td::Bits256::zero(), true};
  ASSERT_TRUE(tos::GenericAccount::get_init_state(max_depth_code, {}).is_null());
  auto message = tos::GenericAccount::create_ext_message_checked(address, max_depth_code, {}, body);
  ASSERT_TRUE(message.is_error());
  ASSERT_EQ(message.error().message(), "Got cell write error");
}

TEST(Toslib, WalletV4) {
  // Test V4 basic functionality: create, init, transfer with op=0
  auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto pub_key = priv_key.get_public_key().move_as_ok();

  tos::WalletV4::InitData init_data;
  init_data.public_key = pub_key.as_octet_string();
  init_data.wallet_id = 42;
  init_data.seqno = 0;

  auto wallet = tos::WalletV4::create(init_data, -1);
  wallet.write().set_global_id(1);
  auto address = wallet->get_address();

  // Verify initial state
  ASSERT_EQ(42u, wallet->get_wallet_id().ok());
  ASSERT_EQ(0u, wallet->get_seqno().ok());

  // Send init message
  auto init_msg = wallet->get_init_message(priv_key).move_as_ok();
  CHECK(wallet.write().send_external_message(init_msg).success);
  ASSERT_EQ(1u, wallet->get_seqno().ok());

  // Send a transfer (op=0)
  tos::WalletInterface::Gift gift;
  gift.gramms = 1;
  gift.destination = address;
  gift.message = "test v4";
  auto gift_msg = wallet->make_a_gift_message(priv_key, 10000, {gift}).move_as_ok();
  auto ans = wallet.write().send_external_message(gift_msg, tos::SmartContract::Args().set_now(9999));
  CHECK(ans.success);
  ASSERT_EQ(2u, wallet->get_seqno().ok());

  // Test expired message is rejected
  auto expired_msg = wallet->make_a_gift_message(priv_key, 100, {gift}).move_as_ok();
  CHECK(!wallet.write().send_external_message(expired_msg, tos::SmartContract::Args().set_now(101)).success);
  ASSERT_EQ(2u, wallet->get_seqno().ok());  // seqno unchanged

  // Test global_id mismatch: set wrong global_id, sign, then try to execute on correct chain
  wallet.write().set_global_id(2);  // wrong chain
  auto wrong_chain_msg = wallet->make_a_gift_message(priv_key, 20000, {gift}).move_as_ok();
  wallet.write().set_global_id(1);  // restore correct chain
  CHECK(!wallet.write().send_external_message(wrong_chain_msg, tos::SmartContract::Args().set_now(19999)).success);
  ASSERT_EQ(2u, wallet->get_seqno().ok());  // seqno unchanged
}

namespace {

// Signs and wraps a wallet-v4 external message body that has already been
// prefixed with global_id, wallet_id, valid_until and seqno.
td::Ref<vm::Cell> sign_wallet_v4_body(const td::Ed25519::PrivateKey& priv_key, vm::CellBuilder& body) {
  auto inner = body.finalize();
  auto signature = priv_key.sign(inner->get_hash().as_slice()).move_as_ok();
  return vm::CellBuilder().store_bytes(signature).append_cellslice(vm::load_cell_slice(inner)).finalize();
}

struct SentMessage {
  td::RefInt256 value;
  td::uint32 body_op = 0;
};

// Walks the action list produced by a transaction and returns every
// outbound internal message with its declared value and body opcode.
std::vector<SentMessage> collect_sent_messages(td::Ref<vm::Cell> actions) {
  std::vector<SentMessage> result;
  while (actions.not_null()) {
    auto cs = vm::load_cell_slice(actions);
    if (cs.size_refs() < 1) {
      break;
    }
    auto prev = cs.fetch_ref();
    if (cs.size() >= 32 && cs.prefetch_ulong(32) == 0x0ec3c86d) {
      cs.advance(32);
      cs.advance(8);  // mode
      auto msg_cs = vm::load_cell_slice(cs.fetch_ref());
      block::gen::CommonMsgInfoRelaxed::Record_int_msg_info info;
      CHECK(tlb::unpack(msg_cs, info));
      SentMessage sent;
      sent.value = block::tlb::t_CurrencyCollection.as_integer(info.value);
      CHECK(msg_cs.fetch_ulong(1) == 0);  // no init
      CHECK(msg_cs.fetch_ulong(1) == 0);  // body inline
      if (msg_cs.size() >= 32) {
        sent.body_op = static_cast<td::uint32>(msg_cs.fetch_ulong(32));
      }
      result.push_back(std::move(sent));
    }
    actions = std::move(prev);
  }
  return result;
}

}  // namespace

TEST(Toslib, WalletV4PluginFundRequest) {
  // A plugin may draw exactly what it asks for, never the rest of the
  // wallet's balance, and only if the wallet can afford it.
  auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto pub_key = priv_key.get_public_key().move_as_ok();

  tos::WalletV4::InitData init_data;
  init_data.public_key = pub_key.as_octet_string();
  init_data.wallet_id = 42;
  init_data.seqno = 0;
  auto wallet = tos::WalletV4::create(init_data, 0);
  wallet.write().set_global_id(1);
  CHECK(wallet.write().send_external_message(wallet->get_init_message(priv_key).move_as_ok()).success);
  ASSERT_EQ(1u, wallet->get_seqno().ok());

  block::StdAddress plugin{0, td::Bits256::ones(), true};
  block::StdAddress stranger{0, td::Bits256::zero(), true};

  // Install the plugin through the owner's signed message (op 1).
  {
    vm::CellBuilder body;
    body.store_long(1, 32).store_long(42, 32).store_long(20000, 32).store_long(1, 32);
    body.store_long(1, 8).store_long(plugin.workchain, 8).store_bits(plugin.addr.cbits(), 256);
    auto msg = sign_wallet_v4_body(priv_key, body);
    CHECK(wallet.write().send_external_message(msg, tos::SmartContract::Args().set_now(10000)).success);
    ASSERT_EQ(2u, wallet->get_seqno().ok());
  }

  const td::uint64 balance = 100'000'000'000ull;  // 100 TOS held by the wallet
  const td::uint64 attached = 1'000'000'000ull;   // 1 TOS attached by the plugin
  auto request_coins = [&](td::uint64 amount) {
    vm::CellBuilder cb;
    cb.store_long(0x706c7567, 32).store_long(7, 64);
    CHECK(block::tlb::t_Tomis.store_integer_value(cb, td::BigInt256(static_cast<long long>(amount))));
    return cb.finalize();
  };

  // An installed plugin asking for 1 TOS receives exactly 1 TOS.
  {
    auto ans = wallet.write().send_internal_message(
        request_coins(1'000'000'000ull),
        tos::SmartContract::Args().set_balance(balance + attached).set_amount(attached).set_sender_address(plugin));
    CHECK(ans.success);
    auto sent = collect_sent_messages(ans.actions);
    ASSERT_EQ(1u, sent.size());
    ASSERT_EQ(td::make_refint(1'000'000'000ull)->to_dec_string(), sent[0].value->to_dec_string());
    ASSERT_EQ(0x706c7567u | 0x80000000u, sent[0].body_op);
  }

  // Asking for more than the wallet holds (beyond the attached value) fails.
  {
    auto ans = wallet.write().send_internal_message(
        request_coins(balance + 1),
        tos::SmartContract::Args().set_balance(balance + attached).set_amount(attached).set_sender_address(plugin));
    CHECK(!ans.success);
  }

  // A sender that is not an installed plugin gets nothing.
  {
    auto ans = wallet.write().send_internal_message(
        request_coins(1'000'000'000ull),
        tos::SmartContract::Args().set_balance(balance + attached).set_amount(attached).set_sender_address(stranger));
    CHECK(ans.success);
    ASSERT_EQ(0u, collect_sent_messages(ans.actions).size());
  }
}

TEST(Toslib, WalletV5) {
  // Test V5 using direct contract interaction (no C++ wrapper class)
  auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto pub_key = priv_key.get_public_key().move_as_ok();

  // Load V5 contract code
  auto code = tos::SmartContractCode::get_code(tos::SmartContractCode::WalletV5);
  CHECK(code.not_null());

  // Build initial data: is_signature_allowed(1) + seqno(32) + wallet_id(32) + public_key(256) + extensions(dict)
  td::uint32 wallet_id = 42;
  auto data = vm::CellBuilder()
                  .store_long(-1, 1)  // is_signature_allowed = true
                  .store_long(0, 32)  // seqno = 0
                  .store_long(wallet_id, 32)
                  .store_bytes(pub_key.as_octet_string())
                  .store_zeroes(1)  // empty extensions dict
                  .finalize();

  tos::SmartContract::State state{code, data};
  auto wallet = tos::SmartContract::create(state);

  // Verify get methods
  auto seqno_res = wallet->run_get_method("seqno");
  ASSERT_EQ(0, seqno_res.stack.write().pop_smallint_range(1000000));

  auto wid_res = wallet->run_get_method("get_subwallet_id");
  ASSERT_EQ(42, wid_res.stack.write().pop_smallint_range(1000000));

  auto pk_res = wallet->run_get_method("get_public_key");
  auto got_pk = pk_res.stack.write().pop_int_finite();
  CHECK(got_pk->bit_size(false) <= 256);

  auto sig_res = wallet->run_get_method("is_signature_allowed");
  ASSERT_EQ(-1, sig_res.stack.write().pop_smallint_range(1, -1));

  // Build and send a signed external message
  // V5 format: prefix(32) | global_id(32) | wallet_id(32) | valid_until(32) | seqno(32) | actions | signature(512)
  // signature is at the END of the message
  td::int32 global_id = 1;
  td::uint32 valid_until = 10000;
  td::uint32 seqno = 0;

  // Build signed body (no actions: empty maybe_ref + no other_actions)
  vm::CellBuilder body_cb;
  body_cb.store_long(0x7369676E, 32);  // prefix::signed_external
  body_cb.store_long(global_id, 32);
  body_cb.store_long(wallet_id, 32);
  body_cb.store_long(valid_until, 32);
  body_cb.store_long(seqno, 32);
  body_cb.store_zeroes(1);  // no c5_actions (Maybe Cell = nothing)
  body_cb.store_zeroes(1);  // no other_actions
  auto body_cell = body_cb.finalize();

  // Sign the body
  auto body_hash = body_cell->get_hash();
  auto signature = priv_key.sign(body_hash.as_slice()).move_as_ok();

  // Append signature at the end
  vm::CellBuilder msg_cb;
  msg_cb.append_cellslice(vm::load_cell_slice(body_cell));
  msg_cb.store_bytes(signature);
  auto ext_msg = msg_cb.finalize();

  // Send external message
  auto ans =
      wallet.write().send_external_message(ext_msg, tos::SmartContract::Args().set_now(9999).set_global_id(global_id));
  CHECK(ans.success);

  // Verify seqno incremented
  seqno_res = wallet->run_get_method("seqno");
  ASSERT_EQ(1, seqno_res.stack.write().pop_smallint_range(1000000));

  // Test global_id mismatch: sign with global_id=2, execute on chain with global_id=1
  seqno = 1;
  vm::CellBuilder bad_body_cb;
  bad_body_cb.store_long(0x7369676E, 32);
  bad_body_cb.store_long(2, 32);  // wrong global_id
  bad_body_cb.store_long(wallet_id, 32);
  bad_body_cb.store_long(valid_until, 32);
  bad_body_cb.store_long(seqno, 32);
  bad_body_cb.store_zeroes(1);
  bad_body_cb.store_zeroes(1);
  auto bad_body = bad_body_cb.finalize();
  auto bad_sig = priv_key.sign(bad_body->get_hash().as_slice()).move_as_ok();
  vm::CellBuilder bad_msg_cb;
  bad_msg_cb.append_cellslice(vm::load_cell_slice(bad_body));
  bad_msg_cb.store_bytes(bad_sig);

  auto bad_ans = wallet.write().send_external_message(bad_msg_cb.finalize(),
                                                      tos::SmartContract::Args().set_now(9999).set_global_id(1));
  CHECK(!bad_ans.success);  // should fail: global_id mismatch

  // Seqno should not have changed
  seqno_res = wallet->run_get_method("seqno");
  ASSERT_EQ(1, seqno_res.stack.write().pop_smallint_range(1000000));
}

namespace std {  // ouch
bool operator<(const tos::MultisigWallet::Mask& a, const tos::MultisigWallet::Mask& b) {
  for (size_t i = 0; i < a.size(); i++) {
    if (a[i] != b[i]) {
      return a[i] < b[i];
    }
  }
  return false;
}
}  // namespace std

TEST(Smartcon, Multisig) {
  auto ms_lib = tos::MultisigWallet::create();

  int n = 50;
  int k = 49;
  td::uint32 wallet_id = std::numeric_limits<td::uint32>::max() - 3;
  std::vector<td::Ed25519::PrivateKey> keys;
  for (int i = 0; i < n; i++) {
    keys.push_back(td::Ed25519::generate_private_key().move_as_ok());
  }
  auto init_state = ms_lib->create_init_data(
      wallet_id, td::transform(keys, [](auto& key) { return key.get_public_key().ok().as_octet_string(); }), k);
  auto ms = tos::MultisigWallet::create(init_state);

  td::uint32 now = 0;
  auto args = [&now]() -> tos::SmartContract::Args { return tos::SmartContract::Args().set_now(now); };

  // first empty query (init)
  CHECK(ms.write().send_external_message(vm::CellBuilder().finalize(), args()).code == 0);
  // first empty query
  CHECK(ms.write().send_external_message(vm::CellBuilder().finalize(), args()).code > 0);

  {
    td::uint64 query_id = 123 | ((now + 10 * 60ull) << 32);
    tos::MultisigWallet::QueryBuilder qb(wallet_id, query_id, vm::CellBuilder().finalize());
    auto query = qb.create(0, keys[0]);
    auto res = ms.write().send_external_message(query, args());
    CHECK(!res.accepted);
    CHECK(res.code == 41);
  }
  {
    for (int i = 1; i <= 11; i++) {
      td::uint64 query_id = i | ((now + 100 * 60ull) << 32);
      tos::MultisigWallet::QueryBuilder qb(wallet_id, query_id, vm::CellBuilder().finalize());
      auto query = qb.create(5, keys[5]);
      auto res = ms.write().send_external_message(query, args());
      if (i <= 10) {
        CHECK(res.accepted);
      } else {
        CHECK(!res.accepted);
      }
    }

    now += 100 * 60 + 100;
    {
      td::uint64 query_id = 200 | ((now + 100 * 60ull) << 32);
      tos::MultisigWallet::QueryBuilder qb(wallet_id, query_id, vm::CellBuilder().finalize());
      auto query = qb.create(6, keys[6]);
      auto res = ms.write().send_external_message(query, args());
      CHECK(res.accepted);
    }

    {
      td::uint64 query_id = 300 | ((now + 100 * 60ull) << 32);
      tos::MultisigWallet::QueryBuilder qb(wallet_id, query_id, vm::CellBuilder().finalize());
      auto query = qb.create(5, keys[5]);
      auto res = ms.write().send_external_message(query, args());
      CHECK(res.accepted);
    }
  }

  td::uint64 query_id = 123 | ((now + 100 * 60ull) << 32);
  tos::MultisigWallet::QueryBuilder qb(wallet_id, query_id, vm::CellBuilder().finalize());
  for (int i = 0; i < 10; i++) {
    auto query = qb.create(i, keys[i]);
    auto ans = ms.write().send_external_message(query, args());
    LOG(INFO) << "CODE: " << ans.code;
    LOG(INFO) << "GAS: " << ans.gas_used;
  }
  for (int i = 0; i + 1 < 25; i++) {
    qb.sign(i, keys[i]);
  }
  auto query = qb.create(24, keys[24]);

  CHECK(ms->get_n_k() == std::make_pair(n, k));
  auto ans = ms.write().send_external_message(query, args());
  LOG(INFO) << "CODE: " << ans.code;
  LOG(INFO) << "GAS: " << ans.gas_used;
  CHECK(ans.success);
  ASSERT_EQ(0, ms->processed(query_id));
  CHECK(ms.write().send_external_message(query, args()).code > 0);
  ASSERT_EQ(0, ms->processed(query_id));

  {
    tos::MultisigWallet::QueryBuilder qb(wallet_id, query_id, vm::CellBuilder().finalize());
    for (int i = 25; i + 1 < 50; i++) {
      qb.sign(i, keys[i]);
    }
    query = qb.create(49, keys[49]);
  }

  ans = ms.write().send_external_message(query, args());
  LOG(INFO) << "CODE: " << ans.code;
  LOG(INFO) << "GAS: " << ans.gas_used;
  ASSERT_EQ(-1, ms->processed(query_id));
}

TEST(Smartcont, MultisigStress) {
  int n = 10;
  int k = 5;
  td::uint32 wallet_id = std::numeric_limits<td::uint32>::max() - 3;

  std::vector<td::Ed25519::PrivateKey> keys;
  for (int i = 0; i < n; i++) {
    keys.push_back(td::Ed25519::generate_private_key().move_as_ok());
  }
  auto public_keys = td::transform(keys, [](auto& key) { return key.get_public_key().ok().as_octet_string(); });
  auto ms_lib = tos::MultisigWallet::create();
  auto init_state_old =
      ms_lib->create_init_data_fast(wallet_id, td::transform(public_keys, [](auto& key) { return key.copy(); }), k);
  auto init_state =
      ms_lib->create_init_data(wallet_id, td::transform(public_keys, [](auto& key) { return key.copy(); }), k);
  CHECK(init_state_old->get_hash() == init_state->get_hash());
  auto ms = tos::MultisigWallet::create(init_state);
  CHECK(ms->get_public_keys() == public_keys);

  td::int32 now = 100 * 60;
  td::int32 qid = 1;
  using Mask = std::bitset<128>;
  struct Query {
    td::int64 id;
    td::Ref<vm::Cell> message;
    Mask signed_mask;
  };

  std::vector<Query> queries;
  int max_queries = 300;

  td::Random::Xorshift128plus rnd(123);

  auto new_query = [&] {
    if (qid > max_queries) {
      return;
    }
    Query query;
    query.id = (static_cast<td::int64>(now) << 32) | qid++;
    query.message = vm::CellBuilder().store_bytes(td::rand_string('a', 'z', rnd.fast(0, 100))).finalize();
    queries.push_back(std::move(query));
  };

  auto verify = [&] {
    auto messages = ms->get_unsigned_messaged();
    std::set<std::tuple<td::uint64, tos::MultisigWallet::Mask, std::string>> s;
    std::set<std::tuple<td::uint64, tos::MultisigWallet::Mask, std::string>> t;

    for (auto& m : messages) {
      auto x = std::make_tuple(m.query_id, m.signed_by, m.message->get_hash().as_slice().str());
      s.insert(std::move(x));
    }

    for (auto& q : queries) {
      if (q.signed_mask.none()) {
        continue;
      }
      t.insert(std::make_tuple(q.id, q.signed_mask, q.message->get_hash().as_slice().str()));
    }
    ASSERT_EQ(t.size(), s.size());
    CHECK(s == t);
  };

  auto sign_query = [&](Query& query, Mask mask) {
    auto qb = tos::MultisigWallet::QueryBuilder(wallet_id, query.id, query.message);
    int first_i = -1;
    for (int i = 0; i < (int)mask.size(); i++) {
      if (mask.test(i)) {
        if (first_i == -1) {
          first_i = i;
        } else {
          qb.sign(i, keys[i]);
        }
      }
    }
    return qb.create(first_i, keys[first_i]);
  };

  auto send_signature = [&](td::Ref<vm::Cell> query) {
    auto ans = ms.write().send_external_message(query);
    LOG(ERROR) << "GAS: " << ans.gas_used;
    return ans.code == 0;
  };

  auto is_ready = [&](Query& query) { return ms->processed(query.id) == -1; };

  auto gen_query = [&](Query& query) {
    auto x = rnd.fast(1, n);
    Mask mask;
    for (int t = 0; t < x; t++) {
      mask.set(rnd() % n);
    }

    auto signature = sign_query(query, mask);
    return std::make_pair(signature, mask);
  };

  auto rand_sign = [&] {
    if (queries.empty()) {
      return;
    }

    size_t query_i = rnd() % queries.size();
    auto& query = queries[query_i];

    Mask mask;
    td::Ref<vm::Cell> signature;
    std::tie(signature, mask) = gen_query(query);
    if (false && rnd() % 6 == 0) {
      Mask mask2;
      td::Ref<vm::Cell> signature2;
      std::tie(signature2, mask2) = gen_query(query);
      for (int i = 0; i < (int)keys.size(); i++) {
        if (mask[i]) {
          signature = ms->merge_queries(std::move(signature), std::move(signature2));
          break;
        }
        if (mask2[i]) {
          signature = ms->merge_queries(std::move(signature2), std::move(signature));
          break;
        }
      }
      //signature = ms->merge_queries(std::move(signature), std::move(signature2));
      mask |= mask2;
    }

    int got_cnt;
    Mask got_cnt_bits;
    std::tie(got_cnt, got_cnt_bits) = ms->check_query_signatures(signature);
    CHECK(mask == got_cnt_bits);

    bool expect_ok = true;
    {
      auto new_mask = mask & ~query.signed_mask;
      expect_ok &= new_mask.any();
      for (size_t i = 0; i < mask.size(); i++) {
        if (mask[i]) {
          expect_ok &= new_mask[i];
          break;
        }
      }
    }

    ASSERT_EQ(expect_ok, send_signature(std::move(signature)));
    if (expect_ok) {
      query.signed_mask |= mask;
    }
    auto expect_is_ready = query.signed_mask.count() >= (size_t)k;
    auto state = ms->get_query_state(query.id);
    ASSERT_EQ(expect_is_ready, (state.state == tos::MultisigWallet::QueryState::Sent));
    CHECK(expect_is_ready || state.mask == query.signed_mask);
    ASSERT_EQ(expect_is_ready, is_ready(query));
    if (expect_is_ready) {
      queries.erase(queries.begin() + query_i);
    }
    verify();
  };
  td::RandomSteps steps({{rand_sign, 2}, {new_query, 1}});
  while (!queries.empty() || qid <= max_queries) {
    steps.step(rnd);
    //LOG(ERROR) << ms->data_size();
  }
  LOG(INFO) << "Final code size: " << ms->code_size();
  LOG(INFO) << "Final data size: " << ms->data_size();
}

class MapDns {
 public:
  using ManualDns = tos::ManualDns;
  struct Entry {
    std::string name;
    td::Bits256 category = td::Bits256::zero();
    std::string text;

    auto key() const {
      return std::tie(name, category);
    }
    bool operator<(const Entry& other) const {
      return key() < other.key();
    }
    bool operator==(const tos::DnsInterface::Entry& other) const {
      return key() == other.key() && other.data.type == ManualDns::EntryData::Type::Text &&
             other.data.data.get<ManualDns::EntryDataText>().text == text;
    }
    bool operator==(const Entry& other) const {
      return key() == other.key() && text == other.text;
    }
    friend td::StringBuilder& operator<<(td::StringBuilder& sb, const Entry& entry) {
      return sb << "[" << entry.name << ":" << entry.category.to_hex() << ":" << entry.text << "]";
    }
  };
  struct Action {
    std::string name;
    td::Bits256 category = td::Bits256::zero();
    td::optional<std::string> text;

    bool does_create_category() const {
      CHECK(!name.empty());
      CHECK(!category.is_zero());
      return static_cast<bool>(text);
    }
    bool does_change_empty() const {
      CHECK(!name.empty());
      CHECK(!category.is_zero());
      return static_cast<bool>(text) && !text.value().empty();
    }
    void make_non_empty() {
      CHECK(!name.empty());
      CHECK(!category.is_zero());
      if (!text) {
        text = "";
      }
    }
    friend td::StringBuilder& operator<<(td::StringBuilder& sb, const Action& entry) {
      return sb << "[" << entry.name << ":" << entry.category.to_hex() << ":"
                << (entry.text ? entry.text.value() : "<empty>") << "]";
    }
  };
  void update(td::Span<Action> actions) {
    for (auto& action : actions) {
      do_update(action);
    }
  }
  using CombinedActions = tos::ManualDns::CombinedActions<Action>;
  void update_combined(td::Span<Action> actions) {
    LOG(ERROR) << "BEGIN";
    LOG(ERROR) << td::format::as_array(actions);
    auto combined_actions = tos::ManualDns::combine_actions(actions);
    for (auto& c : combined_actions) {
      LOG(ERROR) << c.name << ":" << c.category.to_hex();
      if (c.actions) {
        LOG(ERROR) << td::format::as_array(c.actions.value());
      }
    }
    LOG(ERROR) << "END";
    for (auto& combined_action : combined_actions) {
      do_update(combined_action);
    }
  }

  std::vector<Entry> resolve(td::Slice name, td::Bits256 category) {
    std::vector<Entry> res;
    if (name.empty()) {
      for (auto& a : entries_) {
        for (auto& b : a.second) {
          res.push_back({a.first, b.first, b.second});
        }
      }
    } else {
      auto it = entries_.find(name);
      while (it == entries_.end()) {
        auto sz = name.find('.');
        category = tos::DNS_NEXT_RESOLVER_CATEGORY;
        if (sz != td::Slice::npos) {
          name = name.substr(sz + 1);
        } else {
          break;
        }
        it = entries_.find(name);
      }
      if (it != entries_.end()) {
        for (auto& b : it->second) {
          if (category.is_zero() || category == b.first) {
            res.push_back({name.str(), b.first, b.second});
          }
        }
      }
    }

    std::sort(res.begin(), res.end());
    return res;
  }

 private:
  std::map<std::string, std::map<td::Bits256, std::string>, std::less<>> entries_;
  void do_update(const Action& action) {
    if (action.name.empty()) {
      entries_.clear();
      return;
    }
    if (action.category.is_zero()) {
      entries_.erase(action.name);
      return;
    }
    if (action.text) {
      if (action.text.value().empty()) {
        entries_[action.name].erase(action.category);
      } else {
        entries_[action.name][action.category] = action.text.value();
      }
    } else {
      auto it = entries_.find(action.name);
      if (it != entries_.end()) {
        it->second.erase(action.category);
      }
    }
  }

  void do_update(const CombinedActions& actions) {
    if (actions.name.empty()) {
      entries_.clear();
      LOG(ERROR) << "CLEAR";
      if (!actions.actions) {
        return;
      }
      for (auto& action : actions.actions.value()) {
        CHECK(!action.name.empty());
        CHECK(!action.category.is_zero());
        CHECK(action.text);
        if (action.text.value().empty()) {
          entries_[action.name];
        } else {
          entries_[action.name][action.category] = action.text.value();
        }
      }
      return;
    }
    if (actions.category.is_zero()) {
      entries_.erase(actions.name);
      LOG(ERROR) << "CLEAR " << actions.name;
      if (!actions.actions) {
        return;
      }
      entries_[actions.name];
      for (auto& action : actions.actions.value()) {
        CHECK(action.name == actions.name);
        CHECK(!action.category.is_zero());
        CHECK(action.text);
        if (action.text.value().empty()) {
          entries_[action.name];
        } else {
          entries_[action.name][action.category] = action.text.value();
        }
      }
      return;
    }
    CHECK(actions.actions);
    CHECK(actions.actions.value().size() == 1);
    for (auto& action : actions.actions.value()) {
      CHECK(action.name == actions.name);
      CHECK(!action.category.is_zero());
      if (action.text) {
        if (action.text.value().empty()) {
          entries_[action.name].erase(action.category);
        } else {
          entries_[action.name][action.category] = action.text.value();
        }
      } else {
        auto it = entries_.find(action.name);
        if (it != entries_.end()) {
          it->second.erase(action.category);
        }
      }
    }
  }
};

class CheckedDns {
 public:
  explicit CheckedDns(bool check_smc = true, bool check_combine = true) {
    if (check_smc) {
      key_ = td::Ed25519::generate_private_key().move_as_ok();
      dns_ = ManualDns::create(ManualDns::create_init_data_fast(key_.value().get_public_key().move_as_ok(), 123), -1);
    }
    if (check_combine) {
      combined_map_dns_ = MapDns();
    }
  }
  using Action = MapDns::Action;
  using Entry = MapDns::Entry;
  void update(td::Span<Action> entries) {
    if (dns_.not_null()) {
      auto smc_actions = td::transform(entries, [](auto& entry) {
        tos::DnsInterface::Action action;
        action.name = entry.name;
        action.category = entry.category;
        if (entry.text) {
          if (entry.text.value().empty()) {
            action.data = td::Ref<vm::Cell>();
          } else {
            action.data = ManualDns::EntryData::text(entry.text.value()).as_cell().move_as_ok();
          }
        }
        return action;
      });
      auto query = dns_->create_update_query(key_.value(), smc_actions, query_id_++).move_as_ok();
      CHECK(dns_.write().send_external_message(std::move(query)).code == 0);
    }
    map_dns_.update(entries);
    if (combined_map_dns_) {
      combined_map_dns_.value().update_combined(entries);
    }
  }
  void update(const Action& action) {
    return update(td::span_one(action));
  }

  std::vector<Entry> resolve(td::Slice name, td::Bits256 category) {
    LOG(ERROR) << "RESOLVE: " << name << " " << category.to_hex();
    auto res = map_dns_.resolve(name, category);
    LOG(ERROR) << td::format::as_array(res);

    if (dns_.not_null()) {
      auto other_res = dns_->resolve(name, category).move_as_ok();

      std::sort(other_res.begin(), other_res.end());
      if (res.size() != other_res.size()) {
        LOG(ERROR) << td::format::as_array(res);
        LOG(FATAL) << td::format::as_array(other_res);
      }
      for (size_t i = 0; i < res.size(); i++) {
        if (!(res[i] == other_res[i])) {
          LOG(ERROR) << td::format::as_array(res);
          LOG(FATAL) << td::format::as_array(other_res);
        }
      }
    }
    if (combined_map_dns_) {
      auto other_res = combined_map_dns_.value().resolve(name, category);

      std::sort(other_res.begin(), other_res.end());
      if (res.size() != other_res.size()) {
        LOG(ERROR) << td::format::as_array(res);
        LOG(FATAL) << td::format::as_array(other_res);
      }
      for (size_t i = 0; i < res.size(); i++) {
        if (!(res[i] == other_res[i])) {
          LOG(ERROR) << td::format::as_array(res);
          LOG(FATAL) << td::format::as_array(other_res);
        }
      }
    }

    return res;
  }

 private:
  using ManualDns = tos::ManualDns;
  td::optional<td::Ed25519::PrivateKey> key_;
  td::Ref<ManualDns> dns_;
  td::uint32 query_id_ = 1;  // Query id serve as "valid until", but in tests now() == 0

  MapDns map_dns_;
  td::optional<MapDns> combined_map_dns_;

  void do_update_smc(const Action& entry) {
    LOG(ERROR) << td::format::escaped(ManualDns::encode_name(entry.name));
    tos::DnsInterface::Action action;
    action.name = entry.name;
    action.category = entry.category;
    action.data = ManualDns::EntryData::text(entry.text.value()).as_cell().move_as_ok();
  }
};

static td::Bits256 intToCat(td::uint32 x) {
  auto y = td::make_refint(x);
  td::Bits256 cat;
  y->export_bytes(cat.data(), 32, false);
  return cat;
}

void do_dns_test(CheckedDns&& dns) {
  using Action = CheckedDns::Action;
  std::vector<Action> actions;

  td::Random::Xorshift128plus rnd(123);

  auto gen_name = [&] {
    auto cnt = rnd.fast(1, 2);
    std::string res;
    for (int i = 0; i < cnt; i++) {
      if (i != 0) {
        res += '.';
      }
      auto len = rnd.fast(1, 1);
      for (int j = 0; j < len; j++) {
        res += static_cast<char>(rnd.fast('a', 'b'));
      }
    }
    return res;
  };
  auto gen_text = [&] {
    std::string res;
    int len = 5;
    for (int j = 0; j < len; j++) {
      res += static_cast<char>(rnd.fast('a', 'b'));
    }
    return res;
  };

  auto gen_action = [&] {
    Action action;
    if (rnd.fast(0, 1000) == 0) {
      return action;
    }
    action.name = gen_name();
    if (rnd.fast(0, 20) == 0) {
      return action;
    }
    action.category = intToCat(rnd.fast(1, 5));
    if (rnd.fast(0, 4) == 0) {
      return action;
    }
    if (rnd.fast(0, 4) == 0) {
      action.text = "";
      return action;
    }
    action.text = gen_text();
    return action;
  };

  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  for (int i = 0; i < 100000; i++) {
    actions.push_back(gen_action());
    if (rnd.fast(0, 10) == 0) {
      dns.update(actions);
      actions.clear();
    }
    auto name = gen_name();
    dns.resolve(name, intToCat(rnd.fast(0, 5)));
  }
};

TEST(Smartcont, DnsResolverHopBudget) {
  // The shared budget decision every recursive client consults before
  // following a partial (next-resolver) answer. Simulate walking delegation
  // chains of various depths (`depth` = resolver contacts a full resolution
  // would need) and count the contacts actually made.
  auto walk = [](int depth) {
    int contacts = 0;
    int hops_left = tos::DNS_MAX_RESOLVER_HOPS;
    while (true) {
      contacts++;
      bool partial = contacts < depth;  // the final resolver answers terminally
      if (!partial) {
        return std::make_pair(contacts, true);
      }
      if (tos::dns_next_hop_exceeds_budget(hops_left)) {
        return std::make_pair(contacts, false);  // distinct budget error
      }
      hops_left--;
    }
  };
  // a chain the budget covers exactly: eight contacts, success
  CHECK(walk(8) == std::make_pair(8, true));
  // one deeper: still eight contacts (never a ninth), reported as an error
  CHECK(walk(9) == std::make_pair(8, false));
  CHECK(walk(100) == std::make_pair(8, false));
  CHECK(walk(1) == std::make_pair(1, true));

  // Cycle detection is independent of hop exhaustion and fires before the
  // repeated resolver would become another network contact.
  std::vector<int> resolver_path{1, 2, 3};
  CHECK(tos::dns_resolver_path_contains(resolver_path, 1));
  CHECK(tos::dns_resolver_path_contains(resolver_path, 3));
  CHECK(!tos::dns_resolver_path_contains(resolver_path, 4));
}

TEST(Smartcont, DnsTip1Corpus) {
  auto raw = td::read_file_str(current_dir() + "../../test/testdata/tip-1-dns-v1.json").move_as_ok();
  auto json = td::json_decode(raw).move_as_ok();
  CHECK(json.type() == td::JsonValue::Type::Object);
  const auto &root = json.get_object();
  CHECK(root.get_required_string_field("schema").move_as_ok() == "tos.tip-1.dns-v1.v1");

  auto object_field = [](const td::JsonObject &object, td::Slice name) -> const td::JsonObject & {
    for (const auto &field : object.field_values_) {
      if (field.first == name && field.second.type() == td::JsonValue::Type::Object) {
        return field.second.get_object();
      }
    }
    UNREACHABLE();
  };
  const auto &lifecycle = object_field(root, "lifecycle");
  const auto &resolver = object_field(root, "resolver_policy");
  CHECK(lifecycle.get_required_long_field("renewal_interval_seconds").move_as_ok() == 31622400);
  CHECK(resolver.get_required_int_field("maximum_contacts").move_as_ok() == tos::DNS_MAX_RESOLVER_HOPS);

  const auto &categories = object_field(root, "categories");
  const auto &wallet = object_field(categories, "wallet");
  CHECK(wallet.get_required_string_field("sha256").move_as_ok() ==
        "e8d44050873dba865aa7c170ab4cce64d90839a34dcfd6cf71d14e0205443b1b");
}

TEST(Smartcont, DnsManual) {
  using ManualDns = tos::ManualDns;
  auto test_entry_data = [](auto&& entry_data) {
    auto cell = entry_data.as_cell().move_as_ok();
    auto cs = vm::load_cell_slice(cell);
    auto new_entry_data = ManualDns::EntryData::from_cellslice(cs).move_as_ok();
    ASSERT_EQ(entry_data, new_entry_data);
  };
  test_entry_data(ManualDns::EntryData::text("abcd"));
  test_entry_data(ManualDns::EntryData::adnl_address(tos::Bits256{}));

  CHECK(td::Slice("a\0b\0") == ManualDns::encode_name("b.a"));
  CHECK(td::Slice("a\0b\0") == ManualDns::encode_name(".b.a"));
  ASSERT_EQ(".b.a", ManualDns::decode_name("a\0b\0"));
  ASSERT_EQ("b.a", ManualDns::decode_name("a\0b"));
  ASSERT_EQ("", ManualDns::decode_name(""));

  ASSERT_TRUE(ManualDns::resolve_args_raw(std::string(127, 'a'), td::Bits256::zero()).is_ok());
  ASSERT_TRUE(ManualDns::resolve_args_raw(std::string(128, 'a'), td::Bits256::zero()).is_error());

  auto key = td::Ed25519::generate_private_key().move_as_ok();

  auto manual = ManualDns::create(ManualDns::create_init_data_fast(key.get_public_key().move_as_ok(), 123), -1);
  CHECK(manual->get_wallet_id().move_as_ok() == 123);
  auto init_query = manual->create_init_query(key).move_as_ok();
  LOG(ERROR) << "A";
  CHECK(manual.write().send_external_message(init_query).code == 0);
  LOG(ERROR) << "B";
  CHECK(manual.write().send_external_message(init_query).code != 0);

  auto value = vm::CellBuilder().store_bytes("hello world").finalize();
  auto set_query =
      manual
          ->sign(key, manual->prepare(manual->create_set_value_unsigned(intToCat(1), "a\0b\0", value).move_as_ok(), 1)
                          .move_as_ok())
          .move_as_ok();
  CHECK(manual.write().send_external_message(set_query).code == 0);

  auto res = manual->run_get_method(
      "dnsresolve", {vm::load_cell_slice_ref(vm::CellBuilder().store_bytes("a\0b\0").finalize()), td::make_refint(1)});
  CHECK(res.code == 0);
  CHECK(res.stack.write().pop_cell()->get_hash() == value->get_hash());

  CheckedDns dns;
  dns.update(CheckedDns::Action{"a.b.c", intToCat(1), "hello"});
  CHECK(dns.resolve("a.b.c", intToCat(1)).at(0).text == "hello");
  dns.resolve("a", intToCat(1));
  dns.resolve("a.b", intToCat(1));
  CHECK(dns.resolve("a.b.c", intToCat(2)).empty());
  dns.update(CheckedDns::Action{"a.b.c", intToCat(2), "test"});
  CHECK(dns.resolve("a.b.c", intToCat(2)).at(0).text == "test");
  dns.resolve("a.b.c", intToCat(1));
  dns.resolve("a.b.c", intToCat(2));
  LOG(ERROR) << "Test zero category";
  dns.resolve("a.b.c", intToCat(0));
  dns.update(CheckedDns::Action{"", intToCat(0), ""});
  CHECK(dns.resolve("a.b.c", intToCat(2)).empty());

  LOG(ERROR) << "Test multipe update";
  {
    CheckedDns::Action e[4] = {
        CheckedDns::Action{"", intToCat(0), ""}, CheckedDns::Action{"a.b.c", intToCat(1), "hello"},
        CheckedDns::Action{"a.b.c", intToCat(2), "world"}, CheckedDns::Action{"x.y.z", intToCat(3), "abc"}};
    dns.update(td::span(e, 4));
  }
  dns.resolve("a.b.c", intToCat(1));
  dns.resolve("a.b.c", intToCat(2));
  dns.resolve("x.y.z", intToCat(3));

  dns.update(td::span_one(CheckedDns::Action{"x.y.z", intToCat(0), ""}));

  dns.resolve("a.b.c", intToCat(1));
  dns.resolve("a.b.c", intToCat(2));
  dns.resolve("x.y.z", intToCat(3));

  {
    CheckedDns::Action e[3] = {CheckedDns::Action{"x.y.z", intToCat(0), ""},
                               CheckedDns::Action{"x.y.z", intToCat(1), "xxx"},
                               CheckedDns::Action{"x.y.z", intToCat(2), "yyy"}};
    dns.update(td::span(e, 3));
  }
  dns.resolve("a.b.c", intToCat(1));
  dns.resolve("a.b.c", intToCat(2));
  dns.resolve("x.y.z", intToCat(1));
  dns.resolve("x.y.z", intToCat(2));
  dns.resolve("x.y.z", intToCat(3));

  {
    auto actions_ext =
        tos::ManualDns::parse("delete.name one\nset one 1 TEXT:one\ndelete.name two\nset two 2 TEXT:two").move_as_ok();

    auto actions = td::transform(actions_ext, [](auto& action) {
      td::optional<std::string> data;
      if (action.data) {
        data = action.data.value().data.template get<tos::ManualDns::EntryDataText>().text;
      }
      return CheckedDns::Action{action.name, action.category, std::move(data)};
    });

    dns.update(actions);
  }
  dns.resolve("one", intToCat(1));
  dns.resolve("two", intToCat(2));

  // TODO: rethink semantic of creating an empty dictionary
  do_dns_test(CheckedDns(true, true));
}

using namespace tos::pchan;

TEST(Smartcont, PaymentChannelSignedPromiseRoundTrip) {
  auto private_key = td::Ed25519::generate_private_key().move_as_ok();
  auto public_key = private_key.get_public_key().move_as_ok();
  auto cell = SignedPromiseBuilder()
                  .channel_id(0x123456789abcdef0ULL)
                  .promise_A(17)
                  .promise_B(42)
                  .with_key(&private_key)
                  .finalize();
  ASSERT_TRUE(cell.not_null());

  SignedPromise decoded;
  ASSERT_TRUE(decoded.unpack(std::move(cell)));
  ASSERT_EQ(decoded.promise.channel_id, 0x123456789abcdef0ULL);
  ASSERT_EQ(decoded.promise.promise_A, 17u);
  ASSERT_EQ(decoded.promise.promise_B, 42u);
  ASSERT_TRUE(decoded.o_signature);
  auto promise = decoded.promise.serialize();
  ASSERT_TRUE(promise.not_null());
  ASSERT_TRUE(public_key.verify_signature(promise->get_hash().as_slice(), decoded.o_signature.value()).is_ok());
}

template <class T>
struct ValidateState {
  T& self() {
    return static_cast<T&>(*this);
  }

  void init(td::Ref<vm::Cell> state) {
    state_ = state;
    block::gen::ChanData::Record data_rec;
    if (!tlb::unpack_cell(state, data_rec)) {
      on_fatal_error(td::Status::Error("Expected Data"));
      return;
    }
    if (!tlb::unpack_cell(data_rec.state, self().rec)) {
      on_fatal_error(td::Status::Error("Expected StatePayout"));
      return;
    }
    CHECK(self().rec.A.not_null());
  }

  T& expect_tomis(td::Ref<vm::CellSlice> cs, td::uint64 expected, td::Slice name) {
    if (has_fatal_error_) {
      return self();
    }
    td::RefInt256 got;
    CHECK(cs.not_null());
    CHECK(block::tlb::t_Tomis.as_integer_to(cs, got));
    if (got->cmp(expected) != 0) {
      on_error(td::Status::Error(PSLICE() << name << ": expected " << expected << ", got " << got->to_dec_string()));
    }
    return self();
  }
  template <class S>
  T& expect_eq(S a, S expected, td::Slice name) {
    if (has_fatal_error_) {
      return self();
    }
    if (!(a == expected)) {
      on_error(td::Status::Error(PSLICE() << name << ": expected " << expected << ", got " << a));
    }
    return self();
  }

  td::Status finish() {
    if (errors_.empty()) {
      return td::Status::OK();
    }
    std::stringstream ss;
    block::gen::t_ChanData.print_ref(ss, state_);
    td::StringBuilder sb;
    for (auto& error : errors_) {
      sb << error << "\n";
    }
    sb << ss.str();
    return td::Status::Error(sb.as_cslice());
  }

  void on_fatal_error(td::Status error) {
    CHECK(!has_fatal_error_);
    has_fatal_error_ = true;
    on_error(std::move(error));
  }
  void on_error(td::Status error) {
    CHECK(error.is_error());
    errors_.push_back(std::move(error));
  }

 public:
  td::Ref<vm::Cell> state_;
  bool has_fatal_error_{false};
  std::vector<td::Status> errors_;
};

struct ValidateStatePayout : public ValidateState<ValidateStatePayout> {
  ValidateStatePayout& expect_A(td::uint64 a) {
    expect_tomis(rec.A, a, "A");
    return *this;
  }
  ValidateStatePayout& expect_B(td::uint64 b) {
    expect_tomis(rec.B, b, "B");
    return *this;
  }

  ValidateStatePayout(td::Ref<vm::Cell> state) {
    init(std::move(state));
  }

  block::gen::ChanState::Record_chan_state_payout rec;
};

struct ValidateStateInit : public ValidateState<ValidateStateInit> {
  ValidateStateInit& expect_A(td::uint64 a) {
    expect_tomis(rec.A, a, "A");
    return *this;
  }
  ValidateStateInit& expect_B(td::uint64 b) {
    expect_tomis(rec.B, b, "B");
    return *this;
  }
  ValidateStateInit& expect_min_A(td::uint64 a) {
    expect_tomis(rec.min_A, a, "min_A");
    return *this;
  }
  ValidateStateInit& expect_min_B(td::uint64 b) {
    expect_tomis(rec.min_B, b, "min_B");
    return *this;
  }
  ValidateStateInit& expect_expire_at(td::uint32 b) {
    expect_eq(rec.expire_at, b, "expire_at");
    return *this;
  }
  ValidateStateInit& expect_signed_A(bool x) {
    expect_eq(rec.signed_A, x, "signed_A");
    return *this;
  }
  ValidateStateInit& expect_signed_B(bool x) {
    expect_eq(rec.signed_B, x, "signed_B");
    return *this;
  }

  ValidateStateInit(td::Ref<vm::Cell> state) {
    init(std::move(state));
  }

  block::gen::ChanState::Record_chan_state_init rec;
};

struct ValidateStateClose : public ValidateState<ValidateStateClose> {
  ValidateStateClose& expect_A(td::uint64 a) {
    expect_tomis(rec.A, a, "A");
    return *this;
  }
  ValidateStateClose& expect_B(td::uint64 b) {
    expect_tomis(rec.B, b, "B");
    return *this;
  }
  ValidateStateClose& expect_promise_A(td::uint64 a) {
    expect_tomis(rec.promise_A, a, "promise_A");
    return *this;
  }
  ValidateStateClose& expect_promise_B(td::uint64 b) {
    expect_tomis(rec.promise_B, b, "promise_B");
    return *this;
  }
  ValidateStateClose& expect_expire_at(td::uint32 b) {
    expect_eq(rec.expire_at, b, "expire_at");
    return *this;
  }
  ValidateStateClose& expect_signed_A(bool x) {
    expect_eq(rec.signed_A, x, "signed_A");
    return *this;
  }
  ValidateStateClose& expect_signed_B(bool x) {
    expect_eq(rec.signed_B, x, "signed_B");
    return *this;
  }

  ValidateStateClose(td::Ref<vm::Cell> state) {
    init(std::move(state));
  }

  block::gen::ChanState::Record_chan_state_close rec;
};

// config$_ initTimeout:int exitTimeout:int a_key:int256 b_key:int256 a_addr b_addr channel_id:int256 = Config;
TEST(Smarcont, Channel) {
  auto code = tos::SmartContractCode::get_code(tos::SmartContractCode::PaymentChannel);
  Config config;
  auto a_pkey = td::Ed25519::generate_private_key().move_as_ok();
  auto b_pkey = td::Ed25519::generate_private_key().move_as_ok();
  config.init_timeout = 20;
  config.close_timeout = 40;
  auto dest = block::StdAddress::parse("Ef9Tj6fMJP+OqhAdhKXxq36DL+HYSzCc3+9O6UNzqsgPfYFX").move_as_ok();
  config.a_addr = dest;
  config.b_addr = dest;
  config.a_key = a_pkey.get_public_key().ok().as_octet_string();
  config.b_key = b_pkey.get_public_key().ok().as_octet_string();
  config.channel_id = 123;

  Data data;
  data.config = config.serialize();
  data.state = data.init_state();
  auto data_cell = data.serialize();

  auto channel = tos::SmartContract::create(tos::SmartContract::State{code, data_cell});
  ValidateStateInit(channel->get_state().data)
      .expect_A(0)
      .expect_B(0)
      .expect_min_A(0)
      .expect_min_B(0)
      .expect_signed_A(false)
      .expect_signed_B(false)
      .expect_expire_at(0)
      .finish()
      .ensure();

  enum err {
    ok = 0,
    wrong_a_signature = 31,
    wrong_b_signature,
    msg_value_too_small,
    replay_protection,
    no_timeout,
    expected_init,
    expected_close,
    no_promise_signature,
    wrong_channel_id
  };

#define expect_code(description, expected_code, e)                                                            \
  {                                                                                                           \
    auto res = e;                                                                                             \
    LOG_IF(FATAL, expected_code != res.code) << " res.code=" << res.code << " " << description << "\n" << #e; \
  }
#define expect_ok(description, e) expect_code(description, 0, e)

  expect_code("Trying to invoke a timeout while channel is empty", no_timeout,
              channel.write().send_external_message(MsgTimeoutBuilder().finalize(),
                                                    tos::SmartContract::Args().set_now(1000000)));

  expect_code("External init message with no signatures", replay_protection,
              channel.write().send_external_message(MsgInitBuilder().channel_id(config.channel_id).finalize()));
  expect_code("Internal init message with not enough value", msg_value_too_small,
              channel.write().send_internal_message(
                  MsgInitBuilder().channel_id(config.channel_id).inc_A(1000).min_B(2000).with_a_key(&a_pkey).finalize(),
                  tos::SmartContract::Args().set_amount(100)));
  expect_code(
      "Internal init message with wrong channel_id", wrong_channel_id,
      channel.write().send_internal_message(MsgInitBuilder().inc_A(1000).min_B(2000).with_a_key(&a_pkey).finalize(),
                                            tos::SmartContract::Args().set_amount(1000)));
  expect_ok("A init with (inc_A = 1000, min_A = 1, min_B = 2000)",
            channel.write().send_internal_message(MsgInitBuilder()
                                                      .channel_id(config.channel_id)
                                                      .inc_A(1000)
                                                      .min_A(1)
                                                      .min_B(2000)
                                                      .with_a_key(&a_pkey)
                                                      .finalize(),
                                                  tos::SmartContract::Args().set_amount(1000)));
  ValidateStateInit(channel->get_state().data)
      .expect_A(1000)
      .expect_B(0)
      .expect_min_A(1)
      .expect_min_B(2000)
      .expect_signed_A(true)
      .expect_signed_B(false)
      .expect_expire_at(config.init_timeout)
      .finish()
      .ensure();

  expect_code("Repeated init of A init with (inc_A = 100, min_B = 5000). Must be ignored", replay_protection,
              channel.write().send_internal_message(
                  MsgInitBuilder().channel_id(config.channel_id).inc_A(100).min_B(5000).with_a_key(&a_pkey).finalize(),
                  tos::SmartContract::Args().set_amount(1000)));
  expect_code(
      "Trying to invoke a timeout too early", no_timeout,
      channel.write().send_external_message(MsgTimeoutBuilder().finalize(), tos::SmartContract::Args().set_now(0)));

  {
    auto channel_copy = channel;
    expect_ok("Invoke a timeout", channel_copy.write().send_external_message(MsgTimeoutBuilder().finalize(),
                                                                             tos::SmartContract::Args().set_now(21)));
    ValidateStatePayout(channel_copy->get_state().data).expect_A(1000).expect_B(0).finish().ensure();
  }
  {
    auto channel_copy = channel;
    expect_ok("B init with inc_B < min_B. Leads to immediate payout",
              channel_copy.write().send_internal_message(
                  MsgInitBuilder().channel_id(config.channel_id).inc_B(1500).with_b_key(&b_pkey).finalize(),
                  tos::SmartContract::Args().set_amount(1500)));
    ValidateStatePayout(channel_copy->get_state().data).expect_A(1000).expect_B(1500).finish().ensure();
  }

  expect_ok("B init with (inc_B = 2000, min_A = 1, min_A = 1000)",
            channel.write().send_internal_message(
                MsgInitBuilder().channel_id(config.channel_id).inc_B(2000).min_A(1000).with_b_key(&b_pkey).finalize(),
                tos::SmartContract::Args().set_amount(2000)));
  ValidateStateClose(channel->get_state().data)
      .expect_A(1000)
      .expect_B(2000)
      .expect_promise_A(0)
      .expect_promise_B(0)
      .expect_signed_A(false)
      .expect_signed_B(false)
      .expect_expire_at(0)
      .finish()
      .ensure();

  {
    auto channel_copy = channel;
    expect_ok("A&B send Promise(1000000, 1000000 + 10) signed by nobody",
              channel_copy.write().send_external_message(MsgCloseBuilder()
                                                             .signed_promise(SignedPromiseBuilder()
                                                                                 .promise_A(1000000)
                                                                                 .promise_B(1000000 + 10)
                                                                                 .channel_id(config.channel_id)
                                                                                 .finalize())
                                                             .with_a_key(&a_pkey)
                                                             .with_b_key(&b_pkey)
                                                             .finalize(),
                                                         tos::SmartContract::Args().set_now(21)));
    ValidateStatePayout(channel_copy->get_state().data).expect_A(1000 + 10).expect_B(2000 - 10).finish().ensure();
  }
  {
    auto channel_copy = channel;
    expect_ok("A&B send Promise(1000000, 1000000 + 10) signed by A",
              channel_copy.write().send_external_message(MsgCloseBuilder()
                                                             .signed_promise(SignedPromiseBuilder()
                                                                                 .promise_A(1000000)
                                                                                 .promise_B(1000000 + 10)
                                                                                 .with_key(&a_pkey)
                                                                                 .channel_id(config.channel_id)
                                                                                 .finalize())
                                                             .with_a_key(&a_pkey)
                                                             .with_b_key(&b_pkey)
                                                             .finalize(),
                                                         tos::SmartContract::Args().set_now(21)));
    ValidateStatePayout(channel_copy->get_state().data).expect_A(1000 + 10).expect_B(2000 - 10).finish().ensure();
  }

  expect_code(
      "A sends Promise(1000000, 0) signed by A", wrong_b_signature,
      channel.write().send_external_message(
          MsgCloseBuilder()
              .signed_promise(
                  SignedPromiseBuilder().promise_A(1000000).with_key(&a_pkey).channel_id(config.channel_id).finalize())
              .with_a_key(&a_pkey)
              .finalize(),
          tos::SmartContract::Args().set_now(21)));
  expect_code(
      "B sends Promise(1000000, 0) signed by B", wrong_a_signature,
      channel.write().send_external_message(
          MsgCloseBuilder()
              .signed_promise(
                  SignedPromiseBuilder().promise_A(1000000).with_key(&b_pkey).channel_id(config.channel_id).finalize())
              .with_b_key(&b_pkey)
              .finalize(),
          tos::SmartContract::Args().set_now(21)));
  expect_code("B sends Promise(1000000, 0) signed by A with wrong channel_id", wrong_channel_id,
              channel.write().send_external_message(MsgCloseBuilder()
                                                        .signed_promise(SignedPromiseBuilder()
                                                                            .promise_A(1000000)
                                                                            .with_key(&a_pkey)
                                                                            .channel_id(config.channel_id + 1)
                                                                            .finalize())
                                                        .with_b_key(&b_pkey)
                                                        .finalize(),
                                                    tos::SmartContract::Args().set_now(21)));
  expect_code(
      "B sends unsigned Promise(1000000, 0)", no_promise_signature,
      channel.write().send_external_message(
          MsgCloseBuilder()
              .signed_promise(SignedPromiseBuilder().promise_A(1000000).channel_id(config.channel_id).finalize())
              .with_b_key(&b_pkey)
              .finalize(),
          tos::SmartContract::Args().set_now(21)));

  expect_ok(
      "B sends Promise(1000000, 0) signed by A",
      channel.write().send_external_message(
          MsgCloseBuilder()
              .signed_promise(
                  SignedPromiseBuilder().promise_A(1000000).with_key(&a_pkey).channel_id(config.channel_id).finalize())
              .with_b_key(&b_pkey)
              .finalize(),
          tos::SmartContract::Args().set_now(21)));
  ValidateStateClose(channel->get_state().data)
      .expect_A(1000)
      .expect_B(2000)
      .expect_promise_A(1000000)
      .expect_promise_B(0)
      .expect_signed_A(false)
      .expect_signed_B(true)
      .expect_expire_at(21 + config.close_timeout)
      .finish()
      .ensure();

  expect_ok("B sends Promise(0, 1000000 + 10) signed by A",
            channel.write().send_external_message(MsgCloseBuilder()
                                                      .signed_promise(SignedPromiseBuilder()
                                                                          .promise_B(1000000 + 10)
                                                                          .with_key(&b_pkey)
                                                                          .channel_id(config.channel_id)
                                                                          .finalize())
                                                      .with_a_key(&a_pkey)
                                                      .finalize(),
                                                  tos::SmartContract::Args().set_now(21)));
  ValidateStatePayout(channel->get_state().data).expect_A(1000 + 10).expect_B(2000 - 10).finish().ensure();
#undef expect_ok
#undef expect_code
}
