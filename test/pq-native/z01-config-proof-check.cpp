/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Verify a retained liteServer.configInfo proof against one exact masterchain
// BlockIdExt and its separately retained ConfigParam30 cell BOC.
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include "block/check-proof.h"
#include "block/block-db.h"
#include "block/mc-config.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "vm/boc.h"

namespace {

td::Result<td::Bits256> digest(const char* hex) {
  auto bytes = td::hex_decode(td::Slice{hex});
  if (bytes.is_error()) {
    return bytes.move_as_error();
  }
  auto raw = bytes.move_as_ok();
  if (raw.size() != 32) {
    return td::Status::Error("expected a 32-byte digest");
  }
  td::Bits256 result;
  result.as_slice().copy_from(td::Slice(raw));
  return result;
}

int fail(const std::string& message) {
  std::fprintf(stderr, "Z01_CONFIG_PROOF_REJECT: %s\n", message.c_str());
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 10) {
    return fail("usage: z01-config-proof-check <wc> <shard> <seqno> <root-hex> <file-hex> <block-boc> <state-proof> <config-proof> <param30-boc>");
  }
  char* end = nullptr;
  const auto wc = std::strtol(argv[1], &end, 10);
  if (*end || wc != -1) return fail("masterchain workchain must be -1");
  const auto shard = std::strtoull(argv[2], &end, 10);
  if (*end || shard != (1ULL << 63)) return fail("masterchain shard is invalid");
  const auto seqno = std::strtoul(argv[3], &end, 10);
  if (*end || seqno == 0 || seqno > UINT32_MAX) return fail("masterchain seqno is invalid");
  auto root = digest(argv[4]);
  auto file = digest(argv[5]);
  if (root.is_error() || file.is_error()) return fail("block digest is invalid");
  tos::BlockIdExt id{static_cast<td::int32>(wc), static_cast<tos::ShardId>(shard),
                     static_cast<td::uint32>(seqno), root.move_as_ok(), file.move_as_ok()};
  if (!id.root_hash.is_zero() && !id.file_hash.is_zero()) {
    auto block_data = td::read_file(td::CSlice{argv[6]});
    auto state = td::read_file(td::CSlice{argv[7]});
    auto config = td::read_file(td::CSlice{argv[8]});
    auto expected = td::read_file(td::CSlice{argv[9]});
    if (block_data.is_error() || state.is_error() || config.is_error() || expected.is_error())
      return fail("block, proof or parameter BOC is unreadable");
    auto block_bytes = block_data.move_as_ok();
    if (block::compute_file_hash(block_bytes.as_slice()) != id.file_hash)
      return fail("block BOC file hash differs from full BlockIdExt");
    auto block_root = vm::std_boc_deserialize(block_bytes.as_slice());
    if (block_root.is_error() || tos::RootHash{block_root.ok()->get_hash().bits()} != id.root_hash)
      return fail("block BOC root hash differs from full BlockIdExt");
    auto state_bytes = state.move_as_ok();
    auto config_bytes = config.move_as_ok();
    if (state_bytes.empty() || config_bytes.empty()) return fail("a proof is empty");
    auto state_root = block::check_extract_state_proof(id, state_bytes.as_slice(), config_bytes.as_slice());
    if (state_root.is_error()) return fail("state/config proof does not match the block ID");
    auto cfg = block::Config::extract_from_state(state_root.move_as_ok(), 0);
    if (cfg.is_error()) return fail("configuration is absent from proven state");
    auto actual = cfg.move_as_ok()->get_config_param(30);
    auto expected_cell = vm::std_boc_deserialize(expected.move_as_ok());
    if (actual.is_null() || expected_cell.is_error()) return fail("ConfigParam30 or expected BOC is invalid");
    if (actual->get_hash() != expected_cell.ok()->get_hash()) return fail("ConfigParam30 cell differs from proven state");
    std::printf("Z01_CONFIG_PROOF_OK seqno=%lu root=%s file=%s param30=%s\n", seqno,
                id.root_hash.to_hex().c_str(), id.file_hash.to_hex().c_str(), actual->get_hash().to_hex().c_str());
    return 0;
  }
  return fail("zero block digest");
}
