/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Draft offline replay from an externally authenticated zerostate commitment.
// Signature authority for the anchor is deliberately outside this tool.
#include <charconv>
#include <cstdio>
#include <string>

#include "block/block-db.h"
#include "block/block.h"
#include "block/signature-set.h"
#include "block/check-proof.h"
#include "lite-client/lite-client-common.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "tos/lite-tl.hpp"
#include "tl-utils/lite-utils.hpp"
#include "vm/boc.h"

namespace {
constexpr td::int64 max_file_bytes = 16 * 1024 * 1024;
constexpr int max_responses = 32;
int reject(const std::string& reason) {
  std::fprintf(stderr, "Z01_CHAIN_PROOF_REJECT: %s\n", reason.c_str());
  return 1;
}

td::Result<td::Bits256> digest(const char* input) {
  auto decoded = td::hex_decode(input);
  if (decoded.is_error()) return decoded.move_as_error();
  auto bytes = decoded.move_as_ok();
  if (bytes.size() != 32) return td::Status::Error("digest must be32bytes");
  td::Bits256 result;
  result.as_slice().copy_from(bytes);
  if (result.is_zero()) return td::Status::Error("digest is zero");
  return result;
}

td::Status bind_boc(const char* path, const tos::BlockIdExt& id) {
  TRY_RESULT(raw, td::read_file(path, max_file_bytes + 1));
  if (raw.size() > max_file_bytes) return td::Status::Error("raw BOC exceeds size limit");
  if (block::compute_file_hash(raw.as_slice()) != id.file_hash)
    return td::Status::Error("raw BOC file hash differs from fullID");
  TRY_RESULT(root, vm::std_boc_deserialize(raw.as_slice()));
  if (tos::RootHash{root->get_hash().bits()} != id.root_hash)
    return td::Status::Error("raw BOC root hash differs from fullID");
  return td::Status::OK();
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 9) return reject(
      "usage: z01-chain-proof-check <anchor-root> <anchor-file> <zerostate-boc> "
      "<target-seqno> <target-root> <target-file> <target-block-boc> <raw-chain-tl>...");
  if (argc - 8 > max_responses) return reject("too many proof responses");
  auto anchor_root = digest(argv[1]);
  auto anchor_file = digest(argv[2]);
  auto target_root = digest(argv[5]);
  auto target_file = digest(argv[6]);
  if (anchor_root.is_error() || anchor_file.is_error() || target_root.is_error() || target_file.is_error())
    return reject("invalid fullID digest");
  td::uint32 seqno = 0;
  std::string seqno_text{argv[4]};
  auto parsed = std::from_chars(seqno_text.data(), seqno_text.data() + seqno_text.size(), seqno);
  if (parsed.ec != std::errc{} || parsed.ptr != seqno_text.data() + seqno_text.size() || !seqno)
    return reject("target must have nonzero uint32 seqno");
  const tos::BlockIdExt anchor{-1, 1ULL << 63, 0, anchor_root.move_as_ok(), anchor_file.move_as_ok()};
  const tos::BlockIdExt target{-1, 1ULL << 63, seqno, target_root.move_as_ok(), target_file.move_as_ok()};
  auto anchor_bytes = bind_boc(argv[3], anchor);
  if (anchor_bytes.is_error()) return reject("anchor " + anchor_bytes.to_string());
  auto target_bytes = bind_boc(argv[7], target);
  if (target_bytes.is_error()) return reject("target " + target_bytes.to_string());

  auto current = anchor;
  std::size_t links = 0;
  for (int index = 8; index < argc; ++index) {
    auto raw = td::read_file(argv[index], max_file_bytes + 1);
    if (raw.is_error()) return reject("raw chain response unreadable");
    if (raw.ok().size() > max_file_bytes) return reject("raw chain response exceeds size limit");
    auto parsed_chain = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(raw.move_as_ok(), true);
    if (parsed_chain.is_error()) return reject("raw chain TL invalid: " + parsed_chain.error().to_string());
    auto decoded_chain = liteclient::deserialize_proof_chain(parsed_chain.move_as_ok());
    if (decoded_chain.is_error()) return reject("proof chain deserialization failed: " + decoded_chain.error().to_string());
    auto chain = decoded_chain.move_as_ok();
    if (chain->from != current) return reject("chain source differs from authenticated preceding ID");
    if (!chain->link_count()) return reject("empty proof chain");
    for (const auto& link : chain->links) {
      if (!link.is_fwd || link.to.seqno() <= link.from.seqno()) return reject("chain is not strictly forward");
      if (link.sig_set.is_null() || !link.sig_set->is_pq()) return reject("chain signature set is not PQ");
    }
    if (chain->to.seqno() > target.seqno()) return reject("chain exceeds exact target height");
    const bool last = index == argc - 1;
    if (chain->complete != last) return reject("chain completion differs from response position");
    if (last && chain->to != target) return reject("complete chain differs from exact target ID");
    auto result = chain->validate();
    if (result.is_error()) return reject("PQ chain validation failed: " + result.to_string());
    links += chain->link_count();
    current = chain->to;
  }
  if (current != target || !links) return reject("proof responses do not reach exact target");
  std::printf("Z01_CHAIN_PROOF_OK seqno=%u root=%s file=%s links=%zu\n", seqno,
              target.root_hash.to_hex().c_str(), target.file_hash.to_hex().c_str(), links);
  return 0;
}
