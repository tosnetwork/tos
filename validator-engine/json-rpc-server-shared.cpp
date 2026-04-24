/*
    Shared helper implementations for the JSON-RPC server.
    Compiled once, used by multiple domain files via json-rpc-server-internal.h.
*/
#include "json-rpc-server-internal.h"
#include "td/utils/crypto.h"

namespace tos {

td::Result<block::StdAddress> parse_address_param(td::JsonObject& params) {
  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) return td::Status::Error("Missing 'address'");
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_r.ok()))) return td::Status::Error("Invalid address");
  return addr;
}

std::string format_block_id_json(const tos::lite_api::tosNode_blockIdExt& blk) {
  return PSTRING()
      << "{\"@type\":\"tos.blockIdExt\""
      << ",\"workchain\":" << blk.workchain_
      << ",\"shard\":\"" << blk.shard_ << "\""
      << ",\"seqno\":" << blk.seqno_
      << ",\"root_hash\":\"" << td::base64_encode(blk.root_hash_.as_slice()) << "\""
      << ",\"file_hash\":\"" << td::base64_encode(blk.file_hash_.as_slice()) << "\""
      << "}";
}

std::string format_zero_state_json(const tos::lite_api::tosNode_zeroStateIdExt& zs) {
  return PSTRING()
      << "{\"@type\":\"tos.blockIdExt\""
      << ",\"workchain\":" << zs.workchain_
      << ",\"shard\":\"-9223372036854775808\""
      << ",\"seqno\":0"
      << ",\"root_hash\":\"" << td::base64_encode(zs.root_hash_.as_slice()) << "\""
      << ",\"file_hash\":\"" << td::base64_encode(zs.file_hash_.as_slice()) << "\""
      << "}";
}

}  // namespace tos
