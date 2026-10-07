/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include "lite-client/proof-verify/readonly-query.h"
int main() {
  int failures = 0;
  auto check = [&](const char *name, bool ok) { std::printf("PROOF_READONLY_CASE %s %s\n", name, ok ? "PASS" : "FAIL"); if (!ok) ++failures; };
  auto info = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  check("masterchain-query-accepted", tos::proofverify::checked_readonly_query(info.as_slice()).is_ok());
  auto send = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(td::BufferSlice("public test bytes")), true);
  auto refused = tos::proofverify::checked_readonly_query(send.as_slice());
  check("send-message-refused", refused.is_error() && refused.error().message().str().find("kind refused") != std::string::npos);
  auto nested = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(info.clone()), true);
  check("nested-query-refused", tos::proofverify::checked_readonly_query(nested.as_slice()).is_error());
  check("empty-query-refused", tos::proofverify::checked_readonly_query(td::Slice()).is_error());
  td::BufferSlice large(16385);
  check("oversized-query-refused", tos::proofverify::checked_readonly_query(large.as_slice()).is_error());
  auto block = [] { return tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(-1, (-9223372036854775807LL - 1), 1, td::Bits256::zero(), td::Bits256::zero()); };
  auto config = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(12, block()), true);
  check("execution-config-query-accepted", tos::proofverify::checked_readonly_query(config.as_slice()).is_ok());
  auto params = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(0, block(), std::vector<td::int32>(64, 34)), true);
  check("config-limit-accepted", tos::proofverify::checked_readonly_query(params.as_slice()).is_ok());
  auto extra = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(0, block(), std::vector<td::int32>(65, 34)), true);
  check("config-over-limit-refused", tos::proofverify::checked_readonly_query(extra.as_slice()).is_error());
  auto libraries = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getLibrariesWithProof>(block(), 0, std::vector<td::Bits256>(16, td::Bits256::zero())), true);
  check("library-limit-accepted", tos::proofverify::checked_readonly_query(libraries.as_slice()).is_ok());
  auto too_many = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getLibrariesWithProof>(block(), 0, std::vector<td::Bits256>(17, td::Bits256::zero())), true);
  check("library-over-limit-refused", tos::proofverify::checked_readonly_query(too_many.as_slice()).is_error());
  const std::string payload(256u << 10, 'x');
  auto encoded = tos::proofverify::readonly_reply_json(payload);
  const std::string expected = std::string("{\"reply\":\"") + td::base64_encode(payload) + "\"}";
  check("large-proof-response-not-truncated", encoded.is_ok() && encoded.ok() == expected && encoded.ok().size() > (128u << 10));
  check("empty-proof-response-refused", tos::proofverify::readonly_reply_json(td::Slice()).is_error());
  return failures ? 1 : 0;
}
